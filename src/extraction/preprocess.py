"""OpenCV image preprocessing to improve OCR and QR accuracy."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import cv2
import numpy as np


SUPPORTED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tif", ".tiff", ".gif"}
# Formats that can hold several frames (animated GIF / WebP, multi-page TIFF).
MULTI_FRAME_EXTENSIONS = {".gif", ".webp", ".tif", ".tiff"}
# At most this many frames of an animation are analysed, spread evenly over it.
MAX_FRAMES = 8


@dataclass
class PreprocessBundle:
    """Variants to try for OCR / QR."""

    original_bgr: np.ndarray
    upscaled_gray: np.ndarray
    thresholded: np.ndarray
    deskewed: np.ndarray | None = None
    warped: np.ndarray | None = None


def read_image_info(path: str) -> tuple[int, int, int] | None:
    """
    (width, height, frame count) read from the file header, without decoding any pixels.

    Lets the caller refuse decompression bombs before decoding. Returns None when the
    header cannot be read; the decoder then decides whether the file is an image.
    """
    from PIL import Image

    previous = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = None  # Only the header is read here; the caller applies its own limit.
    try:
        with Image.open(path) as image:
            return image.width, image.height, int(getattr(image, "n_frames", 1))
    except Exception:  # noqa: BLE001 — not an image Pillow understands
        return None
    finally:
        Image.MAX_IMAGE_PIXELS = previous


def load_image(path: str) -> np.ndarray:
    """
    Load an image from disk as BGR. Raises ValueError if it cannot be decoded.

    Reads the bytes with NumPy and decodes them in memory, because cv2.imread cannot
    open paths with non-ASCII characters on Windows.
    """
    data = np.fromfile(path, dtype=np.uint8)
    image = cv2.imdecode(data, cv2.IMREAD_COLOR) if data.size else None
    if image is None:
        raise ValueError(f"Unable to decode image: {path}")
    return image


def load_frames(path: str, frame_count: int = 1, max_frames: int = MAX_FRAMES) -> list[np.ndarray]:
    """
    BGR frames to analyse: the image itself, or up to `max_frames` distinct frames of an
    animated GIF / WebP or multi-page TIFF (near-identical frames are skipped).
    """
    suffix = Path(path).suffix.lower()
    if suffix not in MULTI_FRAME_EXTENSIONS or (frame_count <= 1 and suffix != ".gif"):
        return [load_image(path)]

    from PIL import Image

    max_frames = max(1, min(max_frames, MAX_FRAMES))
    frames: list[np.ndarray] = []
    thumbs: list[np.ndarray] = []
    with Image.open(path) as image:
        total = int(getattr(image, "n_frames", 1))
        if total > max_frames:
            # Spread the frames evenly over the animation (just the first one if only one is allowed).
            step = (total - 1) / (max_frames - 1) if max_frames > 1 else 0
            indices = sorted({round(i * step) for i in range(max_frames)})
        else:
            indices = list(range(total))
        for index in indices:
            image.seek(index)
            # Composite transparent areas on white, as a viewer would show them.
            rgba = image.convert("RGBA")
            canvas = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
            rgb = np.asarray(Image.alpha_composite(canvas, rgba).convert("RGB"))
            bgr = cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)
            thumb = cv2.resize(cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY), (32, 32), interpolation=cv2.INTER_AREA)
            thumb = thumb.astype(np.int16)
            if any(np.abs(thumb - seen).mean() < 2.0 for seen in thumbs):
                continue
            thumbs.append(thumb)
            frames.append(bgr)
    if not frames:
        raise ValueError(f"Unable to decode image: {path}")
    return frames


def _upscale_if_small(gray: np.ndarray, min_side: int = 800) -> np.ndarray:
    h, w = gray.shape[:2]
    side = min(h, w)
    if side >= min_side:
        return gray
    scale = min_side / float(side)
    return cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)


def _deskew(gray: np.ndarray) -> np.ndarray:
    """
    Rotate slightly tilted text (0.5-15 degrees, either direction) back to horizontal.

    Uses estimate_skew, which folds the angle into [-45, 45] and so works with both the
    old ([-90, 0)) and the current ((0, 90]) cv2.minAreaRect angle conventions.
    """
    angle = -estimate_skew(gray)
    if abs(angle) < 0.5 or abs(angle) > 15:
        return gray
    h, w = gray.shape[:2]
    matrix = cv2.getRotationMatrix2D((w / 2, h / 2), angle, 1.0)
    return cv2.warpAffine(
        gray, matrix, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE
    )


def estimate_skew(gray: np.ndarray) -> float:
    """Tilt of the dark (text) pixels in degrees, folded into [-45, 45]."""
    blur = cv2.GaussianBlur(gray, (5, 5), 0)
    _, bw = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
    # Dark text on light ground is the usual case; flip for dark-mode screenshots.
    if float(np.mean(np.asarray(bw))) > 127:
        bw = 255 - bw
    coords = np.column_stack(np.where(bw > 0)).astype(np.float32)
    if len(coords) < 50:
        return 0.0
    angle = float(cv2.minAreaRect(coords)[-1])
    while angle > 45:
        angle -= 90
    while angle < -45:
        angle += 90
    return angle


def rotate_bound(image: np.ndarray, angle: float) -> np.ndarray:
    """Rotate by `angle` degrees, enlarging the canvas so no corner is cut off."""
    h, w = image.shape[:2]
    matrix = cv2.getRotationMatrix2D((w / 2, h / 2), angle, 1.0)
    cos, sin = abs(matrix[0, 0]), abs(matrix[0, 1])
    nw, nh = int(h * sin + w * cos), int(h * cos + w * sin)
    matrix[0, 2] += nw / 2 - w / 2
    matrix[1, 2] += nh / 2 - h / 2
    return cv2.warpAffine(image, matrix, (nw, nh), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)


def rotation_candidates(gray: np.ndarray, garbled: bool) -> list[tuple[str, np.ndarray]]:
    """
    Extra OCR inputs for images rotated beyond normal deskew (> 15 degrees).

    Tries the measured tilt in both directions; when OCR produced text that looks
    like garbage (`garbled`), also tries quarter turns for sideways / upside-down shots.
    """
    out: list[tuple[str, np.ndarray]] = []
    angle = estimate_skew(gray)
    if abs(angle) > 0.5:
        out += [(f"rotated_{angle:+.0f}", rotate_bound(gray, angle)), (f"rotated_{-angle:+.0f}", rotate_bound(gray, -angle))]
    if garbled:
        out += [
            ("rotated_90", cv2.rotate(gray, cv2.ROTATE_90_CLOCKWISE)),
            ("rotated_180", cv2.rotate(gray, cv2.ROTATE_180)),
            ("rotated_270", cv2.rotate(gray, cv2.ROTATE_90_COUNTERCLOCKWISE)),
        ]
    return out


def _order_points(pts: np.ndarray) -> np.ndarray:
    rect = np.zeros((4, 2), dtype="float32")
    s = pts.sum(axis=1)
    rect[0] = pts[np.argmin(s)]
    rect[2] = pts[np.argmax(s)]
    diff = np.diff(pts, axis=1)
    rect[1] = pts[np.argmin(diff)]
    rect[3] = pts[np.argmax(diff)]
    return rect


def _perspective_warp(bgr: np.ndarray) -> np.ndarray | None:
    """
    If a large quadrilateral (page / phone screen) is found, warp to a flat view.
    Returns None when no confident document contour exists.
    """
    h, w = bgr.shape[:2]
    ratio = 500.0 / max(h, 1)
    small = cv2.resize(bgr, (int(w * ratio), int(h * ratio)))
    gray = cv2.cvtColor(small, cv2.COLOR_BGR2GRAY)
    blur = cv2.GaussianBlur(gray, (5, 5), 0)
    edged = cv2.Canny(blur, 50, 150)
    contours, _ = cv2.findContours(edged, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)
    contours = sorted(contours, key=cv2.contourArea, reverse=True)[:8]
    screen_area = small.shape[0] * small.shape[1]
    for cnt in contours:
        peri = cv2.arcLength(cnt, True)
        approx = cv2.approxPolyDP(cnt, 0.02 * peri, True)
        if len(approx) != 4:
            continue
        area = cv2.contourArea(approx)
        if area < 0.25 * screen_area:
            continue
        pts = approx.reshape(4, 2).astype("float32") / ratio
        rect = _order_points(pts)
        (tl, tr, br, bl) = rect
        width_a = np.linalg.norm(br - bl)
        width_b = np.linalg.norm(tr - tl)
        max_w = int(max(width_a, width_b))
        height_a = np.linalg.norm(tr - br)
        height_b = np.linalg.norm(tl - bl)
        max_h = int(max(height_a, height_b))
        if max_w < 40 or max_h < 40:
            continue
        dst = np.array(
            [[0, 0], [max_w - 1, 0], [max_w - 1, max_h - 1], [0, max_h - 1]],
            dtype="float32",
        )
        matrix = cv2.getPerspectiveTransform(rect, dst)
        return cv2.warpPerspective(bgr, matrix, (max_w, max_h))
    return None


def preprocess(bgr: np.ndarray) -> PreprocessBundle:
    """
    Build OCR-friendly variants: denoise, grayscale+CLAHE, threshold, deskew, optional warp.
    """
    # Mild bilateral filter preserves edges while reducing sensor noise.
    denoised = cv2.bilateralFilter(bgr, d=7, sigmaColor=50, sigmaSpace=50)
    gray = cv2.cvtColor(denoised, cv2.COLOR_BGR2GRAY)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(gray)
    upscaled = _upscale_if_small(enhanced)

    # Otsu + adaptive combination: use adaptive when lighting is uneven.
    _, otsu = cv2.threshold(upscaled, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    adaptive = cv2.adaptiveThreshold(
        upscaled, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 11
    )
    # Prefer the variant with more near-white text region contrast.
    thresholded = otsu if float(np.mean(np.asarray(otsu))) > 80 else adaptive

    deskewed = _deskew(upscaled)
    warped_bgr = _perspective_warp(denoised)
    warped_gray = None
    if warped_bgr is not None:
        wg = cv2.cvtColor(warped_bgr, cv2.COLOR_BGR2GRAY)
        warped_gray = _upscale_if_small(clahe.apply(wg))

    return PreprocessBundle(
        original_bgr=bgr,
        upscaled_gray=upscaled,
        thresholded=thresholded,
        deskewed=deskewed,
        warped=warped_gray,
    )


def variants_for_ocr(bundle: PreprocessBundle) -> list[tuple[str, np.ndarray]]:
    """Ordered list of (name, image) candidates for OCR."""
    out: list[tuple[str, np.ndarray]] = [
        ("original_color", bundle.original_bgr),
        ("upscaled_gray", bundle.upscaled_gray),
        ("thresholded", bundle.thresholded),
    ]
    if bundle.deskewed is not None:
        out.append(("deskewed", bundle.deskewed))
    if bundle.warped is not None:
        out.append(("warped", bundle.warped))
    return out
