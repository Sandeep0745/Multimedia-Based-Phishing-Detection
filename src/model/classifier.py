"""
Hostname phishing classifier trained on the PhiUSIIL real-world URL dataset.

The model reads only the hostname (``www.`` removed), as character n-grams.
PhiUSIIL's legitimate URLs are all bare ``https://www.<domain>`` homepages while
phishing URLs carry paths, so training on full URLs would teach the shortcut
"has a path = phishing". Path cues are left to the heuristic rules instead.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import platform
import warnings
from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Any

from src.core.config import MODEL_DIR, dataset_path, model_path
from src.extraction.urls import safe_urlparse

logger = logging.getLogger(__name__)

# Why the model file was not used (load error, checksum or version mismatch); None if fine.
_problem: str | None = None


def model_meta_path(path: Path | None = None) -> Path:
    """data/model/url_model.meta.json: checksum and library versions recorded at training time."""
    path = path or model_path()
    return path.with_name(path.stem + ".meta.json")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_model_meta(path: Path, **extra: Any) -> dict[str, Any]:
    """Record the model file's SHA-256 and the library versions that produced it."""
    import numpy
    import sklearn

    meta = {
        "sha256": _sha256(path),
        "sklearn_version": sklearn.__version__,
        "numpy_version": numpy.__version__,
        "python_version": platform.python_version(),
        "created": date.today().isoformat(),
        **extra,
    }
    model_meta_path(path).write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return meta


def _set_problem(message: str) -> None:
    global _problem
    _problem = message
    logger.warning(message)


def model_warning() -> str | None:
    """A one-line reason the ML model could not be used in this process, or None."""
    return _problem


def _check_model_file(path: Path) -> str | None:
    """Reason to refuse the model file, or None. A .joblib file can run code when loaded."""
    meta_path = model_meta_path(path)
    if not meta_path.is_file():
        logger.info("No checksum record for %s; train with python -m src.model.train to create one", path.name)
        return None
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return f"ML model not used: unreadable {meta_path.name} ({exc})"
    expected = meta.get("sha256")
    if expected and _sha256(path) != expected:
        return (
            f"ML model not used: {path.name} does not match the checksum in {meta_path.name} "
            "(retrain with: python -m src.model.train)"
        )
    return None


def normalize_host(url: str) -> str:
    """Lower-case hostname without ``www.``, port, or trailing dot."""
    url = url.strip()
    parsed = safe_urlparse(url if "://" in url else "http://" + url)
    host = ((parsed.hostname if parsed else "") or "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


@lru_cache(maxsize=1)
def _load_model() -> Any | None:
    """
    The trained pipeline, or None. A missing model is normal (heuristics only); a model
    that fails its checksum, cannot be loaded or was saved by another scikit-learn
    version is reported through model_warning() instead of being skipped silently.
    """
    path = model_path()
    if not path.is_file():
        return None
    problem = _check_model_file(path)
    if problem:
        _set_problem(problem)
        return None
    try:
        import joblib

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            model = joblib.load(path)
    except Exception as exc:  # noqa: BLE001 — corrupt file, missing scikit-learn, incompatible pickle
        _set_problem(
            f"ML model not used: could not load {path.name} ({type(exc).__name__}: {exc}); "
            "retrain with: python -m src.model.train"
        )
        return None
    for warning in caught:
        if type(warning.message).__name__ == "InconsistentVersionWarning":
            _set_problem(
                f"ML model was saved by another scikit-learn version and may misbehave; "
                f"retrain with: python -m src.model.train ({str(warning.message).splitlines()[0][:160]})"
            )
            break
    return model


