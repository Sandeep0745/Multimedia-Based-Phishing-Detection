"""
Command-line interface for Multimedia-Based Phishing Detection.

Examples:
  python -m src.cli analyze path/to/image.png
  python -m src.cli analyze path/to/image.png --json -o report.json
  python -m src.cli batch path/to/folder -o reports --summary reports/summary.csv
  python -m src.cli batch path/to/folder --workers 4 --fail-on suspicious
  python -m src.cli evaluate data/samples

Exit codes:
  0  finished (with --fail-on: no file reached that level)
  1  with --fail-on: a file reached the level; evaluate: a label did not match
  2  a file could not be analysed, or bad input (missing folder, no images); wins over 1
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from pathlib import Path

from src.core.config import load_scoring
from src.core.models import AnalysisResult
from src.core.pipeline import analyze_file, analyze_paths
from src.extraction.preprocess import SUPPORTED_EXTENSIONS
from src.reporting.redact import redact_result
from src.reporting.report import format_text_report, write_report, write_summary

# Default per-file limit for batch / evaluate; each file then runs in a worker process.
DEFAULT_TIMEOUT_SECONDS = 300.0


def _utf8_output() -> None:
    """Reports can contain any Unicode (homoglyph links, Rs symbol); never crash on a narrow code page."""
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
        if encoding != "utf8":
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
            except (AttributeError, ValueError, OSError):
                pass


def _collect_images(folder: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(folder.rglob("*")):
        if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS:
            files.append(path)
    return files


def _report_paths(images: list[Path], folder: Path, out_dir: Path, extension: str) -> list[Path]:
    """
    Report file for each image: the same sub-folder under `out_dir`, named after the image.

    Images that would share a report name (x.png and x.jpg) keep their own extension in
    it (x.png.txt), so no report overwrites another.
    """
    targets = [out_dir / p.relative_to(folder).with_suffix(extension) for p in images]
    counts = Counter(targets)
    return [
        out_dir / p.relative_to(folder).parent / (p.name + extension) if counts[t] > 1 else t
        for p, t in zip(images, targets, strict=True)
    ]


def _fail_labels(level: str | None) -> set[str]:
    """Classifications that make --fail-on LEVEL exit with 1. Inconclusive counts at "suspicious"."""
    labels = load_scoring()["labels"]
    if level == "high-risk":
        return {labels["high_risk"]}
    if level == "suspicious":
        return {labels["suspicious"], labels["high_risk"], labels["inconclusive"]}
    return set()


def _exit_code(results: list[AnalysisResult], fail_on: str | None) -> int:
    if any(r.status == "error" for r in results):
        return 2
    failing = _fail_labels(fail_on)
    return 1 if any(r.classification in failing for r in results) else 0


def _progress(total: int, names: list[str]):
    """Callback printing "[ 3/33] name -> verdict" to stderr when it is an interactive terminal."""
    if not sys.stderr.isatty():
        return None
    done = 0

    def report(index: int, result: AnalysisResult) -> None:
        nonlocal done
        done += 1
        print(
            f"[{done:>{len(str(total))}}/{total}] {names[index]} -> {result.classification} ({result.threat_score})",
            file=sys.stderr,
            flush=True,
        )

    return report


def _print_summary(results: list[AnalysisResult]) -> None:
    labels = load_scoring()["labels"]
    order = [labels["high_risk"], labels["suspicious"], labels["inconclusive"], labels["safe"], labels["error"]]
    counts = Counter(r.classification for r in results)
    parts = [f"{label}: {counts[label]}" for label in order if counts[label]]
    print(f"Summary: {len(results)} file(s) - " + ", ".join(parts), file=sys.stderr)


def cmd_analyze(args: argparse.Namespace) -> int:
    result = analyze_file(args.image)
    body = write_report(result, Path(args.output) if args.output else None, as_json=args.json, redact=args.redact)
    print(body)
    return _exit_code([result], args.fail_on)


def cmd_batch(args: argparse.Namespace) -> int:
    folder = Path(args.folder)
    if not folder.is_dir():
        print(f"Not a directory: {folder}", file=sys.stderr)
        return 2
    images = _collect_images(folder)
    if not images:
        print(f"No images found in {folder}", file=sys.stderr)
        return 2
    names = [str(p.relative_to(folder)) for p in images]
    results = analyze_paths(
        images, workers=args.workers, timeout=args.timeout or None, on_result=_progress(len(images), names)
    )

    if args.output:
        targets = _report_paths(images, folder, Path(args.output), ".json" if args.json else ".txt")
        for result, target in zip(results, targets, strict=True):
            write_report(result, target, as_json=args.json, redact=args.redact)
    if args.json:
        # Only JSON on stdout, so the output can be piped into other tools.
        shown = [redact_result(r) if args.redact else r for r in results]
        print(json.dumps([r.to_dict() for r in shown], indent=2))
    else:
        for result in results:
            print(format_text_report(result, redact=args.redact))
            print()
    if args.summary:
        write_summary(results, Path(args.summary), redact=args.redact)
    _print_summary(results)
    return _exit_code(results, args.fail_on)


def _group(allowed: list[str]) -> str:
    return " or ".join(allowed)


def cmd_evaluate(args: argparse.Namespace) -> int:
    """
    Compare predictions against labels.json in a samples directory.

    labels.json format: { "filename.png": "Safe"|"Suspicious"|"High-Risk Phishing" | [allowed, ...], ... }
    """
    folder = Path(args.folder)
    labels_path = folder / "labels.json"
    if not labels_path.is_file():
        print(f"Missing labels.json in {folder}", file=sys.stderr)
        print(
            "Create one with: python data/samples/generate_samples.py, python make_test_qr.py "
            "or python make_test_images.py (or write labels.json yourself)",
            file=sys.stderr,
        )
        return 2
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    passed = 0
    failed = 0
    present: list[tuple[str, list[str]]] = []
    for filename, expected in labels.items():
        allowed = expected if isinstance(expected, list) else [expected]
        if not (folder / filename).is_file():
            print(f"FAIL  {filename}: file missing")
            failed += 1
        else:
            present.append((filename, allowed))

    results: dict[int, AnalysisResult] = {}
    next_to_print = 0

    def show(index: int, result: AnalysisResult) -> None:
        """Print verdicts in labels.json order as soon as all earlier files are done."""
        nonlocal next_to_print, passed, failed
        results[index] = result
        while next_to_print in results:
            filename, allowed = present[next_to_print]
            r = results[next_to_print]
            ok = r.classification in allowed
            print(f"{'PASS' if ok else 'FAIL'}  {filename}: expected={allowed} got={r.classification} score={r.threat_score}")
            if ok:
                passed += 1
            else:
                failed += 1
                for reason in (r.reasons + [f"! {e}" for e in r.errors])[:8]:
                    print(f"       - {reason}")
            next_to_print += 1

    analyze_paths(
        [folder / name for name, _ in present], workers=args.workers, timeout=args.timeout or None, on_result=show
    )

    # Confusion matrix: expected label group (rows) against the classification given (columns).
    columns = list(load_scoring()["labels"].values())
    rows = list(dict.fromkeys(_group(allowed) for _, allowed in present))
    matrix = Counter((_group(allowed), results[i].classification) for i, (_, allowed) in enumerate(present))
    if present:
        width = max(len(r) for r in rows + ["expected \\ got"])
        print("\n" + "expected \\ got".ljust(width) + "".join(f"  {c:>{len(c)}}" for c in columns))
        for row in rows:
            print(row.ljust(width) + "".join(f"  {matrix[(row, c)]:>{len(c)}}" for c in columns))
    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


def _add_batch_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workers", type=int, default=1, help="Files analysed in parallel (default 1)")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Seconds allowed per file before it is reported as an error (default {DEFAULT_TIMEOUT_SECONDS:g}; 0 = no limit)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="multimedia-phishing-detection",
        description="Detect phishing signals hidden in images, QR codes, and screenshots.",
        epilog="Exit codes: 0 done, 1 --fail-on level reached / evaluate mismatch, 2 unreadable file or bad input.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Log diagnostic details to stderr")
    sub = parser.add_subparsers(dest="command", required=True)
    fail_help = "Exit with 1 if a file is classified at this level or higher (suspicious also counts Inconclusive)"

    p_an = sub.add_parser("analyze", help="Analyze a single image")
    p_an.add_argument("image", help="Path to image file")
    p_an.add_argument("--json", action="store_true", help="Emit JSON report")
    p_an.add_argument("-o", "--output", help="Write report to this path")
    p_an.add_argument("--redact", action="store_true", help="Mask phone numbers, OTPs, e-mail / UPI ids, Wi-Fi passwords")
    p_an.add_argument("--fail-on", choices=("suspicious", "high-risk"), help=fail_help)
    p_an.set_defaults(func=cmd_analyze)

    p_batch = sub.add_parser("batch", help="Analyze all images in a folder (and its sub-folders)")
    p_batch.add_argument("folder", help="Folder of images")
    p_batch.add_argument("--json", action="store_true", help="Emit JSON reports")
    p_batch.add_argument("-o", "--output", help="Directory for per-file reports")
    p_batch.add_argument("--summary", help="Write one line per file to this .csv or .jsonl file")
    p_batch.add_argument("--redact", action="store_true", help="Mask phone numbers, OTPs, e-mail / UPI ids, Wi-Fi passwords")
    p_batch.add_argument("--fail-on", choices=("suspicious", "high-risk"), help=fail_help)
    _add_batch_options(p_batch)
    p_batch.set_defaults(func=cmd_batch)

    p_eval = sub.add_parser("evaluate", help="Check predictions against labels.json")
    p_eval.add_argument("folder", nargs="?", default="data/samples", help="Samples folder")
    _add_batch_options(p_eval)
    p_eval.set_defaults(func=cmd_evaluate)

    return parser


def main(argv: list[str] | None = None) -> int:
    _utf8_output()
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s: %(message)s")
    if getattr(args, "workers", 1) < 1:
        parser.error("--workers must be at least 1")
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
