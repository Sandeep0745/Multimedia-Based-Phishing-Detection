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


def predict_phishing_probability(url: str) -> float | None:
    """
    Return P(phishing) in [0, 1] for the URL's hostname, or None if unavailable.

    Callers must treat this as raise-only — never lower a heuristic score.
    """
    model = _load_model()
    host = normalize_host(url)
    if model is None or not host:
        return None
    try:
        return float(model.predict_proba([host])[0][1])
    except Exception as exc:  # noqa: BLE001 — never let the optional model break a scan
        if _problem is None:
            _set_problem(f"ML model not used: prediction failed ({type(exc).__name__}: {exc})")
        return None


def load_hosts(csv_path: Path) -> tuple[list[str], list[int]]:
    """
    Read PhiUSIIL and return unique hostnames with labels (1 = phishing).

    PhiUSIIL uses label 1 = legitimate, 0 = phishing, so labels are inverted.
    Hosts that appear under both labels are dropped as ambiguous.
    """
    labels: dict[str, set[int]] = {}
    with csv_path.open(encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            host = normalize_host(row["URL"])
            if host:
                labels.setdefault(host, set()).add(1 - int(row["label"]))
    hosts = [h for h, ys in labels.items() if len(ys) == 1]
    return hosts, [next(iter(labels[h])) for h in hosts]


def build_pipeline() -> Any:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(2, 5),
                    min_df=3,
                    max_features=300_000,
                    sublinear_tf=True,
                ),
            ),
            ("clf", LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced")),
        ]
    )


def _metrics_at(y_true: list[int], proba: list[float], threshold: float) -> dict[str, float]:
    tp = sum(1 for y, p in zip(y_true, proba, strict=True) if p >= threshold and y == 1)
    fp = sum(1 for y, p in zip(y_true, proba, strict=True) if p >= threshold and y == 0)
    fn = sum(1 for y, p in zip(y_true, proba, strict=True) if p < threshold and y == 1)
    tn = sum(1 for y, p in zip(y_true, proba, strict=True) if p < threshold and y == 0)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "threshold": threshold,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
        "accuracy": round((tp + tn) / len(y_true), 4),
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
    }


def train_and_save(csv_path: Path | None = None, out_path: Path | None = None) -> dict[str, Any]:
    """
    Train on PhiUSIIL hostnames, evaluate on a held-out 20%, then refit on all data.

    The split groups hosts by registrable domain so sub-domains of one site never
    land on both sides. Metrics are written to data/model/metrics.json.
    """
    import joblib
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import GroupShuffleSplit

    from src.analysis.domains import registrable_domain

    csv_path = csv_path or dataset_path()
    out_path = out_path or model_path()
    if not csv_path.is_file():
        raise FileNotFoundError(f"{csv_path} not found. Run: python -m src.model.download_data")

    hosts, labels = load_hosts(csv_path)
    groups = [registrable_domain(h) for h in hosts]
    train_idx, test_idx = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42).split(hosts, labels, groups))

    pipe = build_pipeline()
    pipe.fit([hosts[i] for i in train_idx], [labels[i] for i in train_idx])
    y_test = [labels[i] for i in test_idx]
    proba = [float(p) for p in pipe.predict_proba([hosts[i] for i in test_idx])[:, 1]]

    metrics: dict[str, Any] = {
        "dataset": csv_path.name,
        "unique_hosts": len(hosts),
        "phishing_hosts": sum(labels),
        "legitimate_hosts": len(labels) - sum(labels),
        "test_hosts": len(test_idx),
        "roc_auc": round(roc_auc_score(y_test, proba), 4),
        "at_thresholds": [_metrics_at(y_test, proba, t) for t in (0.5, 0.7, 0.9)],
    }

    # Final model uses every labelled host.
    pipe = build_pipeline()
    pipe.fit(hosts, labels)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, out_path, compress=3)
    write_model_meta(out_path, dataset=csv_path.name, unique_hosts=len(hosts))
    (MODEL_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    reset_model_cache()
    return metrics


def reset_model_cache() -> None:
    """Forget the loaded model and any load problem (after retraining, or in tests)."""
    global _problem
    _problem = None
    _load_model.cache_clear()
