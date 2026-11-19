"""ML model loading: checksum record, load failures and version mismatches are reported, never silent."""

from __future__ import annotations

import warnings

import joblib
import pytest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

import src.model.classifier as clf

HOSTS = ["paypa1-login.xyz", "secure-verify-now.top", "amaz0n-prize.tk", "login-update-bank.icu",
         "google.com", "wikipedia.org", "python.org", "github.com"]
LABELS = [1, 1, 1, 1, 0, 0, 0, 0]


@pytest.fixture
def model_file(tmp_path, monkeypatch):
    """A tiny trained model in a temporary data/model folder, with its checksum record."""
    pipe = Pipeline([("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 3))), ("clf", LogisticRegression())])
    pipe.fit(HOSTS, LABELS)
    path = tmp_path / "url_model.joblib"
    joblib.dump(pipe, path)
    clf.write_model_meta(path, dataset="toy")
    monkeypatch.setattr(clf, "model_path", lambda: path)
    clf.reset_model_cache()
    yield path
    clf.reset_model_cache()


def test_model_with_matching_checksum_is_used(model_file):
    assert clf.model_meta_path(model_file).is_file()
    assert clf.predict_phishing_probability("https://paypa1-login.xyz/") is not None
    assert clf.model_warning() is None


def test_tampered_model_is_refused_with_a_warning(model_file):
    with model_file.open("ab") as fh:
        fh.write(b"tampered")
    clf.reset_model_cache()
    assert clf.predict_phishing_probability("https://paypa1-login.xyz/") is None
    assert "checksum" in clf.model_warning()


def test_unloadable_model_is_reported(model_file):
    model_file.write_bytes(b"not a pickle")
    clf.model_meta_path(model_file).unlink()
    clf.reset_model_cache()
    assert clf.predict_phishing_probability("https://example.com/") is None
    assert "could not load" in clf.model_warning()


def test_model_from_other_sklearn_version_is_flagged(model_file, monkeypatch):
    class InconsistentVersionWarning(UserWarning):
        pass

    real_load = joblib.load

    def load_with_warning(path):
        warnings.warn(InconsistentVersionWarning("Trying to unpickle estimator from version 1.0 when using 1.9.1"), stacklevel=2)
        return real_load(path)

    monkeypatch.setattr(joblib, "load", load_with_warning)
    clf.reset_model_cache()
    assert clf.predict_phishing_probability("https://paypa1-login.xyz/") is not None  # still used
    assert "another scikit-learn version" in clf.model_warning()


def test_missing_model_is_not_a_warning(tmp_path, monkeypatch):
    monkeypatch.setattr(clf, "model_path", lambda: tmp_path / "absent.joblib")
    clf.reset_model_cache()
    try:
        assert clf.predict_phishing_probability("https://example.com/") is None
        assert clf.model_warning() is None
    finally:
        clf.reset_model_cache()


def test_pipeline_result_carries_the_model_warning(model_file, tmp_path):
    import qrcode

    from src.core.pipeline import analyze_file

    model_file.write_bytes(b"broken")
    clf.model_meta_path(model_file).unlink()
    clf.reset_model_cache()
    image = tmp_path / "qr.png"
    qrcode.make("http://unknown-shop-offer.example/deal").save(image)
    result = analyze_file(image)
    assert any("ML model not used" in e for e in result.errors)
