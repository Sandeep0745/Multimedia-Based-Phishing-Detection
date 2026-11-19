"""
Real-world URL evaluation: python -m src.model.evaluate_realworld

Scores data the model never trained on:
- live phishing URLs from the OpenPhish feed (data/config/openphish_feed.txt)
- legitimate sites ranked just below the trusted top-domain list
  (data/datasets/legit_holdout.txt)

The blocklist is switched off, so this measures the heuristics + ML model alone.
A threshold sweep shows how detection and false alarms trade off at other score cut-offs.
Run `python -m src.model.download_data` first to fetch fresh data.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from src.analysis.url_analysis import analyze_url
from src.classification.scorer import label_for_score
from src.core.config import CONFIG_DIR, DATA_DIR, MODEL_DIR, load_scoring

# Score cut-offs for the sweep: a URL counts as flagged when its score is above the cut-off.
# 34 is the current Safe / Suspicious boundary and 69 the Suspicious / High-Risk one.
SWEEP_CUTOFFS = (20, 25, 30, 34, 40, 45, 50, 55, 60, 69, 80)


def _read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]


def evaluate(phish: list[str], legit: list[str]) -> dict[str, Any]:
    """Detection and false-alarm rates with the blocklist off (the feed would otherwise match itself)."""
    phish_scores = [analyze_url(u, use_blocklist=False).score for u in phish]
    legit_scores = [analyze_url(u, use_blocklist=False).score for u in legit]
    p = Counter(label_for_score(s) for s in phish_scores)
    l = Counter(label_for_score(s) for s in legit_scores)  # noqa: E741
    safe = load_scoring()["labels"]["safe"]
    caught = len(phish) - p[safe]
    flagged = len(legit) - l[safe]
    return {
        "phishing_urls": len(phish),
        "phishing_detected": caught,
        "detection_rate": round(caught / len(phish), 4),
        "phishing_breakdown": dict(p),
        "legitimate_urls": len(legit),
        "legitimate_flagged": flagged,
        "false_positive_rate": round(flagged / len(legit), 4),
        "legitimate_breakdown": dict(l),
        "threshold_sweep": [
            {
                "flag_above": cutoff,
                "detection_rate": round(sum(s > cutoff for s in phish_scores) / len(phish), 4),
                "false_positive_rate": round(sum(s > cutoff for s in legit_scores) / len(legit), 4),
            }
            for cutoff in SWEEP_CUTOFFS
        ],
    }


def main() -> None:
    phish = _read_lines(CONFIG_DIR / "openphish_feed.txt")
    legit = ["https://" + d + "/" for d in _read_lines(DATA_DIR / "datasets" / "legit_holdout.txt")]
    if not phish or not legit:
        print("Missing data. Run: python -m src.model.download_data")
        raise SystemExit(2)

    result = evaluate(phish, legit)
    caught, flagged = result["phishing_detected"], result["legitimate_flagged"]
    print(
        f"Live phishing (OpenPhish): {caught}/{len(phish)} detected = {result['detection_rate']:.1%}  "
        f"{result['phishing_breakdown']}"
    )
    print(
        f"Legitimate (held-out):     {flagged}/{len(legit)} flagged  = {result['false_positive_rate']:.1%}  "
        f"{result['legitimate_breakdown']}"
    )
    print("\nThreshold sweep (flag when score > cut-off):")
    print(f"{'cut-off':>8} {'detection':>10} {'false alarms':>13}")
    for row in result["threshold_sweep"]:
        marker = "  <- current Safe band" if row["flag_above"] == load_scoring()["bands"]["safe_max"] else ""
        print(f"{row['flag_above']:>8} {row['detection_rate']:>10.1%} {row['false_positive_rate']:>13.1%}{marker}")
    (MODEL_DIR / "realworld_metrics.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\nSaved {MODEL_DIR / 'realworld_metrics.json'}")


if __name__ == "__main__":
    main()
