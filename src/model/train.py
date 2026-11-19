"""Train the hostname phishing model: python -m src.model.train"""

from __future__ import annotations

import argparse
from pathlib import Path

from src.core.config import model_path
from src.model.classifier import train_and_save


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the URL phishing model on PhiUSIIL.")
    parser.add_argument("--dataset", type=Path, help="Path to PhiUSIIL_Phishing_URL_Dataset.csv")
    args = parser.parse_args()

    print("Training on real-world URLs (takes about a minute)...")
    m = train_and_save(args.dataset)
    print(f"Saved model to {model_path()}")
    print(
        f"Hosts: {m['unique_hosts']} ({m['phishing_hosts']} phishing, {m['legitimate_hosts']} legitimate); "
        f"held-out test set: {m['test_hosts']}"
    )
    print(f"ROC AUC: {m['roc_auc']}")
    print(f"{'threshold':>9} {'precision':>9} {'recall':>7} {'f1':>6} {'accuracy':>8} {'FPR':>6}")
    for row in m["at_thresholds"]:
        print(
            f"{row['threshold']:>9} {row['precision']:>9} {row['recall']:>7} {row['f1']:>6} "
            f"{row['accuracy']:>8} {row['false_positive_rate']:>6}"
        )


if __name__ == "__main__":
    main()
