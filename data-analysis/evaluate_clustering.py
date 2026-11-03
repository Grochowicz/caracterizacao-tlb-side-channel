#!/usr/bin/env python3

import csv
import sys
from itertools import combinations
from pathlib import Path


def execution_identity(attack):
    """
    Treat all TLBleed variants as one attack family. Other attacks
    are identified by their exact attack name.
    """
    if attack.startswith("tlbleed_"):
        return "tlbleed"
    return attack


def read_clusters(filename):
    rows = []

    with open(filename, newline="") as f:
        reader = csv.DictReader(f)

        required = {"attack", "attempt", "cluster"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                f"Missing required columns: {', '.join(sorted(missing))}"
            )

        for row in reader:
            attack = row["attack"].strip()
            if attack == "baseline":
                continue

            rows.append({
                "attack": attack,
                "attempt": int(row["attempt"]),
                "status": row.get("status", ""),
                "cluster": int(row["cluster"]),
            })

    return rows


def evaluate(rows):
    tp = fp = tn = fn = 0

    for left, right in combinations(rows, 2):
        same_attack = (
            execution_identity(left["attack"])
            == execution_identity(right["attack"])
        )
        same_cluster = left["cluster"] == right["cluster"]

        if same_attack and same_cluster:
            tp += 1
        elif not same_attack and same_cluster:
            fp += 1
        elif not same_attack and not same_cluster:
            tn += 1
        else:
            fn += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    return {
        "executions": len(rows),
        "pairs": total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "accuracy": accuracy,
        "f1": f1,
    }


def main():
    if len(sys.argv) not in (2, 3):
        print(
            f"Usage: {sys.argv[0]} <clusters_csv> "
            "[output_csv]"
        )
        return 1

    input_path = Path(sys.argv[1])
    output_path = (
        Path(sys.argv[2])
        if len(sys.argv) == 3
        else input_path.with_name(
            input_path.stem + "_pairwise.csv"
        )
    )

    if not input_path.is_file():
        print(f"Error: input file does not exist: {input_path}")
        return 1

    try:
        rows = read_clusters(input_path)
        metrics = evaluate(rows)
    except (OSError, ValueError) as error:
        print(f"Error: {error}")
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(metrics),
        )
        writer.writeheader()
        writer.writerow(metrics)

    print("Pairwise clustering evaluation")
    print("--------------------------------")
    for key, value in metrics.items():
        if isinstance(value, float):
            print(f"{key}: {value:.6f}")
        else:
            print(f"{key}: {value}")
    print(f"Report written to {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
