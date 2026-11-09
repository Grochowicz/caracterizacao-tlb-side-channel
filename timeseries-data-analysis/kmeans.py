#!/usr/bin/env python3

import csv
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

from tslearn.clustering import TimeSeriesKMeans
from tslearn.utils import to_time_series_dataset


SAKOE_CHIBA_RADIUS = 200


METADATA_COLUMNS = {
    "attack",
    "attempt",
    "status",
    "time",
}

EXCLUDED_FEATURES = {
    "attack_cpu",
    "attack_mem",
    "attack_time",
}

ATTACK_LABELS = {
    "dpm_leak": "generic",
    "vmalloc_leak": "generic",
    "vmemmap_leak": "generic",
    "msg_msg_leak": "heap",
    "file_leak": "heap",
    "seq_file_leak": "heap",
    "pipe_buffer_leak": "heap",
    "pt_leak": "page-table",
    "pmd_leak": "page-table",
    "pud_leak": "page-table",
    "tlbleed_rn1": "tlbleed",
    "tlbleed_rn2": "tlbleed",
    "tlbleed_rj1": "tlbleed",
    "tlbleed_rj2": "tlbleed",
    "advanced_slubstick": "attacks",
    "pipe_unlink": "attacks",
    "dirty_page": "attacks",
    "stack_attack": "attacks",
}


def load_csv(filename):
    executions = defaultdict(list)

    with open(filename, newline="") as f:
        reader = csv.DictReader(f)

        # Normalize column names by removing surrounding whitespace.
        original_names = reader.fieldnames
        normalized_names = [
            name.strip() for name in original_names
        ]

        feature_names = [
            name
            for name in normalized_names
            if name not in METADATA_COLUMNS
            and name not in EXCLUDED_FEATURES
        ]

        for row in reader:

            # Map original CSV headers to normalized names.
            row = {
                normalized_names[i]: value
                for i, value in enumerate(row.values())
                if i < len(normalized_names)
            }

            key = (
                row["attack"],
                int(row["attempt"]),
                row["status"],
            )

            values = []

            for name in feature_names:
                value = row[name]

                if value is None or value.strip() == "":
                    values.append(0.0)
                else:
                    try:
                        values.append(float(value))
                    except ValueError:
                        values.append(0.0)

            executions[key].append(
                (float(row["time"]), values)
            )

    # Ensure chronological ordering.
    for key in executions:
        executions[key].sort(key=lambda x: x[0])

    return executions, feature_names


def filter_high_correlation_features(pearson_csv, feature_names):
    """
    Read pearson correlation CSV and exclude variable_2 if pearson >= 0.9.
    Returns filtered feature names and a set of excluded features.
    """
    features_to_exclude = set()

    with open(pearson_csv, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                pearson_val = float(row["pearson"].strip())
                if pearson_val >= 0.9:
                    var2 = row["variable_2"].strip()
                    features_to_exclude.add(var2)
            except (ValueError, KeyError):
                continue

    filtered_feature_names = [
        f for f in feature_names if f not in features_to_exclude
    ]

    return filtered_feature_names, features_to_exclude


def normalize_features(series, feature_names):
    """
    Normalize each feature independently.

    Each feature is divided by its maximum absolute value
    across all executions and retained timestamps.
    """

    # Find maximum absolute value for each feature.
    maxima = np.zeros(len(feature_names))

    for data in series:
        maxima = np.maximum(
            maxima,
            np.max(np.abs(data), axis=0),
        )

    # Avoid division by zero for constant-zero features.
    maxima[maxima == 0] = 1.0

    print("Feature normalization")
    print("---------------------")

    for name, maximum in zip(feature_names, maxima):
        print(f"{name}: max = {maximum}")

    print()

    # Normalize every execution using the same feature maxima.
    normalized = [
        data / maxima
        for data in series
    ]

    return normalized


def main():

    if len(sys.argv) != 5:
        print(
            f"usage: {sys.argv[0]} "
            "<n_clusters> <input_file> <output_file> <pearson_csv>"
        )
        return 1

    try:
        n_clusters = int(sys.argv[1])
    except ValueError:
        print("error: n_clusters must be an integer")
        return 1

    if n_clusters <= 0:
        print("error: n_clusters must be greater than zero")
        return 1

    input_file = sys.argv[2]
    output_file = sys.argv[3]
    pearson_csv = sys.argv[4]

    executions, feature_names = load_csv(input_file)

    if not executions:
        print("error: no executions found")
        return 1

    # Filter out features where variable_2 has Pearson correlation >= 0.9
    filtered_feature_names, excluded_pearson = filter_high_correlation_features(
        pearson_csv, feature_names
    )

    indices_to_keep = [
        i for i, name in enumerate(feature_names) if name in set(filtered_feature_names)
    ]

    print("Pearson Correlation Filter (>= 0.9)")
    print("-----------------------------------")
    print(f"Original features count: {len(feature_names)}")
    print(f"Features excluded:       {len(excluded_pearson)}")
    if excluded_pearson:
        print(f"Excluded: {', '.join(sorted(excluded_pearson))}")
    print(f"Remaining features:      {len(filtered_feature_names)}")
    print()

    feature_names = filtered_feature_names

    series = []
    metadata = []

    print("Dataset from plot_csv.py")
    print("------------------------")
    print("Warmup/cooldown: already handled by input analysis series")
    print(f"Executions:       {len(executions)}")
    print(f"Features:         {len(feature_names)}")
    print()

    # ------------------------------------------------------------
    # BUILD MULTIVARIATE TIME SERIES
    # ------------------------------------------------------------

    for i, (key, samples) in enumerate(executions.items()):

        trimmed = samples

        if not trimmed:
            print(
                f"error: execution {i} "
                "has no samples after trimming"
            )
            return 1

        # Keep only the non-excluded feature columns
        data = np.array(
            [[values[idx] for idx in indices_to_keep] for _, values in trimmed],
            dtype=float,
        )

        data = np.nan_to_num(
            data,
            nan=0.0,
            posinf=0.0,
            neginf=0.0,
        )

        series.append(data)

        attack, attempt, status = key
        metadata.append(key)

        original_duration = (
            samples[-1][0] - samples[0][0]
        )

        kept_duration = (
            trimmed[-1][0] - trimmed[0][0]
        )

        print(
            f"{i}: {attack} "
            f"attempt={attempt} "
            f"status={status} "
            f"original={original_duration:.1f}s "
            f"kept={kept_duration:.1f}s "
            f"samples={len(trimmed)}"
        )

    print()

    if n_clusters > len(series):
        print(
            f"error: n_clusters={n_clusters} but only "
            f"{len(series)} executions are available"
        )
        return 1

    # ------------------------------------------------------------
    # NORMALIZE EACH FEATURE INDEPENDENTLY
    # ------------------------------------------------------------

    series = normalize_features(
        series,
        feature_names,
    )

    # ------------------------------------------------------------
    # CONVERT TO MULTIVARIATE TSLearn DATASET
    # ------------------------------------------------------------

    X = to_time_series_dataset(series)

    print(f"tslearn dataset shape: {X.shape}")
    print(
        "Dimensions: "
        f"{X.shape[0]} executions, "
        f"{X.shape[1]} timestamps, "
        f"{X.shape[2]} features"
    )
    print()

    # ------------------------------------------------------------
    # MULTIVARIATE DTW K-MEANS
    # ------------------------------------------------------------

    print("Starting multivariate DTW K-Means")
    print("----------------------------------")
    print(f"Clusters: {n_clusters}")
    print(f"Features: {len(feature_names)}")

    model = TimeSeriesKMeans(
        n_clusters=n_clusters,
        metric="dtw",
        metric_params={
            "sakoe_chiba_radius": SAKOE_CHIBA_RADIUS,
        },
        max_iter=50,
        max_iter_barycenter=20,
        n_init=5,
        random_state=42,
        n_jobs=-1,
        verbose=1,
    )

    labels = model.fit_predict(X)

    # ------------------------------------------------------------
    # SAVE AND PRINT CLUSTER ASSIGNMENTS
    # ------------------------------------------------------------

    output_path = Path("out-dtwkmeans") / f"{n_clusters}{output_file}.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_rows = []

    print()
    print("Clustering results")
    print("------------------")

    for i, ((attack, attempt, status), label) in enumerate(
        zip(metadata, labels)
    ):
        print(
            f"{i} {attack} "
            f"attempt={attempt} "
            f"status={status} "
            f"cluster={label}"
        )
        output_rows.append({
            "attack": attack,
            "label": ATTACK_LABELS.get(attack),
            "attempt": attempt,
            "status": status,
            "cluster": int(label),
        })

    missing_labels = sorted({
        row["attack"]
        for row in output_rows
        if row["label"] is None
    })

    if missing_labels:
        print()
        print("Warning: attacks without labels:")
        for attack in missing_labels:
            print(f"  {attack}")

    with output_path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "attack",
                "label",
                "attempt",
                "status",
                "cluster",
            ],
        )
        writer.writeheader()
        writer.writerows(sorted(
            output_rows,
            key=lambda row: (
                row["cluster"],
                row["label"] or "",
                row["attack"],
                row["attempt"],
            ),
        ))

    print()
    print(f"Clusters written to {output_path}")

    print()
    print(f"Inertia: {model.inertia_}")
    print(f"Iterations: {model.n_iter_}")

    # ------------------------------------------------------------
    # PRINT CLUSTER SIZES
    # ------------------------------------------------------------

    print()
    print("Cluster sizes")
    print("-------------")

    for cluster in range(n_clusters):
        count = np.sum(labels == cluster)
        print(f"cluster {cluster}: {count}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

