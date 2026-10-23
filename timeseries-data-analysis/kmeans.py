#!/usr/bin/env python3

import csv
import sys
from collections import defaultdict

import numpy as np
from tslearn.clustering import TimeSeriesKMeans
from tslearn.preprocessing import TimeSeriesScalerMeanVariance
from tslearn.utils import to_time_series_dataset


WARMUP = 12.0
COOLDOWN = 1.0
INTERVAL = 0.1

METADATA_COLUMNS = {
    "attack",
    "attempt",
    "status",
}

# These features do not exist for baseline, and may not exist
# during the first samples of an attack execution.
EXCLUDED_FEATURES = {
    "attack_cpu",
    "attack_mem",
    "attack_time",
}


def load_csv(filename):
    executions = defaultdict(list)

    with open(filename, newline="") as f:
        reader = csv.DictReader(f)

        feature_names = [
            name
            for name in reader.fieldnames
            if name not in METADATA_COLUMNS
            and name not in EXCLUDED_FEATURES
        ]

        for row in reader:
            key = (
                row["attack"],
                int(row["attempt"]),
                row["status"],
            )

            values = []

            for name in feature_names:
                value = row[name]

                if value == "" or value.lower() == "nan":
                    values.append(0.0)
                else:
                    values.append(float(value))

            executions[key].append(
                (float(row["time"]), values)
            )

    return executions, feature_names


def trim_execution(samples):
    start = samples[0][0]
    end = samples[-1][0]

    lower = start + WARMUP
    upper = end - COOLDOWN

    return [
        (timestamp, values)
        for timestamp, values in samples
        if lower <= timestamp <= upper
    ]

def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <n_clusters> <input_file>")
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

    executions, feature_names = load_csv(input_file)

    if n_clusters > len(executions):
        print(
            f"error: n_clusters={n_clusters} but only "
            f"{len(executions)} executions are available"
        )
        return 1

    series = []
    metadata = []

    print("Dataset after warmup/cooldown removal")
    print("--------------------------------------")
    print(f"Warmup removed:   {WARMUP}s")
    print(f"Cooldown removed: {COOLDOWN}s")
    print(f"Executions:       {len(executions)}")
    print(f"Features:         {len(feature_names)}")
    print()

    for i, (key, samples) in enumerate(executions.items()):
        trimmed = trim_execution(samples)

        if not trimmed:
            print(f"error: execution {i} has no samples after trimming")
            return 1

        data = np.array(
            [values for _, values in trimmed],
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

        original_duration = samples[-1][0] - samples[0][0]
        kept_duration = trimmed[-1][0] - trimmed[0][0]

        print(
            f"{i}: {attack} "
            f"attempt={attempt} "
            f"status={status} "
            f"original={original_duration:.1f}s "
            f"kept={kept_duration:.1f}s "
            f"samples={len(trimmed)}"
        )

    print()

    X = to_time_series_dataset(series)

    print(f"tslearn dataset shape: {X.shape}")
    print()

    X = TimeSeriesScalerMeanVariance().fit_transform(X)

    model = TimeSeriesKMeans(
        n_clusters=n_clusters,
        metric="dtw",
        max_iter=50,
        max_iter_barycenter=20,
        n_init=5,
        random_state=42,
        n_jobs=-1,
        verbose=1,
    )

    labels = model.fit_predict(X)

    print()
    print("Clustering results")

    for i, ((attack, attempt, status), label) in enumerate(
        zip(metadata, labels)
    ):
        print(
            f"{i} {attack} "
            f"attempt={attempt} "
            f"cluster={label}"
        )

    print()
    print(f"Inertia: {model.inertia_}")
    print(f"Iterations: {model.n_iter_}")

    print()
    print("Cluster sizes")

    for cluster in range(n_clusters):
        count = np.sum(labels == cluster)
        print(f"cluster {cluster}: {count}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
