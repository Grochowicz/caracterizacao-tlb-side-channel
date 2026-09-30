#!/usr/bin/env python3

import sys
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt

from tslearn.clustering import TimeSeriesKMeans
from tslearn.preprocessing import TimeSeriesScalerMeanVariance
from tslearn.utils import to_time_series_dataset


INPUT_FILE = "timeseries-1q-cpu.csv"
OUTPUT_FILE = "_dtw_attack_clusters.csv"
PLOT_FILE = "_dtw_attack_clusters.png"


# Attack -> directory/category
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
}


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <number_of_clusters>")
        sys.exit(1)

    k = int(sys.argv[1])

    if k < 2:
        print("Error: k must be at least 2.")
        sys.exit(1)

    df = pd.read_csv(INPUT_FILE)

    required_columns = {
        "attack",
        "attempt",
        "status",
        "source",
        "metric",
        "series_id",
        "time",
        "value",
    }

    missing = required_columns - set(df.columns)

    if missing:
        print("Error: missing columns:")

        for column in sorted(missing):
            print(f"  {column}")

        sys.exit(1)

    # Add directory/category label.
    df["label"] = df["attack"].map(ATTACK_LABELS)

    missing_labels = df.loc[
        df["label"].isna(),
        "attack"
    ].unique()

    if len(missing_labels) > 0:
        print("Warning: attacks without labels:")

        for attack in missing_labels:
            print(f"  {attack}")

        print()

    # ------------------------------------------------------------
    # FIND TIME-SERIES TYPES
    # ------------------------------------------------------------

    series_types = sorted(
        df[
            [
                "source",
                "metric",
                "series_id",
            ]
        ]
        .drop_duplicates()
        .itertuples(
            index=False,
            name=None
        )
    )

    if not series_types:
        print("Error: no time-series found.")
        sys.exit(1)

    print(f"Found {len(series_types)} time-series types:\n")

    for source, metric, series_id in series_types:
        print(
            f"  {source}/{metric}/{series_id}"
        )

    print()

    output_dir = Path("out")
    output_dir.mkdir(exist_ok=True)

    all_results = []

    # ------------------------------------------------------------
    # CLUSTER EACH TIME-SERIES TYPE INDEPENDENTLY
    # ------------------------------------------------------------

    for source, metric, series_id in series_types:

        print("=" * 60)
        print(
            f"{source}/{metric}/{series_id}"
        )
        print("=" * 60)

        type_df = df[
            (df["source"] == source)
            & (df["metric"] == metric)
            & (df["series_id"] == series_id)
        ]

        # --------------------------------------------------------
        # BUILD VARIABLE-LENGTH SERIES
        # --------------------------------------------------------

        series = []
        metadata = []

        for (attack, attempt, status), group in type_df.groupby(
            ["attack", "attempt", "status"]
        ):
            group = group.sort_values("time")

            values = group["value"].to_numpy(dtype=float)

            if len(values) == 0:
                continue

            series.append(values)

            metadata.append(
                {
                    "attack": attack,
                    "label": ATTACK_LABELS.get(attack),
                    "attempt": attempt,
                    "status": status,
                }
            )

        if len(series) < k:
            print(
                f"Skipping: only {len(series)} time series "
                f"available, but k={k}."
            )
            print()
            continue

        lengths = [len(x) for x in series]

        print(f"Time series: {len(series)}")
        print(
            f"Length: min={min(lengths)}, "
            f"max={max(lengths)}"
        )

        # --------------------------------------------------------
        # CONVERT TO TSLearn VARIABLE-LENGTH DATASET
        # --------------------------------------------------------
        #
        # This does NOT resample the series.
        #
        # tslearn represents shorter series with trailing NaNs.
        # DTW knows how to deal with this representation.
        #

        X = to_time_series_dataset(series)

        print(f"Dataset shape: {X.shape}")

        # --------------------------------------------------------
        # NORMALIZE EACH TIME SERIES
        # --------------------------------------------------------
        #
        # Each series gets zero mean / unit variance.
        #
        # This makes clustering focus on temporal shape rather
        # than absolute magnitude.
        #

        scaler = TimeSeriesScalerMeanVariance()

        X_scaled = scaler.fit_transform(X)

        # --------------------------------------------------------
        # DTW K-MEANS
        # --------------------------------------------------------

        print(f"k = {k}")
        print("Metric = DTW")

        kmeans = TimeSeriesKMeans(
            n_clusters=k,
            metric="dtw",
            random_state=42,
            n_init=5,
            max_iter=20,
            max_iter_barycenter=20,
            verbose=False,
        )

        try:
            clusters = kmeans.fit_predict(X_scaled)

        except Exception as error:
            print(
                f"Error clustering "
                f"{source}/{metric}/{series_id}:"
            )
            print(f"  {error}")
            print()

            continue

        # --------------------------------------------------------
        # SAVE RESULT
        # --------------------------------------------------------

        result = pd.DataFrame(metadata)

        result["source"] = source
        result["metric"] = metric
        result["series_id"] = series_id
        result["cluster"] = clusters

        all_results.append(result)

        # --------------------------------------------------------
        # PRINT CLUSTERS
        # --------------------------------------------------------

        for cluster in sorted(
            result["cluster"].unique()
        ):
            subset = result[
                result["cluster"] == cluster
            ]

            print(f"\nCluster {cluster}:")

            for _, row in subset.iterrows():
                print(
                    f"  [{row['label']}] "
                    f"{row['attack']} "
                    f"(attempt {row['attempt']}, "
                    f"{row['status']})"
                )

        print()

        # --------------------------------------------------------
        # PLOT DTW BARYCENTERS
        # --------------------------------------------------------

        plt.figure(figsize=(12, 8))

        for cluster in range(k):

            center = kmeans.cluster_centers_[cluster]

            plt.plot(
                center[:, 0],
                linewidth=3,
                label=f"Cluster {cluster}"
            )

        plt.xlabel("Time")
        plt.ylabel("Normalized value")
        plt.title(
            f"DTW K-Means: "
            f"{source}/{metric}/{series_id}"
        )
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.tight_layout()

        safe_name = (
            f"{source}_{metric}_{series_id}"
            .replace("/", "_")
            .replace(" ", "_")
        )

        plot_file = (
            output_dir
            / f"{k}_{safe_name}{PLOT_FILE}"
        )

        plt.savefig(
            plot_file,
            dpi=300,
            bbox_inches="tight"
        )

        plt.close()

        print(f"Plot written to {plot_file}")

    # ------------------------------------------------------------
    # SAVE ALL CLUSTER ASSIGNMENTS
    # ------------------------------------------------------------

    if not all_results:
        print("No clustering results produced.")
        sys.exit(1)

    results = pd.concat(
        all_results,
        ignore_index=True
    )

    output_file = (
        output_dir
        / f"{k}{OUTPUT_FILE}"
    )

    results[
        [
            "source",
            "metric",
            "series_id",
            "attack",
            "label",
            "attempt",
            "status",
            "cluster",
        ]
    ].sort_values(
        [
            "source",
            "metric",
            "series_id",
            "cluster",
            "label",
            "attack",
            "attempt",
        ]
    ).to_csv(
        output_file,
        index=False
    )

    print(
        f"\nClusters written to {output_file}"
    )


if __name__ == "__main__":
    main()
