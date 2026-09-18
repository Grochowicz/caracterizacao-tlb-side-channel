#!/usr/bin/env python3

import sys

import pandas as pd
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA


INPUT_FILE = "attack_statistics.csv"
OUTPUT_FILE = "_means_attack_clusters.csv"
PLOT_FILE = "_means_attack_clusters.png"


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

    df = pd.read_csv(INPUT_FILE)

    # These identify the sample rather than being measurements.
    exclude = {"attack", "attempt", "status"}

    # Keep only numeric measurement columns.
    # Exclude _max columns.
    feature_columns = [
        col
        for col in df.select_dtypes(include="number").columns
        if col not in exclude and "_max" not in col
    ]

    if not feature_columns:
        print("Error: no numeric feature columns found.")
        sys.exit(1)

    if k < 2 or k >= len(df):
        print(
            f"Error: k must be between 2 and {len(df) - 1}."
        )
        sys.exit(1)

    # Add directory/category label.
    df["label"] = df["attack"].map(ATTACK_LABELS)

    # Warn about attacks without a label.
    missing_labels = df.loc[df["label"].isna(), "attack"].unique()

    if len(missing_labels) > 0:
        print("Warning: attacks without labels:")
        for attack in missing_labels:
            print(f"  {attack}")

    print(f"Clustering {len(df)} attempts")
    print(f"Using {len(feature_columns)} features")
    print(f"k = {k}")

    # Feature matrix.
    X = df[feature_columns]

    # Standardize features.
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # K-Means.
    kmeans = KMeans(
        n_clusters=k,
        random_state=42,
        n_init=20
    )

    df["cluster"] = kmeans.fit_predict(X_scaled)

    # Save attack/label/attempt information plus cluster.
    df[
        ["attack", "label", "attempt", "status", "cluster"]
    ].sort_values(
        ["cluster", "label", "attack", "attempt"]
    ).to_csv(
        "out/" + str(k) + OUTPUT_FILE,
        index=False
    )

    print(f"\nClusters written to {'out/' + str(k) + OUTPUT_FILE}\n")

    # Print clusters.
    for cluster in sorted(df["cluster"].unique()):
        subset = df[df["cluster"] == cluster]

        print(f"Cluster {cluster}:")

        for _, row in subset.iterrows():
            print(
                f"  [{row['label']}] "
                f"{row['attack']} "
                f"(attempt {row['attempt']}, {row['status']})"
            )

        print()

    # PCA for 2D visualization.
    pca = PCA(n_components=2, random_state=42)
    X_pca = pca.fit_transform(X_scaled)

    df["pca_x"] = X_pca[:, 0]
    df["pca_y"] = X_pca[:, 1]

    plt.figure(figsize=(12, 8))

    for cluster in sorted(df["cluster"].unique()):
        subset = df[df["cluster"] == cluster]

        plt.scatter(
            subset["pca_x"],
            subset["pca_y"],
            label=f"Cluster {cluster}",
            s=80
        )

        for _, row in subset.iterrows():
            label = f"{row['label']}/{row['attack']} ({row['attempt']})"

            plt.annotate(
                label,
                (row["pca_x"], row["pca_y"]),
                xytext=(5, 5),
                textcoords="offset points",
                fontsize=8
            )

    explained = pca.explained_variance_ratio_

    plt.xlabel(f"PC1 ({explained[0] * 100:.1f}% variance)")
    plt.ylabel(f"PC2 ({explained[1] * 100:.1f}% variance)")
    plt.title("K-Means Clustering of Attack Attempts")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(
        "out/" + str(k) + PLOT_FILE,
        dpi=300,
        bbox_inches="tight"
    )
    plt.close()

    print(f"Plot written to {'out/' + str(k) + PLOT_FILE}")


if __name__ == "__main__":
    main()
