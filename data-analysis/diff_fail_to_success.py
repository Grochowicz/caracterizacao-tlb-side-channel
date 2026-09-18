#!/usr/bin/env python3

import itertools
import numpy as np
import pandas as pd

from sklearn.preprocessing import StandardScaler
from sklearn.metrics.pairwise import cosine_similarity


INPUT_FILE = "attack_statistics.csv"
OUTPUT_FILE = "fail_success_vector_similarity.csv"

# Directory labels
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

    df = pd.read_csv(INPUT_FILE)

    # ------------------------------------------------------------
    # Select measurement features
    # ------------------------------------------------------------

    exclude = {"attack", "attempt", "status"}

    feature_columns = [
        col
        for col in df.select_dtypes(include="number").columns
        if col not in exclude
        and "_max" not in col
    ]

    if not feature_columns:
        print("Error: no numeric feature columns found.")
        return

    print(f"Using {len(feature_columns)} features:")
    for feature in feature_columns:
        print(f"  {feature}")

    # ------------------------------------------------------------
    # Standardize the measurements
    # ------------------------------------------------------------

#    scaler = StandardScaler()

#    df[feature_columns] = scaler.fit_transform(
#        df[feature_columns]
#    )

    # ------------------------------------------------------------
    # Build fail -> success difference vectors
    # ------------------------------------------------------------

    vectors = {}

    for attack in df["attack"].unique():

        attack_df = df[df["attack"] == attack]

        failures = attack_df[
            attack_df["status"].str.lower() == "fail"
        ]

        successes = attack_df[
            attack_df["status"].str.lower() == "success"
        ]

        if failures.empty or successes.empty:
            print(
                f"Skipping {attack}: "
                f"needs at least one failure and one success."
            )
            continue

        attack_vectors = []

        for _, failure in failures.iterrows():
            for _, success in successes.iterrows():

                difference = (
                    success[feature_columns].to_numpy(dtype=float)
                    -
                    failure[feature_columns].to_numpy(dtype=float)
                )

                attack_vectors.append(difference)

        vectors[attack] = attack_vectors

    # ------------------------------------------------------------
    # Compare attacks
    # ------------------------------------------------------------

    results = []

    attacks = sorted(vectors.keys())

    for attack_a, attack_b in itertools.combinations(attacks, 2):

        similarities = []
        correlations = []
        distances = []

        for vector_a in vectors[attack_a]:
            for vector_b in vectors[attack_b]:

                # Cosine similarity
                cosine = cosine_similarity(
                    vector_a.reshape(1, -1),
                    vector_b.reshape(1, -1)
                )[0, 0]

                # Pearson correlation
                if (
                    np.std(vector_a) == 0
                    or np.std(vector_b) == 0
                ):
                    pearson = np.nan
                else:
                    pearson = np.corrcoef(
                        vector_a,
                        vector_b
                    )[0, 1]

                # Euclidean distance
                distance = np.linalg.norm(
                    vector_a - vector_b
                )

                similarities.append(cosine)
                correlations.append(pearson)
                distances.append(distance)

        results.append({
            "attack_1": attack_a,
            "label_1": ATTACK_LABELS.get(attack_a, "unknown"),

            "attack_2": attack_b,
            "label_2": ATTACK_LABELS.get(attack_b, "unknown"),

            "cosine_similarity": np.mean(similarities),
            "pearson_correlation": np.nanmean(correlations),
            "euclidean_distance": np.mean(distances),

            "comparisons": len(similarities),
        })

    # ------------------------------------------------------------
    # Save results
    # ------------------------------------------------------------

    results_df = pd.DataFrame(results)

    if not results_df.empty:
        results_df = results_df.sort_values(
            "cosine_similarity",
            ascending=False
        )

    results_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print()
    print(f"Results written to {OUTPUT_FILE}")
    print()

    # ------------------------------------------------------------
    # Print strongest similarities
    # ------------------------------------------------------------

    print("Most similar fail -> success changes:")
    print()

    for _, row in results_df.head(20).iterrows():

        print(
            f"{row['attack_1']:20s} <-> "
            f"{row['attack_2']:20s} "
            f"cosine={row['cosine_similarity']:.4f} "
            f"pearson={row['pearson_correlation']:.4f} "
            f"distance={row['euclidean_distance']:.4f}"
        )


if __name__ == "__main__":
    main()
