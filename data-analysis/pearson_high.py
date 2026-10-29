#!/usr/bin/env python3

import pandas as pd
import matplotlib.pyplot as plt
import sys
import os

if len(sys.argv) < 3:
    print(
        "Usage: python3 "
        + sys.argv[0]
        + " <input_csv> <output_dir>"
    )
    sys.exit(1)

INPUT = sys.argv[1]
OUTPUT_DIR = sys.argv[2]

if not INPUT.endswith(".csv"):
    raise ValueError("Input file must be a CSV file")

if not os.path.exists(INPUT):
    raise FileNotFoundError(
        f"Input file {INPUT} does not exist"
    )

os.makedirs(OUTPUT_DIR, exist_ok=True)

PLOT_OUTPUT = os.path.join(
    OUTPUT_DIR,
    "pearson_correlation.csv"
)

REPORT_OUTPUT = os.path.join(
    OUTPUT_DIR,
    "high_correlation_pairs.csv"
)

HIGH_CORR_PLOT_OUTPUT = os.path.join(
    OUTPUT_DIR,
    "high_pearson_correlation.png"
)

# Minimum absolute Pearson correlation for a reported pair.
THRESHOLD = 0.7


# ------------------------------------------------------------
# Read CSV
# ------------------------------------------------------------

df = pd.read_csv(INPUT)

# Keep only numeric variables.
numeric_df = df.select_dtypes(include="number")

# Keep metrics' averages only.
# Exclude maximums, standard deviations, skewness, kurtosis, and attempts.
numeric_df = numeric_df[
    [
        col
        for col in numeric_df.columns
        if col.endswith("_avg")
        and "_max" not in col
        and "_stddev" not in col
        and "_skewness" not in col
        and "_kurtosis" not in col
    ]
]

if numeric_df.shape[1] < 2:
    raise ValueError(
        "At least two numeric columns ending in '_avg' "
        "are required to calculate correlations."
    )

# Calculate Pearson correlation matrix.
corr = numeric_df.corr(method="pearson")


# ------------------------------------------------------------
# Save complete Pearson correlation matrix
# ------------------------------------------------------------

corr.to_csv(PLOT_OUTPUT)

print(
    f"Correlation matrix saved to {PLOT_OUTPUT}"
)


# ------------------------------------------------------------
# Write highly correlated pairs to a separate CSV
# ------------------------------------------------------------

pairs = []
columns = corr.columns

for i in range(len(columns)):
    for j in range(i + 1, len(columns)):
        coefficient = corr.iloc[i, j]

        # Skip undefined correlations, e.g. constant variables.
        if pd.isna(coefficient):
            continue

        if abs(coefficient) >= THRESHOLD:
            pairs.append({
                "variable_1": columns[i],
                "variable_2": columns[j],
                "pearson": coefficient
            })

pairs_df = pd.DataFrame(
    pairs,
    columns=["variable_1", "variable_2", "pearson"]
)

# Sort strongest correlations first.
if not pairs_df.empty:
    pairs_df["abs_pearson"] = (
        pairs_df["pearson"].abs()
    )

    pairs_df = pairs_df.sort_values(
        "abs_pearson",
        ascending=False
    ).drop(columns="abs_pearson")

pairs_df.to_csv(
    REPORT_OUTPUT,
    index=False
)

print(
    f"Found {len(pairs_df)} pairs with "
    f"|Pearson| >= {THRESHOLD}"
)

print(
    f"Report saved to {REPORT_OUTPUT}"
)


# ------------------------------------------------------------
# Plot only highly correlated variables
# ------------------------------------------------------------

if not pairs_df.empty:
    # Get every variable involved in at least one
    # high-correlation pair.
    high_corr_columns = sorted(
        set(pairs_df["variable_1"])
        | set(pairs_df["variable_2"])
    )

    high_corr = corr.loc[
        high_corr_columns,
        high_corr_columns
    ]

    fig, ax = plt.subplots(
        figsize=(
            max(10, len(high_corr_columns) * 0.7),
            max(8, len(high_corr_columns) * 0.7)
        )
    )

    im = ax.imshow(
        high_corr,
        vmin=-1,
        vmax=1,
        cmap="coolwarm",
        aspect="auto"
    )

    ax.set_xticks(
        range(len(high_corr.columns))
    )

    ax.set_yticks(
        range(len(high_corr.columns))
    )

    ax.set_xticklabels(
        high_corr.columns,
        rotation=90,
        fontsize=8
    )

    ax.set_yticklabels(
        high_corr.columns,
        fontsize=8
    )

    # Write correlation coefficients in cells.
    for i in range(len(high_corr)):
        for j in range(len(high_corr)):
            value = high_corr.iloc[i, j]

            ax.text(
                j,
                i,
                f"{value:.2f}",
                ha="center",
                va="center",
                fontsize=6
            )

    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label(
        "Pearson correlation coefficient"
    )

    ax.set_title(
        f"Highly Correlated Average Metrics "
        f"(|Pearson| >= {THRESHOLD})"
    )

    plt.tight_layout()

    plt.savefig(
        HIGH_CORR_PLOT_OUTPUT,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        f"High-correlation plot saved to "
        f"{HIGH_CORR_PLOT_OUTPUT}"
    )

else:
    print(
        "No high-correlation pairs found; "
        "high-correlation plot not generated."
    )
