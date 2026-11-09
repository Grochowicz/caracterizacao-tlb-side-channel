#!/usr/bin/env python3

import os
import sys

import pandas as pd
import matplotlib.pyplot as plt


if len(sys.argv) < 3:
    print(
        "Usage: python3 "
        + sys.argv[0]
        + " <timeseries_csv> <output_dir>"
    )
    sys.exit(1)

INPUT = sys.argv[1]
OUTPUT_DIR = sys.argv[2]

if not INPUT.endswith(".csv"):
    raise ValueError("Input file must be a CSV file")

if not os.path.exists(INPUT):
    raise FileNotFoundError(f"Input file {INPUT} does not exist")

os.makedirs(OUTPUT_DIR, exist_ok=True)

CORR_OUTPUT = os.path.join(
    OUTPUT_DIR,
    "pearson_timeseries_correlation.csv"
)
PAIRS_OUTPUT = os.path.join(
    OUTPUT_DIR,
    "pearson_timeseries_high_correlation_pairs.csv"
)
PLOT_OUTPUT = os.path.join(
    OUTPUT_DIR,
    "pearson_timeseries_high_correlation.png"
)

# Minimum absolute Pearson correlation reported as a high correlation.
THRESHOLD = 0.7

# Metadata and the shared time coordinate are not measurement variables.
NON_METRIC_COLUMNS = {
    "attack",
    "attempt",
    "status",
    "time",
}


# ------------------------------------------------------------
# Read time-series CSV
# ------------------------------------------------------------

df = pd.read_csv(INPUT)

metric_columns = [
    column
    for column in df.columns
    if column not in NON_METRIC_COLUMNS
]

if len(metric_columns) < 2:
    raise ValueError(
        "At least two time-series measurement columns are required."
    )

# Convert measurement columns to numeric. Empty cells and invalid values
# become NaN and are handled pairwise by pandas correlation.
numeric_df = df[metric_columns].apply(
    pd.to_numeric,
    errors="coerce"
)

# Exclude columns with fewer than two valid observations or no variation.
usable_columns = [
    column
    for column in numeric_df.columns
    if numeric_df[column].count() >= 2
    and numeric_df[column].nunique(dropna=True) >= 2
]

numeric_df = numeric_df[usable_columns]

if numeric_df.shape[1] < 2:
    raise ValueError(
        "At least two non-constant measurement columns with "
        "two or more valid observations are required."
    )

# Calculate Pearson correlations using all available time-series rows.
# pandas uses pairwise complete observations for each variable pair.
corr = numeric_df.corr(method="pearson")
corr.to_csv(CORR_OUTPUT)

print(f"Correlation matrix saved to {CORR_OUTPUT}")
print(f"Measurements included: {len(usable_columns)}")
print(f"Time-series rows: {len(numeric_df)}")


# ------------------------------------------------------------
# Report highly correlated pairs
# ------------------------------------------------------------

pairs = []
columns = corr.columns

for i in range(len(columns)):
    for j in range(i + 1, len(columns)):
        variable_1 = columns[i]
        variable_2 = columns[j]
        coefficient = corr.iloc[i, j]

        if pd.isna(coefficient):
            continue

        if abs(coefficient) >= THRESHOLD:
            valid_rows = numeric_df[
                [variable_1, variable_2]
            ].dropna().shape[0]

            pairs.append({
                "variable_1": variable_1,
                "variable_2": variable_2,
                "pearson": coefficient,
                "observations": valid_rows,
            })

pairs_df = pd.DataFrame(
    pairs,
    columns=[
        "variable_1",
        "variable_2",
        "pearson",
        "observations",
    ],
)

if not pairs_df.empty:
    pairs_df["abs_pearson"] = pairs_df["pearson"].abs()
    pairs_df = pairs_df.sort_values(
        "abs_pearson",
        ascending=False,
    ).drop(columns="abs_pearson")

pairs_df.to_csv(PAIRS_OUTPUT, index=False)

print(
    f"Found {len(pairs_df)} pairs with "
    f"|Pearson| >= {THRESHOLD}"
)
print(f"Pair report saved to {PAIRS_OUTPUT}")


# ------------------------------------------------------------
# Plot highly correlated variables
# ------------------------------------------------------------

if not pairs_df.empty:
    high_corr_columns = sorted(
        set(pairs_df["variable_1"])
        | set(pairs_df["variable_2"])
    )

    high_corr = corr.loc[
        high_corr_columns,
        high_corr_columns,
    ]

    fig, ax = plt.subplots(
        figsize=(
            max(10, len(high_corr_columns) * 0.7),
            max(8, len(high_corr_columns) * 0.7),
        )
    )

    im = ax.imshow(
        high_corr,
        vmin=-1,
        vmax=1,
        cmap="coolwarm",
        aspect="auto",
    )

    ax.set_xticks(range(len(high_corr.columns)))
    ax.set_yticks(range(len(high_corr.columns)))

    ax.set_xticklabels(
        high_corr.columns,
        rotation=90,
        fontsize=8,
    )
    ax.set_yticklabels(
        high_corr.columns,
        fontsize=8,
    )

    for i in range(len(high_corr)):
        for j in range(len(high_corr)):
            value = high_corr.iloc[i, j]
            ax.text(
                j,
                i,
                f"{value:.2f}",
                ha="center",
                va="center",
                fontsize=6,
            )

    colorbar = fig.colorbar(im, ax=ax)
    colorbar.set_label("Pearson correlation coefficient")

    ax.set_title(
        "Highly Correlated Time-Series Metrics "
        f"(|Pearson| >= {THRESHOLD})"
    )

    plt.tight_layout()
    plt.savefig(
        PLOT_OUTPUT,
        dpi=300,
        bbox_inches="tight",
    )
    plt.close()

    print(f"High-correlation plot saved to {PLOT_OUTPUT}")
else:
    print(
        "No high-correlation pairs found; "
        "high-correlation plot not generated."
    )
