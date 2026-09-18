#!/usr/bin/env python3

import pandas as pd
import matplotlib.pyplot as plt


INPUT = "attack_statistics.csv"
PLOT_OUTPUT = "pearson_correlation.png"
REPORT_OUTPUT = "high_correlation_pairs.csv"

# Threshold for strong correlation
THRESHOLD = 0.9


# Read CSV
df = pd.read_csv(INPUT)

# Keep only numeric variables
numeric_df = df.select_dtypes(include="number")

# Ignore _max columns and attempt number
numeric_df = numeric_df[
    [
        col
        for col in numeric_df.columns
        if "_max" not in col and col != "attempt"
    ]
]

# Calculate Pearson correlation matrix
corr = numeric_df.corr(method="pearson")


# ------------------------------------------------------------
# Write highly correlated pairs to a separate CSV
# ------------------------------------------------------------

pairs = []

columns = corr.columns

for i in range(len(columns)):
    for j in range(i + 1, len(columns)):
        coefficient = corr.iloc[i, j]

        if abs(coefficient) > THRESHOLD:
            pairs.append({
                "variable_1": columns[i],
                "variable_2": columns[j],
                "pearson": coefficient
            })

# Sort strongest correlations first
pairs_df = pd.DataFrame(pairs)

if not pairs_df.empty:
    pairs_df["abs_pearson"] = pairs_df["pearson"].abs()
    pairs_df = pairs_df.sort_values(
        "abs_pearson",
        ascending=False
    ).drop(columns="abs_pearson")

pairs_df.to_csv(REPORT_OUTPUT, index=False)

print(f"Found {len(pairs_df)} pairs with |Pearson| > {THRESHOLD}")
print(f"Report saved to {REPORT_OUTPUT}")

# ------------------------------------------------------------
# Plot only highly correlated variables
# ------------------------------------------------------------

HIGH_CORR_PLOT_OUTPUT = "high_pearson_correlation.png"

if not pairs_df.empty:
    # Get every variable involved in at least one high-correlation pair
    high_corr_columns = sorted(set(
        pairs_df["variable_1"]
    ) | set(
        pairs_df["variable_2"]
    ))

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

    ax.set_xticks(range(len(high_corr.columns)))
    ax.set_yticks(range(len(high_corr.columns)))

    ax.set_xticklabels(
        high_corr.columns,
        rotation=90,
        fontsize=8
    )

    ax.set_yticklabels(
        high_corr.columns,
        fontsize=8
    )

    # Write coefficients in cells
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
    cbar.set_label("Pearson correlation coefficient")

    ax.set_title(
        f"Highly Correlated Variables (|Pearson| > {THRESHOLD})"
    )

    plt.tight_layout()
    plt.savefig(
        HIGH_CORR_PLOT_OUTPUT,
        dpi=300,
        bbox_inches="tight"
    )
    plt.close()

    print(f"High-correlation plot saved to {HIGH_CORR_PLOT_OUTPUT}")

else:
    print("No high-correlation pairs found; high-correlation plot not generated.")
