#!/usr/bin/env python3

import pandas as pd
import matplotlib.pyplot as plt
import sys
import os

if len(sys.argv) < 3:
    print("Usage: python3 pearson.py <input_csv> <output_directory>")
    sys.exit(1)

INPUT = sys.argv[1]
OUTPUT_DIR = sys.argv[2]

if not INPUT.endswith(".csv"):
    raise ValueError("Input file must be a CSV file")
if not os.path.exists(INPUT):
    raise FileNotFoundError(f"Input file {INPUT} does not exist")
if not os.path.isfile(INPUT):
    raise ValueError(f"Input file {INPUT} is not a file")
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)


PLOT_OUTPUT = os.path.join(OUTPUT_DIR, "pearson_correlation.png")
REPORT_OUTPUT = os.path.join(OUTPUT_DIR, "high_correlation_pairs.csv")

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
# Plot correlation matrix
# ------------------------------------------------------------

fig, ax = plt.subplots(figsize=(24, 20))

im = ax.imshow(
    corr,
    vmin=-1,
    vmax=1,
    cmap="coolwarm",
    aspect="auto"
)

ax.set_xticks(range(len(corr.columns)))
ax.set_yticks(range(len(corr.columns)))

ax.set_xticklabels(
    corr.columns,
    rotation=90,
    fontsize=7
)

ax.set_yticklabels(
    corr.columns,
    fontsize=7
)

# Write coefficients in cells
for i in range(len(corr)):
    for j in range(len(corr)):
        value = corr.iloc[i, j]

        ax.text(
            j,
            i,
            f"{value:.2f}",
            ha="center",
            va="center",
            fontsize=5
        )

cbar = fig.colorbar(im, ax=ax)
cbar.set_label("Pearson correlation coefficient")

ax.set_title("Pearson Correlation Matrix")

plt.tight_layout()
plt.savefig(PLOT_OUTPUT, dpi=300, bbox_inches="tight")
plt.close()

print(f"Plot saved to {PLOT_OUTPUT}")
