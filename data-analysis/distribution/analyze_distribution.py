#!/usr/bin/env python3

import argparse
import re
from pathlib import Path

import matplotlib
import pandas as pd


matplotlib.use("Agg")
import matplotlib.pyplot as plt


IDENTIFICATION_COLUMNS = {"attack", "attempt", "status"}
ANALYSIS_STATUSES = ("fail", "success")


def read_input(filename):
    """Read the aggregated per-attempt CSV produced by plot_csv.py."""
    input_path = Path(filename)

    if not input_path.is_file():
        raise FileNotFoundError(
            f"Input CSV does not exist: {input_path}"
        )

    dataframe = pd.read_csv(input_path)

    if "attack" not in dataframe.columns:
        raise ValueError(
            "Input CSV must contain an 'attack' column."
        )

    return dataframe


def select_average_metrics(dataframe):
    """Return numeric columns whose names end with '_avg'."""
    metrics = []

    for column in dataframe.columns:
        if column in IDENTIFICATION_COLUMNS:
            continue

        if not column.endswith("_avg"):
            continue

        numeric_values = pd.to_numeric(
            dataframe[column],
            errors="coerce",
        )

        if numeric_values.notna().any():
            metrics.append(column)

    return metrics


def safe_filename(name):
    """Convert a metric name into a filesystem-safe filename."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)


def generate_boxplots(dataframe, metrics, output_directory):
    """Generate one attack-grouped boxplot PNG for each selected metric."""
    output_directory = Path(output_directory)
    output_directory.mkdir(parents=True, exist_ok=True)

    attacks = sorted(
        dataframe["attack"].dropna().astype(str).unique()
    )

    if not attacks:
        raise ValueError("Input CSV contains no attack values.")

    generated = []

    for metric in metrics:
        values = pd.to_numeric(
            dataframe[metric],
            errors="coerce",
        )

        plot_data = []
        plot_labels = []

        for attack in attacks:
            attack_values = values[
                dataframe["attack"].astype(str) == attack
            ].dropna()

            if attack_values.empty:
                continue

            plot_data.append(attack_values.tolist())
            plot_labels.append(attack)

        if not plot_data:
            continue

        figure_width = max(8, min(24, len(plot_labels) * 0.8))
        figure, axis = plt.subplots(
            figsize=(figure_width, 6)
        )

        axis.boxplot(
            plot_data,
            patch_artist=True,
            boxprops={"facecolor": "#8ecae6"},
            medianprops={"color": "#d00000", "linewidth": 2},
            flierprops={
                "marker": "o",
                "markerfacecolor": "#d00000",
                "markersize": 4,
                "alpha": 0.6,
            },
        )
        axis.set_xticks(range(1, len(plot_labels) + 1))
        axis.set_xticklabels(plot_labels)

        axis.set_xlabel("Ataque")
        axis.set_ylabel(f"Valor de {metric} por tentativa")
        axis.set_title(
            f"Distribuição de {metric} por ataque"
        )
        axis.tick_params(axis="x", rotation=45)
        axis.grid(axis="y", alpha=0.3)

        figure.tight_layout()

        output_path = output_directory / (
            f"{safe_filename(metric)}.png"
        )
        figure.savefig(
            output_path,
            dpi=300,
            bbox_inches="tight",
        )
        plt.close(figure)
        generated.append(output_path)

    return generated


def coefficient_of_variation(values):
    """Return population standard deviation divided by the mean."""
    if values.empty:
        return float("nan")

    average = values.mean()
    if average == 0:
        return float("nan")

    return values.std(ddof=0) / average


def generate_statistics_csv(dataframe, metrics, output_directory):
    """Write status-separated and combined statistics for every attack."""
    output_directory = Path(output_directory)
    output_directory.mkdir(parents=True, exist_ok=True)

    rows = []
    attacks = sorted(dataframe["attack"].dropna().astype(str).unique())

    for attack in attacks:
        attack_rows = dataframe[
            dataframe["attack"].astype(str) == attack
        ]

        # Baseline rows do not represent failed or successful attacks.
        attack_rows = attack_rows[
            attack_rows["status"].astype(str).isin(ANALYSIS_STATUSES)
        ]
        if attack_rows.empty:
            continue

        row = {"attack": attack}

        for metric in metrics:
            numeric_values = pd.to_numeric(
                attack_rows[metric],
                errors="coerce",
            )

            for status in ANALYSIS_STATUSES:
                status_values = numeric_values[
                    attack_rows["status"].astype(str) == status
                ].dropna()
                prefix = f"{metric}_{status}"
                row[f"{prefix}_mean"] = (
                    status_values.mean()
                    if not status_values.empty
                    else float("nan")
                )
                row[f"{prefix}_stddev"] = (
                    status_values.std(ddof=0)
                    if not status_values.empty
                    else float("nan")
                )
                row[f"{prefix}_cv"] = coefficient_of_variation(
                    status_values
                )

            combined_values = numeric_values.dropna()
            prefix = f"{metric}_all"
            row[f"{prefix}_mean"] = (
                combined_values.mean()
                if not combined_values.empty
                else float("nan")
            )
            row[f"{prefix}_stddev"] = (
                combined_values.std(ddof=0)
                if not combined_values.empty
                else float("nan")
            )
            row[f"{prefix}_cv"] = coefficient_of_variation(
                combined_values
            )

        rows.append(row)

    columns = ["attack"]
    for metric in metrics:
        for group in ("fail", "success", "all"):
            columns.extend([
                f"{metric}_{group}_mean",
                f"{metric}_{group}_stddev",
                f"{metric}_{group}_cv",
            ])

    output_path = output_directory / "attack_distribution_statistics.csv"
    pd.DataFrame(rows, columns=columns).to_csv(
        output_path,
        index=False,
        na_rep="",
    )
    return output_path


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Generate per-metric boxplots from plot_csv.py "
            "per-attempt averages."
        )
    )
    parser.add_argument(
        "input_csv",
        help="CSV file generated by plot_csv.py",
    )
    parser.add_argument(
        "output_directory",
        nargs="?",
        default="distribution",
        help="Directory for PNG files (default: distribution)",
    )
    args = parser.parse_args()

    try:
        dataframe = read_input(args.input_csv)
        metrics = select_average_metrics(dataframe)

        if not metrics:
            raise ValueError(
                "No numeric columns ending with '_avg' were found."
            )

        generated = generate_boxplots(
            dataframe,
            metrics,
            args.output_directory,
        )
        statistics_csv = generate_statistics_csv(
            dataframe,
            metrics,
            args.output_directory,
        )
    except (FileNotFoundError, OSError, ValueError) as error:
        parser.error(str(error))

    print(f"Attacks: {dataframe['attack'].nunique()}")
    print(f"Average metrics: {len(metrics)}")
    print(f"Plots written: {len(generated)}")
    print(f"Statistics CSV: {statistics_csv}")
    print(f"Output directory: {Path(args.output_directory)}")


if __name__ == "__main__":
    main()
