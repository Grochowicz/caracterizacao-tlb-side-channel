#!/usr/bin/env python3

import sys
import csv
import re
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


METRICS = [
    "victim_avg_cpu",
    "victim_avg_mem",
    "victim_max_cpu",
    "victim_max_mem",
    "victim_time",

    "attack_avg_cpu",
    "attack_avg_mem",
    "attack_max_cpu",
    "attack_max_mem",
    "attack_time",
]


def read_analysis(filename):
    data = {}

    with open(filename, newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            process = row["process"]

            data[process] = {
                "total_samples": int(row["total_samples"]),
                "samples": int(row["samples"]),
                "avg_cpu": float(row["avg_cpu"]),
                "avg_mem": float(row["avg_mem"]),
                "max_cpu": float(row["max_cpu"]),
                "max_mem": float(row["max_mem"]),
                "time": float(row["time"]),
            }

    return data


def attack_succeeded(attack_file):
    """
    Return True if the last non-empty line of the attack output
    is exactly '[+] success'.
    """

    if not attack_file.exists():
        return False

    with open(attack_file) as f:
        lines = f.readlines()

    lines = [line.strip() for line in lines if line.strip()]

    if not lines:
        return False

    return lines[-1] == "[+] success"


def make_row(filename):
    data = read_analysis(filename)

    victim = data.get("test-tlb")

    if victim is None:
        print(
            f"Warning: faltando test-tlb em {filename}",
            file=sys.stderr,
        )
        return None

    # --------------------------------------------------------
    # Baseline
    # --------------------------------------------------------

    if filename.name == "baseline_analysis.csv":
        return {
            "attack": "baseline",
            "attempt": 0,

            "victim_avg_cpu": victim["avg_cpu"],
            "victim_avg_mem": victim["avg_mem"],
            "victim_max_cpu": victim["max_cpu"],
            "victim_max_mem": victim["max_mem"],
            "victim_time": victim["time"],

            "attack_avg_cpu": 0.0,
            "attack_avg_mem": 0.0,
            "attack_max_cpu": 0.0,
            "attack_max_mem": 0.0,
            "attack_time": 0.0,
        }

    # --------------------------------------------------------
    # Attack
    # --------------------------------------------------------

    match = re.match(
        r"(.+)_([0-9]+)_analysis\.csv$",
        filename.name,
    )

    if not match:
        print(
            f"Warning: nome de arquivo inesperado: {filename}",
            file=sys.stderr,
        )
        return None

    attack = match.group(1)
    attempt = int(match.group(2))

    attack_process = attack + ".elf"

    attack_data = data.get(attack_process)

    if attack_data is None:
        print(
            f"Warning: faltando {attack_process} em {filename}",
            file=sys.stderr,
        )
        return None

    return {
        "attack": attack,
        "attempt": attempt,

        "victim_avg_cpu": victim["avg_cpu"],
        "victim_avg_mem": victim["avg_mem"],
        "victim_max_cpu": victim["max_cpu"],
        "victim_max_mem": victim["max_mem"],
        "victim_time": victim["time"],

        "attack_avg_cpu": attack_data["avg_cpu"],
        "attack_avg_mem": attack_data["avg_mem"],
        "attack_max_cpu": attack_data["max_cpu"],
        "attack_max_mem": attack_data["max_mem"],
        "attack_time": attack_data["time"],
    }


def select_attempts(results_dir, analysis_files):
    """
    For each attack:

      - Include one failing attempt, if one exists.
      - Include one successful attempt, if one exists.
      - If multiple successful attempts exist, use the last one.
      - If multiple failing attempts exist, use the first one.

    Baseline is always included.
    """

    grouped = {}

    for analysis_file in analysis_files:
        if analysis_file.name == "baseline_analysis.csv":
            continue

        match = re.match(
            r"(.+)_([0-9]+)_analysis\.csv$",
            analysis_file.name,
        )

        if not match:
            continue

        attack = match.group(1)
        attempt = int(match.group(2))

        grouped.setdefault(attack, []).append(
            (attempt, analysis_file)
        )

    selected = []

    for attack, attempts in sorted(grouped.items()):
        attempts.sort(key=lambda x: x[0])

        successful = []
        failed = []

        for attempt, analysis_file in attempts:
            attack_file = results_dir / (
                f"{attack}_{attempt}_attack.txt"
            )

            if attack_succeeded(attack_file):
                successful.append(
                    (attempt, analysis_file)
                )
            else:
                failed.append(
                    (attempt, analysis_file)
                )

        # One failing attempt, if available.
        if failed:
            selected.append(("fail",failed[0][1]))

        # Last successful attempt, if available.
        if successful:
            selected.append(("success",successful[-1][1]))

    return selected


def create_csv(rows, output):
    fields = [
        "attack",
        "attempt",
        "status",
        *METRICS,
    ]

    with open(output, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fields,
        )

        writer.writeheader()
        writer.writerows(rows)

    print("CSV:", output)


def create_heatmap(rows, output):
    if not rows:
        return

    labels = []

    for row in rows:
        if row["attack"] == "baseline":
            labels.append("baseline")
        else:
            labels.append(
                f'{row["attack"]}_{row["status"]}'
            )

    matrix = np.array(
        [
            [
                float(row[metric])
                for metric in METRICS
            ]
            for row in rows
        ],
        dtype=float,
    )

    # --------------------------------------------------------
    # Normalize each metric considering baseline as 1 and plotting % change from baseline
    # --------------------------------------------------------

    normalized = np.zeros_like(matrix)

    for j in range(matrix.shape[1]):
        column = matrix[:, j]

        baseline_value = column[0]

        mx = np.max(column)

        if baseline_value == 0:
            normalized[:, j] = column / mx if mx != 0 else column
        else:
            normalized[:, j] = column / baseline_value

        #debug
        #print(f"Metric: {METRICS[j]}, baseline: {baseline_value}, max: {mx}, normalized: {normalized[:, j]}")


    fig_height = max(
        6,
        len(labels) * 0.4,
    )

    fig, ax = plt.subplots(
        figsize=(18, fig_height)
    )

    image = ax.imshow(
        normalized,
        aspect="auto",
        interpolation="nearest",
    )

    ax.set_xticks(range(len(METRICS)))
    ax.set_xticklabels(
        METRICS,
        rotation=90,
    )

    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels)

    ax.set_xlabel("Metrica")
    ax.set_ylabel("Ataque")
    ax.set_title("Estatisticas de ataque (normalizadas)")

    fig.colorbar(
        image,
        ax=ax,
        label="Mudança a partir da baseline (%)",
    )

    fig.tight_layout()
    fig.savefig(
        output,
        dpi=150,
    )

    plt.close(fig)

    print("Heatmap:", output)


def main():
    if len(sys.argv) != 2:
        print(
            f"Usage: {sys.argv[0]} <results_dir>"
        )
        sys.exit(1)

    results_dir = Path(sys.argv[1])

    if not results_dir.is_dir():
        print(
            f"Erro: {results_dir} nao e um diretorio",
            file=sys.stderr,
        )
        sys.exit(1)

    output_dir = Path("./heatmap")
    output_dir.mkdir(exist_ok=True)

    all_analysis_files = sorted(
        results_dir.glob("*_analysis.csv")
    )

    if not all_analysis_files:
        print(
            "Erro: nenhum arquivo de analise encontrado",
            file=sys.stderr,
        )
        sys.exit(1)

    rows = []

    # --------------------------------------------------------
    # Always include baseline.
    # --------------------------------------------------------

    baseline = results_dir / "baseline_analysis.csv"

    if baseline.exists():
        row = make_row(baseline)

        if row is not None:
            rows.append(row)
    else:
        print(
            "Warning: baseline_analysis.csv nao encontrado",
            file=sys.stderr,
        )

    # --------------------------------------------------------
    # Select attempts.
    # --------------------------------------------------------

    selected_files = select_attempts(
        results_dir,
        all_analysis_files,
    )

    for status, analysis_file in selected_files:
        row = make_row(analysis_file)

        if row is not None:
            row["status"] = status
            rows.append(row)

    if not rows:
        print(
            "Erro: nenhuma linha de dados encontrada",
            file=sys.stderr,
        )
        sys.exit(1)

    csv_output = (
        output_dir / "attack_statistics.csv"
    )

    heatmap_output = (
        output_dir / "attack_statistics_heatmap.png"
    )

    create_csv(
        rows,
        csv_output,
    )

    create_heatmap(
        rows,
        heatmap_output,
    )


if __name__ == "__main__":
    main()
