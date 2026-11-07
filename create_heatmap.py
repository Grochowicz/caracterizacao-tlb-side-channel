#!/usr/bin/env python3

import sys
import csv
import re

import matplotlib.pyplot as plt
import numpy as np


# ============================================================
# HEATMAP METRICS
#
# Change the order here to change the order in the heatmap.
#
# Stddev metrics are deliberately NOT included here.
# They are only used as annotations on the corresponding
# average cells.
# ============================================================

METRICS = [
    "victim_avg_cpu",
    "victim_max_cpu",
    "victim_avg_mem",
    "victim_max_mem",
    "victim_time",

    "attack_avg_cpu",
    "attack_max_cpu",
    "attack_avg_mem",
    "attack_max_mem",
    "attack_time",

    "perf_cpu-clock_avg",
    "perf_cpu-clock_max",

    "perf_task-clock_avg",
    "perf_task-clock_max",

    "perf_context-switches_avg",
    "perf_context-switches_max",

    "perf_cpu-migrations_avg",
    "perf_cpu-migrations_max",

    "perf_page-faults_avg",
    "perf_page-faults_max",

    "perf_cycles_avg",
    "perf_cycles_max",

    "perf_instructions_avg",
    "perf_instructions_max",

    "perf_branches_avg",
    "perf_branches_max",

    "perf_branch-misses_avg",
    "perf_branch-misses_max",

    "perf_dtlb_load_misses.stlb_hit_avg",
    "perf_dtlb_load_misses.stlb_hit_max",

    "perf_itlb_misses.stlb_hit_avg",
    "perf_itlb_misses.stlb_hit_max",

    "perf_dtlb_load_misses.walk_active_avg",
    "perf_dtlb_load_misses.walk_active_max",

    "perf_dtlb_load_misses.walk_completed_avg",
    "perf_dtlb_load_misses.walk_completed_max",

    "perf_dTLB-loads_avg",
    "perf_dTLB-loads_max",

    "perf_dTLB-store-misses_avg",
    "perf_dTLB-store-misses_max",

    "perf_iTLB-loads_avg",
    "perf_iTLB-loads_max",

    "victim_avg_latency",
    "victim_max_latency",
]


# ============================================================
# Human-readable PERF names.
# ============================================================

PERF_NAMES = {
    "dtlb_load_misses.stlb_hit": "DTLB_LOAD_MISSES.STLB_HIT",
    "itlb_misses.stlb_hit": "ITLB_MISSES.STLB_HIT",
    "dtlb_load_misses.walk_active": "DTLB_LOAD_MISSES.WALK_ACTIVE",
    "dtlb_load_misses.walk_completed": "DTLB_LOAD_MISSES.WALK_COMPLETED",
    "dTLB-loads": "dTLB-loads",
    "dTLB-store-misses": "dTLB-store-misses",
    "iTLB-loads": "iTLB-loads",
}


# ============================================================
# SELECT ATTEMPTS FOR HEATMAP
# ============================================================

def select_attempts(rows):
    """
    For each attack, keep the first failed attempt and the last
    successful attempt, if each exists. Always keep baseline.
    """
    selected = [
        row for row in rows
        if row.get("attack") == "baseline"
    ]
    grouped = {}

    for row in rows:
        attack = row.get("attack", "")
        if attack == "baseline":
            continue

        try:
            attempt = int(row.get("attempt", 0))
        except (TypeError, ValueError):
            continue

        grouped.setdefault(attack, []).append((attempt, row))

    for attack, attempts in sorted(grouped.items()):
        attempts.sort(key=lambda item: item[0])

        failed = [
            row for _, row in attempts
            if row.get("status") != "success"
        ]
        successful = [
            row for _, row in attempts
            if row.get("status") == "success"
        ]

        if failed:
            selected.append(failed[0])

        if successful:
            selected.append(successful[-1])

    return selected


# ============================================================
# READ CSV
# ============================================================

def read_csv(filename):

    rows = []

    with open(filename, newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            rows.append(row)

    return rows


# ============================================================
# CREATE HEATMAP
# ============================================================

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

    # --------------------------------------------------------
    # Convert CSV values into matrix.
    # --------------------------------------------------------

    matrix = np.array(
        [
            [
                float(row.get(metric, 0.0))
                for metric in METRICS
            ]
            for row in rows
        ],
        dtype=float,
    )

    # --------------------------------------------------------
    # Normalize relative to baseline.
    # --------------------------------------------------------

    normalized = np.zeros_like(matrix)

    for j, metric in enumerate(METRICS):

        column = matrix[:, j]

        # baseline only present if the name of row 0 is "baseline"
        baseline_value = column[0] if labels[0] == "baseline" else 0.0

        difference = column - baseline_value

        maximum = np.max(
            np.abs(difference)
        )

        # Average metrics are normalized using the
        # corresponding max metric.
#        if "_avg" in metric:
#            max_metric = metric.replace(
#                "_avg",
#                "_max",
#            )
#            if max_metric in METRICS:
#                max_index = METRICS.index(
#                    max_metric
#                )
#                maximum = max( maximum, np.max( np.abs( matrix[:, max_index] - matrix[0, max_index])),)

        if maximum == 0:

            normalized[:, j] = 0.0

        else:

            normalized[:, j] = (
                difference / maximum
            )

    # --------------------------------------------------------
    # Figure.
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Annotate stddev on average cells.
    #
    # The stddev itself is NOT plotted as a cell.
    # --------------------------------------------------------

    for i, row in enumerate(rows):

        for j, metric in enumerate(METRICS):

            if "_avg" not in metric:
                continue

            stddev_metric = metric.replace(
                "_avg",
                "_stddev",
            )

            if stddev_metric not in row:
                continue

            stddev_value = float(
                row[stddev_metric]
            )

            value = normalized[i, j]

            # Compact scientific-style formatting for
            # very large values while keeping small values
            # readable.
            text = f"±{stddev_value:.1g}"

            ax.text(
                j,
                i,
                text,
                ha="center",
                va="center",
                fontsize=6,
                fontweight="normal",
                color=(
                    "white"
#                    if value < 0.5
#                    else "black"
               ),
            )

    # --------------------------------------------------------
    # X labels.
    # --------------------------------------------------------

    xlabels = []

    for metric in METRICS:

        xlabel = metric

        if metric.startswith("perf_"):

            for raw, readable in PERF_NAMES.items():

                if raw in metric:

                    xlabel = metric.replace(
                        raw,
                        readable,
                    )

                    break

        xlabels.append(xlabel)

    ax.set_xticks(
        range(len(METRICS))
    )

    ax.set_xticklabels(
        xlabels,
        rotation=90,
    )

    # --------------------------------------------------------
    # Y labels.
    # --------------------------------------------------------

    ax.set_yticks(
        range(len(labels))
    )

    ax.set_yticklabels(
        labels
    )

    ax.set_xlabel("Métrica")
    ax.set_ylabel("Ataque")

    ax.set_title(
        "Estatísticas de ataque (normalizadas)"
    )

    fig.colorbar(
        image,
        ax=ax,
        label="Diferença da baseline (normalizada)",
    )

    fig.tight_layout()

    fig.savefig(
        output,
        dpi=150,
    )

    plt.close(fig)

    print("Heatmap:", output)


# ============================================================
# MAIN
# ============================================================

def main():

    if len(sys.argv) != 3:

        print(
            f"Usage: {sys.argv[0]} "
            "<input_csv> <output_png>"
        )

        sys.exit(1)

    input_csv = sys.argv[1]
    output_png = sys.argv[2]

    rows = read_csv(input_csv)

    # Apply the attempt-selection policy used by the original script.
    rows = select_attempts(rows)

    create_heatmap(
        rows,
        output_png,
    )


if __name__ == "__main__":
    main()
