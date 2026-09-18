#!/usr/bin/env python3

import sys
import csv
import re
from pathlib import Path

import numpy as np


TOP_METRICS = [
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
]


TOP_STDDEV_METRICS = [
    "victim_stddev_cpu",
    "victim_stddev_mem",
    "attack_stddev_cpu",
    "attack_stddev_mem",
]


PERF_EVENTS = [
    "cpu-clock",
    "task-clock",
    "context-switches",
    "cpu-migrations",
    "page-faults",
    "cycles",
    "instructions",
    "branches",
    "branch-misses",
    "r2012",
    "r2011",
#    "r0e12", era para ser algo do tlb mas nao ta disponivel parece
]


PERF_NAMES = {
    "r2012": "DTLB_LOAD_MISSES.STLB_HIT",
    "r2011": "ITLB_MISSES.STLB_HIT",
}


PERF_METRICS = []

PERF_STDDEV_METRICS = []

for event in PERF_EVENTS:
    PERF_METRICS.append(
        "perf_" + event + "_avg"
    )

    PERF_METRICS.append(
        "perf_" + event + "_max"
    )

    PERF_STDDEV_METRICS.append(
        "perf_" + event + "_stddev"
    )


VICTIM_METRICS = [
    "victim_avg_latency",
    "victim_max_latency",
]


VICTIM_STDDEV_METRICS = [
    "victim_stddev_latency",
]


# ------------------------------------------------------------
# METRICS contains ONLY values that should become heatmap
# cells.
#
# Stddev values are deliberately kept out of this list.
# ------------------------------------------------------------

METRICS = (
    TOP_METRICS
    + PERF_METRICS
    + VICTIM_METRICS
)


# ------------------------------------------------------------
# All stddev values are still written to the CSV.
# They are not heatmap cells.
# ------------------------------------------------------------

STDDEV_METRICS = (
    TOP_STDDEV_METRICS
    + PERF_STDDEV_METRICS
    + VICTIM_STDDEV_METRICS
)


# ============================================================
# TOP ANALYSIS
# ============================================================

def read_analysis(filename):
    """
    Read analyze_top.py output.

    The CSV is PID-based:

        pid,total_samples,samples,avg_cpu,stddev_cpu,...

    Return:

        {
            pid: {
                ...
            }
        }
    """

    data = {}

    with open(filename, newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            pid = row["pid"]

            data[pid] = {
                "total_samples": int(row["total_samples"]),
                "samples": int(row["samples"]),

                "avg_cpu": float(row["avg_cpu"]),
                "stddev_cpu": float(row["stddev_cpu"]),
                "max_cpu": float(row["max_cpu"]),

                "avg_mem": float(row["avg_mem"]),
                "stddev_mem": float(row["stddev_mem"]),
                "max_mem": float(row["max_mem"]),

                "time": float(row["time"]),
            }

    return data


# ============================================================
# PERF ANALYSIS
# ============================================================

def read_perf(filename):
    """
    Read the CSV produced by analyze_perf.py.

    Expected format:

        event,samples,average,stddev,max
        page-faults,...
        ...
    """

    data = {}

    if not filename.exists():
        return data

    with open(filename, newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            event = row["event"]

            if event not in PERF_EVENTS:
                print(
                    f"Warning: evento desconhecido em {filename}: {event}",
                    file=sys.stderr,
                )
                continue

            data["perf_" + event + "_avg"] = float(
                row["average"]
            )

            data["perf_" + event + "_stddev"] = float(
                row["stddev"]
            )

            data["perf_" + event + "_max"] = float(
                row["max"]
            )

    return data


# ============================================================
# VICTIM LATENCY
# ============================================================

def read_victim_latency(filename):
    latencies = []

    if not filename.exists():
        print(
            f"Warning: arquivo de latencia do victim nao encontrado: {filename}",
            file=sys.stderr,
        )

        return {
            "victim_avg_latency": 0.0,
            "victim_stddev_latency": 0.0,
            "victim_max_latency": 0.0,
        }

    pattern = re.compile(
        r"measured latency\s*=\s*([0-9.]+)ns"
    )

    with open(filename) as f:
        for line in f:
            match = pattern.search(line)

            if match:
                latencies.append(
                    float(match.group(1))
                )

    if not latencies:
        print(
            f"Warning: nenhuma latencia medida encontrada em {filename}",
            file=sys.stderr,
        )

        return {
            "victim_avg_latency": 0.0,
            "victim_stddev_latency": 0.0,
            "victim_max_latency": 0.0,
        }

    data = {
        "victim_avg_latency": (
            sum(latencies) / len(latencies)
        ),

        "victim_stddev_latency": (
            np.std(latencies)
        ),

        "victim_max_latency": (
            max(latencies)
        ),
    }

    return data


# ============================================================
# ATTACK SUCCESS
# ============================================================

def attack_succeeded(attack_file):
    """
    Return True if the last non-empty line of the attack output
    is exactly '[+] success'.
    """

    if not attack_file.exists():
        return False

    with open(attack_file) as f:
        lines = f.readlines()

    lines = [
        line.strip()
        for line in lines
        if line.strip()
    ]

    if not lines:
        return False

    if attack_file.name.startswith("tlbleed"):
        return True

    return lines[-1] == "[+] success"


# ============================================================
# PID FILE
# ============================================================

def read_pids(filename):
    """
    Read:

        Victim PID: 12345
        Attack PID: 12346

    Return:

        victim_pid, attack_pid
    """

    victim_pid = None
    attack_pid = None

    if not filename.exists():
        return victim_pid, attack_pid

    with open(filename) as f:
        for line in f:
            line = line.strip()

            if line.startswith("Victim PID:"):
                victim_pid = (
                    line.split(":", 1)[1].strip()
                )

            elif line.startswith("Attack PID:"):
                attack_pid = (
                    line.split(":", 1)[1].strip()
                )

    return victim_pid, attack_pid


# ============================================================
# MAKE ROW
# ============================================================

def make_row(filename, results_dir):
    data = read_analysis(filename)

    # --------------------------------------------------------
    # Baseline
    # --------------------------------------------------------

    if filename.name == "baseline_analysis.csv":

        # Baseline only has the victim.
        if not data:
            print(
                f"Warning: nenhum PID encontrado em {filename}",
                file=sys.stderr,
            )
            return None

        # There should only be one process in the baseline.
        victim_pid = next(iter(data))

        victim = data[victim_pid]

        perf_file = (
            results_dir /
            "baseline_perf_analysis.csv"
        )

        perf_data = read_perf(perf_file)

        victim_data = read_victim_latency(
            results_dir / "baseline_victim.txt"
        )

        row = {
            "attack": "baseline",
            "attempt": 0,

            "victim_avg_cpu": victim["avg_cpu"],
            "victim_stddev_cpu": victim["stddev_cpu"],
            "victim_max_cpu": victim["max_cpu"],

            "victim_avg_mem": victim["avg_mem"],
            "victim_stddev_mem": victim["stddev_mem"],
            "victim_max_mem": victim["max_mem"],

            "victim_time": victim["time"],

            "attack_avg_cpu": 0.0,
            "attack_stddev_cpu": 0.0,
            "attack_max_cpu": 0.0,

            "attack_avg_mem": 0.0,
            "attack_stddev_mem": 0.0,
            "attack_max_mem": 0.0,

            "attack_time": 0.0,
        }

        row.update(perf_data)
        row.update(victim_data)

        return row

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

    # --------------------------------------------------------
    # Get the actual PIDs from the corresponding PID file.
    # --------------------------------------------------------

    pid_file = (
        results_dir /
        f"{attack}_{attempt}_pids.txt"
    )

    victim_pid, attack_pid = read_pids(pid_file)

    if victim_pid is None:
        print(
            f"Warning: victim PID nao encontrado em {pid_file}",
            file=sys.stderr,
        )
        return None

    if attack_pid is None:
        print(
            f"Warning: attack PID nao encontrado em {pid_file}",
            file=sys.stderr,
        )
        return None

    # --------------------------------------------------------
    # Find the corresponding rows by PID.
    # --------------------------------------------------------

    victim = data.get(victim_pid)
    attack_data = data.get(attack_pid)

    if victim is None:
        print(
            f"Warning: PID {victim_pid} nao encontrado em {filename}",
            file=sys.stderr,
        )
        return None

    if attack_data is None:
        print(
            f"Warning: PID {attack_pid} nao encontrado em {filename}",
            file=sys.stderr,
        )
        return None

    # --------------------------------------------------------
    # Corresponding perf analysis:
    #
    # dpm_leak_1_perf_analysis.csv
    # --------------------------------------------------------

    perf_file = (
        results_dir /
        f"{attack}_{attempt}_perf_analysis.csv"
    )

    perf_data = read_perf(perf_file)

    victim_data = read_victim_latency(
        results_dir /
        f"{attack}_{attempt}_victim.txt"
    )

    row = {
        "attack": attack,
        "attempt": attempt,

        "victim_avg_cpu": victim["avg_cpu"],
        "victim_stddev_cpu": victim["stddev_cpu"],
        "victim_max_cpu": victim["max_cpu"],

        "victim_avg_mem": victim["avg_mem"],
        "victim_stddev_mem": victim["stddev_mem"],
        "victim_max_mem": victim["max_mem"],

        "victim_time": victim["time"],

        "attack_avg_cpu": attack_data["avg_cpu"],
        "attack_stddev_cpu": attack_data["stddev_cpu"],
        "attack_max_cpu": attack_data["max_cpu"],

        "attack_avg_mem": attack_data["avg_mem"],
        "attack_stddev_mem": attack_data["stddev_mem"],
        "attack_max_mem": attack_data["max_mem"],

        "attack_time": attack_data["time"],
    }

    row.update(perf_data)
    row.update(victim_data)

    return row


# ============================================================
# SELECT ATTEMPTS
# ============================================================

def select_attempts(results_dir, analysis_files):
    """
    For each attack:

      - Include one failing attempt, if one exists.
      - Include one successful attempt, if one exists.
      - If multiple successful attempts exist, use the last one.
      - If multiple failing attempts exist, use the first one.
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

        grouped.setdefault(
            attack,
            []
        ).append(
            (attempt, analysis_file)
        )

    selected = []

    for attack, attempts in sorted(grouped.items()):

        attempts.sort(
            key=lambda x: x[0]
        )

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

        if failed:
            selected.append(
                ("fail", failed[0][1])
            )

        if successful:
            selected.append(
                ("success", successful[-1][1])
            )

    return selected


# ============================================================
# CREATE CSV
# ============================================================

def create_csv(rows, output):

    fields = [
        "attack",
        "attempt",
        "status",
    ] + METRICS + STDDEV_METRICS

    with open(output, "w", newline="") as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fields,
        )

        writer.writeheader()

        for row in rows:

            # Missing metrics become 0.
            #
            # This includes stddev values, which are written
            # to the CSV but are not heatmap cells.
            for metric in METRICS + STDDEV_METRICS:
                if metric not in row:
                    row[metric] = 0.0

            writer.writerow(row)

    print("CSV:", output)


# ============================================================
# MAIN
# ============================================================

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
    # Baseline
    # --------------------------------------------------------

    baseline = (
        results_dir /
        "baseline_analysis.csv"
    )

    if baseline.exists():

        row = make_row(
            baseline,
            results_dir,
        )

        if row is not None:
            row["status"] = "baseline"
            rows.append(row)

    else:
        print(
            "Warning: baseline_analysis.csv nao encontrado",
            file=sys.stderr,
        )

    # --------------------------------------------------------
    # Attacks
    # --------------------------------------------------------

    selected_files = select_attempts(
        results_dir,
        all_analysis_files,
    )

    for status, analysis_file in selected_files:

        row = make_row(
            analysis_file,
            results_dir,
        )

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
        output_dir /
        "attack_statistics.csv"
    )

    create_csv(
        rows,
        csv_output,
    )


if __name__ == "__main__":
    main()
