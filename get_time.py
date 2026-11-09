#!/usr/bin/env python3

import argparse
import csv
import re
from pathlib import Path
from statistics import mean

from analysis_timing import measurement_window


TIME_COLUMNS = ("victim_time", "attack_time")
WARMUP = 12.0
COOLDOWN = 1.0


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "Summarize execution times and check whether zero values "
            "have TOP time-series samples."
        )
    )
    parser.add_argument(
        "--statistics-glob",
        default="justin/heatmap/attack_statistics_*.csv",
        help="Glob for plot_csv.py output files.",
    )
    parser.add_argument(
        "--results-root",
        default="justin",
        help="Directory containing results-* directories.",
    )
    return parser.parse_args()


def load_rows(filename):
    with Path(filename).open(newline="") as file:
        return list(csv.DictReader(file))


def application_name(statistics_file):
    match = re.match(
        r"attack_statistics_(.+)\.csv$",
        Path(statistics_file).name,
    )
    if not match:
        return Path(statistics_file).stem

    suffix = match.group(1)
    if suffix == "1q-cpu-0":
        return "run-ap0"
    if suffix == "1q-cpu-1":
        return "run-ap1"
    if suffix == "3q-por-cpu":
        return "run-noap"
    return suffix


def results_directory(statistics_file, results_root):
    name = Path(statistics_file).name
    suffix = name.removeprefix("attack_statistics_")
    suffix = suffix.removesuffix(".csv")
    return Path(results_root) / f"results-{suffix}"


def read_pid_file(filename):
    pids = {}
    if not filename.is_file():
        return pids

    with filename.open() as file:
        for line in file:
            label, separator, value = line.partition(":")
            if separator:
                try:
                    pids[label.strip().lower().replace(" ", "_")] = int(
                        value.strip()
                    )
                except ValueError:
                    continue
    return pids


def count_top_samples(filename, pid):
    if not filename.is_file():
        return 0

    count = 0
    with filename.open() as file:
        reader = csv.DictReader(file)
        for row in reader:
            if pid is None or str(row.get("pid", "")) == str(pid):
                count += 1
    return count


def read_timing(filename):
    values = {}
    if not filename.is_file():
        return values

    with filename.open() as file:
        for line in file:
            key, separator, value = line.partition("=")
            if separator:
                try:
                    values[key.strip()] = float(value.strip())
                except ValueError:
                    continue
    return values


def count_eligible_top_samples(
    results_dir,
    attack,
    attempt,
    pid,
):
    prefix = f"{attack}_{attempt}"
    top_file = results_dir / f"{prefix}_top.txt"
    timing = read_timing(results_dir / f"{prefix}_timing.txt")

    if not top_file.is_file() or "warmup_start" not in timing:
        return 0

    observed_timestamps = []
    current_timestamp = None

    with top_file.open() as file:
        for line in file:
            if line.startswith("===== SAMPLE "):
                try:
                    current_timestamp = float(line.split()[2])
                except (IndexError, ValueError):
                    current_timestamp = None
                continue

            if (
                current_timestamp is not None
                and line.strip().startswith(str(pid))
            ):
                observed_timestamps.append(current_timestamp)

    if not observed_timestamps:
        return 0

    lower, upper = measurement_window(
        observed_timestamps,
        timing["warmup_start"],
        WARMUP,
        COOLDOWN,
    )
    if lower is None or upper is None or upper < lower:
        return 0

    eligible = 0
    current_timestamp = None
    with top_file.open() as file:
        for line in file:
            if line.startswith("===== SAMPLE "):
                try:
                    current_timestamp = float(line.split()[2])
                except (IndexError, ValueError):
                    current_timestamp = None
                continue

            if (
                current_timestamp is not None
                and lower <= current_timestamp <= upper
                and line.strip().startswith(str(pid))
            ):
                eligible += 1

    return eligible


def collection_for_attempt(results_dir, attack, attempt, role):
    prefix = f"{attack}_{attempt}"
    pids = read_pid_file(results_dir / f"{prefix}_pids.txt")
    pid = pids.get(f"{role}_pid")
    series = results_dir / f"{prefix}_analysis_timeseries.csv"
    return count_top_samples(series, pid), series


def inspect_zero(row, results_dir, metric):
    role = "victim" if metric == "victim_time" else "attack"
    samples, series = collection_for_attempt(
        results_dir,
        row["attack"],
        row["attempt"],
        role,
    )
    pid = read_pid_file(
        results_dir / f"{row['attack']}_{row['attempt']}_pids.txt"
    ).get(f"{role}_pid")
    eligible_samples = count_eligible_top_samples(
        results_dir,
        row["attack"],
        row["attempt"],
        pid,
    )

    if not samples:
        cause = "no_collection_samples"
    elif not eligible_samples:
        cause = "collected_but_removed_by_warmup_cooldown"
    else:
        cause = "collected_and_eligible_but_zero_aggregate"

    return {
        "metric": metric,
        "attack": row["attack"],
        "attempt": row["attempt"],
        "samples": samples,
        "eligible_samples": eligible_samples,
        "series": str(series),
        "cause": cause,
    }


def summarize_metric(rows, metric):
    values = [float(row[metric]) for row in rows]
    nonzero = [value for value in values if value != 0]
    return {
        "n": len(values),
        "mean": mean(values) if values else 0.0,
        "min": min(values) if values else 0.0,
        "max": max(values) if values else 0.0,
        "zero_count": len(values) - len(nonzero),
        "nonzero_mean": mean(nonzero) if nonzero else 0.0,
    }


def print_report(statistics_file, rows, results_dir):
    app = application_name(statistics_file)
    print(f"\n{app} ({Path(statistics_file).name})")
    print("-" * (len(app) + len(Path(statistics_file).name) + 3))

    for metric in TIME_COLUMNS:
        summary = summarize_metric(rows, metric)
        print(
            f"{metric}: n={summary['n']} "
            f"mean={summary['mean']:.3f}s "
            f"min={summary['min']:.3f}s "
            f"max={summary['max']:.3f}s "
            f"zeros={summary['zero_count']} "
            f"mean_without_zeros={summary['nonzero_mean']:.3f}s"
        )

    for row in rows:
        for metric in TIME_COLUMNS:
            if float(row[metric]) != 0:
                continue

            result = inspect_zero(row, results_dir, metric)
            print(
                f"zero: {metric} {result['attack']}_"
                f"{result['attempt']} -> {result['cause']} "
                f"(series_samples={result['samples']}, "
                f"eligible_samples={result['eligible_samples']})"
            )


def main():
    args = parse_arguments()
    statistics_files = sorted(Path(".").glob(args.statistics_glob))

    if not statistics_files:
        raise SystemExit(
            f"No statistics files matched: {args.statistics_glob}"
        )

    for statistics_file in statistics_files:
        rows = [
            row
            for row in load_rows(statistics_file)
            if row.get("status") != "baseline"
        ]
        results_dir = results_directory(
            statistics_file,
            args.results_root,
        )
        print_report(statistics_file, rows, results_dir)


if __name__ == "__main__":
    main()
