#!/usr/bin/env python3

import csv
import sys
from collections import defaultdict
from itertools import combinations
from pathlib import Path
from statistics import mean, median


INTERVAL = 0.01
DEFAULT_RADII = (0, 1, 5, 10, 25, 50, 100, 200, 500, 1000)


def read_execution_lengths(filename):
    """Read the number of timestamps in each execution."""
    executions = defaultdict(int)

    with Path(filename).open(newline="") as file:
        reader = csv.DictReader(file)

        required = {"attack", "attempt", "status", "time"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                "Input CSV is missing columns: "
                + ", ".join(sorted(missing))
            )

        for row in reader:
            key = (
                row["attack"],
                int(row["attempt"]),
                row["status"],
            )
            executions[key] += 1

    return executions


def sakoe_chiba_comparisons(size_a, size_b, radius):
    """Count cells allowed by tslearn's Sakoe-Chiba mask."""
    if size_a <= size_b:
        width = size_b - size_a + radius
        total = 0

        for index in range(size_a):
            lower = max(0, index - radius)
            upper = min(size_b, index + width + 1)
            total += max(0, upper - lower)

        return total

    return sakoe_chiba_comparisons(size_b, size_a, radius)


def format_number(value):
    return f"{value:,.0f}".replace(",", "_")


def print_execution_summary(executions):
    lengths = list(executions.values())
    durations = [(length - 1) * INTERVAL for length in lengths]

    print("=" * 80)
    print("SAKoe-CHIBA BAND ANALYSIS")
    print("=" * 80)
    print(f"Input executions: {len(lengths)}")
    print(f"Sampling interval: {INTERVAL:.3f}s")
    print()
    print("Execution lengths")
    print("-----------------")
    print(f"minimum samples: {min(lengths):,}")
    print(f"median samples:  {median(lengths):,.0f}")
    print(f"mean samples:    {mean(lengths):,.2f}")
    print(f"maximum samples: {max(lengths):,}")
    print(f"minimum duration: {min(durations):.3f}s")
    print(f"median duration:  {median(durations):.3f}s")
    print(f"mean duration:    {mean(durations):.3f}s")
    print(f"maximum duration: {max(durations):.3f}s")
    print()


def print_pair_summary(executions):
    pairs = list(combinations(executions.values(), 2))
    unrestricted = [
        size_a * size_b
        for size_a, size_b in pairs
    ]

    print("Pairwise DTW workload without a band")
    print("-------------------------------------")
    print(f"Execution pairs: {len(pairs)}")
    print(f"Total comparisons: {format_number(sum(unrestricted))}")
    print(f"Mean comparisons/pair: {mean(unrestricted):,.0f}")
    print(f"Median comparisons/pair: {median(unrestricted):,.0f}")
    print(f"Maximum comparisons/pair: {format_number(max(unrestricted))}")
    print()


def print_radius_analysis(executions):
    pairs = list(combinations(executions.values(), 2))
    unrestricted_total = sum(
        size_a * size_b
        for size_a, size_b in pairs
    )

    print("Sakoe-Chiba workload by radius")
    print("------------------------------")
    print(
        f"{'radius':>8} "
        f"{'seconds':>9} "
        f"{'comparisons':>18} "
        f"{'per pair':>14} "
        f"{'reduction':>10}"
    )

    for radius in DEFAULT_RADII:
        comparisons = [
            sakoe_chiba_comparisons(size_a, size_b, radius)
            for size_a, size_b in pairs
        ]
        total = sum(comparisons)
        reduction = 100.0 * (
            1.0 - total / unrestricted_total
        )

        print(
            f"{radius:8d} "
            f"{radius * INTERVAL:9.2f} "
            f"{format_number(total):>18} "
            f"{mean(comparisons):14,.0f} "
            f"{reduction:9.2f}%"
        )

    print()
    print(
        "The seconds column is an approximate interpretation of the "
        "sample radius at the 10 ms input grid."
    )
    print(
        "The comparison counts use tslearn's exact rectangular "
        "Sakoe-Chiba mask, including unequal series lengths."
    )


def main():
    if len(sys.argv) != 2:
        print(
            f"Usage: {sys.argv[0]} <timeseries.csv>",
            file=sys.stderr,
        )
        return 1

    filename = Path(sys.argv[1])
    if not filename.is_file():
        print(f"Error: input file does not exist: {filename}", file=sys.stderr)
        return 1

    try:
        executions = read_execution_lengths(filename)
    except (OSError, ValueError, csv.Error) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    if len(executions) < 2:
        print("Error: at least two executions are required.", file=sys.stderr)
        return 1

    print_execution_summary(executions)
    print_pair_summary(executions)
    print_radius_analysis(executions)
    return 0


if __name__ == "__main__":
    sys.exit(main())
