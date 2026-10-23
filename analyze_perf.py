#!/usr/bin/env python3

import sys
import csv


WARMUP = 12.0
COOLDOWN = 1.0


if len(sys.argv) != 3:
    print(
        f"Usage: {sys.argv[0]} <perf_file> <output_csv>"
    )
    sys.exit(1)


filename = sys.argv[1]
output = sys.argv[2]


# ------------------------------------------------------------
# Events to analyze.
# ------------------------------------------------------------

EVENTS = [
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
    "r0e12",
]


# ------------------------------------------------------------
# Data accumulated across perf samples.
# ------------------------------------------------------------

data = {
    event: {
        "sum": 0.0,
        "max": 0.0,
        "stddev": 0.0,
        "samples": 0,
        "values": [],
    }
    for event in EVENTS
}


# ------------------------------------------------------------
# Time-series data.
#
# One entry per perf sample and event.
# ------------------------------------------------------------

timeseries = []


# ------------------------------------------------------------
# Parse perf output.
#
# Expected format from:
#
# perf stat -C CPU -I 100 -e EVENTS
#
# Example:
#
#  100.123456      1234.56      cpu-clock
#  100.123456      5678.90      cycles
#
# Some events are printed with:
#
#  100.123456      1.23 msec      cpu-clock
#
# ------------------------------------------------------------

with open(filename) as f:
    for line in f:
        parts = line.split()

        if len(parts) < 3:
            continue

        try:
            timestamp = float(parts[0])
        except ValueError:
            continue

        # ----------------------------------------------------
        # Find the event name.
        #
        # Normal:
        #   time count event
        #
        # With unit:
        #   time count unit event
        # ----------------------------------------------------

        event = None
        count = None

        try:
            count = float(parts[1])
        except ValueError:
            continue

        if parts[2] in EVENTS:
            event = parts[2]

        elif len(parts) >= 4 and parts[3] in EVENTS:
            event = parts[3]

        if event is None:
            continue

        # ----------------------------------------------------
        # Preserve the original time-series sample.
        # Warmup/cooldown are intentionally kept here.
        # ----------------------------------------------------

        timeseries.append({
            "timestamp": timestamp,
            "event": event,
            "count": count,
        })


# ------------------------------------------------------------
# Accumulate aggregate statistics after removing warmup/cooldown.
# ------------------------------------------------------------

if timeseries:
    execution_start = min(point["timestamp"] for point in timeseries)
    execution_end = max(point["timestamp"] for point in timeseries)

    warmup_end = execution_start + WARMUP
    cooldown_start = execution_end - COOLDOWN

    for point in timeseries:
        if not (warmup_end <= point["timestamp"] <= cooldown_start):
            continue

        event = point["event"]
        count = point["count"]

        data[event]["sum"] += count
        data[event]["max"] = max(data[event]["max"], count)
        data[event]["samples"] += 1
        data[event]["values"].append(count)


# ------------------------------------------------------------
# Write aggregated CSV.
#
# This is the original output and remains unchanged.
# ------------------------------------------------------------

with open(output, "w", newline="") as f:
    writer = csv.writer(f)

    writer.writerow([
        "event",
        "samples",
        "average",
        "stddev",
        "max",
    ])

    for event in EVENTS:
        d = data[event]

        if d["samples"]:
            average = (
                d["sum"] / d["samples"]
            )

            variance = sum(
                (x - average) ** 2
                for x in d["values"]
            ) / d["samples"]

            d["stddev"] = variance ** 0.5

        else:
            print(
                f"Warning: No samples for event "
                f"'{event}' (analyze_perf.py)"
            )

            average = 0.0
            d["stddev"] = 0.0

        writer.writerow([
            event,
            d["samples"],
            f"{average:.2f}",
            f"{d['stddev']:.2f}",
            f"{d['max']:.2f}",
        ])


# ------------------------------------------------------------
# Write time-series CSV.
#
# One row = one event at one perf timestamp.
# ------------------------------------------------------------

timeseries_output = (
    output.rsplit(".", 1)[0]
    + "_timeseries.csv"
)

with open(timeseries_output, "w", newline="") as f:
    writer = csv.writer(f)

    writer.writerow([
        "timestamp",
        "event",
        "count",
    ])

    for point in timeseries:
        writer.writerow([
            f"{point['timestamp']:.6f}",
            point["event"],
            f"{point['count']:.2f}",
        ])


print(f"CSV: {output}")
print(f"Time-series CSV: {timeseries_output}")
