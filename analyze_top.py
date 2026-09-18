#!/usr/bin/env python3

import sys
import csv


if len(sys.argv) < 3:
    print(
        f"Usage: {sys.argv[0]} <top_file> <output_csv> "
        "<pid1> [pid2 ...]"
    )
    sys.exit(1)


filename = sys.argv[1]
output = sys.argv[2]
pids = sys.argv[3:]

if not pids:
    n = int(input("Number of monitored processes: "))

    for i in range(n):
        pid = input(f"Process {i + 1} PID: ")
        pids.append(pid)


# Convert to integers so PID comparisons are reliable.
pids = [int(pid) for pid in pids]


# ------------------------------------------------------------
# Data accumulated across snapshots.
# ------------------------------------------------------------

data = {
    pid: {
        "cpu_sum": 0.0,
        "cpu_max": 0.0,
        "cpu_values": [],

        "mem_sum": 0.0,
        "mem_max": 0.0,
        "mem_values": [],

        "samples": 0,
        "time": 0.0,
    }
    for pid in pids
}


# Number of TOP snapshots.
total_samples = 0


# ------------------------------------------------------------
# Current snapshot.
# ------------------------------------------------------------

def reset_snapshot():
    return {
        pid: {
            "cpu": 0.0,
            "mem": 0.0,
            "time": 0.0,
            "observed": False,
        }
        for pid in pids
    }


snapshot_data = reset_snapshot()

in_top = False
in_snapshot = False


def finish_snapshot(snapshot):
    global total_samples

    if not in_snapshot:
        return

    total_samples += 1

    for pid in pids:
        d = snapshot[pid]

        # A PID is considered observed in this snapshot if
        # at least one TOP row for it was present.
        if not d["observed"]:
            continue

        result = data[pid]

        result["cpu_sum"] += d["cpu"]
        result["mem_sum"] += d["mem"]

        result["cpu_max"] = max(
            result["cpu_max"],
            d["cpu"],
        )

        result["mem_max"] = max(
            result["mem_max"],
            d["mem"],
        )

        result["cpu_values"].append(d["cpu"])
        result["mem_values"].append(d["mem"])

        result["samples"] += 1

        # TIME+ is cumulative, so keep the largest value seen.
        result["time"] = max(
            result["time"],
            d["time"],
        )


# ------------------------------------------------------------
# Parse TOP file.
# ------------------------------------------------------------

with open(filename) as f:
    for line in f:
        stripped = line.strip()

        # ----------------------------------------------------
        # Start of a new snapshot.
        # ----------------------------------------------------

        if stripped.startswith("===== SAMPLE "):

            if in_snapshot:
                finish_snapshot(snapshot_data)

            snapshot_data = reset_snapshot()

            in_snapshot = True
            in_top = False

            continue

        if not in_snapshot:
            continue

        # ----------------------------------------------------
        # TOP section.
        # ----------------------------------------------------

        if stripped == "--- TOP ---":
            in_top = True
            continue

        if stripped == "--- PS ---":
            in_top = False
            continue

        if not in_top:
            continue

        # Skip TOP header.
        if stripped.startswith("PID "):
            continue

        parts = line.split()

        # PID USER PR NI VIRT RES SHR S %CPU %MEM TIME+ COMMAND
        if len(parts) < 12:
            continue

        # ----------------------------------------------------
        # PID
        # ----------------------------------------------------

        try:
            pid = int(parts[0])
        except ValueError:
            continue

        if pid not in snapshot_data:
            continue

        # ----------------------------------------------------
        # CPU / MEM
        # ----------------------------------------------------

        try:
            cpu = float(parts[8])
            mem = float(parts[9])
        except ValueError:
            continue

        # ----------------------------------------------------
        # TIME+
        # ----------------------------------------------------

        time_str = parts[10]

        try:
            if ":" in time_str:
                minutes, seconds = time_str.split(":", 1)
                cpu_time = (
                    float(minutes) * 60
                    + float(seconds)
                )
            else:
                cpu_time = float(time_str)

        except ValueError:
            continue

        # ----------------------------------------------------
        # Add this occurrence to the current snapshot.
        #
        # Multiple rows for the same PID are combined.
        # ----------------------------------------------------

        snapshot_data[pid]["cpu"] += cpu
        snapshot_data[pid]["mem"] += mem
        snapshot_data[pid]["time"] += cpu_time
        snapshot_data[pid]["observed"] = True


# Finish final snapshot.
if in_snapshot:
    finish_snapshot(snapshot_data)


# ------------------------------------------------------------
# Write CSV.
# ------------------------------------------------------------

with open(output, "w", newline="") as f:
    writer = csv.writer(f)

    writer.writerow([
        "pid",
        "total_samples",
        "samples",
        "avg_cpu",
        "stddev_cpu",
        "max_cpu",
        "avg_mem",
        "stddev_mem",
        "max_mem",
        "time",
    ])

    for pid in pids:
        d = data[pid]

        if d["samples"]:
            average_cpu = (
                d["cpu_sum"] / d["samples"]
            )

            variance_cpu = sum(
                (value - average_cpu) ** 2
                for value in d["cpu_values"]
            ) / d["samples"]

            stddev_cpu = variance_cpu ** 0.5

            average_mem = (
                d["mem_sum"] / d["samples"]
            )

            variance_mem = sum(
                (value - average_mem) ** 2
                for value in d["mem_values"]
            ) / d["samples"]

            stddev_mem = variance_mem ** 0.5

        else:
            print(
                f"Warning: PID {pid} has no samples "
                f"(analyze_top.py)."
            )

            average_cpu = 0.0
            average_mem = 0.0
            stddev_cpu = 0.0
            stddev_mem = 0.0

        writer.writerow([
            pid,
            total_samples,
            d["samples"],
            f"{average_cpu:.2f}",
            f"{stddev_cpu:.2f}",
            f"{d['cpu_max']:.2f}",
            f"{average_mem:.2f}",
            f"{stddev_mem:.2f}",
            f"{d['mem_max']:.2f}",
            f"{d['time']:.2f}",
        ])


print(f"CSV: {output}")
