import csv
import re
import sys
from pathlib import Path

from statistics_utils import summarize
from analysis_timing import measurement_window, read_timing


WARMUP = 12.0
COOLDOWN = 1.0


def read_victim_latency(filename):
    measurements = []

    if not filename.exists():
        print(
            f"Warning: arquivo de latencia do victim nao encontrado: {filename}",
            file=sys.stderr,
        )

        return {
            "victim_avg_latency": 0.0,
            "victim_stddev_latency": 0.0,
            "victim_skewness_latency": 0.0,
            "victim_kurtosis_latency": 0.0,
            "victim_max_latency": 0.0,
        }

    pattern = re.compile(
        r"timestamp\s*=\s*([0-9.]+)\s*,\s*"
        r"elapsed time\s*=\s*([0-9.]+)\s*ms,\s*"
        r"measured latency\s*=\s*([0-9.]+)(ns|us)"
    )

    with open(filename) as f:
        for line in f:
            match = pattern.search(line)

            if match:
                timestamp = float(match.group(1))
                elapsed_ms = float(match.group(2))
                latency_ns = float(match.group(3))
                if match.group(4) == "us":
                    latency_ns *= 1000.0
                measurements.append((timestamp, elapsed_ms, latency_ns))

    if not measurements:
        print(
            f"Warning: nenhuma latencia medida encontrada em {filename}",
            file=sys.stderr,
        )

        return {
            "victim_avg_latency": 0.0,
            "victim_stddev_latency": 0.0,
            "victim_skewness_latency": 0.0,
            "victim_kurtosis_latency": 0.0,
            "victim_max_latency": 0.0,
        }

    measurements.sort(key=lambda x: x[0])

    # The victim may begin printing long after collection started.
    timing = read_timing(filename)
    warmup_start = timing["warmup_start"]
    execution_end = measurements[-1][0]

    window_start, window_end = measurement_window(
        [measurement[0] for measurement in measurements],
        warmup_start,
        WARMUP,
        COOLDOWN,
    )

    latencies = [
        latency_ns
        for timestamp, elapsed_ms, latency_ns in measurements
        if window_start <= timestamp <= window_end
    ]

    if not latencies:
        print(
            f"Warning: nenhuma latencia permanece apos warmup/cooldown em {filename}",
            file=sys.stderr,
        )
        return {
            "victim_avg_latency": 0.0,
            "victim_stddev_latency": 0.0,
            "victim_skewness_latency": 0.0,
            "victim_kurtosis_latency": 0.0,
            "victim_max_latency": 0.0,
        }

    stats = summarize(latencies)

    return {
        "victim_avg_latency": stats["average"],
        "victim_stddev_latency": stats["stddev"],
        "victim_skewness_latency": stats["skewness"],
        "victim_kurtosis_latency": stats["kurtosis"],
        "victim_max_latency": max(latencies),
    }


def read_victim_latency_timeseries(filename):
    measurements = []

    if not filename.exists():
        print(
            f"Warning: arquivo de latencia do victim nao encontrado: {filename}",
            file=sys.stderr,
        )
        return measurements

    pattern = re.compile(
        r"timestamp\s*=\s*([0-9.]+)\s*,\s*"
        r"elapsed time\s*=\s*([0-9.]+)\s*ms,\s*"
        r"measured latency\s*=\s*([0-9.]+)(ns|us)"
    )

    with open(filename) as f:
        for line in f:
            match = pattern.search(line)

            if match:
                timestamp = float(match.group(1))
                elapsed_ms = float(match.group(2))
                latency_ns = float(match.group(3))
                if match.group(4) == "us":
                    latency_ns *= 1000.0

                measurements.append(
                    (timestamp, elapsed_ms, latency_ns)
                )

    return measurements


def write_victim_latency_timeseries(
    filename,
    output_filename,
):
    measurements = read_victim_latency_timeseries(filename)
    timing = read_timing(filename)
    window_start, window_end = measurement_window(
        [measurement[0] for measurement in measurements],
        timing["warmup_start"],
        WARMUP,
        COOLDOWN,
    )
    measurements = [
        measurement
        for measurement in measurements
        if window_start <= measurement[0] <= window_end
    ]

    if not measurements:
        print(
            f"Warning: nenhuma latencia medida encontrada em {filename}",
            file=sys.stderr,
        )
        return

    measurements.sort(key=lambda x: x[1])

    with open(output_filename, "w", newline="") as f:
        writer = csv.writer(f)

        writer.writerow([
            "timestamp",
            "event",
            "count",
        ])

        for timestamp, elapsed_ms, latency in measurements:
            writer.writerow([
                f"{elapsed_ms / 1000:.9f}",
                "victim-latency",
                f"{latency:.2f}",
            ])


def write_victim_latency_summary(
    filename,
    output_filename,
):
    data = read_victim_latency(filename)

    with open(output_filename, "w", newline="") as f:
        writer = csv.writer(f)

        writer.writerow([
            "victim_avg_latency",
            "victim_stddev_latency",
            "victim_skewness_latency",
            "victim_kurtosis_latency",
            "victim_max_latency",
        ])

        writer.writerow([
            f"{data['victim_avg_latency']:.2f}",
            f"{data['victim_stddev_latency']:.2f}",
            f"{data['victim_skewness_latency']:.6f}",
            f"{data['victim_kurtosis_latency']:.6f}",
            f"{data['victim_max_latency']:.2f}",
        ])


def main():
    if len(sys.argv) != 3:
        print(
            f"Usage: {sys.argv[0]} <input_file> <output_file>",
            file=sys.stderr,
        )
        sys.exit(1)

    input_filename = Path(sys.argv[1])
    output_filename = Path(sys.argv[2])

    # Accumulated statistics.
    write_victim_latency_summary(
        input_filename,
        output_filename,
    )

    # Preserve the victim's native measurement interval.
    timeseries_filename = Path(
        str(output_filename).replace(
            ".csv",
            "_timeseries.csv",
        )
    )

    write_victim_latency_timeseries(
        input_filename,
        timeseries_filename,
    )


if __name__ == "__main__":
    main()
