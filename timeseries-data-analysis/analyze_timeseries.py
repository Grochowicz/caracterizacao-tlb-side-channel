#!/usr/bin/env python3

import sys
import csv
from pathlib import Path
from collections import defaultdict

import numpy as np


INTERVAL = 0.01
TIME_TOLERANCE = 1e-6


def read_csv(filename):
    executions = defaultdict(list)

    with open(filename, newline="") as f:
        reader = csv.DictReader(f)

        fields = reader.fieldnames

        metadata_fields = {
            "attack",
            "attempt",
            "status",
            "time",
        }

        features = [
            field
            for field in fields
            if field not in metadata_fields
        ]

        for row in reader:
            key = (
                row["attack"],
                int(row["attempt"]),
                row["status"],
            )

            timestamp = float(row["time"])

            values = {}

            for feature in features:
                value = row[feature].strip()

                if value == "":
                    values[feature] = np.nan
                else:
                    try:
                        values[feature] = float(value)
                    except ValueError:
                        values[feature] = np.nan

            executions[key].append(
                {
                    "time": timestamp,
                    "values": values,
                }
            )

    return executions, features


def expected_time_grid(start, end):
    start = round(start, 10)
    end = round(end, 10)

    first = int(np.ceil(
        start / INTERVAL - TIME_TOLERANCE
    ))

    last = int(np.floor(
        end / INTERVAL + TIME_TOLERANCE
    ))

    return np.array([
        round(i * INTERVAL, 10)
        for i in range(first, last + 1)
    ])


def analyze_execution(key, rows, features):
    times = np.array(
        [row["time"] for row in rows],
        dtype=float,
    )

    times_sorted = np.sort(times)

    start = times_sorted[0]
    end = times_sorted[-1]
    duration = end - start

    expected_count = int(
        round(duration / INTERVAL)
    ) + 1

    actual_count = len(times)

    unique_times = np.unique(times)

    duplicate_count = (
        actual_count - len(unique_times)
    )

    deltas = np.diff(times_sorted)

    if len(deltas):
        delta_min = np.min(deltas)
        delta_max = np.max(deltas)
        delta_mean = np.mean(deltas)

        bad_intervals = np.sum(
            np.abs(
                deltas - INTERVAL
            ) > TIME_TOLERANCE
        )

        gaps = deltas[
            deltas > INTERVAL + TIME_TOLERANCE
        ]

    else:
        delta_min = 0.0
        delta_max = 0.0
        delta_mean = 0.0
        bad_intervals = 0
        gaps = np.array([])

    expected_grid = expected_time_grid(
        start,
        end,
    )

    actual_set = {
        round(time, 10)
        for time in unique_times
    }

    missing_timestamps = [
        time
        for time in expected_grid
        if round(time, 10) not in actual_set
    ]

    missing_values = {}
    leading_missing = {}
    interior_missing = {}
    trailing_missing = {}
    complete_missing = {}

    for feature in features:
        values = np.array(
            [
                row["values"][feature]
                for row in rows
            ],
            dtype=float,
        )

        missing = np.isnan(values)

        count = int(np.sum(missing))

        missing_values[feature] = count

        if count == 0:
            leading_missing[feature] = 0
            interior_missing[feature] = 0
            trailing_missing[feature] = 0
            complete_missing[feature] = False
            continue

        non_missing = np.flatnonzero(~missing)

        if len(non_missing) == 0:
            leading_missing[feature] = count
            interior_missing[feature] = 0
            trailing_missing[feature] = 0
            complete_missing[feature] = True
            continue

        first = non_missing[0]
        last = non_missing[-1]

        leading = int(np.sum(
            missing[:first]
        ))

        trailing = int(np.sum(
            missing[last + 1:]
        ))

        interior = count - leading - trailing

        leading_missing[feature] = leading
        interior_missing[feature] = interior
        trailing_missing[feature] = trailing
        complete_missing[feature] = False

    return {
        "key": key,
        "start": start,
        "end": end,
        "duration": duration,
        "actual_count": actual_count,
        "expected_count": expected_count,
        "count_difference": actual_count - expected_count,
        "unique_count": len(unique_times),
        "duplicate_count": duplicate_count,
        "delta_min": delta_min,
        "delta_max": delta_max,
        "delta_mean": delta_mean,
        "bad_intervals": bad_intervals,
        "gap_count": len(gaps),
        "largest_gap": (
            float(np.max(gaps))
            if len(gaps)
            else 0.0
        ),
        "missing_timestamps": missing_timestamps,
        "missing_values": missing_values,
        "leading_missing": leading_missing,
        "interior_missing": interior_missing,
        "trailing_missing": trailing_missing,
        "complete_missing": complete_missing,
    }


def analyze_feature_scales(executions, features):
    values = {
        feature: []
        for feature in features
    }

    for rows in executions.values():
        for row in rows:
            for feature in features:
                value = row["values"][feature]

                if not np.isnan(value):
                    values[feature].append(value)

    result = {}

    for feature in features:
        data = np.asarray(
            values[feature],
            dtype=float,
        )

        if len(data) == 0:
            result[feature] = {
                "count": 0,
                "min": np.nan,
                "max": np.nan,
                "mean": np.nan,
                "std": np.nan,
                "range": np.nan,
            }
            continue

        minimum = np.min(data)
        maximum = np.max(data)
        mean = np.mean(data)
        std = np.std(data)

        result[feature] = {
            "count": len(data),
            "min": minimum,
            "max": maximum,
            "mean": mean,
            "std": std,
            "range": maximum - minimum,
        }

    return result


def print_header(title):
    print()
    print("=" * 80)
    print(title)
    print("=" * 80)


def print_execution_analysis(analyses):
    print_header("EXECUTION OVERVIEW")

    print(
        f"{'attack':20}"
        f"{'attempt':8}"
        f"{'status':10}"
        f"{'start':10}"
        f"{'end':10}"
        f"{'duration':12}"
        f"{'samples':10}"
        f"{'expected':10}"
    )

    for analysis in analyses:
        attack, attempt, status = analysis["key"]

        print(
            f"{attack:20}"
            f"{attempt:<8}"
            f"{status:10}"
            f"{analysis['start']:<10.3f}"
            f"{analysis['end']:<10.3f}"
            f"{analysis['duration']:<12.3f}"
            f"{analysis['actual_count']:<10}"
            f"{analysis['expected_count']:<10}"
        )


def print_sampling_analysis(analyses):
    print_header("SAMPLING / TIMESTAMP ANALYSIS")

    for analysis in analyses:
        attack, attempt, status = analysis["key"]

        print(
            f"\n{attack} attempt={attempt} "
            f"status={status}"
        )

        print(
            f"  time range: "
            f"{analysis['start']:.3f} -> "
            f"{analysis['end']:.3f}"
        )

        print(
            f"  duration: "
            f"{analysis['duration']:.3f} s"
        )

        print(
            f"  samples: "
            f"{analysis['actual_count']}"
        )

        print(
            f"  expected at {INTERVAL:.3f}s: "
            f"{analysis['expected_count']}"
        )

        print(
            f"  duplicate timestamps: "
            f"{analysis['duplicate_count']}"
        )

        print(
            f"  interval min/mean/max: "
            f"{analysis['delta_min']:.6f} / "
            f"{analysis['delta_mean']:.6f} / "
            f"{analysis['delta_max']:.6f} s"
        )

        print(
            f"  intervals different from "
            f"{INTERVAL:.3f}s: "
            f"{analysis['bad_intervals']}"
        )

        print(
            f"  gaps larger than "
            f"{INTERVAL:.3f}s: "
            f"{analysis['gap_count']}"
        )

        print(
            f"  largest gap: "
            f"{analysis['largest_gap']:.6f}s"
        )

        print(
            f"  missing grid timestamps: "
            f"{len(analysis['missing_timestamps'])}"
        )

        if analysis["missing_timestamps"]:
            print(
                "  missing timestamps:"
            )

            print(
                "   ",
                ", ".join(
                    f"{x:.3f}"
                    for x in analysis["missing_timestamps"][:30]
                ),
            )

            if len(
                analysis["missing_timestamps"]
            ) > 30:
                print("    ...")


def print_missing_analysis(analyses, features):
    print_header("MISSING VALUES")

    for analysis in analyses:
        attack, attempt, status = analysis["key"]

        print(
            f"\n{attack} attempt={attempt} "
            f"status={status}"
        )

        found = False

        for feature in features:
            count = analysis["missing_values"][feature]

            if count == 0:
                continue

            found = True

            print(
                f"  {feature:30}"
                f"missing={count:<5}"
                f"leading={analysis['leading_missing'][feature]:<5}"
                f"interior={analysis['interior_missing'][feature]:<5}"
                f"trailing={analysis['trailing_missing'][feature]:<5}"
            )

        if not found:
            print("  No missing values.")

        completely_missing = [
            feature
            for feature in features
            if analysis["complete_missing"][feature]
        ]

        if completely_missing:
            print(
                "  COMPLETELY MISSING:"
            )

            for feature in completely_missing:
                print(
                    f"    {feature}"
                )


def print_global_missing(analyses, features):
    print_header("GLOBAL MISSINGNESS BY FEATURE")

    print(
        f"{'feature':32}"
        f"{'missing':12}"
        f"{'present':12}"
        f"{'executions':12}"
        f"{'complete':12}"
    )

    for feature in features:
        missing = sum(
            analysis["missing_values"][feature]
            for analysis in analyses
        )

        total = sum(
            analysis["actual_count"]
            for analysis in analyses
        )

        complete_missing = sum(
            analysis["complete_missing"][feature]
            for analysis in analyses
        )

        executions_with_missing = sum(
            analysis["missing_values"][feature] > 0
            for analysis in analyses
        )

        print(
            f"{feature:32}"
            f"{missing:<12}"
            f"{total - missing:<12}"
            f"{executions_with_missing:<12}"
            f"{complete_missing:<12}"
        )


def print_duration_analysis(analyses):
    print_header("DURATION ANALYSIS")

    durations = np.array([
        analysis["duration"]
        for analysis in analyses
    ])

    sample_counts = np.array([
        analysis["actual_count"]
        for analysis in analyses
    ])

    print(
        f"minimum duration: "
        f"{np.min(durations):.3f}s"
    )

    print(
        f"maximum duration: "
        f"{np.max(durations):.3f}s"
    )

    print(
        f"mean duration:    "
        f"{np.mean(durations):.3f}s"
    )

    print(
        f"median duration:  "
        f"{np.median(durations):.3f}s"
    )

    print(
        f"duration stddev:  "
        f"{np.std(durations):.3f}s"
    )

    print()

    print(
        f"minimum samples: "
        f"{np.min(sample_counts)}"
    )

    print(
        f"maximum samples: "
        f"{np.max(sample_counts)}"
    )

    print(
        f"mean samples:    "
        f"{np.mean(sample_counts):.2f}"
    )

    print(
        f"median samples:  "
        f"{np.median(sample_counts):.2f}"
    )


def print_scale_analysis(scale_analysis):
    print_header("FEATURE SCALE ANALYSIS")

    print(
        f"{'feature':32}"
        f"{'count':10}"
        f"{'min':16}"
        f"{'max':16}"
        f"{'mean':16}"
        f"{'std':16}"
        f"{'range':16}"
    )

    for feature, data in scale_analysis.items():
        if data["count"] == 0:
            print(
                f"{feature:32}"
                f"{0:<10}"
            )
            continue

        print(
            f"{feature:32}"
            f"{data['count']:<10}"
            f"{data['min']:<16.4g}"
            f"{data['max']:<16.4g}"
            f"{data['mean']:<16.4g}"
            f"{data['std']:<16.4g}"
            f"{data['range']:<16.4g}"
        )


def print_common_grid_analysis(analyses):
    print_header("COMMON GRID ANALYSIS")

    min_duration = min(
        analysis["duration"]
        for analysis in analyses
    )

    max_duration = max(
        analysis["duration"]
        for analysis in analyses
    )

    min_samples = min(
        analysis["actual_count"]
        for analysis in analyses
    )

    max_samples = max(
        analysis["actual_count"]
        for analysis in analyses
    )

    common_samples = int(
        np.floor(min_duration / INTERVAL)
    ) + 1

    print(
        f"Shortest execution: "
        f"{min_duration:.3f}s"
    )

    print(
        f"Longest execution:  "
        f"{max_duration:.3f}s"
    )

    print(
        f"Duration difference: "
        f"{max_duration - min_duration:.3f}s"
    )

    print()

    print(
        f"Shortest sample count: "
        f"{min_samples}"
    )

    print(
        f"Longest sample count:  "
        f"{max_samples}"
    )

    print(
        f"Sample count difference: "
        f"{max_samples - min_samples}"
    )

    print()

    print(
        f"Common duration without padding: "
        f"{(common_samples - 1) * INTERVAL:.3f}s"
    )

    print(
        f"Common timestamp count: "
        f"{common_samples}"
    )

    print()

    print(
        "If all executions are truncated to this "
        "common grid:"
    )

    for analysis in analyses:
        discarded = (
            analysis["actual_count"]
            - min_samples
        )

        print(
            f"  {analysis['key'][0]:20}"
            f"attempt={analysis['key'][1]:<4}"
            f"discarded≈{max(0, discarded)} samples"
        )


def print_recommendation(analyses, features):
    print_header("PREPROCESSING DIAGNOSIS")

    total_missing = sum(
        sum(analysis["missing_values"].values())
        for analysis in analyses
    )

    total_samples = sum(
        analysis["actual_count"]
        for analysis in analyses
    )

    timestamp_gaps = sum(
        len(analysis["missing_timestamps"])
        for analysis in analyses
    )

    bad_intervals = sum(
        analysis["bad_intervals"]
        for analysis in analyses
    )

    duplicate_timestamps = sum(
        analysis["duplicate_count"]
        for analysis in analyses
    )

    durations = [
        analysis["duration"]
        for analysis in analyses
    ]

    min_duration = min(durations)
    max_duration = max(durations)

    print(
        f"Executions: {len(analyses)}"
    )

    print(
        f"Features:   {len(features)}"
    )

    print(
        f"Total samples: {total_samples}"
    )

    print(
        f"Total missing fields: {total_missing}"
    )

    print(
        f"Missing timestamps: {timestamp_gaps}"
    )

    print(
        f"Bad sampling intervals: {bad_intervals}"
    )

    print(
        f"Duplicate timestamps: {duplicate_timestamps}"
    )

    print()

    print(
        f"Duration range: "
        f"{min_duration:.3f}s -> "
        f"{max_duration:.3f}s"
    )

    print(
        f"Duration spread: "
        f"{max_duration - min_duration:.3f}s"
    )

    print()

    if duplicate_timestamps:
        print(
            "ACTION: duplicate timestamps need to "
            "be resolved before resampling."
        )
    else:
        print(
            "OK: no duplicate timestamps detected."
        )

    if timestamp_gaps:
        print(
            "ACTION: missing timestamps exist; "
            "resampling/interpolation may be required."
        )
    else:
        print(
            "OK: timestamps form complete grids."
        )

    if bad_intervals:
        print(
            "ACTION: sampling is not perfectly "
            "regular; inspect interval deviations."
        )
    else:
        print(
            "OK: sampling intervals are regular."
        )

    if total_missing:
        print(
            "ACTION: missing feature values exist; "
            "their position determines whether "
            "forward-fill/interpolation is appropriate."
        )
    else:
        print(
            "OK: no missing feature values."
        )

    if max_duration - min_duration > INTERVAL:
        print(
            "ACTION: executions have different "
            "durations. A common time horizon or "
            "resampling strategy is needed."
        )
    else:
        print(
            "OK: execution durations are effectively equal."
        )

    print()

    print(
        "Do NOT interpolate yet. The measurements above "
        "should determine the preprocessing strategy."
    )


def main():
    if len(sys.argv) != 2:
        print(
            f"Usage: {sys.argv[0]} <timeseries.csv>"
        )
        sys.exit(1)

    filename = Path(sys.argv[1])

    if not filename.exists():
        print(
            f"Error: file not found: {filename}",
            file=sys.stderr,
        )
        sys.exit(1)

    executions, features = read_csv(filename)

    if not executions:
        print(
            "Error: no executions found.",
            file=sys.stderr,
        )
        sys.exit(1)

    analyses = [
        analyze_execution(
            key,
            rows,
            features,
        )
        for key, rows in executions.items()
    ]

    scale_analysis = analyze_feature_scales(
        executions,
        features,
    )

    print_execution_analysis(analyses)
    print_duration_analysis(analyses)
    print_sampling_analysis(analyses)
    print_missing_analysis(
        analyses,
        features,
    )
    print_global_missing(
        analyses,
        features,
    )
    print_scale_analysis(
        scale_analysis,
    )
    print_common_grid_analysis(
        analyses,
    )
    print_recommendation(
        analyses,
        features,
    )


if __name__ == "__main__":
    main()
