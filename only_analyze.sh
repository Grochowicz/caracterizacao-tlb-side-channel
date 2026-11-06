#!/usr/bin/env bash

# Re-run only the offline analysis scripts on data already collected.
#
# Usage:
#   ./only_analyze.sh                       # all justin/results-* directories
#   ./only_analyze.sh justin/results-1q-cpu-1

set -u

ROOT="./justin"

analyze_result_directory() {
    local out="$1"
    local top_output stem pids_file victim_pid attack_pid

    if [[ ! -d "$out" ]]; then
        echo "Warning: results directory not found: $out" >&2
        return 0
    fi

    echo "Analyzing $out"

    shopt -s nullglob
    local top_files=("$out"/*_top.txt)
    shopt -u nullglob

    if (( ${#top_files[@]} == 0 )); then
        echo "Warning: no *_top.txt files found in $out" >&2
        return 0
    fi

    for top_output in "${top_files[@]}"; do
        stem="${top_output%_top.txt}"
        pids_file="${stem}_pids.txt"

        if [[ ! -f "$pids_file" ]]; then
            echo "Warning: missing PID file: $pids_file" >&2
            continue
        fi

        victim_pid=$(awk -F': ' '$1 == "Victim PID" {print $2; exit}' "$pids_file")
        attack_pid=$(awk -F': ' '$1 == "Attack PID" {print $2; exit}' "$pids_file")

        if [[ -z "$victim_pid" ]]; then
            echo "Warning: missing victim PID in $pids_file" >&2
            continue
        fi

        python3 analyze_top.py \
            "$top_output" \
            "${stem}_analysis.csv" \
            "$victim_pid" \
            ${attack_pid:+"$attack_pid"}

        if [[ -f "${stem}_perf.txt" ]]; then
            python3 analyze_perf.py \
                "${stem}_perf.txt" \
                "${stem}_perf_analysis.csv"
        else
            echo "Warning: missing perf file: ${stem}_perf.txt" >&2
        fi

        if [[ -f "${stem}_victim.txt" ]]; then
            python3 analyze_victim.py \
                "${stem}_victim.txt" \
                "${stem}_victim_analysis.csv"
        else
            echo "Warning: missing victim file: ${stem}_victim.txt" >&2
        fi
    done
}

if (( $# > 0 )); then
    analyze_result_directory "$1"
    exit 0
fi

shopt -s nullglob
result_directories=("$ROOT"/results-*)
shopt -u nullglob

if (( ${#result_directories[@]} == 0 )); then
    echo "Error: no results-* directories found under $ROOT" >&2
    exit 1
fi

for result_directory in "${result_directories[@]}"; do
    analyze_result_directory "$result_directory"
done
