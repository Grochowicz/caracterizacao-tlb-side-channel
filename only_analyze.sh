#!/usr/bin/env bash

AP=./test-tlb/test-tlb
ATTACKS=./TLBSideChannel
OUT=./results-1q-cpu

CPU=0

EVENTS=cpu-clock,task-clock,context-switches,cpu-migrations,page-faults,cycles,instructions,branches,branch-misses,r2012,r2011,r0e12
INTERVAL=100
WARMUP=2
COOLDOWN=1
MAX_ATTEMPTS=5
MONITOR_INTERVAL=0.1

mkdir -p "$OUT"

monitor_top() {
    local output="$1"
    local victim_pid="$2"
    local attack_pid="$3"

    while true; do
        {
            echo "===== SAMPLE $(date +%s.%N) ====="

            echo "--- TOP ---"
            top -b -n 2 -d 0.2 | head -n 20 | tail -n +7

            echo "--- PS ---"

            if [[ -n "$attack_pid" ]]; then
                ps -L -p "$victim_pid,$attack_pid" \
                    -o pid,tid,psr,pcpu,comm
            else
                ps -L -p "$victim_pid" \
                    -o pid,tid,psr,pcpu,comm
            fi

            echo
        } >> "$output"

        sleep "$MONITOR_INTERVAL"
    done
}


# ============================================================
# BASELINE
# ============================================================

echo "baseline"

top_output="$OUT/baseline_top.txt"
perf_output="$OUT/baseline_perf.txt"
analysis_output="$OUT/baseline_analysis.csv"

victim_pid=$(grep "Victim PID" "$OUT/baseline_pids.txt" | awk '{print $3}')

python3 analyze_top.py \
    "$top_output" \
    "$analysis_output" \
    "$victim_pid"

python3 analyze_perf.py \
    "$perf_output" \
    "$OUT/baseline_perf_analysis.csv"


# ============================================================
# ATTACKS
# ============================================================

for attack in \
    generic/dpm_leak.elf \
    generic/vmalloc_leak.elf \
    generic/vmemmap_leak.elf \
    heap/msg_msg_leak.elf \
    heap/file_leak.elf \
    heap/seq_file_leak.elf \
    heap/pipe_buffer_leak.elf \
    page-table/pt_leak.elf \
    page-table/pmd_leak.elf \
    page-table/pud_leak.elf
#   attacks/advanced_slubstick.elf \
#   attacks/pipe_unlink.elf \
#   attacks/dirty_page.elf \
#   attacks/stack_attack.elf
do
    name=$(basename "$attack" .elf)

    for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
        top_output="$OUT/${name}_${attempt}_top.txt"
        perf_output="$OUT/${name}_${attempt}_perf.txt"
        analysis_output="$OUT/${name}_${attempt}_analysis.csv"

		# read pids from files for analysis
		victim_pid=$(grep "Victim PID" "$OUT/${name}_${attempt}_pids.txt" | awk '{print $3}')
		attack_pid=$(grep "Attack PID" "$OUT/${name}_${attempt}_pids.txt" | awk '{print $3}')

        echo "$attack (attempt $attempt)"

        # ----------------------------------------------------
        # Analysis
        # ----------------------------------------------------

        python3 analyze_top.py \
            "$top_output" \
            "$analysis_output" \
            "$victim_pid" \
            "$attack_pid"

        python3 analyze_perf.py \
            "$perf_output" \
            "$OUT/${name}_${attempt}_perf_analysis.csv"

        if grep -qF '[+] success' \
            "$OUT/${name}_${attempt}_attack.txt"; then
            break
        fi
    done
done

# ============================================================
# TLBLEED
# ============================================================

for attack in rn1 rn2 rj1 rj2; do
    name="tlbleed_${attack}"
    attempt=1

    top_output="$OUT/${name}_${attempt}_top.txt"
    perf_output="$OUT/${name}_${attempt}_perf.txt"
    analysis_output="$OUT/${name}_${attempt}_analysis.csv"

	# read pids from files for analysis
	victim_pid=$(grep "Victim PID" "$OUT/${name}_${attempt}_pids.txt" | awk '{print $3}')
	attack_pid=$(grep "Attack PID" "$OUT/${name}_${attempt}_pids.txt" | awk '{print $3}')

    echo "$attack (attempt $attempt)"
       >> "$OUT/${name}_${attempt}_pids.txt"

    # --------------------------------------------------------
    # Analysis
    # --------------------------------------------------------

    python3 analyze_top.py \
        "$top_output" \
        "$analysis_output" \
        "$victim_pid" \
        "$attack_pid"

    python3 analyze_perf.py \
        "$perf_output" \
        "$OUT/${name}_${attempt}_perf_analysis.csv"

done
