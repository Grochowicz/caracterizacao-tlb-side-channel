#!/usr/bin/env bash

AP=./test-tlb/test-tlb
ATTACKS=./TLBSideChannel
OUT=./results-3q-por-cpu
MADTLB=./tlbdr/case-studies/tlbleed/madtlb

CPU=0

EVENTS=cpu-clock,task-clock,context-switches,cpu-migrations,page-faults,cycles,instructions,branches,branch-misses,r2012,r2011,r0e12
INTERVAL=10
WARMUP=12
COOLDOWN=1
MAX_ATTEMPTS=5
MONITOR_INTERVAL=0.01

mkdir -p "$OUT"


monitor_top() {
    local output="$1"
    local victim_pid="$2"
    local attack_pid="$3"
    local pid_pattern="$victim_pid"

    if [ -n "$attack_pid" ]; then
        pid_pattern="$pid_pattern|$attack_pid"
    fi

    while true; do
        {
            echo "===== SAMPLE $(date +%s.%N) ====="

            echo "--- TOP ---"
            top -b -n 2 -d 0.01 | grep -E "^[[:space:]]*($pid_pattern)[[:space:]]"

            echo
        } >> "$output"

        sleep "$MONITOR_INTERVAL"
    done
}

mark_warmup() {
    local timing_output="$1"
    local perf_start="$2"
    local warmup_start

    warmup_start=$(date +%s.%N)
    {
        echo "warmup_start=$warmup_start"
        echo "perf_start=$perf_start"
    } > "$timing_output"

    sleep "$WARMUP"
}


# ============================================================
# BASELINE
# ============================================================

echo "baseline"

top_output="$OUT/baseline_top.txt"
perf_output="$OUT/baseline_perf.txt"
timing_output="$OUT/baseline_timing.txt"
analysis_output="$OUT/baseline_analysis.csv"

taskset -c "$CPU" "$AP" -r 67108864 4096 \
    > "$OUT/baseline_victim.txt" 2>&1 &
victim_pid=$!

perf_start=$(date +%s.%N)
perf stat \
    -C "$CPU" \
    -I "$INTERVAL" \
    -e "$EVENTS" \
    > "$perf_output" 2>&1 &
perf_pid=$!

monitor_top "$top_output" "$victim_pid" "" &
top_pid=$!

mark_warmup "$timing_output" "$perf_start"

sleep 1

sleep "$COOLDOWN"

kill "$top_pid" "$perf_pid" "$victim_pid" 2>/dev/null || true

wait "$top_pid" "$perf_pid" "$victim_pid" 2>/dev/null || true

python3 analyze_top.py \
    "$top_output" \
    "$analysis_output" \
    "$victim_pid"

python3 analyze_perf.py \
    "$perf_output" \
    "$OUT/baseline_perf_analysis.csv"


# ============================================================
# LOCATION DISCLOSURE ATTACKS
#
# ISOLATED CONDITION:
#   CPU 0 -> attack only
#   AP    -> NOT running
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
#    attacks/advanced_slubstick.elf \
#    attacks/pipe_unlink.elf \
#    attacks/dirty_page.elf \
#    attacks/stack_attack.elf
do
    name=$(basename "$attack" .elf)

    for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
        top_output="$OUT/${name}_${attempt}_top.txt"
        perf_output="$OUT/${name}_${attempt}_perf.txt"
        timing_output="$OUT/${name}_${attempt}_timing.txt"
        analysis_output="$OUT/${name}_${attempt}_analysis.csv"

        # ----------------------------------------------------
        # Attack
        #
        # No AP is running on CPU.
        # ----------------------------------------------------

        taskset -c "$CPU" "$ATTACKS/$attack" \
            > "$OUT/${name}_${attempt}_attack.txt" 2>&1 &
        attack_pid=$!

        # ----------------------------------------------------
        # Perf
        # ----------------------------------------------------

        perf_start=$(date +%s.%N)
        perf stat \
            -C "$CPU" \
            -I "$INTERVAL" \
            -e "$EVENTS" \
            > "$perf_output" 2>&1 &
        perf_pid=$!

        # ----------------------------------------------------
        # Warmup monitoring
        #
        # There is no victim. The attack itself is monitored.
        # ----------------------------------------------------

        monitor_top "$top_output" "$attack_pid" "" &
        top_pid=$!

        mark_warmup "$timing_output" "$perf_start"

        echo "$attack (attempt $attempt)"

        # ----------------------------------------------------
        # Wait for attack
        # ----------------------------------------------------

        wait "$attack_pid"

        # ----------------------------------------------------
        # Cooldown
        # ----------------------------------------------------

        sleep "$COOLDOWN"

        # ----------------------------------------------------
        # Cleanup
        # ----------------------------------------------------

        kill "$top_pid" "$perf_pid" 2>/dev/null || true

        wait "$top_pid" "$perf_pid" 2>/dev/null || true

        # ----------------------------------------------------
        # Save PID
        # ----------------------------------------------------

        echo "Attack PID: $attack_pid" \
            > "$OUT/${name}_${attempt}_pids.txt"

        # ----------------------------------------------------
        # Analysis
        #
        # Pass attack PID as the main monitored process.
        # ----------------------------------------------------

        python3 analyze_top.py \
            "$top_output" \
            "$analysis_output" \
            "$attack_pid"

        python3 analyze_perf.py \
            "$perf_output" \
            "$OUT/${name}_${attempt}_perf_analysis.csv"

#        if grep -qF '[+] success' \
#            "$OUT/${name}_${attempt}_attack.txt"; then
#            break
#        fi
    done
done


# ============================================================
# TLBLEED
#
# ISOLATED CONDITION:
#   CPU 0 -> TLBleed only
#   AP    -> NOT running
# ============================================================

for attack in rn1 rn2 rj1 rj2; do
    name="tlbleed_${attack}"
    attempt=1

    top_output="$OUT/${name}_${attempt}_top.txt"
    perf_output="$OUT/${name}_${attempt}_perf.txt"
    timing_output="$OUT/${name}_${attempt}_timing.txt"
    analysis_output="$OUT/${name}_${attempt}_analysis.csv"

    # --------------------------------------------------------
    # Attack
    #
    # No AP is running on CPU.
    # --------------------------------------------------------

    taskset -c "$CPU" "$MADTLB" "-$attack" \
        > "$OUT/${name}_${attempt}_attack.txt" 2>&1 &
    attack_pid=$!

    # --------------------------------------------------------
    # Perf
    # --------------------------------------------------------

    perf_start=$(date +%s.%N)
    perf stat \
        -C "$CPU" \
        -I "$INTERVAL" \
        -e "$EVENTS" \
        > "$perf_output" 2>&1 &
    perf_pid=$!

    # --------------------------------------------------------
    # Monitoring
    # --------------------------------------------------------

    monitor_top "$top_output" "$attack_pid" "" &
    top_pid=$!

    mark_warmup "$timing_output" "$perf_start"

    echo "$attack (attempt $attempt)"

    # --------------------------------------------------------
    # Wait for attack
    # --------------------------------------------------------

    wait "$attack_pid"

    # --------------------------------------------------------
    # Cooldown
    # --------------------------------------------------------

    sleep "$COOLDOWN"

    # --------------------------------------------------------
    # Cleanup
    # --------------------------------------------------------

    kill "$top_pid" "$perf_pid" 2>/dev/null || true

    wait "$top_pid" "$perf_pid" 2>/dev/null || true

    # --------------------------------------------------------
    # Save PID
    # --------------------------------------------------------

    echo "Attack PID: $attack_pid" \
        > "$OUT/${name}_${attempt}_pids.txt"

    # --------------------------------------------------------
    # Analysis
    # --------------------------------------------------------

    python3 analyze_top.py \
        "$top_output" \
        "$analysis_output" \
        "$attack_pid"

    python3 analyze_perf.py \
        "$perf_output" \
        "$OUT/${name}_${attempt}_perf_analysis.csv"

done
