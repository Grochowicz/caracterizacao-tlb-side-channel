#!/usr/bin/env bash

ATTACKS=./TLBSideChannel
OUT=./results-1q-cpu
MADTLB=./tlbdr/case-studies/tlbleed/madtlb

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
    local attack_pid="$2"

    while true; do
        {
            echo "===== SAMPLE $(date +%s.%N) ====="

            echo "--- TOP ---"
            top -b -n 2 -d 0.2 | head -n 20 | tail -n +7

            echo "--- PS ---"
            ps -L -p "$attack_pid" \
                -o pid,tid,psr,pcpu,comm

            echo
        } >> "$output"

        sleep "$MONITOR_INTERVAL"
    done
}


# ============================================================
# LOCATION DISCLOSURE ATTACKS
#
# ISOLATED CONDITION:
#   CPU 0 -> attack only
#   AP    -> not running
#   perf  -> attached only to attack PID
# ============================================================

for attack in \
    generic/dpm_leak.elf
#    generic/vmalloc_leak.elf \
#    generic/vmemmap_leak.elf \
#    heap/msg_msg_leak.elf \
#    heap/file_leak.elf \
#    heap/seq_file_leak.elf \
#    heap/pipe_buffer_leak.elf \
#    page-table/pt_leak.elf \
#    page-table/pmd_leak.elf \
#    page-table/pud_leak.elf \
#    attacks/advanced_slubstick.elf \
#    attacks/pipe_unlink.elf \
#    attacks/dirty_page.elf \
#    attacks/stack_attack.elf
do
    name=$(basename "$attack" .elf)

    for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
        top_output="$OUT/${name}_${attempt}_top.txt"
        perf_output="$OUT/${name}_${attempt}_perf.txt"
        analysis_output="$OUT/${name}_${attempt}_analysis.csv"

        # ----------------------------------------------------
        # Attack
        # ----------------------------------------------------

        taskset -c "$CPU" "$ATTACKS/$attack" \
            > "$OUT/${name}_${attempt}_attack.txt" 2>&1 &
        attack_pid=$!

        # ----------------------------------------------------
        # Perf
        #
        # Monitor ONLY the attack process.
        # ----------------------------------------------------

        perf stat \
            -p "$attack_pid" \
            -I "$INTERVAL" \
            -e "$EVENTS" \
            > "$perf_output" 2>&1 &
        perf_pid=$!

        # ----------------------------------------------------
        # Monitoring
        # ----------------------------------------------------

        monitor_top "$top_output" "$attack_pid" &
        top_pid=$!

        echo "$attack (attempt $attempt)"

        sleep "$WARMUP"

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
        # ----------------------------------------------------

        python3 analyze_top.py \
            "$top_output" \
            "$analysis_output" \
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
#
# ISOLATED CONDITION:
#   CPU 0 -> TLBleed only
#   AP    -> not running
#   perf  -> attached only to TLBleed PID
# ============================================================

for attack in rn1 rn2 rj1 rj2; do
    name="tlbleed_${attack}"
    attempt=1

    top_output="$OUT/${name}_${attempt}_top.txt"
    perf_output="$OUT/${name}_${attempt}_perf.txt"
    analysis_output="$OUT/${name}_${attempt}_analysis.csv"

    # --------------------------------------------------------
    # Attack
    # --------------------------------------------------------

    taskset -c "$CPU" "$MADTLB" "-$attack" \
        > "$OUT/${name}_${attempt}_attack.txt" 2>&1 &
    attack_pid=$!

    # --------------------------------------------------------
    # Perf
    #
    # Monitor ONLY the TLBleed process.
    # --------------------------------------------------------

    perf stat \
        -p "$attack_pid" \
        -I "$INTERVAL" \
        -e "$EVENTS" \
        > "$perf_output" 2>&1 &
    perf_pid=$!

    # --------------------------------------------------------
    # Monitoring
    # --------------------------------------------------------

    monitor_top "$top_output" "$attack_pid" &
    top_pid=$!

    echo "$attack (attempt $attempt)"

    sleep "$WARMUP"

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
