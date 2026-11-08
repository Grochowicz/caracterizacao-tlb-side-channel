#!/usr/bin/env bash

AP=./test-tlb/test-tlb
ATTACKS=./TLBSideChannel
OUT=./results-3q-por-cpu
MADTLB=./tlbdr/case-studies/tlbleed/madtlb

CPU=0

EVENTS=cpu-clock,task-clock,context-switches,cpu-migrations,page-faults,cycles,instructions,branches,branch-misses,dtlb_load_misses.stlb_hit,itlb_misses.stlb_hit,dtlb_load_misses.walk_active,dtlb_load_misses.walk_completed,dTLB-loads,dTLB-store-misses,iTLB-loads
INTERVAL=10
WARMUP=12
COOLDOWN=1
MAX_ATTEMPTS=5
ATTACK_TIMEOUT=180
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

wait_for_attack() {
    local pid="$1"
    local start_time
    local elapsed
    local state

    start_time=$(date +%s)
    while kill -0 "$pid" 2>/dev/null; do
        state=$(ps -o stat= -p "$pid" 2>/dev/null | tr -d ' ')
        case "$state" in
            Z*|X*)
                wait "$pid" 2>/dev/null
                return $?
                ;;
        esac

        elapsed=$(( $(date +%s) - start_time ))
        if [ "$elapsed" -ge "$ATTACK_TIMEOUT" ]; then
            echo "Attack PID $pid exceeded ${ATTACK_TIMEOUT}s; retrying attempt." >&2
            kill "$pid" 2>/dev/null || true
            sleep 1
            kill -KILL "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            return 124
        fi
        sleep 1
    done

    wait "$pid" 2>/dev/null
}

start_monitor() {
    local monitor_function

    monitor_function=$(declare -f monitor_top)
    exec env MONITOR_INTERVAL="$MONITOR_INTERVAL" \
        setsid bash -c "$monitor_function; monitor_top \"\$@\"" \
        monitor_top "$@"
}

stop_monitor_group() {
    local pid="$1"
    local pgid

    pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
    if [ -n "$pgid" ] && [ "$pgid" != "0" ]; then
        kill -- "-$pgid" 2>/dev/null || true
    else
        kill "$pid" 2>/dev/null || true
    fi
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

start_monitor "$top_output" "$victim_pid" "" &
top_pid=$!

mark_warmup "$timing_output" "$perf_start"

sleep 1

sleep "$COOLDOWN"

stop_monitor_group "$top_pid"
kill "$perf_pid" "$victim_pid" 2>/dev/null || true

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
    page-table/pud_leak.elf \
    attacks/advanced_slubstick.elf \
    attacks/pipe_unlink.elf \
    attacks/dirty_page.elf \
    attacks/stack_attack.elf
do
    name=$(basename "$attack" .elf)

    attempt=1
    while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
        top_output="$OUT/${name}_${attempt}_top.txt"
        perf_output="$OUT/${name}_${attempt}_perf.txt"
        timing_output="$OUT/${name}_${attempt}_timing.txt"
        analysis_output="$OUT/${name}_${attempt}_analysis.csv"
        : > "$top_output"

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

        start_monitor "$top_output" "$attack_pid" "" &
        top_pid=$!

        mark_warmup "$timing_output" "$perf_start"

        echo "$attack (attempt $attempt)"

        # ----------------------------------------------------
        # Wait for attack
        # ----------------------------------------------------

        wait_for_attack "$attack_pid"
        attack_status=$?
        if [ "$attack_status" -eq 124 ]; then
            stop_monitor_group "$top_pid"
            kill "$perf_pid" 2>/dev/null || true
            wait "$top_pid" "$perf_pid" 2>/dev/null || true
            continue
        fi

        # ----------------------------------------------------
        # Cooldown
        # ----------------------------------------------------

        sleep "$COOLDOWN"

        # ----------------------------------------------------
        # Cleanup
        # ----------------------------------------------------

        stop_monitor_group "$top_pid"
        kill "$perf_pid" 2>/dev/null || true

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
        attempt=$((attempt + 1))
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
    while true; do

    top_output="$OUT/${name}_${attempt}_top.txt"
    perf_output="$OUT/${name}_${attempt}_perf.txt"
    timing_output="$OUT/${name}_${attempt}_timing.txt"
    analysis_output="$OUT/${name}_${attempt}_analysis.csv"
    : > "$top_output"

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

    start_monitor "$top_output" "$attack_pid" "" &
    top_pid=$!

    mark_warmup "$timing_output" "$perf_start"

    echo "$attack (attempt $attempt)"

    # --------------------------------------------------------
    # Wait for attack
    # --------------------------------------------------------

    wait_for_attack "$attack_pid"
    attack_status=$?
    if [ "$attack_status" -eq 124 ]; then
        stop_monitor_group "$top_pid"
        kill "$perf_pid" 2>/dev/null || true
        wait "$top_pid" "$perf_pid" 2>/dev/null || true
        continue
    fi

    # --------------------------------------------------------
    # Cooldown
    # --------------------------------------------------------

    sleep "$COOLDOWN"

    # --------------------------------------------------------
    # Cleanup
    # --------------------------------------------------------

    stop_monitor_group "$top_pid"
    kill "$perf_pid" 2>/dev/null || true

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

    break
    done
done
