#!/usr/bin/env bash

AP1=(./test-tlb/test-tlb -r 67108864 4096)
AP2=(./resnet/resnet50.py)
AP3=(./test-tlb/test-tlb 1k 64)
AP4=(./test-tlb/test-tlb -r 1k 64)
AP5=(./test-tlb/test-tlb 64k 4k)

APS=(AP1 AP2 AP3 AP4 AP5)

if [ $# -eq 0 ]; then
	echo "No argument provided; choose AP."
    exit
fi

if [ $1 -ge ${#APS[@]} ]; then
    echo "Index $1 is out of bounds for APS array (size ${#APS[@]})."
    exit
else
	declare -n AP=${APS[$1]}
fi

echo "Running $0 for AP ${AP[@]}..."

ATTACKS=./TLBSideChannel
OUT=./results-1q-cpu-$1
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
            Z*)
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

taskset -c "$CPU" "${AP[@]}" > "$OUT/baseline_victim.txt" 2>&1 &
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

python3 analyze_victim.py \
	"$OUT/baseline_victim.txt" \
	"$OUT/baseline_victim_analysis.csv"

#save pids
echo "Victim PID: $victim_pid" \
	> "$OUT/baseline_pids.txt"
echo "Perf PID: $perf_pid" \
	>> "$OUT/baseline_pids.txt"
echo "Top PID: $top_pid" \
	>> "$OUT/baseline_pids.txt"


# ============================================================
# LOCATION DISCLOSURE ATTACKS
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
        # Victim
        # ----------------------------------------------------

        taskset -c "$CPU" "${AP[@]}" > "$OUT/${name}_${attempt}_victim.txt" 2>&1 &
        victim_pid=$!

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
        # ----------------------------------------------------

        monitor_top "$top_output" "$victim_pid" "" &
        top_pid=$!

        mark_warmup "$timing_output" "$perf_start"

        # ----------------------------------------------------
        # Attack
        # ----------------------------------------------------
		
		taskset -c "$CPU" "$ATTACKS/$attack" \
			> "$OUT/${name}_${attempt}_attack.txt" 2>&1 &
		attack_pid=$!

        # Restart monitor so it also tracks the attack.
        kill "$top_pid" 2>/dev/null || true
        wait "$top_pid" 2>/dev/null || true

        monitor_top "$top_output" "$victim_pid" "$attack_pid" &
        top_pid=$!

        echo "$attack (attempt $attempt)"

        wait_for_attack "$attack_pid"
        attack_status=$?
        if [ "$attack_status" -eq 124 ]; then
            kill "$top_pid" "$perf_pid" "$victim_pid" 2>/dev/null || true
            wait "$top_pid" "$perf_pid" "$victim_pid" 2>/dev/null || true
            continue
        fi

        # ----------------------------------------------------
        # Cooldown
        # ----------------------------------------------------

        sleep "$COOLDOWN"

        # ----------------------------------------------------
        # Cleanup
        # ----------------------------------------------------

        kill "$top_pid" "$perf_pid" "$victim_pid" 2>/dev/null || true

        wait "$top_pid" "$perf_pid" "$victim_pid" 2>/dev/null || true

        # ----------------------------------------------------
        # Save PIDs
        # ----------------------------------------------------

        echo "Victim PID: $victim_pid" \
            > "$OUT/${name}_${attempt}_pids.txt"

        echo "Attack PID: $attack_pid" \
            >> "$OUT/${name}_${attempt}_pids.txt"

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

		python3 analyze_victim.py \
			"$OUT/${name}_${attempt}_victim.txt" \
			"$OUT/${name}_${attempt}_victim_analysis.csv"

#        if grep -qF '[+] success' \
#            "$OUT/${name}_${attempt}_attack.txt"; then
#            break
#        fi
        attempt=$((attempt + 1))
    done
done

# ============================================================
# TLBLEED
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
    # Victim
    # --------------------------------------------------------

    taskset -c "$CPU" "${AP[@]}" > "$OUT/${name}_${attempt}_victim.txt" 2>&1 &
    victim_pid=$!

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
    # Warmup monitoring
    # --------------------------------------------------------

    monitor_top "$top_output" "$victim_pid" "" &
    top_pid=$!

    mark_warmup "$timing_output" "$perf_start"

    # --------------------------------------------------------
    # Attack
    # --------------------------------------------------------

    taskset -c "$CPU" "$MADTLB" "-$attack" \
        > "$OUT/${name}_${attempt}_attack.txt" 2>&1 &
    attack_pid=$!

    # Restart monitor so it also tracks the attack.
    kill "$top_pid" 2>/dev/null || true
    wait "$top_pid" 2>/dev/null || true

    monitor_top "$top_output" "$victim_pid" "$attack_pid" &
    top_pid=$!

    echo "$attack (attempt $attempt)"

    wait_for_attack "$attack_pid"
    attack_status=$?
    if [ "$attack_status" -eq 124 ]; then
        kill "$top_pid" "$perf_pid" "$victim_pid" 2>/dev/null || true
        wait "$top_pid" "$perf_pid" "$victim_pid" 2>/dev/null || true
        continue
    fi

    # --------------------------------------------------------
    # Cooldown
    # --------------------------------------------------------

    sleep "$COOLDOWN"

    # --------------------------------------------------------
    # Cleanup
    # --------------------------------------------------------

    kill "$top_pid" "$perf_pid" "$victim_pid" 2>/dev/null || true

    wait "$top_pid" "$perf_pid" "$victim_pid" 2>/dev/null || true

    # --------------------------------------------------------
    # Save PIDs
    # --------------------------------------------------------

    echo "Victim PID: $victim_pid" \
        > "$OUT/${name}_${attempt}_pids.txt"

    echo "Attack PID: $attack_pid" \
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

	python3 analyze_victim.py \
		"$OUT/${name}_${attempt}_victim.txt" \
		"$OUT/${name}_${attempt}_victim_analysis.csv"

    break
    done
done
