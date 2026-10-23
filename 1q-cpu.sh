#!/usr/bin/env bash

AP1=(./test-tlb/test-tlb -r 67108864 4096)
AP2=(./resnet/resnet50.py)

APS=(AP1 AP2)

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

EVENTS=cpu-clock,task-clock,context-switches,cpu-migrations,page-faults,cycles,instructions,branches,branch-misses,r2012,r2011,r0e12
INTERVAL=100
WARMUP=12
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

taskset -c "$CPU" "${AP[@]}" > "$OUT/baseline_victim.txt" 2>&1 &
victim_pid=$!

perf stat \
    -C "$CPU" \
    -I "$INTERVAL" \
    -e "$EVENTS" \
    > "$perf_output" 2>&1 &
perf_pid=$!

monitor_top "$top_output" "$victim_pid" "" &
top_pid=$!

sleep "$WARMUP"

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

        # ----------------------------------------------------
        # Victim
        # ----------------------------------------------------

        taskset -c "$CPU" "${AP[@]}" > "$OUT/${name}_${attempt}_victim.txt" 2>&1 &
        victim_pid=$!

        # ----------------------------------------------------
        # Perf
        # ----------------------------------------------------

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

        sleep "$WARMUP"

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

        wait "$attack_pid"

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

    # --------------------------------------------------------
    # Victim
    # --------------------------------------------------------

    taskset -c "$CPU" "${AP[@]}" > "$OUT/${name}_${attempt}_victim.txt" 2>&1 &
    victim_pid=$!

    # --------------------------------------------------------
    # Perf
    # --------------------------------------------------------

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

    sleep "$WARMUP"

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

    wait "$attack_pid"

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

done
