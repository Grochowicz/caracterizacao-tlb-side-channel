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

declare -A MESSAGE_QUEUE_BASELINE=()
MESSAGE_QUEUE_OWNER="${USER:-$(id -un)}"
MESSAGE_QUEUE_SNAPSHOT_VALID=0

monitor_top() {
    local output="$1"
    local victim_pid="$2"
    local attack_pid="$3"
    local pid_list="$victim_pid"

    if [ -n "$attack_pid" ]; then
        pid_list="$pid_list,$attack_pid"
    fi

    while true; do
        {
            echo "===== SAMPLE $(date +%s.%N) ====="

            echo "--- TOP ---"
            if ! top -b -n 1 -d "$MONITOR_INTERVAL" -w 512 -p "$pid_list"; then
                echo "monitor_top: top failed for PIDs $pid_list" >&2
                return 1
            fi

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

snapshot_message_queues() {
    local queue_snapshot

    MESSAGE_QUEUE_BASELINE=()
    MESSAGE_QUEUE_SNAPSHOT_VALID=0
    if ! queue_snapshot=$(ipcs -q 2>/dev/null); then
        echo "IPC snapshot failed (PID $$); refusing queue cleanup." >&2
        return 1
    fi

    while IFS= read -r queue_id; do
        MESSAGE_QUEUE_BASELINE["$queue_id"]=1
    done < <(printf '%s\n' "$queue_snapshot" |
        awk -v owner="$MESSAGE_QUEUE_OWNER" '$2 ~ /^[0-9]+$/ && $3 == owner {print $2}')
    MESSAGE_QUEUE_SNAPSHOT_VALID=1
}

cleanup_new_message_queues() {
    local queue_id queue_snapshot

    if [ "$MESSAGE_QUEUE_SNAPSHOT_VALID" -ne 1 ]; then
        return 0
    fi
    if ! queue_snapshot=$(ipcs -q 2>/dev/null); then
        echo "IPC cleanup snapshot failed (PID $$); leaving queues untouched." >&2
        return 1
    fi

    while IFS= read -r queue_id; do
        if [[ -z "${MESSAGE_QUEUE_BASELINE[$queue_id]+present}" ]]; then
            if ! ipcrm -q "$queue_id"; then
                echo "cleanup: failed to remove new message queue $queue_id (PID $$)." >&2
            fi
        fi
    done < <(printf '%s\n' "$queue_snapshot" |
        awk -v owner="$MESSAGE_QUEUE_OWNER" '$2 ~ /^[0-9]+$/ && $3 == owner {print $2}')
}

handle_signal() {
    local status="$1"
    local pid

    if [ -n "${top_pid:-}" ]; then
        stop_monitor_group "$top_pid"
    fi

    for pid in "${perf_pid:-}" "${victim_pid:-}" "${attack_pid:-}"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
    done

    for pid in "${top_pid:-}" "${perf_pid:-}" "${victim_pid:-}" "${attack_pid:-}"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done

    cleanup_new_message_queues
    exit "$status"
}

trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

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

        start_monitor "$top_output" "$victim_pid" "" &
        top_pid=$!

        mark_warmup "$timing_output" "$perf_start"

        # ----------------------------------------------------
        # Attack
        # ----------------------------------------------------

        if ! snapshot_message_queues; then
            echo "attack=$attack attempt=$attempt stage=ipc-snapshot failed; aborting." >&2
            exit 1
        fi
        taskset -c "$CPU" "$ATTACKS/$attack" \
            > "$OUT/${name}_${attempt}_attack.txt" 2>&1 &
        attack_pid=$!

        # Restart monitor so it also tracks the attack.
        stop_monitor_group "$top_pid"
        wait "$top_pid" 2>/dev/null || true

        start_monitor "$top_output" "$victim_pid" "$attack_pid" &
        top_pid=$!

        echo "$attack (attempt $attempt)"

        wait_for_attack "$attack_pid"
        attack_status=$?
        if [ "$attack_status" -eq 124 ]; then
            stop_monitor_group "$top_pid"
            kill "$perf_pid" "$victim_pid" 2>/dev/null || true
            wait "$top_pid" "$perf_pid" "$victim_pid" 2>/dev/null || true
            cleanup_new_message_queues
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
        kill "$perf_pid" "$victim_pid" 2>/dev/null || true

        wait "$top_pid" "$perf_pid" "$victim_pid" 2>/dev/null || true
        cleanup_new_message_queues

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
    while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do

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

    start_monitor "$top_output" "$victim_pid" "" &
    top_pid=$!

    mark_warmup "$timing_output" "$perf_start"

    # --------------------------------------------------------
    # Attack
    # --------------------------------------------------------

    if ! snapshot_message_queues; then
        echo "attack=$attack attempt=$attempt stage=ipc-snapshot failed; aborting." >&2
        exit 1
    fi
    taskset -c "$CPU" "$MADTLB" "-$attack" \
        > "$OUT/${name}_${attempt}_attack.txt" 2>&1 &
    attack_pid=$!

    # Restart monitor so it also tracks the attack.
    stop_monitor_group "$top_pid"
    wait "$top_pid" 2>/dev/null || true

    start_monitor "$top_output" "$victim_pid" "$attack_pid" &
    top_pid=$!

    echo "$attack (attempt $attempt)"

    wait_for_attack "$attack_pid"
    attack_status=$?
    if [ "$attack_status" -eq 124 ]; then
        stop_monitor_group "$top_pid"
        kill "$perf_pid" "$victim_pid" 2>/dev/null || true
        wait "$top_pid" "$perf_pid" "$victim_pid" 2>/dev/null || true
        cleanup_new_message_queues
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
    kill "$perf_pid" "$victim_pid" 2>/dev/null || true

    wait "$top_pid" "$perf_pid" "$victim_pid" 2>/dev/null || true
    cleanup_new_message_queues

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

    attempt=$((attempt + 1))
    done
done
