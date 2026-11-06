from pathlib import Path


def measurement_window(
    timestamps,
    warmup_start,
    warmup_duration,
    cooldown_duration,
):
    """Return inclusive timestamp bounds using observed boundary samples."""
    ordered = sorted(timestamp for timestamp in timestamps if timestamp is not None)
    if not ordered:
        return None, None

    execution_end = ordered[-1]
    warmup_end = warmup_start + warmup_duration
    cooldown_start = execution_end - cooldown_duration

    warmup_samples = [
        timestamp
        for timestamp in ordered
        if warmup_start <= timestamp <= warmup_end
    ]
    cooldown_samples = [
        timestamp
        for timestamp in ordered
        if cooldown_start <= timestamp <= execution_end
    ]

    lower = max(warmup_samples) if warmup_samples else warmup_end
    upper = min(cooldown_samples) if cooldown_samples else cooldown_start
    return lower, upper


def timing_filename(data_filename):
    name = Path(data_filename).name

    for suffix in (
        "_top.txt",
        "_perf.txt",
        "_victim.txt",
    ):
        if name.endswith(suffix):
            return Path(data_filename).with_name(
                name[:-len(suffix)] + "_timing.txt"
            )

    raise ValueError(
        f"Cannot infer timing metadata filename from {data_filename}"
    )


def read_timing(data_filename):
    values = {}
    filename = timing_filename(data_filename)

    with open(filename) as f:
        for line in f:
            key, separator, value = line.partition("=")
            if separator:
                values[key.strip()] = float(value.strip())

    return values
