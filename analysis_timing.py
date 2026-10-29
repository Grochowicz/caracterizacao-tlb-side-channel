from pathlib import Path


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
