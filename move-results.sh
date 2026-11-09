
#!/usr/bin/env bash

set -u

mkdir -p DATA

if [ -d heatmap ]; then
    mv heatmap DATA/
fi

for path in results-*; do
    if [ -e "$path" ]; then
        mv "$path" DATA/
    fi
done

if [ -d data-analysis/out ]; then
    mv data-analysis/out DATA/data-analysis-out
fi

for path in data-analysis/_* data-analysis/get_time_*.txt; do
    if [ -e "$path" ]; then
        mv "$path" DATA/
    fi
done

if [ -d timeseries-data-analysis/out-dtwkmeans ]; then
    mv timeseries-data-analysis/out-dtwkmeans DATA/timeseries-data-analysis-out
fi

for path in timeseries-data-analysis/_clusters_*.txt \
            timeseries-data-analysis/_pearson_timeseries_*; do
    if [ -e "$path" ]; then
        mv "$path" DATA/
    fi
done

if [ -e log.txt ]; then
    mv log.txt DATA/
fi

