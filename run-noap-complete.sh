#!/bin/bash
RUN_BASELINE="${1:-true}"
RUN_LOCATION_DISCLOSURE="${2:-true}"
RUN_TLBLEED="${3:-true}"
# coletar dados
./3q-por-cpu.sh "$RUN_BASELINE" "$RUN_LOCATION_DISCLOSURE" "$RUN_TLBLEED"
# ataques isolados
source data-analysis/.venv/bin/activate
python3 plot_csv.py results-3q-por-cpu
mv heatmap/attack_statistics.csv heatmap/attack_statistics_3q-por-cpu.csv
mv heatmap/attack_timeseries.csv heatmap/attack_timeseries_3q-por-cpu.csv
python3 create_heatmap.py heatmap/attack_statistics_3q-por-cpu.csv heatmap/plot_3q-por-cpu.png
cd data-analysis
python3 pearson_high.py ../heatmap/attack_statistics_3q-por-cpu.csv _pearson_high_3q-por-cpu
python3 kmeans.py 18 ../heatmap/attack_statistics_3q-por-cpu.csv _clusters_3q-por-cpu
python3 evaluate_clustering.py out/18_clusters_3q-por-cpu.csv out/18_clusters_3q-por-cpu_evaluation.csv
cd ../timeseries-data-analysis
python3 kmeans.py 18 ../heatmap/attack_timeseries_1q-cpu-$IDX.csv _clusters_1q-cpu-$IDX > _clusters_1q-cpu-$IDX.txt
python3 ../data-analysis/evaluate_clustering.py out-dtwkmeans/18_clusters_1q-cpu-$IDX.csv out-dtwkmeans/18_clusters_1q-cpu-${IDX}_evaluation.csv
cd ..
python3 get_time.py --statistics-glob "heatmap/attack_statistics_3q-por-cpu.csv" --results-root . > data-analysis/get_time_3q-por-cpu.txt
