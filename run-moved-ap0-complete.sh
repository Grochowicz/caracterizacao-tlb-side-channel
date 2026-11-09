#!/bin/bash
IDX=0
RUN_BASELINE="${1:-true}"
RUN_LOCATION_DISCLOSURE="${2:-true}"
RUN_TLBLEED="${3:-true}"
# venv para resnet e análise de dados
source data-analysis/.venv/bin/activate
# coletar dados
#./1q-cpu.sh "$IDX" "$RUN_BASELINE" "$RUN_LOCATION_DISCLOSURE" "$RUN_TLBLEED"
# análise ataque + ap
python3 plot_csv.py DATA/results-1q-cpu-$IDX
mv heatmap/attack_statistics.csv DATA/heatmap/attack_statistics_1q-cpu-$IDX.csv
mv heatmap/attack_timeseries.csv DATA/heatmap/attack_timeseries_1q-cpu-$IDX.csv
python3 create_heatmap.py DATA/heatmap/attack_statistics_1q-cpu-$IDX.csv DATA/heatmap/plot_1q-cpu-$IDX.png
cd data-analysis
python3 pearson_high.py ../DATA/heatmap/attack_statistics_1q-cpu-$IDX.csv ../DATA/_pearson_high_1q-cpu-$IDX

python3 kmeans.py 18 ../DATA/heatmap/attack_statistics_1q-cpu-$IDX.csv _clusters_1q-cpu-$IDX

mv out/* ../DATA/data-analysis-out/ 2>/dev/null || true
rm -rf out

python3 evaluate_clustering.py ../DATA/data-analysis-out/18_clusters_1q-cpu-$IDX.csv ../DATA/data-analysis-out/18_clusters_1q-cpu-${IDX}_evaluation.csv


cd ../timeseries-data-analysis

python3 pearson_timeseries.py ../DATA/heatmap/attack_timeseries_1q-cpu-0.csv ../DATA/_pearson_timeseries_1q-cpu-$IDX/

python3 kmeans.py 18 ../DATA/heatmap/attack_timeseries_1q-cpu-$IDX.csv ../DATA/_clusters_1q-cpu-$IDX \
../DATA/_pearson_timeseries_1q-cpu-$IDX/pearson_timeseries_high_correlation_pairs.csv \
> _clusters_1q-cpu-$IDX.txt

mv out-dtwkmeans/* ../DATA/timeseries-data-analysis-out/ 2>/dev/null || true
rm -rf out-dtwkmeans

python3 ../data-analysis/evaluate_clustering.py ../DATA/timeseries-data-analysis-out/18_clusters_1q-cpu-$IDX.csv ../DATA/timeseries-data-analysis-out/18_clusters_1q-cpu-${IDX}_evaluation.csv
cd ..
python3 get_time.py --statistics-glob "DATA/heatmap/attack_statistics_1q-cpu-$IDX.csv" --results-root . > DATA/get_time_1q-cpu-$IDX.txt
