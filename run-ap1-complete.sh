IDX=1
# venv para resnet e análise de dados
source data-analysis/.venv/bin/activate
# coletar dados
./1q-cpu.sh $IDX
# análise ataque + ap
python3 plot_csv.py results-1q-cpu-$IDX
mv heatmap/attack_statistics.csv heatmap/attack_statistics_1q-cpu-$IDX.csv
mv heatmap/attack_timeseries.csv heatmap/attack_timeseries_1q-cpu-$IDX.csv
python3 create_heatmap.py heatmap/attack_statistics_1q-cpu-$IDX.csv heatmap/plot_1q-cpu-$IDX.png
cd data-analysis
python3 pearson_high.py ../heatmap/attack_statistics_1q-cpu-$IDX.csv _pearson_high_1q-cpu-$IDX
python3 kmeans.py 5 ../heatmap/attack_statistics_1q-cpu-$IDX.csv _clusters_1q-cpu-$IDX
cd ../timeseries-data-analysis
python3 kmeans.py 5 ../heatmap/attack_timeseries_1q-cpu-$IDX.csv _clusters_1q-cpu-$IDX > _clusters_1q-cpu-$IDX.txt
