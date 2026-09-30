IDX=1
#coletar dados
./1q-cpu.sh IDX
# análise ataque + ap
source data-analysis/.venv/bin/activate
python3 plot_csv.py results-1q-cpu-$IDX
mv heatmap/attack_statistics.csv heatmap/attack_statistics_1q-cpu-$IDX.csv
python3 create_heatmap.py heatmap/attack_statistics_1q-cpu.csv heatmap/plot_1q-cpu-$IDX.png
cd data-analysis
python3 pearson_high.py ../heatmap/attack_statistics_1q-cpu.csv _pearson_high_1q-cpu-$IDX
python3 kmeans.py 5 ../heatmap/attack_statistics_1q-cpu.csv _clusters_1q-cpu-$IDX
