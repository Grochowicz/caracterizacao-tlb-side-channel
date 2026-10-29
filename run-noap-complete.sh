# coletar dados
./3q-por-cpu.sh
# ataques isolados
source data-analysis/.venv/bin/activate
python3 plot_csv.py results-3q-por-cpu && python3 create_heatmap.py heatmap/attack_statistics_3q-por-cpu.csv heatmap/plot_3q-por-cpu.png
cd data-analysis
python3 pearson_high.py ../heatmap/attack_statistics_3q-por-cpu.csv _pearson_high_3q-por-cpu
python3 kmeans.py 14 ../heatmap/attack_statistics_3q-por-cpu.csv _clusters_3q-por-cpu
