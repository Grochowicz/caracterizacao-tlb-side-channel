./1q-cpu.sh
python3 plot_csv.py results-1q-cpu && python3 create_heatmap.py heatmap/attack_statistics_1q-cpu.csv heatmap/plot_1q-cpu.png
cd data-analysis
source .venv/bin/activate
python3 pearson_high.py ../heatmap/attack_statistics_1q-cpu.csv _pearson_high_1q-cpu
python3 kmeans.py 5 ../heatmap/attack_statistics_1q-cpu.csv _clusters_1q-cpu
cd ..
./3q-por-cpu.sh
python3 plot_csv.py results-3q-por-cpu && python3 create_heatmap.py heatmap/attack_statistics_3q-por-cpu.csv heatmap/plot_3q-por-cpu.png
cd data-analysis
python3 pearson_high.py ../heatmap/attack_statistics_3q-por-cpu.csv _pearson_high_3q-por-cpu
python3 kmeans.py 5 ../heatmap/attack_statistics_3q-por-cpu.csv _clusters_3q-por-cpu
cd ..
