#!/usr/bin/env zsh
python3 plot_csv.py results-1q-cpu && python3 create_heatmap.py heatmap/attack_statistics.csv heatmap/plot.png
