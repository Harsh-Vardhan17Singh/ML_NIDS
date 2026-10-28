"""
Dataset Inspector: Analyzes the raw CIC-IDS2017 CSV files in dataset/TrafficLabelling.
Profiles column names, row counts, unique labels, memory usage, and column formatting.
"""

import sys
from pathlib import Path
import pandas as pd

DATASET_DIR = Path("dataset/TrafficLabelling")


def inspect_dataset():
    if not DATASET_DIR.is_dir():
        print(f"Error: {DATASET_DIR} not found.")
        return

    csv_files = sorted(list(DATASET_DIR.glob("*.csv")))
    print(f"Found {len(csv_files)} CSV files in {DATASET_DIR}:\n")

    total_rows = 0
    all_columns_set = set()
    file_profiles = []

    for f in csv_files:
        size_mb = f.stat().st_size / (1024 * 1024)
        # Read header only first
        df_head = pd.read_csv(f, nrows=5)
        # Strip whitespace from column names because CIC-IDS2017 often has leading/trailing spaces
        cols = [c.strip() for c in df_head.columns]
        all_columns_set.update(cols)
        
        # Count rows and labels efficiently
        # Read only the Label column to count quickly
        # The label column is usually 'Label' or contains 'Label'
        label_col = [c for c in df_head.columns if 'label' in c.lower()]
        label_col_name = label_col[0] if label_col else None
        
        if label_col_name:
            df_labels = pd.read_csv(f, usecols=[label_col_name], encoding='cp1252', low_memory=False)
            num_rows = len(df_labels)
            label_counts = df_labels[label_col_name].value_counts().to_dict()
        else:
            num_rows = sum(1 for _ in open(f, 'rb')) - 1
            label_counts = {}

        total_rows += num_rows
        file_profiles.append({
            "filename": f.name,
            "size_mb": round(size_mb, 2),
            "rows": num_rows,
            "cols_count": len(cols),
            "labels": label_counts
        })
        print(f"-> {f.name} ({size_mb:.1f} MB, {num_rows:,} rows, {len(cols)} cols)")
        for lbl, count in label_counts.items():
            print(f"     * {lbl}: {count:,}")
        print()

    print("=" * 60)
    print(f"TOTAL ROWS: {total_rows:,}")
    print(f"TOTAL UNIQUE COLUMNS ACROSS FILES: {len(all_columns_set)}")
    print("=" * 60)


if __name__ == "__main__":
    inspect_dataset()

