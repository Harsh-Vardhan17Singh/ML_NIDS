"""
Comprehensive Dataset Profiler for CIC-IDS2017.
Analyzes missing values, infinite values, duplicates, zero-variance columns,
negative value anomalies, and label distribution across all 8 files.
"""

import sys
import gc
from pathlib import Path
import numpy as np
import pandas as pd

DATASET_DIR = Path("dataset/TrafficLabelling")


def profile_all_files():
    csv_files = sorted(list(DATASET_DIR.glob("*.csv")))
    print(f"Profiling {len(csv_files)} dataset files...\n")

    overall_stats = {
        "total_rows": 0,
        "null_counts": {},
        "inf_counts": {},
        "zero_variance_cols": set(),
        "negative_val_cols": {},
        "all_labels": {},
        "duplicate_rows_sample": 0
    }

    first_file = True
    constant_candidate_cols = set()

    for idx, f in enumerate(csv_files, 1):
        print(f"[{idx}/{len(csv_files)}] Reading {f.name}...")
        # Read with cp1252 or utf-8 with replacement
        df = pd.read_csv(f, encoding="cp1252", low_memory=False)
        # Strip column names
        df.columns = [c.strip() for c in df.columns]
        
        num_rows = len(df)
        overall_stats["total_rows"] += num_rows

        # Track labels
        label_col = "Label"
        if label_col in df.columns:
            # Clean label
            cleaned_labels = df[label_col].astype(str).str.strip().replace({
                r"Web Attack\s*\s*": "Web Attack - "
            }, regex=True)
            for lbl, cnt in cleaned_labels.value_counts().items():
                overall_stats["all_labels"][lbl] = overall_stats["all_labels"].get(lbl, 0) + cnt

        # Identify numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        
        # Check infs and nulls
        for c in numeric_cols:
            null_count = int(df[c].isna().sum())
            if null_count > 0:
                overall_stats["null_counts"][c] = overall_stats["null_counts"].get(c, 0) + null_count
                
            inf_count = int(np.isinf(df[c]).sum())
            if inf_count > 0:
                overall_stats["inf_counts"][c] = overall_stats["inf_counts"].get(c, 0) + inf_count

            # Check for negative anomalies in counters/durations
            neg_count = int((df[c] < 0).sum())
            if neg_count > 0:
                overall_stats["negative_val_cols"][c] = overall_stats["negative_val_cols"].get(c, 0) + neg_count

        # Check for constant columns
        file_constants = set()
        for c in numeric_cols:
            if df[c].nunique(dropna=False) <= 1:
                file_constants.add(c)
                
        if first_file:
            constant_candidate_cols = file_constants
            first_file = False
        else:
            constant_candidate_cols.intersection_update(file_constants)

        del df
        gc.collect()

    overall_stats["zero_variance_cols"] = constant_candidate_cols
    
    print("\n" + "=" * 70)
    print("PROFILING SUMMARY")
    print("=" * 70)
    print(f"Total Rows Analyzed: {overall_stats['total_rows']:,}")
    print("\n--- Label Distribution ---")
    for lbl, count in sorted(overall_stats["all_labels"].items(), key=lambda x: x[1], reverse=True):
        pct = (count / overall_stats['total_rows']) * 100
        print(f"  * {lbl:30s}: {count:10,d} ({pct:6.2f}%)")

    print("\n--- Columns with NaN / Null Values ---")
    if overall_stats["null_counts"]:
        for col, cnt in overall_stats["null_counts"].items():
            print(f"  * {col:30s}: {cnt:10,d} nulls")
    else:
        print("  None")

    print("\n--- Columns with Infinite (inf / -inf) Values ---")
    if overall_stats["inf_counts"]:
        for col, cnt in overall_stats["inf_counts"].items():
            print(f"  * {col:30s}: {cnt:10,d} infs")
    else:
        print("  None")

    print("\n--- Constant (Zero-Variance) Columns across ALL files ---")
    if overall_stats["zero_variance_cols"]:
        for col in sorted(overall_stats["zero_variance_cols"]):
            print(f"  * {col}")
    else:
        print("  None")

    print("\n--- Columns with Negative Value Anomalies ---")
    for col, cnt in sorted(overall_stats["negative_val_cols"].items(), key=lambda x: x[1], reverse=True):
        print(f"  * {col:30s}: {cnt:10,d} negative records")

    print("=" * 70)


if __name__ == "__main__":
    profile_all_files()

