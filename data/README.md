# SentinelNIDS Dataset Directory

This directory organizes the datasets used for training, evaluating, and testing SentinelNIDS machine learning models.

---

## Directory Hierarchy

- `data/raw/`: **Immutable raw training datasets** (e.g. CIC-IDS2017, CSE-CIC-IDS2018, or user-provided flow CSV/Parquet files).
  - *Status:* Gitignored. Do NOT modify files in this directory once placed.
- `data/interim/`: **Intermediate cleaned data** (e.g. normalized column names, deduplicated rows, filtered invalid records).
  - *Status:* Gitignored.
- `data/processed/`: **Final train/validation/test splits** with leakage-controlled boundaries.
  - *Status:* Gitignored.
- `data/sample/`: **Small, safe, redistributable test fixtures** used for automated unit tests and schema verification.
  - *Status:* Committed to Git.

---

## Instructions for Providing Training Dataset

When ready to provide your training dataset for **Phase 2 (ML Training)**:
1. Place your raw dataset file(s) into:
   ```text
   data/raw/
   ```
2. Supported formats:
   - CSV (`.csv`) or compressed CSV (`.csv.gz`)
   - Apache Parquet (`.parquet`)
   - Zeek JSON/TSV connection logs (`conn.log`)
3. Expected Flow Columns (or easily mappable fields):
   - Timestamps / Duration (`duration_ms` or flow duration)
   - Network endpoints (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`)
   - Volume metrics (`packets_out`, `packets_in`, `bytes_out`, `bytes_in`)
   - Target label column: `label` (e.g., `"BENIGN"`, `"PortScan"`, `"DDoS"`, etc.)

Once the dataset is placed, Phase 2 will execute the dataset profiler, generate train/test splits, verify feature compatibility, and fit the versioned ML pipeline.
