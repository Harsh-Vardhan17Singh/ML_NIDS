# SentinelNIDS — Comprehensive Dataset Preparation & Preprocessing Report

> **Dataset:** CIC-IDS2017 (Canadian Institute for Cybersecurity)  
> **Source Directory:** `dataset/TrafficLabelling/`  
> **Output Directory:** `data/processed/`  
> **Artifacts Directory:** `ml/artifacts/`  
> **Status:** Cleaned, Transformed, Scaled & Ready for Model Training

---

## 1. Executive Summary

A comprehensive, leakage-free data preparation pipeline was executed over the full CIC-IDS2017 network intrusion detection dataset. 
The pipeline converted raw, messy, and potentially leaky flow captures into standardized, scaled, and stratified training, validation, and testing partitions.

- **Total Raw Lines Loaded**: 3,119,345
- **Empty / Trailing Rows Dropped**: 288,602
- **Exact Duplicate Rows Dropped**: 203
- **Final Cleaned & Valid Dataset**: 2,830,540 flow records
- **Initial Feature Count**: 85 columns
- **Final Model Feature Count**: 71 curated features
- **Split Partitions**: 
  - **Training Set (70%)**: 1,981,378 rows
  - **Validation Set (15%)**: 424,581 rows
  - **Testing Set (15%)**: 424,581 rows

---

## 2. Data Cleaning & Integrity Decisions

### 2.1 Handling Empty & Duplicate Records
1. **Trailing Empty Lines**: In `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`, exactly 288,602 trailing rows contained empty commas/null values across all 85 columns due to an exporter formatting artifact. These were cleanly dropped without losing any telemetry.
2. **Duplicate Records**: 203 exact duplicate rows were detected and removed. Keeping identical flows across training and evaluation partitions causes data leakage and artificial metric inflation.

### 2.2 Eliminating Data Leakage & Identifier Shortcut Learning
The following columns were deliberately **excluded from model inputs**:
- `Flow ID`: Unique connection hash string.
- `Source IP` & `Destination IP`: Memorizes specific host addresses in the test lab (e.g., attacker at `172.16.0.1`, victim at `192.168.10.50`). Models trained on IP addresses suffer catastrophic failure in production where IP topologies differ.
- `Timestamp`: Temporal shortcut that leaks attack scheduling windows.
- `Fwd Header Length.1`: Exact redundant duplicate of `Fwd Header Length`.

### 2.3 Eliminating Invariant / Zero-Variance Features
The following 8 features had a standard deviation of 0.0 (constant value 0 across all records):
`['Bwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd PSH Flags', 'Bwd URG Flags', 'Fwd Avg Bulk Rate', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk']`.
They were removed because constant features provide zero predictive information while consuming compute and memory.

### 2.4 Handling NaN, Infinite Values, and Counter Overflows
- **`Flow Bytes/s`**: Contained 1,357 NaN occurrences and 1,506 infinite values resulting from division by zero (`Flow Duration == 0`). Infinite values were imputed to the 99.9th percentile ($P_{99.9}$) upper bound, and NaNs were imputed with the median.
- **`Flow Packets/s`**: Contained 2,863 infinite values, cleanly clamped to the 99.9th percentile.
- **Negative Durations & Counters**: 115 rows with negative duration and 2,891 negative inter-arrival times caused by 32-bit counter roll-overs in CICFlowMeter were clamped to 0.

---

## 3. Label Architecture & Class Distribution

SentinelNIDS establishes a dual-objective target structure:
1. **Binary Target (`is_attack`)**: Differentiates benign traffic from any network attack.
2. **Multi-Class Target (`attack_category`)**: Consolidates 15 granular labels into 8 coherent attack families to eliminate extreme sparsity while preserving attack semantics.

### 3.1 Class Distribution Breakdown

| Attack Family | Original Classes Included | Cleaned Record Count | Proportion (%) |
|---|---|---|---|
| **BENIGN** | BENIGN | 2,272,895 | 80.30% |
| **DoS** | DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest | 252,660 | 8.93% |
| **PortScan** | PortScan | 158,930 | 5.61% |
| **DDoS** | DDoS | 128,027 | 4.52% |
| **BruteForce** | FTP-Patator, SSH-Patator | 13,835 | 0.49% |
| **WebAttack** | Brute Force, XSS, Sql Injection | 2,180 | 0.08% |
| **Botnet** | Bot | 1,966 | 0.07% |
| **Infiltration** | Infiltration, Heartbleed | 47 | 0.002% |

### 3.2 Handling Class Imbalance
To counteract the 80/20 class imbalance, balanced class weights were computed on the training partition:
```json
{
  "0": 0.6227,
  "1": 2.5379
}
```
These weights can be directly passed into `class_weight` parameters in estimators (e.g. Random Forest, Logistic Regression, XGBoost, LightGBM) to prevent the classifier from optimizing purely for majority benign accuracy.

---

## 4. Preprocessing Pipeline & Partitioning

### 4.1 Zero-Leakage Transformation
- **Partitioning Strategy**: 70% Train, 15% Validation, 15% Test, using stratified sampling on `attack_category`.
- **Scaling Algorithm**: `RobustScaler(unit_variance=True)`. RobustScaler removes the median and scales according to the interquartile range (IQR, 25th–75th quantile), making it resilient to extreme outliers inherent to volumetric network traffic bursts.
- **Fitting Rule**: The pipeline was fitted strictly on `X_train`. Validation and Test sets were transformed using the frozen training parameters.

### 4.2 Output Artifacts

| Artifact | Location | Description |
|---|---|---|
| Training Split | `data/processed/train.csv.gz` | 1,981,378 rows, scaled features & targets |
| Validation Split | `data/processed/val.csv.gz` | 424,581 rows, scaled features & targets |
| Testing Split | `data/processed/test.csv.gz` | 424,581 rows, scaled features & targets |
| Preprocessing Pipeline | `ml/artifacts/preprocessor.joblib` | Serialized scikit-learn pipeline (imputer + scaler) |
| Feature Schema | `ml/artifacts/feature_schema.json` | JSON schema with feature names & data types |
| Label Mapping | `ml/artifacts/label_mappings.json` | Standardized category mappings |
| Class Weights | `ml/artifacts/class_weights.json` | Computed inverse frequency weights |

---

## 5. Verification & Readiness

All generated files have been validated for integrity:
- Zero NaN values in final feature matrices.
- Zero infinite values in final feature matrices.
- Stratified class balance verified across Train, Validation, and Test partitions.
- Preprocessor is reproducible and ready for immediate model training.
