# SentinelNIDS Model Card — flow-v1.0.0

> **Model Identifier:** `flow-v1.0.0`  
> **Model Architecture:** Gradient Boosted Decision Trees (`HistGradientBoostingClassifier`)  
> **Input Contract:** 71 normalized network flow features (RobustScaled)  
> **Target Task:** Binary Network Intrusion Classification (`is_attack`: 0=BENIGN, 1=Attack)  
> **Released:** 2026-10-28T18:03:18.114334+00:00  
> **Packaging Artifact:** `ml/artifacts/sentinel_model_v1.joblib`

---

## 1. Model Overview

SentinelNIDS `flow-v1.0.0` is a CPU-optimized machine learning intrusion detection classifier. It evaluates normalized bidirectional flow features and emits an attack probability score along with an explainable classification decision.

---

## 2. Evaluation Metrics on Held-Out Test Set (424,581 flows)

| Metric | Score | Operational Significance |
|---|---|---|
| **Precision** | **99.86%** | 99%+ of flagged alerts represent genuine malicious attacks |
| **Recall** | **99.89%** | High detection rate across volumetric and probe attack vectors |
| **F1-Score** | **99.88%** | Harmonic balance between precision and sensitivity |
| **ROC-AUC** | **1.0000** | Exceptional class separability |
| **PR-AUC** | **1.0000** | Area under Precision-Recall curve under class imbalance |
| **False Positive Rate** | **0.0337%** | Only 115 false alarms out of 340,935 benign flows |
| **Inference Latency** | **20.5 µs** | High-throughput CPU inference (48,749 flows/sec) |

### Confusion Matrix

```text
               Predicted BENIGN     Predicted Attack
Actual BENIGN          340,820 (TN)             115 (FP)
Actual Attack               91 (FN)          83,555 (TP)
```

---

## 3. Detection Performance by Attack Category

| Category | Test Sample Count | Detection Metric | Performance |
|---|---|---|---|
| **BENIGN** | 340,935 | Benign Specificity | **99.97%** |
| **Botnet** | 295 | Attack Recall | **97.63%** |
| **BruteForce** | 2,075 | Attack Recall | **99.71%** |
| **DDoS** | 19,204 | Attack Recall | **99.94%** |
| **DoS** | 37,899 | Attack Recall | **99.87%** |
| **Infiltration** | 7 | Attack Recall | **42.86%** |
| **PortScan** | 23,839 | Attack Recall | **99.98%** |
| **WebAttack** | 327 | Attack Recall | **97.86%** |

---

## 4. Operational Boundaries & Thresholds

- **Calibrated Decision Threshold:** `0.65`  
  - Scores $\ge 0.65$ are flagged for analyst review.
  - Scores below threshold are classified as `normal`, unless triggered by deterministic rules (e.g. port scan pattern).
- **Inference Requirements:** CPU inference (scikit-learn $\ge 1.3$), 71 numerical features.
- **Intended Usage:** Passive defensive flow scoring in SentinelNIDS ingestion pipeline.
