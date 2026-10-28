"""
Machine Learning Inference Service for SentinelNIDS.
Loads packaged sentinel_model_v1.joblib, converts CanonicalFlow instances
into model-compatible feature representations, and executes fast CPU scoring.
"""

import time
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import joblib
import numpy as np
import pandas as pd
from sensor.schemas import CanonicalFlow
from backend.app.core.config import settings

logger = logging.getLogger("sentinelnids.services.inference")


class InferenceService:
    """Singleton inference engine managing model lifecycle and online scoring."""

    _instance: Optional["InferenceService"] = None

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = Path(model_path or settings.MODEL_PATH)
        self.model_loaded = False
        self.model_artifact: Optional[Dict[str, Any]] = None
        self.estimator = None
        self.preprocessor = None
        self.feature_names: List[str] = []
        self.optimal_threshold: float = 0.5
        self.model_version: str = settings.ACTIVE_MODEL_VERSION

        self.load_model()

    @classmethod
    def get_instance(cls) -> "InferenceService":
        if cls._instance is None:
            cls._instance = InferenceService()
        return cls._instance

    def load_model(self) -> bool:
        """Load and verify serialized model artifact."""
        if not self.model_path.is_file():
            logger.warning(f"Model artifact not found at {self.model_path}. ML inference will be in observe/rule-only mode.")
            self.model_loaded = False
            return False

        try:
            artifact = joblib.load(self.model_path)
            self.model_artifact = artifact
            self.estimator = artifact.get("estimator")
            self.preprocessor = artifact.get("preprocessor")
            self.feature_names = artifact.get("feature_names", [])
            self.optimal_threshold = float(artifact.get("optimal_threshold", 0.5))
            self.model_version = str(artifact.get("model_version", settings.ACTIVE_MODEL_VERSION))
            self.model_loaded = True
            logger.info(f"Loaded ML model {self.model_version} with {len(self.feature_names)} features (threshold: {self.optimal_threshold}).")
            return True
        except Exception as e:
            logger.error(f"Failed to load model artifact from {self.model_path}: {e}")
            self.model_loaded = False
            return False

    def flow_to_feature_row(self, flow: CanonicalFlow) -> Dict[str, float]:
        """
        Maps a CanonicalFlow into the exact 71 feature dictionary.
        Known flow fields populate directly; derived rates and packet stats are computed;
        remaining statistical fields default to zero or are handled by the imputer.
        """
        proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
        proto_num = proto_map.get(flow.protocol.lower(), 0)

        duration_sec = max(flow.duration_ms / 1000.0, 1e-6)
        total_pkts = flow.packets_out + flow.packets_in
        total_bytes = flow.bytes_out + flow.bytes_in

        bytes_per_sec = float(total_bytes) / duration_sec
        pkts_per_sec = float(total_pkts) / duration_sec

        fwd_pkt_mean = float(flow.bytes_out / flow.packets_out) if flow.packets_out > 0 else 0.0
        bwd_pkt_mean = float(flow.bytes_in / flow.packets_in) if flow.packets_in > 0 else 0.0
        avg_pkt_size = float(total_bytes / total_pkts) if total_pkts > 0 else 0.0
        down_up_ratio = float(flow.packets_in / flow.packets_out) if flow.packets_out > 0 else 0.0

        row = {
            "Source Port": float(flow.src_port or 0),
            "Destination Port": float(flow.dst_port or 0),
            "Protocol": float(proto_num),
            "Flow Duration": float(flow.duration_ms * 1000.0),  # converted to microseconds as in CIC-IDS2017
            "Total Fwd Packets": float(flow.packets_out),
            "Total Backward Packets": float(flow.packets_in),
            "Total Length of Fwd Packets": float(flow.bytes_out),
            "Total Length of Bwd Packets": float(flow.bytes_in),
            "Fwd Packet Length Max": float(flow.bytes_out),
            "Fwd Packet Length Min": 0.0,
            "Fwd Packet Length Mean": fwd_pkt_mean,
            "Fwd Packet Length Std": 0.0,
            "Bwd Packet Length Max": float(flow.bytes_in),
            "Bwd Packet Length Min": 0.0,
            "Bwd Packet Length Mean": bwd_pkt_mean,
            "Bwd Packet Length Std": 0.0,
            "Flow Bytes/s": bytes_per_sec,
            "Flow Packets/s": pkts_per_sec,
            "Flow IAT Mean": float(flow.duration_ms * 1000.0 / max(total_pkts, 1)),
            "Flow IAT Std": 0.0,
            "Flow IAT Max": float(flow.duration_ms * 1000.0),
            "Flow IAT Min": 0.0,
            "Fwd IAT Total": float(flow.duration_ms * 1000.0),
            "Fwd IAT Mean": float(flow.duration_ms * 1000.0 / max(flow.packets_out, 1)),
            "Fwd IAT Std": 0.0,
            "Fwd IAT Max": float(flow.duration_ms * 1000.0),
            "Fwd IAT Min": 0.0,
            "Bwd IAT Total": float(flow.duration_ms * 1000.0),
            "Bwd IAT Mean": float(flow.duration_ms * 1000.0 / max(flow.packets_in, 1)),
            "Bwd IAT Std": 0.0,
            "Bwd IAT Max": float(flow.duration_ms * 1000.0),
            "Bwd IAT Min": 0.0,
            "Fwd PSH Flags": 0.0,
            "Fwd URG Flags": 0.0,
            "Fwd Header Length": float(flow.packets_out * 20),
            "Bwd Header Length": float(flow.packets_in * 20),
            "Fwd Packets/s": float(flow.packets_out) / duration_sec,
            "Bwd Packets/s": float(flow.packets_in) / duration_sec,
            "Min Packet Length": 0.0,
            "Max Packet Length": float(max(flow.bytes_out, flow.bytes_in)),
            "Packet Length Mean": avg_pkt_size,
            "Packet Length Std": 0.0,
            "Packet Length Variance": 0.0,
            "FIN Flag Count": 0.0,
            "SYN Flag Count": 1.0 if flow.protocol == "tcp" else 0.0,
            "RST Flag Count": 0.0,
            "PSH Flag Count": 0.0,
            "ACK Flag Count": 1.0 if flow.protocol == "tcp" and flow.packets_in > 0 else 0.0,
            "URG Flag Count": 0.0,
            "CWE Flag Count": 0.0,
            "ECE Flag Count": 0.0,
            "Down/Up Ratio": down_up_ratio,
            "Average Packet Size": avg_pkt_size,
            "Avg Fwd Segment Size": fwd_pkt_mean,
            "Avg Bwd Segment Size": bwd_pkt_mean,
            "Subflow Fwd Packets": float(flow.packets_out),
            "Subflow Fwd Bytes": float(flow.bytes_out),
            "Subflow Bwd Packets": float(flow.packets_in),
            "Subflow Bwd Bytes": float(flow.bytes_in),
            "Init_Win_bytes_forward": 65535.0 if flow.protocol == "tcp" else 0.0,
            "Init_Win_bytes_backward": 65535.0 if flow.protocol == "tcp" and flow.packets_in > 0 else 0.0,
            "act_data_pkt_fwd": float(flow.packets_out),
            "min_seg_size_forward": 20.0,
            "Active Mean": 0.0,
            "Active Std": 0.0,
            "Active Max": 0.0,
            "Active Min": 0.0,
            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Idle Max": 0.0,
            "Idle Min": 0.0
        }

        # Fill any missing expected feature with 0.0
        return {feat: row.get(feat, 0.0) for feat in self.feature_names}

    def predict_flow(self, flow: CanonicalFlow) -> Tuple[float, str, float]:
        """
        Scores a single canonical flow.
        Returns (score, decision, latency_ms).
        """
        if not self.model_loaded:
            return 0.0, "normal", 0.0

        t0 = time.time()
        try:
            feat_dict = self.flow_to_feature_row(flow)
            df_feat = pd.DataFrame([feat_dict], columns=self.feature_names)
            
            # Apply preprocessor (RobustScaler)
            X_scaled = self.preprocessor.transform(df_feat)
            X_scaled_df = pd.DataFrame(X_scaled, columns=self.feature_names)
            
            # Predict probability
            prob = float(self.estimator.predict_proba(X_scaled_df)[0, 1])
            decision = "review" if prob >= self.optimal_threshold else "normal"
            latency_ms = (time.time() - t0) * 1000.0
            return prob, decision, latency_ms
        except Exception as e:
            logger.error(f"Inference failed for flow {flow.event_id}: {e}")
            latency_ms = (time.time() - t0) * 1000.0
            return 0.0, "inference_error", latency_ms

