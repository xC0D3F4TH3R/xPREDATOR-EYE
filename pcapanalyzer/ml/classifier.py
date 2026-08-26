"""
classifier.py - ML-based network traffic classification.

Uses XGBoost/Random Forest for classifying network flows as benign,
malware C2, exfiltration, DoS, or other threat categories.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from ..utils import get_logger

logger = get_logger("ml_classifier")

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import StandardScaler
    import pickle
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    np = None  # type: ignore[assignment]


TRAFFIC_CLASSES = {
    0: "benign",
    1: "malware_c2",
    2: "exfiltration",
    3: "dos_ddos",
    4: "reconnaissance",
    5: "lateral_movement",
}


class NetworkClassifier:
    """ML classifier for network traffic classification.

    Uses Random Forest for supervised classification and Isolation Forest
    for anomaly detection.
    """

    def __init__(self) -> None:
        self._classifier = None
        self._anomaly_detector = None
        self._scaler = None
        self._is_trained = False

        if ML_AVAILABLE:
            self._classifier = RandomForestClassifier(
                n_estimators=100, max_depth=15, random_state=42,
                n_jobs=-1, class_weight="balanced",
            )
            self._anomaly_detector = IsolationForest(
                n_estimators=100, contamination=0.1, random_state=42,
            )
            self._scaler = StandardScaler()

    def train(self, X: list[list[float]], y: list[int]) -> dict:
        """Train the classifier on labeled flow features."""
        if not ML_AVAILABLE:
            return {"error": "ML libraries not installed"}

        X_array = np.array(X)
        y_array = np.array(y)

        X_scaled = self._scaler.fit_transform(X_array)
        self._classifier.fit(X_scaled, y_array)
        self._anomaly_detector.fit(X_scaled)

        self._is_trained = True

        train_score = self._classifier.score(X_scaled, y_array)
        importances = self._classifier.feature_importances_

        return {
            "accuracy": float(train_score),
            "n_samples": len(X),
            "n_features": X_array.shape[1],
            "feature_importances": importances.tolist(),
            "classes": [TRAFFIC_CLASSES.get(i, f"class_{i}") for i in self._classifier.classes_],
        }

    def predict(self, features: list[float]) -> dict:
        """Predict traffic class for a single flow feature vector."""
        if not ML_AVAILABLE or not self._is_trained:
            return {"class": "unknown", "confidence": 0.0, "anomaly_score": 0.0}

        X = np.array([features])
        X_scaled = self._scaler.transform(X)

        prediction = self._classifier.predict(X_scaled)[0]
        probabilities = self._classifier.predict_proba(X_scaled)[0]
        anomaly_score = self._anomaly_detector.decision_function(X_scaled)[0]

        return {
            "class": TRAFFIC_CLASSES.get(int(prediction), f"class_{prediction}"),
            "class_id": int(prediction),
            "confidence": float(max(probabilities)),
            "probabilities": {
                TRAFFIC_CLASSES.get(i, f"class_{i}"): float(p)
                for i, p in enumerate(probabilities)
            },
            "anomaly_score": float(-anomaly_score),
            "is_anomaly": bool(anomaly_score < -0.5),
        }

    def predict_batch(self, X: list[list[float]]) -> list[dict]:
        """Predict traffic class for multiple flow feature vectors."""
        if not ML_AVAILABLE or not self._is_trained:
            return [{"class": "unknown", "confidence": 0.0} for _ in X]

        X_array = np.array(X)
        X_scaled = self._scaler.transform(X_array)

        predictions = self._classifier.predict(X_scaled)
        probabilities = self._classifier.predict_proba(X_scaled)
        anomaly_scores = self._anomaly_detector.decision_function(X_scaled)

        results = []
        for i, pred in enumerate(predictions):
            results.append({
                "class": TRAFFIC_CLASSES.get(int(pred), f"class_{pred}"),
                "class_id": int(pred),
                "confidence": float(max(probabilities[i])),
                "anomaly_score": float(-anomaly_scores[i]),
                "is_anomaly": bool(anomaly_scores[i] < -0.5),
            })
        return results

    def save_model(self, path: str | Path) -> None:
        """Save trained model to disk."""
        if not self._is_trained:
            return
        model_data = {
            "classifier": self._classifier,
            "scaler": self._scaler,
            "anomaly_detector": self._anomaly_detector,
        }
        with open(path, "wb") as f:
            pickle.dump(model_data, f)
        logger.info("Model saved to %s", path)

    def load_model(self, path: str | Path) -> bool:
        """Load trained model from disk."""
        if not ML_AVAILABLE:
            return False
        try:
            with open(path, "rb") as f:
                model_data = pickle.load(f)
            self._classifier = model_data["classifier"]
            self._scaler = model_data["scaler"]
            self._anomaly_detector = model_data["anomaly_detector"]
            self._is_trained = True
            logger.info("Model loaded from %s", path)
            return True
        except Exception as exc:
            logger.error("Failed to load model: %s", exc)
            return False

    @property
    def is_trained(self) -> bool:
        return self._is_trained


class AnomalyDetector:
    """Isolation Forest-based anomaly detector for network traffic."""

    def __init__(self, contamination: float = 0.1) -> None:
        self._detector = None
        self._scaler = None
        self._is_fitted = False

        if ML_AVAILABLE:
            self._detector = IsolationForest(
                n_estimators=100, contamination=contamination, random_state=42,
            )
            self._scaler = StandardScaler()

    def fit(self, X: list[list[float]]) -> dict:
        """Fit the anomaly detector on normal traffic features."""
        if not ML_AVAILABLE:
            return {"error": "ML libraries not installed"}

        X_array = np.array(X)
        X_scaled = self._scaler.fit_transform(X_array)
        self._detector.fit(X_scaled)
        self._is_fitted = True

        scores = self._detector.decision_function(X_scaled)
        return {
            "n_samples": len(X),
            "mean_anomaly_score": float(-scores.mean()),
            "max_anomaly_score": float(-scores.max()),
        }

    def detect(self, features: list[float]) -> dict:
        """Detect if a single flow is anomalous."""
        if not ML_AVAILABLE or not self._is_fitted:
            return {"is_anomaly": False, "score": 0.0}

        X = np.array([features])
        X_scaled = self._scaler.transform(X)
        score = self._detector.decision_function(X_scaled)[0]
        prediction = self._detector.predict(X_scaled)[0]

        return {
            "is_anomaly": bool(prediction == -1),
            "score": float(-score),
            "threshold": 0.0,
        }
