import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
from typing import List, Union
from ..utils.logger import logger
from ..config import settings

class MLDetector:
    def __init__(self, model_path: str = "data/models/anomaly_model.joblib"):
        self.model_path = model_path
        self.scaler = StandardScaler()
        self.model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            try:
                data = joblib.load(self.model_path)
                self.model = data['model']
                self.scaler = data['scaler']
                logger.info("ML Model loaded successfully from disk.")
            except Exception as e:
                logger.error(f"Error loading ML model: {e}")

    def train(self, X: Union[List[List[float]], np.ndarray]):
        if len(X) < 10:
            logger.warning("Not enough data to train ML model. Need at least 10 samples.")
            return False

        X_arr = np.array(X)
        X_scaled = self.scaler.fit_transform(X_arr)
        self.model.fit(X_scaled)

        # Save model and scaler
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump({'model': self.model, 'scaler': self.scaler}, self.model_path)
        logger.info("ML Model trained and saved successfully.")
        return True

    def predict_score(self, features: List[float]) -> float:
        """
        Returns an anomaly score between 0 and 1.
        1.0 = Highly anomalous, 0.0 = Normal.
        """
        if not hasattr(self.model, "offset_"):
            return 0.0 # Not trained yet

        X = np.array(features).reshape(1, -1)
        X_scaled = self.scaler.transform(X)

        # IsolationForest.decision_function returns values where lower = more anomalous
        # Usually ranges from -0.5 to 0.5 approx.
        raw_score = self.model.decision_function(X_scaled)[0]

        # Normalize raw_score (approx -0.5 to 0.5) to 0 to 1 range
        # where 1.0 is most anomalous.
        # raw_score = 0 -> score = 0.5
        # raw_score = -0.5 -> score = 1.0
        # raw_score = 0.5 -> score = 0.0
        normalized_score = 0.5 - raw_score
        return float(np.clip(normalized_score, 0.0, 1.0))
