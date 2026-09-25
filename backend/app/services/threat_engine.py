from typing import List, Dict, Any
from .rule_detector import RuleDetector
from .anomaly_detector import MLDetector
from ..config import settings

class ThreatEngine:
    def __init__(self, rule_detector: RuleDetector, ml_detector: MLDetector):
        self.rule_detector = rule_detector
        self.ml_detector = ml_detector
        self.weights = settings.firewall_config.get("threat_score", {
            "rule_weight": 0.45,
            "ml_weight": 0.35,
            "behavior_weight": 0.20
        })

    def calculate_threat(self, features: List[float], behavior_score: float = 0.0) -> Dict[str, Any]:
        # 1. Rule-based score
        rule_result = self.rule_detector.evaluate(features)
        rule_score = rule_result["score"]
        rule_reasons = rule_result["reasons"]

        # 2. ML-based score (normalize 0-1 to 0-100)
        ml_raw_score = self.ml_detector.predict_score(features)
        ml_score = ml_raw_score * 100.0
        ml_reason = [f"ML anomaly detected (score: {ml_score:.1f})"] if ml_raw_score > 0.6 else []

        # 3. Aggregated Score
        # Use configured weights to calculate the true score
        final_score = (
            (rule_score * self.weights["rule_weight"]) +
            (ml_score * self.weights["ml_weight"]) +
            (behavior_score * self.weights["behavior_weight"])
        )

        final_score = min(max(final_score, 0.0), 100.0)

        # 4. Severity Classification
        severity = "LOW"
        if final_score >= 75: severity = "CRITICAL"
        elif final_score >= 50: severity = "HIGH"
        elif final_score >= 25: severity = "MODERATE"

        # Combine reasons
        all_reasons = rule_reasons + ml_reason
        if behavior_score > 50:
            all_reasons.append("Repeated suspicious behavior detected")

        return {
            "score": final_score,
            "severity": severity,
            "reasons": all_reasons
        }
