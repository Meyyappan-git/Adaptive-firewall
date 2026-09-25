import unittest
import os
import shutil
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Import components
import sys
sys.path.append('/Users/vishaladith/Documents/Projects/Adaptive FireWall')
from backend.app.services.feature_extractor import FeatureExtractor
from backend.app.services.rule_detector import RuleDetector
from backend.app.services.threat_engine import ThreatEngine
from backend.app.services.anomaly_detector import MLDetector
from backend.app.services.rule_manager import RuleManager
from backend.app.services.firewall_engine import SimulationFirewall
from backend.app.database import Base, TrafficEvent, FirewallRule, SessionLocal

class TestFirewallLogic(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor(window_seconds=60)
        self.rule_det = RuleDetector()
        self.ml_det = MLDetector()
        self.threat_eng = ThreatEngine(self.rule_det, self.ml_det)
        self.firewall = SimulationFirewall()
        self.rule_mgr = RuleManager(self.firewall)

    def test_feature_extraction(self):
        ip = "1.2.3.4"
        for p in range(20):
            self.extractor.update({
                "source_ip": ip,
                "destination_ip": "8.8.8.8",
                "source_port": 1000 + p,
                "destination_port": 80 + p,
                "protocol": "TCP",
                "packet_count": 1,
                "byte_count": 64,
                "timestamp": datetime.utcnow(),
                "success": True
            })

        features = self.extractor.extract_features(ip)
        self.assertEqual(features[5], 20.0)

    def test_rule_detection_portscan(self):
        features = [0.0] * 11
        features[5] = 20.0
        result = self.rule_det.evaluate(features)
        self.assertGreaterEqual(result["score"], 40.0)
        self.assertTrue(any("unique destination ports" in r for r in result["reasons"]))

    def test_threat_scoring_critical(self):
        # Force Rule Score = 100, ML Score = 100, Behavior = 100
        # Weights: 0.45, 0.35, 0.20 -> Result = 100

        self.rule_det.evaluate = lambda x: {"score": 100.0, "reasons": ["Max rules triggered"]}
        self.ml_det.predict_score = lambda x: 1.0

        threat = self.threat_eng.calculate_threat([0.0]*11, behavior_score=100.0)
        self.assertEqual(threat["severity"], "CRITICAL")
        self.assertEqual(threat["score"], 100.0)

    def test_duplicate_rule_prevention(self):
        ip = "10.0.0.3"
        threat_info = {"score": 50.0, "severity": "HIGH", "reasons": ["Test"]}

        id1 = self.rule_mgr.create_adaptive_rule(ip, threat_info)
        threat_info_high = {"score": 80.0, "severity": "CRITICAL", "reasons": ["Worse"]}
        id2 = self.rule_mgr.create_adaptive_rule(ip, threat_info_high)

        self.assertEqual(id1, id2, "Should update existing rule instead of creating new one")

if __name__ == "__main__":
    unittest.main()
