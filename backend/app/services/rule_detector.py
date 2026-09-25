from typing import List, Dict, Any
from ..utils.logger import logger
from ..config import settings

class RuleDetector:
    def __init__(self):
        self.config = settings.firewall_config.get("thresholds", {})

    def evaluate(self, features: List[float]) -> Dict[str, Any]:
        """
        Evaluates features against configured rules.
        Returns { "score": float, "reasons": List[str] }
        """
        # Feature indices from FeatureExtractor
        # [0:packet_count, 1:byte_count, 2:connection_count, 3:pps, 4:bps,
        #  5:unique_ports, 6:unique_dests, 7:failed_conns, 8:conn_rate, 9:avg_pkt, 10:duration]

        reasons = []
        score = 0.0

        # 1. Port Scan Detection
        if features[5] > self.config.get("port_scan_ports", 15):
            reasons.append(f"High number of unique destination ports ({int(features[5])})")
            score += 40.0

        # 2. Connection Rate Detection
        if features[8] > self.config.get("connection_rate", 20):
            reasons.append(f"Connection rate above threshold ({features[8]:.2f} conn/s)")
            score += 30.0

        # 3. Failed Connection Detection
        if features[7] > self.config.get("failed_connections", 10):
            reasons.append(f"High number of failed connections ({int(features[7])})")
            score += 30.0

        # 4. Bandwidth Detection
        if features[4] > self.config.get("bandwidth_bytes_per_second", 1000000):
            reasons.append(f"Bandwidth usage exceeds threshold ({features[4]:.2f} bytes/s)")
            score += 20.0

        return {
            "score": min(score, 100.0),
            "reasons": reasons
        }
