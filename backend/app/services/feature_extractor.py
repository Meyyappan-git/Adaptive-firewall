import numpy as np
from typing import List, Dict, Any
from collections import defaultdict
from datetime import datetime, timedelta

class FeatureExtractor:
    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        # Store traffic history per source IP
        # { ip: [ (timestamp, packet_data), ... ] }
        self.history = defaultdict(list)

    def update(self, packet: Dict[str, Any]):
        src_ip = packet["source_ip"]
        self.history[src_ip].append((packet["timestamp"], packet))
        self._cleanup(src_ip)

    def _cleanup(self, src_ip: str):
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window_seconds)
        self.history[src_ip] = [
            item for item in self.history[src_ip] if item[0] > cutoff
        ]

    def extract_features(self, src_ip: str) -> List[float]:
        events = [item[1] for item in self.history[src_ip]]
        if not events:
            return [0.0] * 11

        # Metrics calculations
        packet_count = sum(e["packet_count"] for e in events)
        byte_count = sum(e["byte_count"] for e in events)
        connection_count = len(events)

        unique_ports = len(set(e["destination_port"] for e in events))
        unique_dests = len(set(e["destination_ip"] for e in events))
        failed_conns = sum(1 for e in events if not e.get("success", True))

        duration = (events[-1]["timestamp"] - events[0]["timestamp"]).total_seconds()
        duration = max(duration, 1.0) # avoid div by zero

        pps = packet_count / duration
        bps = byte_count / duration
        conn_rate = connection_count / duration
        avg_packet_size = byte_count / max(packet_count, 1)

        return [
            float(packet_count),
            float(byte_count),
            float(connection_count),
            float(pps),
            float(bps),
            float(unique_ports),
            float(unique_dests),
            float(failed_conns),
            float(conn_rate),
            float(avg_packet_size),
            float(duration)
        ]

    def clear_ip(self, src_ip: str):
        if src_ip in self.history:
            del self.history[src_ip]
