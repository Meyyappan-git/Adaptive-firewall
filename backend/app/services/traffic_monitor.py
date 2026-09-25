from abc import ABC, abstractmethod
from typing import List, Dict, Any
import random
import time
from datetime import datetime
from ..utils.logger import logger

class TrafficSource(ABC):
    @abstractmethod
    def get_next_packet(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    def stop(self):
        pass

class SimulationTrafficSource(TrafficSource):
    def __init__(self):
        self.running = True
        self.scenario = "NORMAL" # NORMAL, PORT_SCAN, BURST, HIGH_TRAFFIC, FAILED_CONN
        self.ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "10.0.0.5", "172.16.0.1"]
        self.dest_ips = ["192.168.1.1", "8.8.8.8", "1.1.1.1"]

    def set_scenario(self, scenario: str):
        logger.info(f"Simulation scenario changed to: {scenario}")
        self.scenario = scenario

    def get_next_packet(self) -> Dict[str, Any]:
        if not self.running:
            return None

        src_ip = random.choice(self.ips)
        dst_ip = random.choice(self.dest_ips)

        if self.scenario == "NORMAL":
            return self._generate_normal_packet(src_ip, dst_ip)
        elif self.scenario == "PORT_SCAN":
            return self._generate_port_scan_packet(src_ip, dst_ip)
        elif self.scenario == "BURST":
            return self._generate_burst_packet(src_ip, dst_ip)
        elif self.scenario == "HIGH_TRAFFIC":
            return self._generate_high_traffic_packet(src_ip, dst_ip)
        elif self.scenario == "FAILED_CONN":
            return self._generate_failed_conn_packet(src_ip, dst_ip)
        elif self.scenario == "MIXED":
            # Randomly mix scenarios for realistic mixed traffic
            choice = random.choice(["NORMAL", "NORMAL", "PORT_SCAN", "BURST", "FAILED_CONN"])
            if choice == "PORT_SCAN":
                return self._generate_port_scan_packet(src_ip, dst_ip)
            elif choice == "BURST":
                return self._generate_burst_packet(src_ip, dst_ip)
            elif choice == "FAILED_CONN":
                return self._generate_failed_conn_packet(src_ip, dst_ip)
            else:
                return self._generate_normal_packet(src_ip, dst_ip)
        else:
            return self._generate_normal_packet(src_ip, dst_ip)


    def _generate_normal_packet(self, src, dst):
        protocols = ["TCP", "UDP", "ICMP"]
        ports = [80, 443, 53, 22]
        return {
            "source_ip": src,
            "destination_ip": dst,
            "source_port": random.randint(1024, 65535),
            "destination_port": random.choice(ports),
            "protocol": random.choice(protocols),
            "packet_count": random.randint(1, 5),
            "byte_count": random.randint(64, 1500),
            "timestamp": datetime.utcnow(),
            "success": True
        }

    def _generate_port_scan_packet(self, src, dst):
        # Fix: Focus scan on a single IP to trigger detection faster
        # We'll use a specific scan_ip for this scenario
        scan_ip = "10.0.0.66"
        return {
            "source_ip": scan_ip,
            "destination_ip": dst,
            "source_port": random.randint(1024, 65535),
            "destination_port": random.randint(1, 1000),
            "protocol": "TCP",
            "packet_count": 1,
            "byte_count": 40,
            "timestamp": datetime.utcnow(),
            "success": random.choice([True, False])
        }

    def _generate_burst_packet(self, src, dst):
        return {
            "source_ip": src,
            "destination_ip": dst,
            "source_port": random.randint(1024, 65535),
            "destination_port": 80,
            "protocol": "TCP",
            "packet_count": random.randint(50, 100),
            "byte_count": random.randint(5000, 10000),
            "timestamp": datetime.utcnow(),
            "success": True
        }

    def _generate_high_traffic_packet(self, src, dst):
        return {
            "source_ip": src,
            "destination_ip": dst,
            "source_port": random.randint(1024, 65535),
            "destination_port": 443,
            "protocol": "TCP",
            "packet_count": random.randint(100, 500),
            "byte_count": random.randint(100000, 1000000),
            "timestamp": datetime.utcnow(),
            "success": True
        }

    def _generate_failed_conn_packet(self, src, dst):
        return {
            "source_ip": src,
            "destination_ip": dst,
            "source_port": random.randint(1024, 65535),
            "destination_port": 22,
            "protocol": "TCP",
            "packet_count": 1,
            "byte_count": 40,
            "timestamp": datetime.utcnow(),
            "success": False
        }

    def stop(self):
        self.running = False
