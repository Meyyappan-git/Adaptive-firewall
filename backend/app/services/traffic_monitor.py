from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import random
import time
import socket
from datetime import datetime
import psutil
from ..utils.logger import logger


class TrafficSource(ABC):
    scenario: str

    @abstractmethod
    def get_next_packet(self) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def stop(self):
        pass


class SimulationTrafficSource(TrafficSource):
    def __init__(self):
        self.running = True
        self.scenario = "NORMAL"  # NORMAL, PORT_SCAN, BURST, HIGH_TRAFFIC, FAILED_CONN, MIXED
        self.ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "10.0.0.5", "172.16.0.1"]
        self.dest_ips = ["192.168.1.1", "8.8.8.8", "1.1.1.1"]

    def set_scenario(self, scenario: str):
        logger.info(f"Simulation scenario changed to: {scenario}")
        self.scenario = scenario

    def get_next_packet(self) -> Optional[Dict[str, Any]]:
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


class LiveHostTrafficSource(TrafficSource):
    """
    Captures actual live network socket activity and OS interface traffic in real-time
    using psutil network socket subsystem and net_io_counters.
    """
    def __init__(self):
        self.running = True
        self.scenario = "LIVE_HOST"
        self._last_io = psutil.net_io_counters()
        self._last_check_time = time.time()
        self._cached_conns: List[Any] = []
        self._conn_index = 0
        self._last_conn_refresh = 0.0

    def set_scenario(self, scenario: str):
        self.scenario = scenario

    def _refresh_connections(self):
        now = time.time()
        if now - self._last_conn_refresh > 1.0 or not self._cached_conns:
            try:
                conns = psutil.net_connections(kind='inet')
                # Prioritize actual external/remote network connections over pure internal loopback
                remote_conns = [
                    c for c in conns
                    if c.raddr and c.raddr.ip not in ("127.0.0.1", "::1", "0.0.0.0")
                ]
                if remote_conns:
                    active = remote_conns
                else:
                    # Fallback to general sockets if no external connections active
                    active = [c for c in conns if c.raddr] or conns
                self._cached_conns = active
                self._conn_index = 0
                self._last_conn_refresh = now
            except Exception as e:
                logger.debug(f"Error fetching live net connections: {e}")

    def get_next_packet(self) -> Optional[Dict[str, Any]]:
        if not self.running:
            return None

        self._refresh_connections()

        if not self._cached_conns:
            return None

        # Round robin over live connections
        conn = self._cached_conns[self._conn_index % len(self._cached_conns)]
        self._conn_index += 1

        # Extract source and destination
        src_ip = "127.0.0.1"
        src_port = 0
        dst_ip = "127.0.0.1"
        dst_port = 0

        if conn.laddr:
            dst_ip = conn.laddr.ip
            dst_port = conn.laddr.port

        if conn.raddr:
            src_ip = conn.raddr.ip
            src_port = conn.raddr.port
        else:
            # Listening socket
            src_ip = "0.0.0.0"
            src_port = random.randint(1024, 65535)

        # Compute delta bytes and packets from system interface
        current_io = psutil.net_io_counters()
        bytes_delta = max(current_io.bytes_recv - self._last_io.bytes_recv, 64)
        packets_delta = max(current_io.packets_recv - self._last_io.packets_recv, 1)
        self._last_io = current_io

        # Protocol
        protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"

        is_failed = conn.status in ["TIME_WAIT", "CLOSE_WAIT", "SYN_SENT"]

        return {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": protocol,
            "packet_count": min(packets_delta, 100),
            "byte_count": min(bytes_delta, 65535),
            "timestamp": datetime.utcnow(),
            "success": not is_failed
        }

    def stop(self):
        self.running = False
