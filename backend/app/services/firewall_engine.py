import os
import sys
import subprocess
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from ..utils.logger import logger


def is_admin_or_root() -> bool:
    """Check if the current process has administrator / root privileges."""
    try:
        if sys.platform == "win32":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            return os.geteuid() == 0
    except Exception as e:
        logger.warning(f"Failed to check admin privileges: {e}")
        return False


class FirewallBackend(ABC):
    @abstractmethod
    def add_rule(self, rule: Dict[str, Any]) -> int:
        pass

    @abstractmethod
    def remove_rule(self, rule_id: int) -> bool:
        pass

    @abstractmethod
    def list_rules(self) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def clear_rules(self):
        pass

    @abstractmethod
    def check_status(self) -> Dict[str, Any]:
        pass


class SimulationFirewall(FirewallBackend):
    def __init__(self):
        self.rules: Dict[int, Dict[str, Any]] = {}
        self._counter = 1

    def add_rule(self, rule: Dict[str, Any]) -> int:
        rule_id = rule.get("id") or self._counter
        rule["id"] = rule_id
        rule["enforced_at_os"] = False
        self.rules[rule_id] = rule
        self._counter = max(self._counter, rule_id + 1)
        logger.info(f"[Simulation] Rule Added (ID: {rule_id}): {rule.get('source')} -> {rule.get('action')}")
        return rule_id

    def remove_rule(self, rule_id: int) -> bool:
        if rule_id in self.rules:
            removed = self.rules.pop(rule_id)
            logger.info(f"[Simulation] Rule Removed (ID: {rule_id}): {removed.get('source')}")
            return True
        return False

    def list_rules(self) -> List[Dict[str, Any]]:
        return list(self.rules.values())

    def clear_rules(self):
        self.rules.clear()
        logger.info("[Simulation] Firewall rules cleared.")

    def check_status(self) -> Dict[str, Any]:
        return {
            "backend": "Simulation",
            "platform": sys.platform,
            "is_elevated": is_admin_or_root(),
            "os_enforcement_supported": True,
            "os_enforcement_active": False,
            "active_rules_count": len(self.rules),
            "message": "Running in software simulation mode (safe sandbox)."
        }


class WindowsFirewall(FirewallBackend):
    """
    Enforces network rules directly into Windows Defender Firewall using `netsh advfirewall`.
    Requires Administrator privileges for kernel-level packet drops.
    """
    RULE_PREFIX = "AdaptiveFirewall_Block_"

    def __init__(self):
        self.rules: Dict[int, Dict[str, Any]] = {}
        self._ip_to_rule_id: Dict[str, int] = {}
        self._counter = 1
        self.last_error: Optional[str] = None

    def _rule_name_for_ip(self, ip: str) -> str:
        # Sanitize IP for netsh rule name
        sanitized = ip.replace(":", "_").replace("/", "_")
        return f"{self.RULE_PREFIX}{sanitized}"

    def add_rule(self, rule: Dict[str, Any]) -> int:
        rule_id = rule.get("id") or self._counter
        rule["id"] = rule_id
        source_ip = rule.get("source")
        action = rule.get("action", "BLOCK").upper()

        if not source_ip or source_ip in ["127.0.0.1", "::1", "localhost", "0.0.0.0"] or source_ip.startswith("127."):
            logger.debug(f"[Windows Defender Firewall] Skipping OS rule for loopback/whitelisted IP: {source_ip}")
            self.rules[rule_id] = rule
            return rule_id

        rule_name = self._rule_name_for_ip(source_ip)
        rule["os_rule_name"] = rule_name
        rule["enforced_at_os"] = False

        if action in ["BLOCK", "TEMPORARY_BLOCK"]:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={source_ip}",
                "enable=yes",
                f"description=Adaptive Firewall Automated Block for {source_ip}"
            ]
            try:
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False
                )
                if res.returncode == 0:
                    rule["enforced_at_os"] = True
                    self.last_error = None
                    logger.info(f"[Windows Defender Firewall] ENFORCED: Inbound BLOCK rule created for {source_ip}")
                else:
                    err_msg = res.stderr.strip() or res.stdout.strip()
                    self.last_error = err_msg
                    logger.warning(
                        f"[Windows Defender Firewall] Failed to enforce rule for {source_ip}: {err_msg}. "
                        "Note: Administrator privileges required for Windows Defender kernel packet dropping."
                    )
            except Exception as e:
                self.last_error = str(e)
                logger.error(f"[Windows Defender Firewall] Exception executing netsh: {e}")

        self.rules[rule_id] = rule
        if source_ip:
            self._ip_to_rule_id[source_ip] = rule_id
        self._counter = max(self._counter, rule_id + 1)
        return rule_id

    def remove_rule(self, rule_id: int) -> bool:
        rule = self.rules.get(rule_id)
        if not rule:
            # Attempt to find by rule_id if passed
            return False

        source_ip = rule.get("source")
        rule_name = rule.get("os_rule_name") or self._rule_name_for_ip(source_ip)

        cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
            if res.returncode == 0:
                logger.info(f"[Windows Defender Firewall] REMOVED: Inbound rule deleted for {source_ip}")
            else:
                logger.debug(f"[Windows Defender Firewall] Rule delete response: {res.stdout.strip()} {res.stderr.strip()}")
        except Exception as e:
            logger.error(f"[Windows Defender Firewall] Exception deleting rule: {e}")

        self.rules.pop(rule_id, None)
        if source_ip in self._ip_to_rule_id:
            del self._ip_to_rule_id[source_ip]
        return True

    def list_rules(self) -> List[Dict[str, Any]]:
        return list(self.rules.values())

    def clear_rules(self):
        # 1. Clear known tracked rules
        for rule in list(self.rules.values()):
            self.remove_rule(rule["id"])

        # 2. Cleanup any residual rules created by Adaptive Firewall
        try:
            # Use PowerShell to remove any rule matching AdaptiveFirewall_Block_*
            ps_cmd = f'Get-NetFirewallRule -DisplayName "{self.RULE_PREFIX}*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule'
            subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, timeout=10, check=False)
            logger.info("[Windows Defender Firewall] All AdaptiveFirewall rules cleared.")
        except Exception as e:
            logger.warning(f"Error purging residual Windows firewall rules: {e}")

        self.rules.clear()
        self._ip_to_rule_id.clear()

    def check_status(self) -> Dict[str, Any]:
        elevated = is_admin_or_root()
        msg = "Windows Defender Firewall kernel enforcement ACTIVE." if elevated else (
            "Elevation required: Run terminal/IDE as Administrator for Windows Defender packet-level dropping. "
            "Application-level enforcement remains active."
        )
        return {
            "backend": "Windows Defender Firewall (netsh/WFP)",
            "platform": "win32",
            "is_elevated": elevated,
            "os_enforcement_supported": True,
            "os_enforcement_active": elevated,
            "active_rules_count": len(self.rules),
            "last_error": self.last_error,
            "message": msg
        }


class LinuxFirewall(FirewallBackend):
    """
    Enforces network rules directly into Linux iptables/nftables.
    Requires root/sudo privileges.
    """
    def __init__(self):
        self.rules: Dict[int, Dict[str, Any]] = {}
        self._counter = 1
        self.last_error: Optional[str] = None

    def add_rule(self, rule: Dict[str, Any]) -> int:
        rule_id = rule.get("id") or self._counter
        rule["id"] = rule_id
        source_ip = rule.get("source")
        action = rule.get("action", "BLOCK").upper()
        rule["enforced_at_os"] = False

        if action in ["BLOCK", "TEMPORARY_BLOCK"]:
            cmd = ["iptables", "-I", "INPUT", "-s", source_ip, "-j", "DROP", "-m", "comment", "--comment", "AdaptiveFirewall"]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
                if res.returncode == 0:
                    rule["enforced_at_os"] = True
                    logger.info(f"[Linux iptables] ENFORCED: DROP rule added for {source_ip}")
                else:
                    self.last_error = res.stderr.strip()
                    logger.warning(f"[Linux iptables] Failed to enforce: {self.last_error}")
            except Exception as e:
                self.last_error = str(e)
                logger.error(f"[Linux iptables] Exception: {e}")

        self.rules[rule_id] = rule
        self._counter = max(self._counter, rule_id + 1)
        return rule_id

    def remove_rule(self, rule_id: int) -> bool:
        rule = self.rules.get(rule_id)
        if not rule:
            return False
        source_ip = rule.get("source")
        cmd = ["iptables", "-D", "INPUT", "-s", source_ip, "-j", "DROP"]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
            logger.info(f"[Linux iptables] REMOVED: DROP rule removed for {source_ip}")
        except Exception as e:
            logger.error(f"[Linux iptables] Error removing rule: {e}")

        self.rules.pop(rule_id, None)
        return True

    def list_rules(self) -> List[Dict[str, Any]]:
        return list(self.rules.values())

    def clear_rules(self):
        for rule in list(self.rules.values()):
            self.remove_rule(rule["id"])
        self.rules.clear()

    def check_status(self) -> Dict[str, Any]:
        elevated = is_admin_or_root()
        return {
            "backend": "Linux iptables / Netfilter",
            "platform": "linux",
            "is_elevated": elevated,
            "os_enforcement_supported": True,
            "os_enforcement_active": elevated,
            "active_rules_count": len(self.rules),
            "last_error": self.last_error,
            "message": "iptables active." if elevated else "Root privileges required for iptables manipulation."
        }


class MacOSFirewall(FirewallBackend):
    """
    Enforces network rules on macOS using pfctl (Packet Filter).
    """
    def __init__(self):
        self.rules: Dict[int, Dict[str, Any]] = {}
        self._counter = 1
        self.last_error: Optional[str] = None

    def add_rule(self, rule: Dict[str, Any]) -> int:
        rule_id = rule.get("id") or self._counter
        rule["id"] = rule_id
        source_ip = rule.get("source")
        rule["enforced_at_os"] = False

        cmd = ["pfctl", "-t", "adaptive_block", "-T", "add", source_ip]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
            if res.returncode == 0:
                rule["enforced_at_os"] = True
                logger.info(f"[macOS pfctl] ENFORCED: Added {source_ip} to pf table")
            else:
                self.last_error = res.stderr.strip()
        except Exception as e:
            self.last_error = str(e)

        self.rules[rule_id] = rule
        self._counter = max(self._counter, rule_id + 1)
        return rule_id

    def remove_rule(self, rule_id: int) -> bool:
        rule = self.rules.get(rule_id)
        if not rule:
            return False
        source_ip = rule.get("source")
        cmd = ["pfctl", "-t", "adaptive_block", "-T", "delete", source_ip]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
        except Exception as e:
            logger.error(f"[macOS pfctl] Error removing rule: {e}")
        self.rules.pop(rule_id, None)
        return True

    def list_rules(self) -> List[Dict[str, Any]]:
        return list(self.rules.values())

    def clear_rules(self):
        for rule in list(self.rules.values()):
            self.remove_rule(rule["id"])
        self.rules.clear()

    def check_status(self) -> Dict[str, Any]:
        elevated = is_admin_or_root()
        return {
            "backend": "macOS Packet Filter (pfctl)",
            "platform": "darwin",
            "is_elevated": elevated,
            "os_enforcement_supported": True,
            "os_enforcement_active": elevated,
            "active_rules_count": len(self.rules),
            "last_error": self.last_error,
            "message": "pfctl active." if elevated else "sudo required for pfctl."
        }


class NativeHostFirewall(FirewallBackend):
    """
    Composite / Auto-Detecting Native Host Firewall.
    Detects host OS (Windows, Linux, macOS) and delegates enforcement to the respective native subsystem.
    """
    def __init__(self):
        if sys.platform == "win32":
            self.delegate: FirewallBackend = WindowsFirewall()
        elif sys.platform == "darwin":
            self.delegate: FirewallBackend = MacOSFirewall()
        else:
            self.delegate: FirewallBackend = LinuxFirewall()
        logger.info(f"Initialized Native Host Firewall for platform '{sys.platform}' ({self.delegate.__class__.__name__})")

    def add_rule(self, rule: Dict[str, Any]) -> int:
        return self.delegate.add_rule(rule)

    def remove_rule(self, rule_id: int) -> bool:
        return self.delegate.remove_rule(rule_id)

    def list_rules(self) -> List[Dict[str, Any]]:
        return self.delegate.list_rules()

    def clear_rules(self):
        self.delegate.clear_rules()

    def check_status(self) -> Dict[str, Any]:
        return self.delegate.check_status()


def get_firewall_backend(mode: str) -> FirewallBackend:
    """Factory to get the appropriate firewall backend based on mode."""
    normalized_mode = (mode or "simulation").strip().lower()
    if normalized_mode in ["live", "native", "enforced", "production"]:
        return NativeHostFirewall()
    return SimulationFirewall()
