from abc import ABC, abstractmethod
from typing import List, Dict, Any
from ..utils.logger import logger

class FirewallBackend(ABC):
    @abstractmethod
    def add_rule(self, rule: Dict[str, Any]):
        pass

    @abstractmethod
    def remove_rule(self, rule_id: int):
        pass

    @abstractmethod
    def list_rules(self) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def clear_rules(self):
        pass

class SimulationFirewall(FirewallBackend):
    def __init__(self):
        self.rules = {}
        self._counter = 1

    def add_rule(self, rule: Dict[str, Any]):
        rule_id = self._counter
        rule["id"] = rule_id
        self.rules[rule_id] = rule
        self._counter += 1
        logger.info(f"Simulated Rule Added: {rule}")
        return rule_id

    def remove_rule(self, rule_id: int):
        if rule_id in self.rules:
            del self.rules[rule_id]
            logger.info(f"Simulated Rule Removed: {rule_id}")

    def list_rules(self) -> List[Dict[str, Any]]:
        return list(self.rules.values())

    def clear_rules(self):
        self.rules = {}
        logger.info("Simulated Firewall rules cleared.")
