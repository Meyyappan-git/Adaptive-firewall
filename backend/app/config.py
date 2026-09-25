import os
import yaml
from pydantic_settings import BaseSettings
from typing import Dict, Any
from pathlib import Path

class Settings(BaseSettings):
    APP_NAME: str = "Adaptive Firewall"
    DEBUG: bool = True
    # Use absolute path for database to avoid "unable to open database file" errors
    DATABASE_URL: str = f"sqlite:///{Path(__file__).parents[2]/ 'data/database/firewall.db'}"
    CONFIG_PATH: str = f"{Path(__file__).parents[2]/ 'configs/firewall.yaml'}"
    firewall_config: Dict[str, Any] = {}

    def __init__(self, **values):
        super().__init__(**values)
        self.firewall_config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        config_path = Path(self.CONFIG_PATH)
        if not config_path.exists():
            # Default config if file missing
            return {
                "firewall": {"mode": "simulation"},
                "thresholds": {"port_scan_ports": 15},
                "threat_score": {"rule_weight": 0.45, "ml_weight": 0.35, "behavior_weight": 0.20},
                "actions": {"low": "allow", "moderate": "monitor", "high": "temporary_block", "critical": "block"},
                "temporary_block": {"default_duration_seconds": 300}
            }
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)

settings = Settings()
