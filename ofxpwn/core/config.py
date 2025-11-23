"""
Configuration Management

Handles loading and accessing configuration from YAML files
with support for runtime overrides.
"""

import yaml
from pathlib import Path
from typing import Any, Dict, Optional


class Config:
    """Configuration manager for OFXpwn

    Loads configuration from YAML files and provides easy access
    to config values with support for runtime overrides.
    """

    def __init__(self, config_path: str):
        """Initialize config from file

        Args:
            config_path: Path to YAML configuration file
        """
        self.config_path = Path(config_path)
        self._config: Dict[str, Any] = {}
        self._load()

    def _load(self):
        """Load configuration from YAML file"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")

        with open(self.config_path, "r") as f:
            self._config = yaml.safe_load(f) or {}

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value

        Supports dot notation for nested keys:
            config.get("target.url")
            config.get("proxy.enabled")

        Args:
            key: Configuration key (supports dot notation)
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key.split(".")
        value = self._config

        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default

        return value if value is not None else default

    def set(self, key: str, value: Any):
        """Set configuration value (runtime override)

        Supports dot notation for nested keys.

        Args:
            key: Configuration key (supports dot notation)
            value: Value to set
        """
        keys = key.split(".")
        config = self._config

        # Navigate to the nested dict
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        # Set the final value
        config[keys[-1]] = value

    def get_target_url(self) -> str:
        """Get target URL"""
        return self.get("target.url", "")

    def get_target_org(self) -> Optional[str]:
        """Get target organization"""
        return self.get("target.org")

    def get_target_fid(self) -> Optional[str]:
        """Get target FID"""
        return self.get("target.fid")

    def get_proxy_url(self) -> Optional[str]:
        """Get proxy URL if enabled"""
        if self.get("proxy.enabled", False):
            return self.get("proxy.url")
        return None

    def get_proxy_verify_ssl(self) -> bool:
        """Get proxy SSL verification setting"""
        return self.get("proxy.verify_ssl", True)

    def get_output_dir(self) -> Path:
        """Get output directory"""
        return Path(self.get("output.directory", "./output"))

    def get_max_threads(self) -> int:
        """Get max threads for concurrent operations"""
        return self.get("testing.max_threads", 50)

    def get_timeout(self) -> int:
        """Get request timeout in seconds"""
        return self.get("testing.timeout", 30)

    def get_rate_limit(self) -> int:
        """Get rate limit (requests per second)"""
        return self.get("testing.rate_limit", 0)

    def is_proxy_enabled(self) -> bool:
        """Check if proxy is enabled"""
        return self.get("proxy.enabled", False)

    def should_save_requests(self) -> bool:
        """Check if requests should be saved"""
        return self.get("output.save_requests", True)

    def should_save_responses(self) -> bool:
        """Check if responses should be saved"""
        return self.get("output.save_responses", True)

    def get_log_level(self) -> str:
        """Get logging level"""
        return self.get("logging.level", "INFO")

    def as_dict(self) -> Dict[str, Any]:
        """Get entire config as dictionary"""
        return self._config.copy()

    def __repr__(self) -> str:
        return f"Config(path={self.config_path})"
