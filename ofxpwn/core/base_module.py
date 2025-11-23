"""
Base Module

Abstract base class that all OFXpwn modules inherit from.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger


class BaseModule(ABC):
    """Abstract base class for all OFXpwn modules

    All modules must inherit from this class and implement the run() method.
    """

    # Module metadata (override in subclasses)
    __author__ = "Mike Piekarski"
    __version__ = "1.0.0"

    def __init__(self):
        """Initialize module"""
        self.config: Optional[Config] = None
        self.logger: Optional[Logger] = None
        self.results: Dict[str, Any] = {}

    @abstractmethod
    def run(self, config: Config, logger: Logger) -> Dict[str, Any]:
        """Run the module

        This method must be implemented by all modules.

        Args:
            config: Configuration object
            logger: Logger object

        Returns:
            Dictionary of results
        """
        pass

    @classmethod
    @abstractmethod
    def get_description(cls) -> str:
        """Get module description

        Returns:
            Module description string
        """
        pass

    @classmethod
    def get_name(cls) -> str:
        """Get module name

        Returns:
            Module name
        """
        return cls.__name__

    @classmethod
    def get_author(cls) -> str:
        """Get module author

        Returns:
            Author name
        """
        return cls.__author__

    @classmethod
    def get_version(cls) -> str:
        """Get module version

        Returns:
            Version string
        """
        return cls.__version__

    def log_finding(
        self,
        severity: str,
        title: str,
        description: str,
        evidence: Optional[str] = None
    ):
        """Log a security finding

        Args:
            severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
            title: Finding title
            description: Finding description
            evidence: Optional evidence
        """
        if self.logger:
            self.logger.finding(severity, title, description, evidence)

    def log_result(self, key: str, value: Any):
        """Log a result value

        Args:
            key: Result key
            value: Result value
        """
        self.results[key] = value

    def get_results(self) -> Dict[str, Any]:
        """Get module results

        Returns:
            Results dictionary
        """
        return self.results
