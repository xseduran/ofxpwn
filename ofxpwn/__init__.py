"""
OFXpwn - Open Financial Exchange Security Testing Framework

A modular penetration testing toolkit for OFX servers.

Author: Mike Piekarski
GitHub: https://github.com/pect0ral/ofxpwn
Company: Breach Craft (https://breachcraft.io)
"""

__version__ = "1.0.0"
__author__ = "Mike Piekarski"
__license__ = "MIT"
__url__ = "https://github.com/pect0ral/ofxpwn"

from ofxpwn.core.config import Config
from ofxpwn.core.protocol import OFXRequest, OFXResponse
from ofxpwn.core.logger import Logger

__all__ = [
    "__version__",
    "__author__",
    "Config",
    "OFXRequest",
    "OFXResponse",
    "Logger",
]
