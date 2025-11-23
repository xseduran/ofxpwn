"""
Fuzzing Modules

Modules for fuzzing OFX protocol and fields to identify parser issues.
"""

from .protocol import ProtocolFuzzModule
from .fields import FieldsFuzzModule

__all__ = [
    'ProtocolFuzzModule',
    'FieldsFuzzModule',
]
