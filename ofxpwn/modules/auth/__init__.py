"""
Authentication Testing Modules

Modules for testing authentication mechanisms in OFX servers.
"""

from .login import LoginModule
from .default_creds import DefaultCredsModule
from .injection import InjectionModule
from .bruteforce import BruteforceModule
from .param_fuzzer import ParamFuzzerModule

__all__ = [
    'LoginModule',
    'DefaultCredsModule',
    'InjectionModule',
    'BruteforceModule',
    'ParamFuzzerModule',
]
