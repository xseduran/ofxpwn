"""
Pytest configuration and fixtures
"""

import pytest
import tempfile
import shutil
from pathlib import Path

from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing"""
    temp = tempfile.mkdtemp()
    yield temp
    shutil.rmtree(temp, ignore_errors=True)


@pytest.fixture
def sample_config():
    """Sample configuration for testing"""
    return {
        'target': {
            'url': 'https://test.example.com/OFXServer/ofxsrvr.dll',
            'org': 'TESTORG',
            'fid': '12345'
        },
        'proxy': {
            'enabled': False,
            'url': 'http://127.0.0.1:8080',
            'verify_ssl': False
        },
        'output': {
            'logs_dir': tempfile.mkdtemp(),
            'evidence_dir': tempfile.mkdtemp(),
            'verbose': False
        },
        'credentials': {
            'username': '',
            'password': ''
        }
    }


@pytest.fixture
def config(sample_config):
    """Config instance for testing"""
    return Config(sample_config)


@pytest.fixture
def logger(config):
    """Logger instance for testing"""
    return Logger(config, verbose=False, session_id='pytest')
