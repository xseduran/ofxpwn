"""
Tests for Sender module
"""

import pytest
import tempfile
import os
import yaml

from ofxpwn.core.sender import OFXSender
from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger


def _create_test_config(config_dict):
    """Helper to create temporary config file"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(config_dict, f)
        return f.name


def test_sender_initialization():
    """Test sender initialization"""
    temp_output = tempfile.mkdtemp()
    config_dict = {
        'target': {
            'url': 'https://test.com/ofx'
        },
        'output': {
            'directory': temp_output
        }
    }

    temp_path = _create_test_config(config_dict)

    try:
        config = Config(temp_path)
        logger = Logger(config, session_id='test_sender')
        sender = OFXSender(config, logger)

        assert sender.config == config
        assert sender.logger == logger
    finally:
        os.unlink(temp_path)


def test_sender_proxy_configuration():
    """Test sender proxy configuration"""
    temp_output = tempfile.mkdtemp()
    config_dict = {
        'target': {
            'url': 'https://test.com/ofx'
        },
        'proxy': {
            'enabled': True,
            'url': 'http://127.0.0.1:8080',
            'verify_ssl': False
        },
        'output': {
            'directory': temp_output
        }
    }

    temp_path = _create_test_config(config_dict)

    try:
        config = Config(temp_path)
        logger = Logger(config, session_id='test_proxy')
        sender = OFXSender(config, logger)

        proxies = sender._get_proxies()

        assert proxies is not None
        assert proxies['http'] == 'http://127.0.0.1:8080'
        assert proxies['https'] == 'http://127.0.0.1:8080'
    finally:
        os.unlink(temp_path)


def test_sender_no_proxy():
    """Test sender without proxy"""
    temp_output = tempfile.mkdtemp()
    config_dict = {
        'target': {
            'url': 'https://test.com/ofx'
        },
        'proxy': {
            'enabled': False
        },
        'output': {
            'directory': temp_output
        }
    }

    temp_path = _create_test_config(config_dict)

    try:
        config = Config(temp_path)
        logger = Logger(config, session_id='test_no_proxy')
        sender = OFXSender(config, logger)

        proxies = sender._get_proxies()

        # When disabled, returns None or empty dict
        assert proxies is None or proxies == {}
    finally:
        os.unlink(temp_path)


def test_sender_stats():
    """Test sender statistics tracking"""
    temp_output = tempfile.mkdtemp()
    config_dict = {
        'target': {
            'url': 'https://test.com/ofx'
        },
        'output': {
            'directory': temp_output
        }
    }

    temp_path = _create_test_config(config_dict)

    try:
        config = Config(temp_path)
        logger = Logger(config, session_id='test_stats')
        sender = OFXSender(config, logger)

        stats = sender.get_stats()

        assert 'requests_sent' in stats
        assert stats['requests_sent'] == 0
    finally:
        os.unlink(temp_path)


def test_sender_get_stats():
    """Test sender statistics after initialization"""
    temp_output = tempfile.mkdtemp()
    config_dict = {
        'target': {
            'url': 'https://test.com/ofx'
        },
        'output': {
            'directory': temp_output
        }
    }

    temp_path = _create_test_config(config_dict)

    try:
        config = Config(temp_path)
        logger = Logger(config, session_id='test_stats2')
        sender = OFXSender(config, logger)

        stats = sender.get_stats()

        # Verify stats structure
        assert isinstance(stats, dict)
        assert 'requests_sent' in stats
    finally:
        os.unlink(temp_path)
