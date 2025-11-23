"""
Tests for Logger module
"""

import pytest
import tempfile
import os
import yaml
from pathlib import Path

from ofxpwn.core.logger import Logger
from ofxpwn.core.config import Config


def _create_test_config(config_dict):
    """Helper to create temporary config file"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(config_dict, f)
        return f.name


def test_logger_initialization():
    """Test logger initialization"""
    temp_output = tempfile.mkdtemp()
    config_dict = {
        'output': {
            'directory': temp_output
        }
    }

    temp_path = _create_test_config(config_dict)

    try:
        config = Config(temp_path)
        logger = Logger(config, verbose=False, session_id='test123')

        assert logger.session_id == 'test123'
        assert logger.config == config
        assert logger.verbose is False
    finally:
        os.unlink(temp_path)


def test_logger_creates_log_files():
    """Test that logger creates log files"""
    temp_output = tempfile.mkdtemp()

    config_dict = {
        'output': {
            'directory': temp_output
        }
    }

    temp_path = _create_test_config(config_dict)

    try:
        config = Config(temp_path)
        logger = Logger(config, verbose=False, session_id='test_session')

        # Write to each log stream
        logger.info("Test info message")
        logger.log_request("POST", "https://test.com/ofx", {}, "test body")
        logger.log_response(200, {}, "test response", 0.5)

        # Check files were created in logs directory
        logs_dir = Path(temp_output) / "logs"
        log_files = list(logs_dir.glob('*.log'))
        assert len(log_files) >= 3  # main, requests, responses logs
    finally:
        os.unlink(temp_path)


def test_logger_severity_levels():
    """Test different severity levels"""
    config_dict = {
        'output': {
            'logs_dir': tempfile.mkdtemp(),
            'evidence_dir': tempfile.mkdtemp()
        }
    }

    temp_path = _create_test_config(config_dict)

    try:
        config = Config(temp_path)
        logger = Logger(config, verbose=True, session_id='test_severity')

        # Should not raise exceptions
        logger.debug("Debug message")
        logger.info("Info message")
        logger.success("Success message")
        logger.warning("Warning message")
        logger.error("Error message")
    finally:
        os.unlink(temp_path)


def test_logger_finding():
    """Test finding logging"""
    temp_output = tempfile.mkdtemp()

    config_dict = {
        'output': {
            'directory': temp_output
        }
    }

    temp_path = _create_test_config(config_dict)

    try:
        config = Config(temp_path)
        logger = Logger(config, session_id='test_finding')

        logger.finding('HIGH', 'Test Finding', 'Description', 'Recommendation')

        # Check findings log was created
        logs_dir = Path(temp_output) / "logs"
        findings_log = list(logs_dir.glob('findings_*.log'))
        assert len(findings_log) > 0
    finally:
        os.unlink(temp_path)


def test_logger_session_id():
    """Test logger session ID"""
    temp_output = tempfile.mkdtemp()

    config_dict = {
        'output': {
            'directory': temp_output
        }
    }

    temp_path = _create_test_config(config_dict)

    try:
        config = Config(temp_path)
        logger = Logger(config, session_id='custom_session')

        assert logger.get_session_id() == 'custom_session'
    finally:
        os.unlink(temp_path)
