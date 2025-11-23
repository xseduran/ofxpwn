"""
Tests for Config module
"""

import pytest
import tempfile
import os
import yaml
from pathlib import Path

from ofxpwn.core.config import Config


def _create_test_config(config_dict):
    """Helper to create temporary config file"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(config_dict, f)
        return f.name


def test_config_load_from_file():
    """Test loading config from YAML file"""
    config_dict = {
        'target': {
            'url': 'https://test.com/ofx',
            'org': 'TEST',
            'fid': '12345'
        }
    }

    temp_path = _create_test_config(config_dict)

    try:
        config = Config(temp_path)

        assert config.get('target.url') == 'https://test.com/ofx'
        assert config.get('target.org') == 'TEST'
        assert config.get('target.fid') == '12345'
    finally:
        os.unlink(temp_path)


def test_config_load_complex_file():
    """Test loading config from YAML file with all options"""
    yaml_content = """
target:
  url: "https://example.com/ofx"
  org: "EXAMPLE"
  fid: "99999"

proxy:
  enabled: false
  url: "http://127.0.0.1:8080"
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(yaml_content)
        temp_path = f.name

    try:
        config = Config(temp_path)

        assert config.get('target.url') == 'https://example.com/ofx'
        assert config.get('target.org') == 'EXAMPLE'
        assert config.get('target.fid') == '99999'
        assert config.get('proxy.enabled') is False
    finally:
        os.unlink(temp_path)


def test_config_dot_notation():
    """Test dot notation access"""
    config_dict = {
        'level1': {
            'level2': {
                'level3': 'value'
            }
        }
    }

    temp_path = _create_test_config(config_dict)

    try:
        config = Config(temp_path)

        assert config.get('level1.level2.level3') == 'value'
        assert config.get('nonexistent', 'default') == 'default'
    finally:
        os.unlink(temp_path)


def test_config_set_value():
    """Test setting values with dot notation"""
    config_dict = {'target': {}}
    temp_path = _create_test_config(config_dict)

    try:
        config = Config(temp_path)
        config.set('target.url', 'https://new.com/ofx')

        assert config.get('target.url') == 'https://new.com/ofx'
    finally:
        os.unlink(temp_path)


def test_config_helper_methods():
    """Test helper methods for common values"""
    config_dict = {
        'target': {
            'url': 'https://test.com/ofx',
            'org': 'TESTORG',
            'fid': '54321'
        }
    }

    temp_path = _create_test_config(config_dict)

    try:
        config = Config(temp_path)

        assert config.get_target_url() == 'https://test.com/ofx'
        assert config.get_target_org() == 'TESTORG'
        assert config.get_target_fid() == '54321'
    finally:
        os.unlink(temp_path)


def test_config_defaults():
    """Test default values"""
    config_dict = {}
    temp_path = _create_test_config(config_dict)

    try:
        config = Config(temp_path)

        assert config.get('nonexistent.key', 'default_value') == 'default_value'
        assert config.get('missing.nested.key') is None
    finally:
        os.unlink(temp_path)
