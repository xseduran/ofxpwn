"""
Tests for Module Loader
"""

import pytest

from ofxpwn.core.module_loader import ModuleLoader


def test_module_loader_initialization():
    """Test module loader initialization"""
    loader = ModuleLoader()
    assert loader is not None


def test_list_all_modules():
    """Test listing all modules"""
    loader = ModuleLoader()
    modules = loader.list_modules()
    
    # Should have modules
    assert len(modules) > 0
    
    # Each module should have required fields
    for module in modules:
        assert 'name' in module
        assert 'category' in module
        assert 'description' in module


def test_list_modules_by_category():
    """Test listing modules by category"""
    loader = ModuleLoader()
    
    categories = ['auth', 'recon', 'exploit', 'fuzz', 'infra']
    
    for category in categories:
        modules = loader.list_modules(category=category)
        
        # Should have modules in each category
        assert len(modules) > 0
        
        # All modules should be from requested category
        for module in modules:
            assert module['category'] == category


def test_load_module():
    """Test loading a specific module"""
    loader = ModuleLoader()
    
    # Load a known module
    module = loader.load_module('auth/default_creds')
    
    assert module is not None
    assert hasattr(module, 'run')
    assert hasattr(module, 'get_description')


def test_load_multiple_modules():
    """Test loading multiple modules"""
    loader = ModuleLoader()
    
    test_modules = [
        'auth/default_creds',
        'recon/fingerprint',
        'exploit/xxe',
        'fuzz/protocol',
        'infra/headers'
    ]
    
    for module_path in test_modules:
        module = loader.load_module(module_path)
        assert module is not None


def test_load_nonexistent_module():
    """Test loading a module that doesn't exist"""
    loader = ModuleLoader()
    
    with pytest.raises(Exception):
        loader.load_module('nonexistent/module')


def test_module_has_required_methods():
    """Test that loaded modules have required methods"""
    loader = ModuleLoader()
    
    module = loader.load_module('auth/default_creds')
    
    # Check for required methods
    assert hasattr(module, 'run')
    assert hasattr(module, 'get_description')
    assert callable(module.run)
    assert callable(module.get_description)


def test_get_module_description():
    """Test getting module description"""
    loader = ModuleLoader()
    
    module = loader.load_module('auth/default_creds')
    description = module.get_description()
    
    assert isinstance(description, str)
    assert len(description) > 0


def test_all_categories_exist():
    """Test that all expected categories have modules"""
    loader = ModuleLoader()
    
    expected_categories = ['auth', 'recon', 'exploit', 'fuzz', 'infra']
    
    for category in expected_categories:
        modules = loader.list_modules(category=category)
        assert len(modules) > 0, f"Category {category} should have modules"


def test_module_count():
    """Test that we have expected number of modules"""
    loader = ModuleLoader()
    
    all_modules = loader.list_modules()
    
    # Should have at least 11 modules
    assert len(all_modules) >= 11
    
    # Count by category
    auth_modules = loader.list_modules(category='auth')
    assert len(auth_modules) >= 3  # default_creds, injection, bruteforce
    
    recon_modules = loader.list_modules(category='recon')
    assert len(recon_modules) >= 2  # fingerprint, profile
    
    exploit_modules = loader.list_modules(category='exploit')
    assert len(exploit_modules) >= 1  # xxe
    
    fuzz_modules = loader.list_modules(category='fuzz')
    assert len(fuzz_modules) >= 2  # protocol, fields
    
    infra_modules = loader.list_modules(category='infra')
    assert len(infra_modules) >= 3  # headers, ssl, directories
