"""
Tests for Protocol module
"""

import pytest

from ofxpwn.core.protocol import OFXRequest


def test_ofx_request_initialization():
    """Test OFXRequest initialization"""
    ofx = OFXRequest(org='TESTORG', fid='12345')
    
    assert ofx.org == 'TESTORG'
    assert ofx.fid == '12345'


def test_build_sgml_header():
    """Test SGML header generation"""
    ofx = OFXRequest()
    
    header = ofx.build_sgml_header(version='102')
    
    assert 'OFXHEADER:100' in header
    assert 'DATA:OFXSGML' in header
    assert 'VERSION:102' in header
    assert header.endswith('\n\n')


def test_build_sgml_header_different_versions():
    """Test SGML header with different versions"""
    ofx = OFXRequest()
    
    for version in ['102', '103', '151', '160']:
        header = ofx.build_sgml_header(version=version)
        assert f'VERSION:{version}' in header


def test_build_signon_sgml():
    """Test SGML signon generation"""
    ofx = OFXRequest(org='TESTORG', fid='99999')
    
    signon = ofx.build_signon_sgml('testuser', 'testpass')
    
    assert '<SIGNONMSGSRQV1>' in signon
    assert '<SONRQ>' in signon
    assert '<USERID>testuser' in signon
    assert '<USERPASS>testpass' in signon
    assert '<FI>' in signon
    assert '<ORG>TESTORG' in signon
    assert '<FID>99999' in signon


def test_build_signon_sgml_with_clientuid():
    """Test SGML signon with CLIENTUID"""
    ofx = OFXRequest(org='TEST', fid='123')
    
    signon = ofx.build_signon_sgml('user', 'pass', clientuid='unique-client-id')
    
    assert '<CLIENTUID>unique-client-id' in signon


def test_build_signon_sgml_override_org_fid():
    """Test SGML signon with overridden ORG/FID"""
    ofx = OFXRequest(org='DEFAULT', fid='000')
    
    signon = ofx.build_signon_sgml('user', 'pass', org='OVERRIDE', fid='999')
    
    assert '<ORG>OVERRIDE' in signon
    assert '<FID>999' in signon
    assert '<ORG>DEFAULT' not in signon
    assert '<FID>000' not in signon


def test_build_xml_header():
    """Test XML header generation"""
    ofx = OFXRequest()
    
    header = ofx.build_xml_header(version='200')
    
    assert '<?xml version="1.0"' in header
    assert 'OFXHEADER="200"' in header


def test_build_signon_xml():
    """Test XML signon generation"""
    ofx = OFXRequest(org='XMLTEST', fid='54321')
    
    signon = ofx.build_signon_xml('xmluser', 'xmlpass')
    
    assert '<SIGNONMSGSRQV1>' in signon
    assert '<SONRQ>' in signon
    assert '<USERID>xmluser</USERID>' in signon
    assert '<USERPASS>xmlpass</USERPASS>' in signon
    assert '<ORG>XMLTEST</ORG>' in signon
    assert '<FID>54321</FID>' in signon


def test_build_profile_request():
    """Test profile request generation"""
    ofx = OFXRequest(org='PROFORG', fid='11111')
    
    profile = ofx.build_profile_request('anonymous', 'anonymous', use_xml=False)
    
    assert '<PROFMSGSRQV1>' in profile
    assert '<PROFRQ>' in profile
    assert 'CLIENTROUTING' in profile
    assert 'DTPROFUP' in profile


def test_full_sgml_request():
    """Test complete SGML request"""
    ofx = OFXRequest(org='FULLTEST', fid='77777')
    
    request = ofx.build_sgml_header() + "<OFX>\n"
    request += ofx.build_signon_sgml('fulluser', 'fullpass')
    request += "</OFX>\n"
    
    # Verify structure
    assert request.startswith('OFXHEADER:100')
    assert '<OFX>' in request
    assert '<SIGNONMSGSRQV1>' in request
    assert '</OFX>' in request
    assert '<USERID>fulluser' in request
