"""Tests for cryptographic vulnerability checking."""

import pytest
from unittest.mock import patch, MagicMock
from ssl_tester.vulnerabilities import (
    check_cryptographic_flaws,
    check_poodle,
    check_drown,
    check_freak,
    check_sweet32,
    check_heartbleed,
    check_ticketbleed,
    check_logjam,
    check_ccs_injection,
)
from ssl_tester.models import Severity


def test_check_poodle_structure():
    """Test POODLE check result structure."""
    result = check_poodle("example.com", 443, timeout=5.0)
    
    assert result.vulnerability_name == "POODLE"
    assert result.cve_id == "CVE-2014-3566"
    assert isinstance(result.vulnerable, bool)
    assert result.severity in [Severity.OK, Severity.FAIL]
    assert isinstance(result.description, str)
    assert result.recommendation is None or isinstance(result.recommendation, str)


def test_check_drown_structure():
    """Test DROWN check result structure."""
    result = check_drown("example.com", 443, timeout=5.0)
    
    assert result.vulnerability_name == "DROWN"
    assert result.cve_id == "CVE-2016-0800"
    assert isinstance(result.vulnerable, bool)
    assert result.severity in [Severity.OK, Severity.FAIL]
    assert isinstance(result.description, str)


def test_check_freak_structure():
    """Test FREAK check result structure."""
    result = check_freak("example.com", 443, timeout=5.0)
    
    assert result.vulnerability_name == "FREAK"
    assert result.cve_id == "CVE-2015-0204"
    assert isinstance(result.vulnerable, bool)
    assert result.severity in [Severity.OK, Severity.FAIL]
    assert isinstance(result.description, str)


def test_check_sweet32_structure():
    """Test Sweet32 check result structure."""
    result = check_sweet32("example.com", 443, timeout=5.0)
    
    assert result.vulnerability_name == "Sweet32"
    assert result.cve_id == "CVE-2016-2183"
    assert isinstance(result.vulnerable, bool)
    assert result.severity in [Severity.OK, Severity.WARN]
    assert isinstance(result.description, str)


def test_check_cryptographic_flaws_structure():
    """Test that check_cryptographic_flaws returns list of results."""
    results = check_cryptographic_flaws("example.com", 443, timeout=5.0)
    
    assert isinstance(results, list)
    assert len(results) > 0
    
    # Should check multiple vulnerabilities
    vulnerability_names = [r.vulnerability_name for r in results]
    assert "POODLE" in vulnerability_names
    assert "DROWN" in vulnerability_names
    assert "FREAK" in vulnerability_names
    assert "Sweet32" in vulnerability_names
    assert "CCS Injection" in vulnerability_names
    
    # Each result should have correct structure
    for result in results:
        assert hasattr(result, "vulnerability_name")
        assert hasattr(result, "cve_id")
        assert hasattr(result, "vulnerable")
        assert hasattr(result, "severity")
        assert hasattr(result, "description")
        assert result.severity in [Severity.OK, Severity.WARN, Severity.FAIL]


@patch("ssl_tester.vulnerabilities.get_nmap_path")
@patch("ssl_tester.vulnerabilities.run_nmap_script")
def test_check_heartbleed_with_nmap(mock_run_nmap, mock_get_nmap):
    """Test Heartbleed check with nmap."""
    # Mock nmap available
    mock_get_nmap.return_value = "/usr/bin/nmap"
    mock_run_nmap.return_value = (
        True,
        "State: NOT VULNERABLE\nRisk factor: None",
        "",
    )
    
    result = check_heartbleed("example.com", 443, timeout=5.0)
    
    assert result.vulnerability_name == "Heartbleed"
    assert result.cve_id == "CVE-2014-0160"
    assert isinstance(result.vulnerable, bool)
    assert result.severity in [Severity.OK, Severity.FAIL]
    mock_run_nmap.assert_called_once()


@patch("ssl_tester.vulnerabilities.get_nmap_path")
def test_check_heartbleed_without_nmap(mock_get_nmap):
    """Test Heartbleed check without nmap (fallback)."""
    # Mock nmap not available
    mock_get_nmap.return_value = None
    
    result = check_heartbleed("example.com", 443, timeout=5.0)
    
    assert result.vulnerability_name == "Heartbleed"
    assert result.cve_id == "CVE-2014-0160"
    assert "simplified check" in result.description.lower() or "nmap" in result.description.lower()


@patch("ssl_tester.vulnerabilities.ensure_nmap_available")
def test_check_cryptographic_flaws_nmap_check(mock_ensure_nmap):
    """Test that check_cryptographic_flaws calls ensure_nmap_available."""
    mock_ensure_nmap.return_value = (False, None)
    
    results = check_cryptographic_flaws("example.com", 443, timeout=5.0)
    
    mock_ensure_nmap.assert_called_once()
    assert isinstance(results, list)
    assert len(results) > 0


@patch("ssl_tester.vulnerabilities.get_nmap_path")
@patch("ssl_tester.vulnerabilities.run_nmap_script")
def test_check_poodle_with_nmap(mock_run_nmap, mock_get_nmap):
    """Test POODLE check with nmap."""
    mock_get_nmap.return_value = "/usr/bin/nmap"
    mock_run_nmap.return_value = (
        True,
        "State: NOT VULNERABLE\nSSL 3.0 not supported",
        "",
    )
    
    result = check_poodle("example.com", 443, timeout=5.0)
    
    assert result.vulnerability_name == "POODLE"
    mock_run_nmap.assert_called_once()


@patch("ssl_tester.vulnerabilities.get_nmap_path")
@patch("ssl_tester.vulnerabilities.run_nmap_script")
def test_nmap_vulnerable_output_parsing(mock_run_nmap, mock_get_nmap):
    """Test parsing of nmap vulnerable output."""
    mock_get_nmap.return_value = "/usr/bin/nmap"
    mock_run_nmap.return_value = (
        True,
        "State: VULNERABLE\nRisk factor: High\nRead 65535 bytes",
        "",
    )
    
    result = check_heartbleed("example.com", 443, timeout=5.0)
    
    assert result.vulnerable is True
    assert result.severity == Severity.FAIL

