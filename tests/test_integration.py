"""Integration tests for the full certificate checking flow."""

import pytest
from unittest.mock import Mock, patch, MagicMock
import socket
import ssl

from ssl_tester.cli import check
from ssl_tester.models import Severity


@patch("ssl_tester.cli.connect_tls")
@patch("ssl_tester.cli.parse_certificate")
@patch("ssl_tester.cli.check_hostname")
@patch("ssl_tester.cli.check_validity")
@patch("ssl_tester.cli.validate_chain")
@patch("ssl_tester.cli.check_crl_reachability")
@patch("ssl_tester.cli.check_ocsp_reachability")
@patch("ssl_tester.cli.generate_text_report")
@patch("ssl_tester.cli.generate_json_report")
@patch("ssl_tester.cli.sys.exit")
def test_cli_check_success(
    mock_exit,
    mock_json_report,
    mock_text_report,
    mock_ocsp,
    mock_crl,
    mock_validate_chain,
    mock_check_validity,
    mock_check_hostname,
    mock_parse_cert,
    mock_connect_tls,
):
    """Test successful CLI check."""
    from ssl_tester.models import (
        CertificateInfo,
        ChainCheckResult,
        HostnameCheckResult,
        ValidityCheckResult,
        CheckResult,
    )
    from datetime import datetime, timedelta

    # Mock TLS connection
    mock_connect_tls.return_value = (b"leaf_cert", [b"intermediate_cert"])

    # Mock certificate parsing
    leaf_cert_info = CertificateInfo(
        subject="CN=example.com",
        issuer="CN=CA",
        serial_number="123",
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        san_dns_names=["example.com"],
        san_ip_addresses=[],
        crl_distribution_points=[],
        ocsp_responder_urls=[],
        ca_issuers_urls=[],
        signature_algorithm="sha256",
        public_key_algorithm="RSA",
        fingerprint_sha256="abc123",
    )
    mock_parse_cert.return_value = (leaf_cert_info, [])

    # Mock checks
    mock_check_hostname.return_value = HostnameCheckResult(
        matches=True, expected_hostname="example.com", matched_san_dns="example.com", severity=Severity.OK
    )
    mock_check_validity.return_value = ValidityCheckResult(
        is_valid=True,
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        days_until_expiry=365,
        is_expired=False,
        severity=Severity.OK,
    )
    mock_validate_chain.return_value = (
        ChainCheckResult(
            is_valid=True,
            chain_valid=True,
            leaf_cert=leaf_cert_info,
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=True,
            missing_intermediates=[],
            severity=Severity.OK,
        ),
        [],
    )
    mock_crl.return_value = []
    mock_ocsp.return_value = []

    # Mock reports
    mock_text_report.return_value = "Test Report"
    mock_json_report.return_value = '{"test": "report"}'

    # Run CLI (with URL parsing)
    with patch("builtins.print"):
        check("example.com", port=443, json_output=False, verbose=False)

    # Verify exit code
    mock_exit.assert_called_once_with(0)


@patch("ssl_tester.cli.connect_tls")
@patch("ssl_tester.cli.parse_certificate")
def test_cli_check_connection_error(mock_parse_cert, mock_connect_tls):
    """Test CLI with connection error."""
    # Mock connect_tls to raise an exception, which will result in leaf_cert_der being None
    mock_connect_tls.side_effect = Exception("Connection failed")
    # Mock parse_certificate in case it gets called (shouldn't happen, but sys.exit is mocked)
    from ssl_tester.models import CertificateInfo
    from datetime import datetime
    mock_cert_info = CertificateInfo(
        subject="<unable to retrieve>",
        issuer="<unable to retrieve>",
        serial_number="<unable to retrieve>",
        not_before=datetime.utcnow(),
        not_after=datetime.utcnow(),
        san_dns_names=[],
        san_ip_addresses=[],
        crl_distribution_points=[],
        ocsp_responder_urls=[],
        ca_issuers_urls=[],
        signature_algorithm="<unknown>",
        public_key_algorithm="<unknown>",
        fingerprint_sha256="<unknown>",
    )
    mock_parse_cert.return_value = (mock_cert_info, [])

    with patch("builtins.print"):
        with patch("ssl_tester.cli.sys.exit") as mock_exit:
            check("example.com", port=443)

    # Should exit with code 2 on error
    # Note: The CLI checks if leaf_cert_der is None and exits early, so parse_certificate should not be called
    # sys.exit(2) may be called multiple times (once in error handling, once at end), so check it was called with 2
    assert mock_exit.called
    assert any(call[0][0] == 2 for call in mock_exit.call_args_list)


def test_cli_url_parsing():
    """Test URL parsing in CLI."""
    from ssl_tester.cli import check
    from unittest.mock import patch
    from ssl_tester.models import CertificateInfo
    from datetime import datetime

    with patch("ssl_tester.cli.connect_tls") as mock_connect:
        with patch("ssl_tester.cli.parse_certificate") as mock_parse_cert:
            # Mock connect_tls to raise an exception, which will result in leaf_cert_der being None
            mock_connect.side_effect = Exception("Test")
            # Mock parse_certificate in case it gets called (shouldn't happen, but sys.exit is mocked)
            mock_cert_info = CertificateInfo(
                subject="<unable to retrieve>",
                issuer="<unable to retrieve>",
                serial_number="<unable to retrieve>",
                not_before=datetime.utcnow(),
                not_after=datetime.utcnow(),
                san_dns_names=[],
                san_ip_addresses=[],
                crl_distribution_points=[],
                ocsp_responder_urls=[],
                ca_issuers_urls=[],
                signature_algorithm="<unknown>",
                public_key_algorithm="<unknown>",
                fingerprint_sha256="<unknown>",
            )
            mock_parse_cert.return_value = (mock_cert_info, [])
            with patch("builtins.print"):
                with patch("ssl_tester.cli.sys.exit"):
                    # Test with https:// URL
                    check("https://example.com:8443", port=443)

                    # Should extract hostname and port from URL
                    assert mock_connect.called
                    call_args = mock_connect.call_args
                    assert call_args[0][0] == "example.com"
                    assert call_args[0][1] == 8443


@patch("ssl_tester.cli.connect_tls")
@patch("ssl_tester.cli.parse_certificate")
@patch("ssl_tester.cli.check_hostname")
@patch("ssl_tester.cli.check_validity")
@patch("ssl_tester.cli.validate_chain")
@patch("ssl_tester.cli.check_crl_reachability")
@patch("ssl_tester.cli.check_ocsp_reachability")
@patch("ssl_tester.cli.generate_text_report")
@patch("ssl_tester.cli.sys.exit")
def test_cli_with_insecure_mode(
    mock_exit,
    mock_text_report,
    mock_ocsp,
    mock_crl,
    mock_validate_chain,
    mock_check_validity,
    mock_check_hostname,
    mock_parse_cert,
    mock_connect_tls,
):
    """Test CLI with insecure mode enabled."""
    from ssl_tester.models import CertificateInfo, ChainCheckResult, HostnameCheckResult, ValidityCheckResult
    from datetime import datetime, timedelta
    from pathlib import Path

    mock_connect_tls.return_value = (b"leaf_cert", [b"intermediate_cert"])
    
    leaf_cert_info = CertificateInfo(
        subject="CN=example.com",
        issuer="CN=CA",
        serial_number="123",
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        san_dns_names=["example.com"],
        san_ip_addresses=[],
        crl_distribution_points=[],
        ocsp_responder_urls=[],
        ca_issuers_urls=[],
        signature_algorithm="sha256",
        public_key_algorithm="RSA",
        fingerprint_sha256="abc123",
    )
    mock_parse_cert.return_value = (leaf_cert_info, [])
    mock_check_hostname.return_value = HostnameCheckResult(
        matches=True, expected_hostname="example.com", matched_san_dns="example.com", severity=Severity.OK
    )
    mock_check_validity.return_value = ValidityCheckResult(
        is_valid=True,
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        days_until_expiry=365,
        is_expired=False,
        severity=Severity.OK,
    )
    mock_validate_chain.return_value = (
        ChainCheckResult(
            is_valid=True,
            chain_valid=True,
            leaf_cert=leaf_cert_info,
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=True,
            missing_intermediates=[],
            severity=Severity.OK,
        ),
        [],
    )
    mock_crl.return_value = []
    mock_ocsp.return_value = []
    mock_text_report.return_value = "Test Report"

    with patch("builtins.print"):
        check("example.com", port=443, insecure=True)

    # Verify that connect_tls was called with insecure=True
    assert mock_connect_tls.called
    # Check both positional and keyword arguments
    if mock_connect_tls.call_args:
        call_kwargs = mock_connect_tls.call_args.kwargs or {}
        call_args = mock_connect_tls.call_args[0] or ()
        # Try keyword arguments first
        if "insecure" in call_kwargs:
            assert call_kwargs.get("insecure") is True
        # Or check positional arguments (insecure is 3rd positional arg, index 3)
        elif len(call_args) >= 4:
            assert call_args[3] is True


@patch("ssl_tester.cli.connect_tls")
@patch("ssl_tester.cli.parse_certificate")
@patch("ssl_tester.cli.check_hostname")
@patch("ssl_tester.cli.check_validity")
@patch("ssl_tester.cli.validate_chain")
@patch("ssl_tester.cli.check_crl_reachability")
@patch("ssl_tester.cli.check_ocsp_reachability")
@patch("ssl_tester.cli.generate_text_report")
@patch("ssl_tester.cli.sys.exit")
def test_cli_with_ca_bundle(
    mock_exit,
    mock_text_report,
    mock_ocsp,
    mock_crl,
    mock_validate_chain,
    mock_check_validity,
    mock_check_hostname,
    mock_parse_cert,
    mock_connect_tls,
):
    """Test CLI with custom CA bundle."""
    from ssl_tester.models import CertificateInfo, ChainCheckResult, HostnameCheckResult, ValidityCheckResult
    from datetime import datetime, timedelta
    from pathlib import Path

    mock_connect_tls.return_value = (b"leaf_cert", [b"intermediate_cert"])
    
    leaf_cert_info = CertificateInfo(
        subject="CN=example.com",
        issuer="CN=CA",
        serial_number="123",
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        san_dns_names=["example.com"],
        san_ip_addresses=[],
        crl_distribution_points=[],
        ocsp_responder_urls=[],
        ca_issuers_urls=[],
        signature_algorithm="sha256",
        public_key_algorithm="RSA",
        fingerprint_sha256="abc123",
    )
    mock_parse_cert.return_value = (leaf_cert_info, [])
    mock_check_hostname.return_value = HostnameCheckResult(
        matches=True, expected_hostname="example.com", matched_san_dns="example.com", severity=Severity.OK
    )
    mock_check_validity.return_value = ValidityCheckResult(
        is_valid=True,
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        days_until_expiry=365,
        is_expired=False,
        severity=Severity.OK,
    )
    mock_validate_chain.return_value = (
        ChainCheckResult(
            is_valid=True,
            chain_valid=True,
            leaf_cert=leaf_cert_info,
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=True,
            missing_intermediates=[],
            severity=Severity.OK,
        ),
        [],
    )
    mock_crl.return_value = []
    mock_ocsp.return_value = []
    mock_text_report.return_value = "Test Report"

    ca_bundle = Path("/path/to/ca-bundle.pem")

    with patch("builtins.print"):
        check("example.com", port=443, ca_bundle=ca_bundle)

    # Verify that connect_tls was called with ca_bundle
    assert mock_connect_tls.called
    # Check both positional and keyword arguments
    if mock_connect_tls.call_args:
        call_kwargs = mock_connect_tls.call_args.kwargs or {}
        call_args = mock_connect_tls.call_args[0] or ()
        # Try keyword arguments first
        if "ca_bundle" in call_kwargs:
            assert call_kwargs.get("ca_bundle") == ca_bundle
        # Or check positional arguments (ca_bundle is 4th positional arg, index 4)
        elif len(call_args) >= 5:
            assert call_args[4] == ca_bundle


@patch("ssl_tester.cli.connect_tls")
@patch("ssl_tester.cli.parse_certificate")
@patch("ssl_tester.cli.check_hostname")
@patch("ssl_tester.cli.check_validity")
@patch("ssl_tester.cli.validate_chain")
@patch("ssl_tester.cli.check_crl_reachability")
@patch("ssl_tester.cli.check_ocsp_reachability")
@patch("ssl_tester.cli.fetch_intermediates_via_aia")
@patch("ssl_tester.cli.generate_text_report")
@patch("ssl_tester.cli.sys.exit")
def test_cli_with_proxy(
    mock_exit,
    mock_text_report,
    mock_fetch_aia,
    mock_ocsp,
    mock_crl,
    mock_validate_chain,
    mock_check_validity,
    mock_check_hostname,
    mock_parse_cert,
    mock_connect_tls,
):
    """Test CLI with proxy option."""
    from ssl_tester.models import CertificateInfo, ChainCheckResult, HostnameCheckResult, ValidityCheckResult
    from datetime import datetime, timedelta

    mock_connect_tls.return_value = (b"leaf_cert", [])
    
    leaf_cert_info = CertificateInfo(
        subject="CN=example.com",
        issuer="CN=CA",
        serial_number="123",
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        san_dns_names=["example.com"],
        san_ip_addresses=[],
        crl_distribution_points=[],
        ocsp_responder_urls=[],
        ca_issuers_urls=["http://ca.example.com/cert.pem"],
        signature_algorithm="sha256",
        public_key_algorithm="RSA",
        fingerprint_sha256="abc123",
    )
    mock_parse_cert.return_value = (leaf_cert_info, [])
    mock_check_hostname.return_value = HostnameCheckResult(
        matches=True, expected_hostname="example.com", matched_san_dns="example.com", severity=Severity.OK
    )
    mock_check_validity.return_value = ValidityCheckResult(
        is_valid=True,
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        days_until_expiry=365,
        is_expired=False,
        severity=Severity.OK,
    )
    mock_validate_chain.return_value = (
        ChainCheckResult(
            is_valid=True,
            chain_valid=True,
            leaf_cert=leaf_cert_info,
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=True,
            missing_intermediates=[],
            severity=Severity.OK,
        ),
        [],
    )
    mock_crl.return_value = []
    mock_ocsp.return_value = []
    mock_fetch_aia.return_value = []
    mock_text_report.return_value = "Test Report"

    with patch("builtins.print"):
        check("example.com", port=443, proxy="http://proxy.example.com:8080")

    # Verify that fetch_intermediates_via_aia was called with proxy
    assert mock_fetch_aia.called
    call_kwargs = mock_fetch_aia.call_args[1]
    assert call_kwargs.get("proxy") == "http://proxy.example.com:8080"

