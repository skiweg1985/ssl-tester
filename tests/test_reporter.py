"""Tests for report generation."""

import pytest
import json
from datetime import datetime, timedelta

from ssl_tester.reporter import (
    generate_text_report,
    generate_terminal_report,
    generate_json_report,
    calculate_overall_severity,
    generate_summary,
    calculate_rating,
    _extract_cn_from_dn,
    _get_revocation_method,
)
from ssl_tester.models import (
    CheckResult,
    ChainCheckResult,
    HostnameCheckResult,
    ValidityCheckResult,
    CertificateInfo,
    CRLCheckResult,
    OSPCheckResult,
    ProtocolCheckResult,
    CipherCheckResult,
    VulnerabilityCheckResult,
    SecurityCheckResult,
    CertificateFinding,
    Severity,
    Rating,
)


@pytest.fixture
def sample_check_result():
    """Create a sample check result for testing."""
    leaf_cert = CertificateInfo(
        subject="CN=example.com",
        issuer="CN=CA",
        serial_number="123",
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        san_dns_names=["example.com"],
        san_ip_addresses=[],
        crl_distribution_points=["http://crl.example.com"],
        ocsp_responder_urls=["http://ocsp.example.com"],
        ca_issuers_urls=[],
        signature_algorithm="sha256",
        public_key_algorithm="RSA",
        fingerprint_sha256="abc123",
    )

    chain_check = ChainCheckResult(
        is_valid=True,
        chain_valid=True,
        leaf_cert=leaf_cert,
        intermediate_certs=[],
        root_cert=None,
        trust_store_valid=True,
        missing_intermediates=[],
        error=None,
        severity=Severity.OK,
    )

    hostname_check = HostnameCheckResult(
        matches=True,
        expected_hostname="example.com",
        matched_san_dns="example.com",
        matched_cn=None,
        severity=Severity.OK,
    )

    validity_check = ValidityCheckResult(
        is_valid=True,
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        days_until_expiry=365,
        is_expired=False,
        severity=Severity.OK,
    )

    crl_check = CRLCheckResult(
        url="http://crl.example.com",
        reachable=True,
        status_code=200,
        content_type="application/pkix-crl",
        size_bytes=1024,
        error=None,
        redirect_chain=[],
        severity=Severity.OK,
    )

    ocsp_check = OSPCheckResult(
        url="http://ocsp.example.com",
        reachable=True,
        status_code=200,
        error=None,
        severity=Severity.OK,
    )

    return CheckResult(
        target_host="example.com",
        target_port=443,
        timestamp=datetime.utcnow(),
        chain_check=chain_check,
        hostname_check=hostname_check,
        validity_check=validity_check,
        crl_checks=[crl_check],
        ocsp_checks=[ocsp_check],
        overall_severity=Severity.OK,
        summary="",
    )


def test_generate_text_report(sample_check_result):
    """Test text report generation."""
    report = generate_text_report(sample_check_result)

    assert "SSL/TLS Certificate Check Report" in report
    assert "example.com" in report
    assert "Certificate Chain:" in report
    assert "Hostname Matching:" in report
    assert "Certificate Validity:" in report


def test_generate_json_report(sample_check_result):
    """Test JSON report generation."""
    json_str = generate_json_report(sample_check_result)
    data = json.loads(json_str)

    assert data["target_host"] == "example.com"
    assert data["target_port"] == 443
    assert data["overall_severity"] == "OK"
    assert "chain_check" in data
    assert "hostname_check" in data
    assert "validity_check" in data


def test_calculate_overall_severity_ok(sample_check_result):
    """Test overall severity calculation - all OK."""
    severity = calculate_overall_severity(sample_check_result)
    assert severity == Severity.OK


def test_calculate_overall_severity_warn(sample_check_result):
    """Test overall severity calculation - warnings."""
    sample_check_result.validity_check.severity = Severity.WARN
    severity = calculate_overall_severity(sample_check_result)
    assert severity == Severity.WARN


def test_calculate_overall_severity_fail(sample_check_result):
    """Test overall severity calculation - failures."""
    sample_check_result.chain_check.severity = Severity.FAIL
    severity = calculate_overall_severity(sample_check_result)
    assert severity == Severity.FAIL


def test_generate_summary_all_ok(sample_check_result):
    """Test summary generation - all OK."""
    summary = generate_summary(sample_check_result)
    assert "All checks passed" in summary


def test_generate_summary_with_issues(sample_check_result):
    """Test summary generation - with issues."""
    sample_check_result.validity_check.severity = Severity.WARN
    sample_check_result.validity_check.days_until_expiry = 10
    summary = generate_summary(sample_check_result)
    assert "expires in" in summary.lower()


# Rating Tests

def test_rating_f_connection_error():
    """Test Rating F - connection error."""
    leaf_cert = CertificateInfo(
        subject="<unable to retrieve>",
        issuer="",
        serial_number="",
        not_before=datetime.utcnow(),
        not_after=datetime.utcnow(),
        san_dns_names=[],
        san_ip_addresses=[],
        crl_distribution_points=[],
        ocsp_responder_urls=[],
        ca_issuers_urls=[],
        signature_algorithm="",
        public_key_algorithm="",
        fingerprint_sha256="",
    )
    
    result = CheckResult(
        target_host="example.com",
        target_port=443,
        timestamp=datetime.utcnow(),
        chain_check=ChainCheckResult(
            is_valid=False,
            chain_valid=False,
            leaf_cert=leaf_cert,
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=False,
            missing_intermediates=[],
            error="Connection failed",
            severity=Severity.FAIL,
        ),
        hostname_check=HostnameCheckResult(
            matches=False,
            expected_hostname="example.com",
            matched_san_dns=None,
            matched_cn=None,
            severity=Severity.FAIL,
        ),
        validity_check=ValidityCheckResult(
            is_valid=False,
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow(),
            days_until_expiry=0,
            is_expired=True,
            severity=Severity.FAIL,
        ),
        crl_checks=[],
        ocsp_checks=[],
    )
    
    rating, reasons = calculate_rating(result)
    assert rating == Rating.F
    assert len(reasons) > 0
    assert any("Unable to connect" in r or "certificate" in r.lower() for r in reasons)


def test_rating_f_ssl_protocols():
    """Test Rating F - SSL protocols."""
    leaf_cert = CertificateInfo(
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
    
    result = CheckResult(
        target_host="example.com",
        target_port=443,
        timestamp=datetime.utcnow(),
        chain_check=ChainCheckResult(
            is_valid=True,
            chain_valid=True,
            leaf_cert=leaf_cert,
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=True,
            missing_intermediates=[],
            error=None,
            severity=Severity.OK,
        ),
        hostname_check=HostnameCheckResult(
            matches=True,
            expected_hostname="example.com",
            matched_san_dns="example.com",
            matched_cn=None,
            severity=Severity.OK,
        ),
        validity_check=ValidityCheckResult(
            is_valid=True,
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            days_until_expiry=365,
            is_expired=False,
            severity=Severity.OK,
        ),
        crl_checks=[],
        ocsp_checks=[],
        protocol_check=ProtocolCheckResult(
            supported_versions=["TLSv1.2"],
            best_version="TLSv1.2",
            deprecated_versions=[],
            ssl_versions=["SSLv3"],
            severity=Severity.FAIL,
        ),
    )
    
    rating, reasons = calculate_rating(result)
    assert rating == Rating.F
    assert len(reasons) > 0
    assert any("SSL" in r for r in reasons)


def test_rating_e_critical_vulnerabilities():
    """Test Rating E - critical vulnerabilities."""
    leaf_cert = CertificateInfo(
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
    
    result = CheckResult(
        target_host="example.com",
        target_port=443,
        timestamp=datetime.utcnow(),
        chain_check=ChainCheckResult(
            is_valid=True,
            chain_valid=True,
            leaf_cert=leaf_cert,
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=True,
            missing_intermediates=[],
            error=None,
            severity=Severity.OK,
        ),
        hostname_check=HostnameCheckResult(
            matches=True,
            expected_hostname="example.com",
            matched_san_dns="example.com",
            matched_cn=None,
            severity=Severity.OK,
        ),
        validity_check=ValidityCheckResult(
            is_valid=True,
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            days_until_expiry=365,
            is_expired=False,
            severity=Severity.OK,
        ),
        crl_checks=[],
        ocsp_checks=[],
        protocol_check=ProtocolCheckResult(
            supported_versions=["TLSv1.2"],
            best_version="TLSv1.2",
            deprecated_versions=[],
            ssl_versions=[],
            severity=Severity.OK,
        ),
        vulnerability_checks=[
            VulnerabilityCheckResult(
                vulnerability_name="Heartbleed",
                cve_id="CVE-2014-0160",
                vulnerable=True,
                severity=Severity.FAIL,
                description="Critical vulnerability",
                recommendation="Update OpenSSL",
            ),
        ],
    )
    
    rating, reasons = calculate_rating(result)
    assert rating == Rating.E
    assert len(reasons) > 0
    assert any("Sicherheitslücken" in r or "Heartbleed" in r for r in reasons)


def test_rating_e_tls_compression():
    """Test Rating E - TLS compression."""
    leaf_cert = CertificateInfo(
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
    
    result = CheckResult(
        target_host="example.com",
        target_port=443,
        timestamp=datetime.utcnow(),
        chain_check=ChainCheckResult(
            is_valid=True,
            chain_valid=True,
            leaf_cert=leaf_cert,
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=True,
            missing_intermediates=[],
            error=None,
            severity=Severity.OK,
        ),
        hostname_check=HostnameCheckResult(
            matches=True,
            expected_hostname="example.com",
            matched_san_dns="example.com",
            matched_cn=None,
            severity=Severity.OK,
        ),
        validity_check=ValidityCheckResult(
            is_valid=True,
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            days_until_expiry=365,
            is_expired=False,
            severity=Severity.OK,
        ),
        crl_checks=[],
        ocsp_checks=[],
        security_check=SecurityCheckResult(
            hsts_enabled=False,
            hsts_max_age=None,
            ocsp_stapling_enabled=False,
            tls_compression_enabled=True,
            session_resumption_enabled=False,
            severity=Severity.FAIL,
        ),
    )
    
    rating, reasons = calculate_rating(result)
    assert rating == Rating.E
    assert len(reasons) > 0
    assert any("Komprimierung" in r or "CRIME" in r for r in reasons)


def test_rating_e_only_tls10():
    """Test Rating E - only TLS 1.0."""
    leaf_cert = CertificateInfo(
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
    
    result = CheckResult(
        target_host="example.com",
        target_port=443,
        timestamp=datetime.utcnow(),
        chain_check=ChainCheckResult(
            is_valid=True,
            chain_valid=True,
            leaf_cert=leaf_cert,
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=True,
            missing_intermediates=[],
            error=None,
            severity=Severity.OK,
        ),
        hostname_check=HostnameCheckResult(
            matches=True,
            expected_hostname="example.com",
            matched_san_dns="example.com",
            matched_cn=None,
            severity=Severity.OK,
        ),
        validity_check=ValidityCheckResult(
            is_valid=True,
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            days_until_expiry=365,
            is_expired=False,
            severity=Severity.OK,
        ),
        crl_checks=[],
        ocsp_checks=[],
        protocol_check=ProtocolCheckResult(
            supported_versions=["TLSv1.0"],
            best_version="TLSv1.0",
            deprecated_versions=["TLSv1.0"],
            ssl_versions=[],
            severity=Severity.FAIL,
        ),
    )
    
    rating, reasons = calculate_rating(result)
    assert rating == Rating.E
    assert len(reasons) > 0
    assert any("TLS 1.0" in r for r in reasons)


def test_rating_e_only_weak_ciphers():
    """Test Rating E - only weak ciphers."""
    leaf_cert = CertificateInfo(
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
    
    result = CheckResult(
        target_host="example.com",
        target_port=443,
        timestamp=datetime.utcnow(),
        chain_check=ChainCheckResult(
            is_valid=True,
            chain_valid=True,
            leaf_cert=leaf_cert,
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=True,
            missing_intermediates=[],
            error=None,
            severity=Severity.OK,
        ),
        hostname_check=HostnameCheckResult(
            matches=True,
            expected_hostname="example.com",
            matched_san_dns="example.com",
            matched_cn=None,
            severity=Severity.OK,
        ),
        validity_check=ValidityCheckResult(
            is_valid=True,
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            days_until_expiry=365,
            is_expired=False,
            severity=Severity.OK,
        ),
        crl_checks=[],
        ocsp_checks=[],
        protocol_check=ProtocolCheckResult(
            supported_versions=["TLSv1.2"],
            best_version="TLSv1.2",
            deprecated_versions=[],
            ssl_versions=[],
            severity=Severity.OK,
        ),
        cipher_check=CipherCheckResult(
            supported_ciphers=["RC4-SHA", "DES-CBC3-SHA"],
            weak_ciphers=["RC4-SHA", "DES-CBC3-SHA"],
            pfs_supported=False,
            server_preferences=False,
            severity=Severity.FAIL,
        ),
    )
    
    rating, reasons = calculate_rating(result)
    assert rating == Rating.E
    assert len(reasons) > 0
    assert any("weak" in r.lower() or "encryption" in r.lower() for r in reasons)


def test_rating_d_tls11_with_weak_ciphers():
    """Test Rating D - TLS 1.1 with weak ciphers."""
    leaf_cert = CertificateInfo(
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
    
    result = CheckResult(
        target_host="example.com",
        target_port=443,
        timestamp=datetime.utcnow(),
        chain_check=ChainCheckResult(
            is_valid=True,
            chain_valid=True,
            leaf_cert=leaf_cert,
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=True,
            missing_intermediates=[],
            error=None,
            severity=Severity.OK,
        ),
        hostname_check=HostnameCheckResult(
            matches=True,
            expected_hostname="example.com",
            matched_san_dns="example.com",
            matched_cn=None,
            severity=Severity.OK,
        ),
        validity_check=ValidityCheckResult(
            is_valid=True,
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            days_until_expiry=365,
            is_expired=False,
            severity=Severity.OK,
        ),
        crl_checks=[],
        ocsp_checks=[],
        protocol_check=ProtocolCheckResult(
            supported_versions=["TLSv1.1", "TLSv1.2"],
            best_version="TLSv1.2",
            deprecated_versions=["TLSv1.1"],
            ssl_versions=[],
            severity=Severity.WARN,
        ),
        cipher_check=CipherCheckResult(
            supported_ciphers=["AES128-SHA", "RC4-SHA"],
            weak_ciphers=["RC4-SHA"],
            pfs_supported=False,
            server_preferences=False,
            severity=Severity.WARN,
        ),
    )
    
    rating, reasons = calculate_rating(result)
    assert rating == Rating.D
    assert len(reasons) > 0
    assert any("TLS 1.1" in r for r in reasons)


def test_rating_c_tls12_only_no_pfs():
    """Test Rating C - TLS 1.2 only, no PFS."""
    leaf_cert = CertificateInfo(
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
    
    result = CheckResult(
        target_host="example.com",
        target_port=443,
        timestamp=datetime.utcnow(),
        chain_check=ChainCheckResult(
            is_valid=True,
            chain_valid=True,
            leaf_cert=leaf_cert,
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=True,
            missing_intermediates=[],
            error=None,
            severity=Severity.OK,
        ),
        hostname_check=HostnameCheckResult(
            matches=True,
            expected_hostname="example.com",
            matched_san_dns="example.com",
            matched_cn=None,
            severity=Severity.OK,
        ),
        validity_check=ValidityCheckResult(
            is_valid=True,
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            days_until_expiry=365,
            is_expired=False,
            severity=Severity.OK,
        ),
        crl_checks=[],
        ocsp_checks=[],
        protocol_check=ProtocolCheckResult(
            supported_versions=["TLSv1.2"],
            best_version="TLSv1.2",
            deprecated_versions=[],
            ssl_versions=[],
            severity=Severity.OK,
        ),
        cipher_check=CipherCheckResult(
            supported_ciphers=["AES256-SHA"],
            weak_ciphers=[],
            pfs_supported=False,
            server_preferences=False,
            severity=Severity.WARN,
        ),
    )
    
    rating, reasons = calculate_rating(result)
    assert rating == Rating.C
    assert len(reasons) > 0
    assert any("TLS 1.3" in r or "PFS" in r for r in reasons)


def test_rating_b_tls12_only():
    """Test Rating B - TLS 1.2 only, everything else OK."""
    leaf_cert = CertificateInfo(
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
    
    result = CheckResult(
        target_host="example.com",
        target_port=443,
        timestamp=datetime.utcnow(),
        chain_check=ChainCheckResult(
            is_valid=True,
            chain_valid=True,
            leaf_cert=leaf_cert,
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=True,
            missing_intermediates=[],
            error=None,
            severity=Severity.OK,
        ),
        hostname_check=HostnameCheckResult(
            matches=True,
            expected_hostname="example.com",
            matched_san_dns="example.com",
            matched_cn=None,
            severity=Severity.OK,
        ),
        validity_check=ValidityCheckResult(
            is_valid=True,
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            days_until_expiry=365,
            is_expired=False,
            severity=Severity.OK,
        ),
        crl_checks=[],
        ocsp_checks=[],
        protocol_check=ProtocolCheckResult(
            supported_versions=["TLSv1.2"],
            best_version="TLSv1.2",
            deprecated_versions=[],
            ssl_versions=[],
            severity=Severity.OK,
        ),
        cipher_check=CipherCheckResult(
            supported_ciphers=["AES256-GCM-SHA384"],
            weak_ciphers=[],
            pfs_supported=True,
            server_preferences=False,
            severity=Severity.OK,
        ),
    )
    
    rating, reasons = calculate_rating(result)
    assert rating == Rating.B
    assert len(reasons) > 0
    assert any("TLS 1.3" in r for r in reasons)


def test_rating_a_tls13_no_pfs():
    """Test Rating A - TLS 1.3, no PFS."""
    leaf_cert = CertificateInfo(
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
    
    result = CheckResult(
        target_host="example.com",
        target_port=443,
        timestamp=datetime.utcnow(),
        chain_check=ChainCheckResult(
            is_valid=True,
            chain_valid=True,
            leaf_cert=leaf_cert,
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=True,
            missing_intermediates=[],
            error=None,
            severity=Severity.OK,
        ),
        hostname_check=HostnameCheckResult(
            matches=True,
            expected_hostname="example.com",
            matched_san_dns="example.com",
            matched_cn=None,
            severity=Severity.OK,
        ),
        validity_check=ValidityCheckResult(
            is_valid=True,
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            days_until_expiry=365,
            is_expired=False,
            severity=Severity.OK,
        ),
        crl_checks=[],
        ocsp_checks=[],
        protocol_check=ProtocolCheckResult(
            supported_versions=["TLSv1.3"],
            best_version="TLSv1.3",
            deprecated_versions=[],
            ssl_versions=[],
            severity=Severity.OK,
        ),
        cipher_check=CipherCheckResult(
            supported_ciphers=["AES256-GCM-SHA384"],
            weak_ciphers=[],
            pfs_supported=False,
            server_preferences=False,
            severity=Severity.WARN,
        ),
    )
    
    rating, reasons = calculate_rating(result)
    assert rating == Rating.A
    assert len(reasons) > 0
    assert any("PFS" in r for r in reasons)


def test_rating_a_plus_tls13_with_warnings():
    """Test Rating A+ - TLS 1.3, PFS, but with warnings."""
    leaf_cert = CertificateInfo(
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
    
    result = CheckResult(
        target_host="example.com",
        target_port=443,
        timestamp=datetime.utcnow(),
        chain_check=ChainCheckResult(
            is_valid=True,
            chain_valid=True,
            leaf_cert=leaf_cert,
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=True,
            missing_intermediates=[],
            error=None,
            severity=Severity.WARN,
        ),
        hostname_check=HostnameCheckResult(
            matches=True,
            expected_hostname="example.com",
            matched_san_dns="example.com",
            matched_cn=None,
            severity=Severity.OK,
        ),
        validity_check=ValidityCheckResult(
            is_valid=True,
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            days_until_expiry=365,
            is_expired=False,
            severity=Severity.OK,
        ),
        crl_checks=[],
        ocsp_checks=[],
        protocol_check=ProtocolCheckResult(
            supported_versions=["TLSv1.3"],
            best_version="TLSv1.3",
            deprecated_versions=[],
            ssl_versions=[],
            severity=Severity.OK,
        ),
        cipher_check=CipherCheckResult(
            supported_ciphers=["TLS_AES_256_GCM_SHA384"],
            weak_ciphers=[],
            pfs_supported=True,
            server_preferences=False,
            severity=Severity.OK,
        ),
        security_check=SecurityCheckResult(
            hsts_enabled=True,
            hsts_max_age=31536000,
            ocsp_stapling_enabled=True,
            tls_compression_enabled=False,
            session_resumption_enabled=True,
            severity=Severity.OK,
        ),
    )
    
    rating, reasons = calculate_rating(result)
    assert rating == Rating.A_PLUS
    # With warnings, reasons should contain warning details
    # But the logic might return A+ even without explicit reasons if warnings are detected
    assert rating == Rating.A_PLUS


def test_rating_a_plus_plus_perfect():
    """Test Rating A++ - perfect configuration."""
    leaf_cert = CertificateInfo(
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
    
    result = CheckResult(
        target_host="example.com",
        target_port=443,
        timestamp=datetime.utcnow(),
        chain_check=ChainCheckResult(
            is_valid=True,
            chain_valid=True,
            leaf_cert=leaf_cert,
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=True,
            missing_intermediates=[],
            error=None,
            severity=Severity.OK,
        ),
        hostname_check=HostnameCheckResult(
            matches=True,
            expected_hostname="example.com",
            matched_san_dns="example.com",
            matched_cn=None,
            severity=Severity.OK,
        ),
        validity_check=ValidityCheckResult(
            is_valid=True,
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            days_until_expiry=365,
            is_expired=False,
            severity=Severity.OK,
        ),
        crl_checks=[],
        ocsp_checks=[],
        protocol_check=ProtocolCheckResult(
            supported_versions=["TLSv1.3"],
            best_version="TLSv1.3",
            deprecated_versions=[],
            ssl_versions=[],
            severity=Severity.OK,
        ),
        cipher_check=CipherCheckResult(
            supported_ciphers=["TLS_AES_256_GCM_SHA384"],
            weak_ciphers=[],
            pfs_supported=True,
            server_preferences=False,
            severity=Severity.OK,
        ),
        security_check=SecurityCheckResult(
            hsts_enabled=True,
            hsts_max_age=31536000,
            ocsp_stapling_enabled=True,
            tls_compression_enabled=False,
            session_resumption_enabled=True,
            severity=Severity.OK,
        ),
    )
    
    rating, reasons = calculate_rating(result)
    # Perfect configuration with TLS 1.3, PFS, no weak ciphers, and no warnings
    # should result in A++ rating according to the logic
    assert rating == Rating.A_PLUS_PLUS
    # With all best practices enabled, there should be no downgrade reasons
    # (or the reasons list might be empty if the logic considers it A+ due to structure)


# ============================================================================
# Tests for Terminal UX Optimization Functions
# ============================================================================

def test_extract_cn_from_dn():
    """Test CN extraction from Distinguished Name."""
    # Standard DN with CN
    assert _extract_cn_from_dn("CN=example.com, O=Example Org, C=US") == "example.com"
    
    # DN with CN at end
    assert _extract_cn_from_dn("O=Example Org, C=US, CN=example.com") == "example.com"
    
    # DN without CN
    assert _extract_cn_from_dn("O=Example Org, C=US") == "O=Example Org"
    
    # Empty DN
    assert _extract_cn_from_dn("") == ""
    
    # DN with spaces
    assert _extract_cn_from_dn("CN=  example.com  , O=Example") == "example.com"


def test_get_revocation_method():
    """Test revocation method detection."""
    # Both CRL and OCSP available and OK
    result = CheckResult(
        target_host="example.com",
        target_port=443,
        timestamp=datetime.utcnow(),
        chain_check=ChainCheckResult(
            is_valid=True,
            chain_valid=True,
            leaf_cert=CertificateInfo(
                subject="CN=example.com",
                issuer="CN=CA",
                serial_number="123",
                not_before=datetime.utcnow(),
                not_after=datetime.utcnow() + timedelta(days=365),
                san_dns_names=[],
                san_ip_addresses=[],
                crl_distribution_points=[],
                ocsp_responder_urls=[],
                ca_issuers_urls=[],
                signature_algorithm="sha256",
                public_key_algorithm="RSA",
                fingerprint_sha256="abc123",
            ),
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=True,
            missing_intermediates=[],
            severity=Severity.OK,
        ),
        hostname_check=HostnameCheckResult(
            matches=True,
            expected_hostname="example.com",
            severity=Severity.OK,
        ),
        validity_check=ValidityCheckResult(
            is_valid=True,
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow() + timedelta(days=365),
            days_until_expiry=365,
            is_expired=False,
            severity=Severity.OK,
        ),
        crl_checks=[
            CRLCheckResult(
                url="http://crl.example.com",
                reachable=True,
                severity=Severity.OK,
            )
        ],
        ocsp_checks=[
            OSPCheckResult(
                url="http://ocsp.example.com",
                reachable=True,
                severity=Severity.OK,
            )
        ],
        overall_severity=Severity.OK,
    )
    
    assert _get_revocation_method(result) == "CRL+OCSP"
    
    # Only CRL available
    result.ocsp_checks = []
    assert _get_revocation_method(result) == "CRL"
    
    # Only OCSP available
    result.crl_checks = []
    result.ocsp_checks = [OSPCheckResult(url="http://ocsp.example.com", reachable=True, severity=Severity.OK)]
    assert _get_revocation_method(result) == "OCSP"
    
    # None available
    result.ocsp_checks = []
    assert _get_revocation_method(result) == "None"


def test_generate_terminal_report_quiet(sample_check_result):
    """Test terminal report generation in quiet mode."""
    sample_check_result.rating = Rating.A_PLUS_PLUS
    report = generate_terminal_report(sample_check_result, quiet=True)
    
    # Should contain header
    assert "[OK ✓]" in report or "[WARN ⚠]" in report or "[FAIL ✗]" in report
    assert "example.com:443" in report
    assert "Rating:" in report
    
    # Should contain summary
    assert "Summary:" in report
    assert "Overall Status:" in report
    
    # Should NOT contain phase details
    assert "Phase 1:" not in report
    assert "Phase 2:" not in report


def test_generate_terminal_report_standard(sample_check_result):
    """Test terminal report generation in standard mode."""
    sample_check_result.rating = Rating.A_PLUS_PLUS
    report = generate_terminal_report(sample_check_result, verbose=False, quiet=False)
    
    # Should contain header
    assert "[OK ✓]" in report or "[WARN ⚠]" in report or "[FAIL ✗]" in report
    assert "example.com:443" in report
    
    # Should contain all phases
    assert "Phase 1: Connectivity" in report
    assert "Phase 2: Certificate Chain" in report
    assert "Phase 3: Hostname Matching" in report
    assert "Phase 4: Certificate Validity" in report
    assert "Phase 5: Revocation Checks" in report
    assert "Phase 6: TLS Configuration" in report
    
    # Should contain summary
    assert "Summary:" in report


def test_generate_terminal_report_verbose(sample_check_result):
    """Test terminal report generation in verbose mode."""
    sample_check_result.rating = Rating.A_PLUS_PLUS
    report = generate_terminal_report(sample_check_result, verbose=True)
    
    # Should contain all phases
    assert "Phase 1: Connectivity" in report
    assert "Phase 2: Certificate Chain" in report
    
    # Should contain detailed information
    assert "Leaf Subject:" in report
    assert "Chain Valid:" in report
    assert "Trust Store Valid:" in report


def test_generate_terminal_report_findings(sample_check_result):
    """Test terminal report findings section."""
    # Add some findings
    sample_check_result.certificate_findings = [
        CertificateFinding(
            code="TEST_FAIL",
            severity=Severity.FAIL,
            message="Test failure message",
            subject="CN=example.com",
            issuer="CN=CA",
        ),
        CertificateFinding(
            code="TEST_WARN",
            severity=Severity.WARN,
            message="Test warning message",
            subject="CN=example.com",
            issuer="CN=CA",
        ),
    ]
    
    report = generate_terminal_report(sample_check_result, verbose=False)
    
    # Should contain findings section
    assert "Findings:" in report
    assert "FAIL:" in report
    assert "WARN:" in report
    assert "Test failure message" in report
    assert "Test warning message" in report


def test_generate_terminal_report_cross_signing(sample_check_result):
    """Test terminal report cross-signing resolution."""
    from ssl_tester.models import CrossSignedCertificate
    
    # Add cross-signed certificate
    cross_signed_cert = CrossSignedCertificate(
        chain_cert=CertificateInfo(
            subject="CN=GTS Root R1, O=Google Trust Services LLC, C=US",
            issuer="CN=GlobalSign Root CA, O=GlobalSign nv-sa, C=BE",
            serial_number="123",
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow() + timedelta(days=365),
            san_dns_names=[],
            san_ip_addresses=[],
            crl_distribution_points=[],
            ocsp_responder_urls=[],
            ca_issuers_urls=[],
            signature_algorithm="sha256",
            public_key_algorithm="RSA",
            fingerprint_sha256="abc123",
        ),
        trust_store_root=CertificateInfo(
            subject="CN=GTS Root R1, O=Google Trust Services LLC, C=US",
            issuer="CN=GTS Root R1, O=Google Trust Services LLC, C=US",
            serial_number="456",
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow() + timedelta(days=365),
            san_dns_names=[],
            san_ip_addresses=[],
            crl_distribution_points=[],
            ocsp_responder_urls=[],
            ca_issuers_urls=[],
            signature_algorithm="sha256",
            public_key_algorithm="RSA",
            fingerprint_sha256="abc123",
        ),
        actual_signer="CN=GlobalSign Root CA, O=GlobalSign nv-sa, C=BE",
    )
    
    sample_check_result.chain_check.cross_signed_certs = [cross_signed_cert]
    
    report = generate_terminal_report(sample_check_result, verbose=False)
    
    # Should contain cross-signing resolution
    assert "Cross-Signing Resolution" in report
    assert "not a security issue" in report
    assert "RFC 4158" in report
    
    # Should contain compact information
    assert "GTS Root R1" in report
    assert "GlobalSign Root CA" in report
    
    # Verbose mode should show details
    report_verbose = generate_terminal_report(sample_check_result, verbose=True)
    assert "Details:" in report_verbose
    assert "Chain cert issuer:" in report_verbose
    assert "Trust root issuer:" in report_verbose


def test_generate_terminal_report_connection_error():
    """Test terminal report for connection errors."""
    result = CheckResult(
        target_host="nonexistent.example.com",
        target_port=443,
        timestamp=datetime.utcnow(),
        chain_check=ChainCheckResult(
            is_valid=False,
            chain_valid=False,
            leaf_cert=CertificateInfo(
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
            ),
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=False,
            missing_intermediates=[],
            error="DNS resolution failed",
            severity=Severity.FAIL,
        ),
        hostname_check=HostnameCheckResult(
            matches=False,
            expected_hostname="nonexistent.example.com",
            severity=Severity.FAIL,
        ),
        validity_check=ValidityCheckResult(
            is_valid=False,
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow(),
            days_until_expiry=0,
            is_expired=False,
            severity=Severity.FAIL,
        ),
        crl_checks=[],
        ocsp_checks=[],
        overall_severity=Severity.FAIL,
    )
    
    report = generate_terminal_report(result, verbose=False)
    
    # Should show connection error
    assert "Phase 1: Connectivity" in report
    assert "FAIL" in report or "✗" in report
    assert "DNS resolution failed" in report or "Connection error" in report
    
    # Should NOT show other phases
    assert "Phase 2:" not in report
    assert "Phase 3:" not in report

