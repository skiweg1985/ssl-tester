"""Data models for certificate checking results."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List
from datetime import datetime


class Severity(str, Enum):
    """Severity levels for check results."""

    OK = "OK"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass
class CertificateInfo:
    """Information about a single certificate."""

    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    san_dns_names: List[str]
    san_ip_addresses: List[str]
    crl_distribution_points: List[str]  # URLs
    ocsp_responder_urls: List[str]  # AIA OCSP URLs
    ca_issuers_urls: List[str]  # AIA CA Issuers URLs
    signature_algorithm: str
    public_key_algorithm: str
    fingerprint_sha256: str
    key_usage: Optional[List[str]] = None
    extended_key_usage: Optional[List[str]] = None
    basic_constraints: Optional[dict] = None
    authority_key_identifier: Optional[str] = None
    subject_key_identifier: Optional[str] = None


@dataclass
class CRLCheckResult:
    """Result of a CRL reachability check."""

    url: str
    reachable: bool
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    size_bytes: Optional[int] = None
    error: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    severity: Severity = Severity.OK
    certificate_subject: Optional[str] = None  # Subject of the certificate that has this CRL URL
    certificate_type: Optional[str] = None  # "Leaf", "Intermediate", or "Root"


@dataclass
class OSPCheckResult:
    """Result of an OCSP reachability check."""

    url: str
    reachable: bool
    status_code: Optional[int] = None
    error: Optional[str] = None
    severity: Severity = Severity.OK


@dataclass
class CrossSignedCertificate:
    """Information about a cross-signed certificate."""
    
    chain_cert: CertificateInfo  # The cross-signed certificate from chain
    trust_store_root: CertificateInfo  # The self-signed root from trust store that replaced it
    actual_signer: str  # The actual signer of the cross-signed cert (e.g., Starfield)


@dataclass
class ChainCheckResult:
    """Result of chain validation."""

    is_valid: bool  # Overall validity (chain_valid and trust_store_valid)
    chain_valid: bool  # Chain structure and signature validity (without trust store)
    leaf_cert: CertificateInfo
    intermediate_certs: List[CertificateInfo]
    root_cert: Optional[CertificateInfo]
    trust_store_valid: bool
    missing_intermediates: List[str]  # Issuer DNs
    error: Optional[str] = None
    severity: Severity = Severity.FAIL
    skipped: bool = False  # True if check was explicitly skipped via --skip-chain
    intermediates_fetched_via_aia: bool = False  # True if intermediates were fetched via AIA
    intermediates_fetched_count: int = 0  # Number of intermediates fetched via AIA
    cross_signed_certs: List[CrossSignedCertificate] = field(default_factory=list)  # Cross-signed certificates detected


@dataclass
class HostnameCheckResult:
    """Result of hostname matching."""

    matches: bool
    expected_hostname: str
    matched_san_dns: Optional[str] = None
    matched_cn: Optional[str] = None
    severity: Severity = Severity.FAIL
    skipped: bool = False  # True if check was explicitly skipped via --skip-hostname


@dataclass
class ValidityCheckResult:
    """Result of validity check (NotBefore/NotAfter)."""

    is_valid: bool
    not_before: datetime
    not_after: datetime
    days_until_expiry: int
    is_expired: bool
    severity: Severity = Severity.FAIL


@dataclass
class CertificateFinding:
    """Finding for a certificate (e.g., non-positive serial number)."""

    code: str  # e.g., "CERT_SERIAL_NON_POSITIVE"
    severity: Severity
    message: str
    subject: str
    issuer: str
    fingerprint_sha256: Optional[str] = None
    context: Optional[dict] = None


@dataclass
class ProtocolCheckResult:
    """Result of protocol version check."""

    supported_versions: List[str]  # ["TLSv1.2", "TLSv1.3"]
    best_version: str
    deprecated_versions: List[str]  # ["TLSv1.0", "TLSv1.1"]
    ssl_versions: List[str] = field(default_factory=list)  # ["SSLv2", "SSLv3"] - should be empty
    severity: Severity = Severity.OK


@dataclass
class CipherCheckResult:
    """Result of cipher suite check."""

    supported_ciphers: List[str]
    weak_ciphers: List[str]
    pfs_supported: bool
    server_preferences: bool
    severity: Severity = Severity.OK


@dataclass
class VulnerabilityCheckResult:
    """Result of a cryptographic vulnerability check."""

    vulnerability_name: str  # "Heartbleed", "POODLE", etc.
    cve_id: Optional[str]
    vulnerable: bool
    severity: Severity
    description: str
    recommendation: Optional[str] = None


@dataclass
class SecurityCheckResult:
    """Result of security best practices check."""

    hsts_enabled: bool = False
    hsts_max_age: Optional[int] = None
    ocsp_stapling_enabled: bool = False
    tls_compression_enabled: bool = False
    session_resumption_enabled: bool = False
    severity: Severity = Severity.OK


class Rating(str, Enum):
    """SSL/TLS security rating."""

    A_PLUS_PLUS = "A++"
    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"


@dataclass
class CheckResult:
    """Overall result of all checks."""

    target_host: str
    target_port: int
    timestamp: datetime
    chain_check: ChainCheckResult
    hostname_check: HostnameCheckResult
    validity_check: ValidityCheckResult
    crl_checks: List[CRLCheckResult]
    ocsp_checks: List[OSPCheckResult]
    certificate_findings: List[CertificateFinding] = field(default_factory=list)
    protocol_check: Optional[ProtocolCheckResult] = None
    cipher_check: Optional[CipherCheckResult] = None
    vulnerability_checks: List[VulnerabilityCheckResult] = field(default_factory=list)
    security_check: Optional[SecurityCheckResult] = None
    service_type: Optional[str] = None  # "HTTPS", "SMTP", "IMAP", etc.
    overall_severity: Severity = Severity.OK
    summary: str = ""
    rating: Optional[Rating] = None  # Security rating (A++ to F)
    rating_reasons: List[str] = field(default_factory=list)  # Reasons for rating downgrade
    only_checks: Optional[List[str]] = None  # List of checks that were explicitly selected (for filtering report)
    target_ip: Optional[str] = None  # IP-Adresse des aufgerufenen Hosts
    insecure_mode: bool = False  # Flag: Explicit insecure mode was enabled (validation skipped)

