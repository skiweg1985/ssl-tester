"""Report generation (text and JSON)."""

import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import asdict

from ssl_tester.models import CheckResult, Severity, Rating

logger = logging.getLogger(__name__)

# Global flag for colored output
_use_color = True


def set_color_output(enabled: bool) -> None:
    """Enable or disable colored output."""
    global _use_color
    _use_color = enabled


def generate_text_report(result: CheckResult, severity_filter: Optional[Severity] = None) -> str:
    """
    Generate human-readable text report.

    Args:
        result: CheckResult to report
        severity_filter: Optional severity filter (only show checks with this severity or worse)

    Returns:
        Formatted text report
    """
    # Check if it's a connection error (certificate could not be retrieved)
    is_connection_error = (
        result.chain_check.leaf_cert.subject == "<unable to retrieve>" and
        result.chain_check.error is not None
    )
    
    # Check if it's a DNS or connection error
    connection_error_indicators = [
        "DNS resolution failed",
        "Connection error",
        "Connection timeout",
        "Could not resolve",
    ]
    is_dns_or_connection_error = (
        result.chain_check.error and
        any(indicator in result.chain_check.error for indicator in connection_error_indicators)
    )
    
    lines = []
    lines.append("=" * 70)
    lines.append("SSL/TLS Certificate Check Report")
    lines.append("=" * 70)
    lines.append(f"Target: {result.target_host}:{result.target_port}")
    if result.service_type:
        lines.append(f"Service: {result.service_type}")
    lines.append(f"Timestamp: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")

    # For connection errors: simplified report
    if is_connection_error and is_dns_or_connection_error:
        lines.append("Connection Error:")
        error_msg = result.chain_check.error
        if "SSL" in error_msg or "TLS" in error_msg or "certificate verify failed" in error_msg:
            error_msg = _simplify_ssl_error(error_msg)
        lines.append(f"  {error_msg}")
        lines.append("")
        lines.append("Note: Certificate checks could not be performed due to connection failure.")
        lines.append("")
    else:
        # Determine which sections to show based on only_checks
        only_checks_set = set(result.only_checks) if result.only_checks else None
        
        # Full report when certificate could be retrieved
        # Chain Check (always shown if not skipped, or if in only_checks)
        if only_checks_set is None or "chain" in only_checks_set:
            lines.append("Certificate Chain:")
        if result.chain_check.skipped:
            lines.append(f"  Status: SKIPPED (--skip-chain)")
        else:
            lines.append(f"  Status: {_format_severity(result.chain_check.severity)}")
        lines.append(f"  Leaf Subject: {result.chain_check.leaf_cert.subject}")
        lines.append(f"  Leaf Issuer: {result.chain_check.leaf_cert.issuer}")
        lines.append(f"  Leaf Serial Number: {result.chain_check.leaf_cert.serial_number}")
        lines.append(f"  Chain Valid: {result.chain_check.chain_valid}")
        lines.append(f"  Trust Store Valid: {result.chain_check.trust_store_valid}")
        lines.append(f"  Intermediates: {len(result.chain_check.intermediate_certs)}")
        for i, intermediate in enumerate(result.chain_check.intermediate_certs, 1):
            lines.append(f"    Intermediate {i}: {intermediate.subject}")
            lines.append(f"      Serial Number: {intermediate.serial_number}")
        if result.chain_check.root_cert:
            lines.append(f"  Root: {result.chain_check.root_cert.subject}")
            lines.append(f"    Serial Number: {result.chain_check.root_cert.serial_number}")
        
        # Cross-Signed Certificates Section
        if result.chain_check.cross_signed_certs:
            lines.append("")
            lines.append("Cross-Signed Certificates:")
            for cross_signed in result.chain_check.cross_signed_certs:
                chain_cert = cross_signed.chain_cert
                trust_root = cross_signed.trust_store_root
                actual_signer = cross_signed.actual_signer
                
                lines.append(f"  Certificate: {chain_cert.subject}")
                lines.append(f"    Chain Serial: {chain_cert.serial_number}")
                lines.append(f"    Trust Store Root Serial: {trust_root.serial_number}")
                lines.append(f"    Actually Signed By: {actual_signer}")
                lines.append(f"    Status: INFO ℹ️")
                lines.append(f"    Note: Cross-signed certificate replaced by trust store root (browser behavior)")
                lines.append(f"    Explanation: The certificate chain contains a cross-signed version of '{chain_cert.subject}'")
                lines.append(f"                 that was signed by '{actual_signer}'. This has been replaced by the")
                lines.append(f"                 self-signed '{trust_root.subject}' from the trust store, which is the")
                lines.append(f"                 standard browser behavior for handling cross-signed certificates.")
        
        if result.chain_check.missing_intermediates:
            lines.append(f"  Missing Intermediates: {', '.join(result.chain_check.missing_intermediates)}")
        if result.chain_check.error:
            # Simplify SSL error messages for better readability
            error_msg = result.chain_check.error
            if "SSL" in error_msg or "TLS" in error_msg or "certificate verify failed" in error_msg:
                error_msg = _simplify_ssl_error(error_msg)
            lines.append(f"  Error: {error_msg}")
        lines.append("")

        # Hostname Check (only if in only_checks or not using only_checks)
        if only_checks_set is None or "hostname" in only_checks_set:
            lines.append("Hostname Matching:")
        if result.hostname_check.skipped:
            lines.append(f"  Status: SKIPPED (--skip-hostname)")
        else:
            lines.append(f"  Status: {_format_severity(result.hostname_check.severity)}")
        lines.append(f"  Expected: {result.hostname_check.expected_hostname}")
        if result.hostname_check.skipped:
            lines.append(f"  Matches: N/A (check skipped)")
        else:
            lines.append(f"  Matches: {result.hostname_check.matches}")
        if result.hostname_check.matched_san_dns:
            lines.append(f"  Matched SAN DNS: {result.hostname_check.matched_san_dns}")
        elif result.hostname_check.matched_cn:
            lines.append(f"  Matched CN: {result.hostname_check.matched_cn} (deprecated)")
        lines.append("")

        # Validity Check (always shown if chain is shown, as it's part of chain validation)
        if only_checks_set is None or "chain" in only_checks_set:
            lines.append("Certificate Validity:")
        lines.append(f"  Status: {_format_severity(result.validity_check.severity)}")
        lines.append(f"  Valid: {result.validity_check.is_valid}")
        lines.append(f"  Not Before: {result.validity_check.not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"  Not After: {result.validity_check.not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"  Days Until Expiry: {result.validity_check.days_until_expiry}")
        if result.validity_check.is_expired:
            lines.append("  ⚠️  CERTIFICATE EXPIRED")
        lines.append("")

        # CRL Checks (only if in only_checks or not using only_checks)
        if only_checks_set is None or "crl" in only_checks_set:
            lines.append("CRL Distribution Points:")
            
            # Group CRL checks by certificate type and show for each certificate
            leaf_crl_checks = [c for c in result.crl_checks if c.certificate_type == "Leaf"]
            intermediate_crl_checks = [c for c in result.crl_checks if c.certificate_type == "Intermediate"]
            root_crl_checks = [c for c in result.crl_checks if c.certificate_type == "Root"]
            unknown_crl_checks = [c for c in result.crl_checks if not c.certificate_type]
            
            # Leaf certificate
            if result.chain_check.leaf_cert:
                lines.append("  Leaf Certificate:")
                if leaf_crl_checks:
                    for crl_check in leaf_crl_checks:
                        lines.append(f"    URL: {crl_check.url}")
                        lines.append(f"      Status: {_format_severity(crl_check.severity)}")
                        lines.append(f"      Reachable: {crl_check.reachable}")
                        if crl_check.status_code:
                            lines.append(f"      HTTP Status: {crl_check.status_code}")
                        if crl_check.content_type:
                            lines.append(f"      Content-Type: {crl_check.content_type}")
                        if crl_check.size_bytes:
                            # Format size nicely
                            if crl_check.size_bytes < 1024:
                                size_str = f"{crl_check.size_bytes} bytes"
                            elif crl_check.size_bytes < 1024 * 1024:
                                size_str = f"{crl_check.size_bytes / 1024:.2f} KB"
                            else:
                                size_str = f"{crl_check.size_bytes / (1024 * 1024):.2f} MB"
                            lines.append(f"      Size: {size_str} ({crl_check.size_bytes} bytes)")
                        if crl_check.redirect_chain and len(crl_check.redirect_chain) > 1:
                            lines.append(f"      Redirects ({len(crl_check.redirect_chain)}): {' -> '.join(crl_check.redirect_chain)}")
                        if crl_check.error:
                            lines.append(f"      Error: {crl_check.error}")
                else:
                    lines.append("    No CRL Distribution Points found")
            
            # Intermediate certificates
            if result.chain_check.intermediate_certs:
                for idx, intermediate in enumerate(result.chain_check.intermediate_certs, 1):
                    lines.append(f"  Intermediate Certificate {idx}:")
                    intermediate_crls = [c for c in intermediate_crl_checks if c.certificate_subject == intermediate.subject]
                    if intermediate_crls:
                        for crl_check in intermediate_crls:
                            lines.append(f"    URL: {crl_check.url}")
                            lines.append(f"      Status: {_format_severity(crl_check.severity)}")
                            lines.append(f"      Reachable: {crl_check.reachable}")
                            if crl_check.status_code:
                                lines.append(f"      HTTP Status: {crl_check.status_code}")
                            if crl_check.content_type:
                                lines.append(f"      Content-Type: {crl_check.content_type}")
                            if crl_check.size_bytes:
                                # Format size nicely
                                if crl_check.size_bytes < 1024:
                                    size_str = f"{crl_check.size_bytes} bytes"
                                elif crl_check.size_bytes < 1024 * 1024:
                                    size_str = f"{crl_check.size_bytes / 1024:.2f} KB"
                                else:
                                    size_str = f"{crl_check.size_bytes / (1024 * 1024):.2f} MB"
                                lines.append(f"      Size: {size_str} ({crl_check.size_bytes} bytes)")
                            if crl_check.redirect_chain and len(crl_check.redirect_chain) > 1:
                                lines.append(f"      Redirects ({len(crl_check.redirect_chain)}): {' -> '.join(crl_check.redirect_chain)}")
                            if crl_check.error:
                                lines.append(f"      Error: {crl_check.error}")
                    else:
                        lines.append("    No CRL Distribution Points found")
            
            # Root certificate (only show if CRL URLs are present)
            if result.chain_check.root_cert and root_crl_checks:
                lines.append("  Root Certificate:")
                for crl_check in root_crl_checks:
                    lines.append(f"    URL: {crl_check.url}")
                    lines.append(f"      Status: {_format_severity(crl_check.severity)}")
                    lines.append(f"      Reachable: {crl_check.reachable}")
                    if crl_check.status_code:
                        lines.append(f"      HTTP Status: {crl_check.status_code}")
                    if crl_check.content_type:
                        lines.append(f"      Content-Type: {crl_check.content_type}")
                    if crl_check.size_bytes:
                        # Format size nicely
                        if crl_check.size_bytes < 1024:
                            size_str = f"{crl_check.size_bytes} bytes"
                        elif crl_check.size_bytes < 1024 * 1024:
                            size_str = f"{crl_check.size_bytes / 1024:.2f} KB"
                        else:
                            size_str = f"{crl_check.size_bytes / (1024 * 1024):.2f} MB"
                        lines.append(f"      Size: {size_str} ({crl_check.size_bytes} bytes)")
                    if crl_check.redirect_chain and len(crl_check.redirect_chain) > 1:
                        lines.append(f"      Redirects ({len(crl_check.redirect_chain)}): {' -> '.join(crl_check.redirect_chain)}")
                    if crl_check.error:
                        lines.append(f"      Error: {crl_check.error}")
            
            # Unknown certificates (fallback for backwards compatibility)
            if unknown_crl_checks:
                for crl_check in unknown_crl_checks:
                    lines.append(f"  URL: {crl_check.url}")
                    lines.append(f"    Status: {_format_severity(crl_check.severity)}")
                    lines.append(f"    Reachable: {crl_check.reachable}")
                    if crl_check.status_code:
                        lines.append(f"    HTTP Status: {crl_check.status_code}")
                    if crl_check.content_type:
                        lines.append(f"    Content-Type: {crl_check.content_type}")
                    if crl_check.size_bytes:
                        # Format size nicely
                        if crl_check.size_bytes < 1024:
                            size_str = f"{crl_check.size_bytes} bytes"
                        elif crl_check.size_bytes < 1024 * 1024:
                            size_str = f"{crl_check.size_bytes / 1024:.2f} KB"
                        else:
                            size_str = f"{crl_check.size_bytes / (1024 * 1024):.2f} MB"
                        lines.append(f"    Size: {size_str} ({crl_check.size_bytes} bytes)")
                    if crl_check.redirect_chain and len(crl_check.redirect_chain) > 1:
                        lines.append(f"    Redirects ({len(crl_check.redirect_chain)}): {' -> '.join(crl_check.redirect_chain)}")
                    if crl_check.error:
                        lines.append(f"    Error: {crl_check.error}")
            
            # If no CRL checks at all
            if not result.crl_checks:
                lines.append("  No CRL Distribution Points found in any certificate")
            
            lines.append("")

        # OCSP Checks (only if in only_checks or not using only_checks)
        if only_checks_set is None or "ocsp" in only_checks_set:
            if result.ocsp_checks:
                lines.append("OCSP Responders:")
                for ocsp_check in result.ocsp_checks:
                    lines.append(f"  URL: {ocsp_check.url}")
                    lines.append(f"    Status: {_format_severity(ocsp_check.severity)}")
                    lines.append(f"    Reachable: {ocsp_check.reachable}")
                    if ocsp_check.status_code:
                        lines.append(f"    HTTP Status: {ocsp_check.status_code}")
                    if ocsp_check.error:
                        lines.append(f"    Error: {ocsp_check.error}")
                lines.append("")
            else:
                lines.append("OCSP Responders: None found")
                lines.append("")

        # Certificate Findings (always shown if chain is shown, as they come from chain validation)
        if (only_checks_set is None or "chain" in only_checks_set) and result.certificate_findings:
            lines.append("Certificate Findings:")
            for finding in result.certificate_findings:
                lines.append(f"  Code: {finding.code}")
                lines.append(f"    Status: {_format_severity(finding.severity)}")
                lines.append(f"    Message: {finding.message}")
                lines.append(f"    Subject: {finding.subject}")
                lines.append(f"    Issuer: {finding.issuer}")
                # Show serial number from context if available
                if finding.context and "serial_number" in finding.context:
                    lines.append(f"    Serial Number: {finding.context['serial_number']}")
                if finding.fingerprint_sha256:
                    lines.append(f"    Fingerprint (SHA256): {finding.fingerprint_sha256}")
            lines.append("")
        elif only_checks_set is None or "chain" in only_checks_set:
            lines.append("Certificate Findings: None")
            lines.append("")

        # Protocol Version Check (only if in only_checks or not using only_checks)
        if only_checks_set is None or "protocol" in only_checks_set:
            if result.protocol_check:
                lines.append("Protocol Versions:")
                lines.append(f"  Status: {_format_severity(result.protocol_check.severity)}")
                lines.append(f"  Supported Versions: {', '.join(result.protocol_check.supported_versions) if result.protocol_check.supported_versions else 'None'}")
                lines.append(f"  Best Version: {result.protocol_check.best_version if result.protocol_check.best_version else 'None'}")
                if result.protocol_check.deprecated_versions:
                    lines.append(f"  Deprecated Versions: {', '.join(result.protocol_check.deprecated_versions)} ⚠")
                if result.protocol_check.ssl_versions:
                    lines.append(f"  SSL Versions (CRITICAL): {', '.join(result.protocol_check.ssl_versions)} ✗")
                lines.append("")
            else:
                lines.append("Protocol Versions: Not checked (--skip-protocol)")
                lines.append("")

        # Cipher Suite Check (only if in only_checks or not using only_checks)
        if only_checks_set is None or "cipher" in only_checks_set:
            if result.cipher_check:
                lines.append("Cipher Suites:")
                lines.append(f"  Status: {_format_severity(result.cipher_check.severity)}")
                lines.append(f"  Supported Ciphers: {len(result.cipher_check.supported_ciphers)}")
                if result.cipher_check.supported_ciphers:
                    # Show first 5 ciphers, then "... and X more" if there are more
                    display_ciphers = result.cipher_check.supported_ciphers[:5]
                    for cipher in display_ciphers:
                        lines.append(f"    - {cipher}")
                    if len(result.cipher_check.supported_ciphers) > 5:
                        lines.append(f"    ... and {len(result.cipher_check.supported_ciphers) - 5} more")
                if result.cipher_check.weak_ciphers:
                    lines.append(f"  Weak Ciphers: {', '.join(result.cipher_check.weak_ciphers)} ⚠")
                lines.append(f"  Perfect Forward Secrecy (PFS): {'Yes ✓' if result.cipher_check.pfs_supported else 'No ⚠'}")
                lines.append(f"  Server Preferences: {'Yes' if result.cipher_check.server_preferences else 'No'}")
                lines.append("")
            else:
                lines.append("Cipher Suites: Not checked (--skip-cipher)")
                lines.append("")

        # Cryptographic Vulnerabilities (only if in only_checks or not using only_checks)
        if only_checks_set is None or "vulnerabilities" in only_checks_set:
            if result.vulnerability_checks:
                lines.append("Cryptographic Vulnerabilities:")
                vulnerable_found = [v for v in result.vulnerability_checks if v.vulnerable]
                if vulnerable_found:
                    lines.append(f"  Status: {_format_severity(Severity.FAIL if any(v.severity == Severity.FAIL for v in vulnerable_found) else Severity.WARN)}")
                    lines.append(f"  Vulnerable: {len(vulnerable_found)} of {len(result.vulnerability_checks)}")
                    for vuln in vulnerable_found:
                        lines.append(f"    {vuln.vulnerability_name} ({vuln.cve_id}): {_format_severity(vuln.severity)}")
                        if vuln.recommendation:
                            lines.append(f"      Recommendation: {vuln.recommendation}")
                else:
                    lines.append(f"  Status: {_format_severity(Severity.OK)}")
                    lines.append(f"  Vulnerable: 0 of {len(result.vulnerability_checks)}")
                
                # Show all vulnerabilities with their status
                lines.append("  Vulnerability Checks:")
                for vuln in result.vulnerability_checks:
                    if vuln.vulnerable:
                        status = "NICHT OK"
                    elif "test skipped" in vuln.description.lower() or "nmap required" in vuln.description.lower():
                        status = "ÜBERSPRUNGEN (nmap fehlt)"
                    elif "test failed" in vuln.description.lower():
                        status = "FEHLER"
                    else:
                        status = "OK"
                    lines.append(f"    {vuln.vulnerability_name}: {status}")
                lines.append("")
            else:
                lines.append("Cryptographic Vulnerabilities: Not checked (--skip-vulnerabilities)")
                lines.append("")

        # Security Best Practices (only if in only_checks or not using only_checks)
        if only_checks_set is None or "security" in only_checks_set:
            if result.security_check:
                lines.append("Security Best Practices:")
                lines.append(f"  Status: {_format_severity(result.security_check.severity)}")
                lines.append(f"  HSTS Enabled: {'Yes ✓' if result.security_check.hsts_enabled else 'No ⚠'}")
                if result.security_check.hsts_max_age:
                    lines.append(f"  HSTS Max-Age: {result.security_check.hsts_max_age} seconds")
                lines.append(f"  OCSP Stapling: {'Yes ✓' if result.security_check.ocsp_stapling_enabled else 'No ⚠'}")
                lines.append(f"  TLS Compression: {'Enabled ✗ (CRIME vulnerability)' if result.security_check.tls_compression_enabled else 'Disabled ✓'}")
                lines.append(f"  Session Resumption: {'Yes ✓' if result.security_check.session_resumption_enabled else 'No'}")
                lines.append("")
            else:
                lines.append("Security Best Practices: Not checked (--skip-security)")
                lines.append("")

    # Summary (only show if all checks were performed, not for partial checks)
    lines.append("=" * 70)
    lines.append("Summary:")
    if result.only_checks:
        # Partial check - no rating, just show what was checked
        lines.append(f"  Partial Check: Only {', '.join(sorted(set(result.only_checks)))} checks performed")
        lines.append(f"  Overall Status: {_format_severity(result.overall_severity)}")
    else:
        # Full check - show rating and summary
        if result.rating:
            lines.append(f"  Security Rating: {result.rating.value}")
            if result.rating_reasons:
                lines.append("  Downgrade Reasons:")
                for reason in result.rating_reasons:
                    lines.append(f"    - {reason}")
        
        # Notes on Security Best Practices (only if not according to recommendations)
        hints = []
        if result.security_check:
            # HSTS: Recommendation = enabled
            if not result.security_check.hsts_enabled:
                hints.append("HSTS not enabled (recommended for better security)")
            
            # OCSP Stapling: Recommendation = enabled
            if not result.security_check.ocsp_stapling_enabled:
                hints.append("OCSP Stapling not enabled (recommended for better performance)")
            
            # TLS Compression: Recommendation = disabled
            if result.security_check.tls_compression_enabled:
                hints.append("TLS Compression enabled (should be disabled - CRIME vulnerability)")
            
            # Session Resumption: Recommendation = enabled
            if not result.security_check.session_resumption_enabled:
                hints.append("Session Resumption not enabled (recommended for better performance)")
        
        # Note about AIA fetching (informational)
        if result.chain_check.intermediates_fetched_via_aia:
            count = result.chain_check.intermediates_fetched_count
            if result.service_type and result.service_type in ["SMTP", "IMAP", "POP3"]:
                hints.append(
                    f"{count} intermediate certificate(s) were fetched via AIA because the server did not send a complete certificate chain "
                    f"(common for {result.service_type} STARTTLS connections)"
                )
            else:
                hints.append(
                    f"{count} intermediate certificate(s) were fetched via AIA because the server did not send a complete certificate chain "
                    f"(handled automatically via AIA)"
                )
        
        if hints:
            lines.append("  Notes:")
            for hint in hints:
                lines.append(f"    - {hint}")
        
        lines.append(f"  Overall Status: {_format_severity(result.overall_severity)}")
        if result.summary:
            lines.append(f"  {result.summary}")
    lines.append("=" * 70)

    return "\n".join(lines)


def _format_severity(severity: Severity) -> str:
    """Format severity with visual indicator."""
    if _use_color:
        try:
            from rich.console import Console
            from io import StringIO
            output = StringIO()
            console = Console(file=output, force_terminal=True, width=1000)
            if severity == Severity.OK:
                console.print(f"[green]{severity.value} ✓[/green]", end="")
            elif severity == Severity.WARN:
                console.print(f"[yellow]{severity.value} ⚠[/yellow]", end="")
            else:
                console.print(f"[red]{severity.value} ✗[/red]", end="")
            return output.getvalue().strip()
        except (ImportError, Exception):
            pass
    
    # Fallback without color
    if severity == Severity.OK:
        return f"{severity.value} ✓"
    elif severity == Severity.WARN:
        return f"{severity.value} ⚠"
    else:
        return f"{severity.value} ✗"


def generate_json_report(result: CheckResult) -> str:
    """
    Generate JSON report.

    Args:
        result: CheckResult to report

    Returns:
        JSON string
    """
    # Convert to dict, handling datetime serialization
    def serialize_datetime(obj: Any) -> str:
        if isinstance(obj, datetime):
            return obj.isoformat() + "Z"
        elif isinstance(obj, Severity):
            return obj.value
        elif isinstance(obj, Rating):
            return obj.value
        raise TypeError(f"Type {type(obj)} not serializable")

    data = asdict(result)
    return json.dumps(data, indent=2, default=serialize_datetime)


def calculate_rating(result: CheckResult) -> tuple[Rating, list[str]]:
    """
    Calculate SSL/TLS security rating (A++ to F) based on all checks.
    
    Args:
        result: CheckResult
        
    Returns:
        Tuple of (Rating (A++ to F), List of downgrade reasons)
    """
    reasons: list[str] = []
    
    # Connection error or no certificate = F
    if result.chain_check.leaf_cert.subject == "<unable to retrieve>":
        reasons.append("Unable to connect to server or certificate could not be retrieved")
        return Rating.F, reasons
    
    # Check for SSL protocols (SSLv2, SSLv3) - automatic F
    if result.protocol_check and result.protocol_check.ssl_versions:
        ssl_versions_str = ", ".join(result.protocol_check.ssl_versions)
        reasons.append(f"Deprecated SSL protocols are supported: {ssl_versions_str}")
        return Rating.F, reasons
    
    # Check for critical vulnerabilities
    critical_vulns = [
        v for v in result.vulnerability_checks 
        if v.vulnerable and v.severity == Severity.FAIL
    ]
    if critical_vulns:
        vuln_names = [v.vulnerability_name for v in critical_vulns]
        reasons.append(f"Critical security vulnerabilities found: {', '.join(vuln_names)}")
        return Rating.E, reasons
    
    # Check for TLS compression (CRIME) - automatic E
    if result.security_check and result.security_check.tls_compression_enabled:
        reasons.append("TLS compression is enabled (CRIME attack possible)")
        return Rating.E, reasons
    
    # Check protocol versions
    has_tls13 = False
    has_tls12 = False
    has_tls11 = False
    has_tls10 = False
    has_deprecated = False
    
    if result.protocol_check:
        if "TLSv1.3" in result.protocol_check.supported_versions:
            has_tls13 = True
        if "TLSv1.2" in result.protocol_check.supported_versions:
            has_tls12 = True
        if "TLSv1.1" in result.protocol_check.supported_versions:
            has_tls11 = True
            has_deprecated = True
        if "TLSv1.0" in result.protocol_check.supported_versions:
            has_tls10 = True
            has_deprecated = True
    
    # Check cipher suites
    has_weak_ciphers = False
    has_pfs = False
    only_weak_ciphers = False
    
    if result.cipher_check:
        has_pfs = result.cipher_check.pfs_supported
        if result.cipher_check.weak_ciphers:
            has_weak_ciphers = True
            if len(result.cipher_check.weak_ciphers) == len(result.cipher_check.supported_ciphers):
                only_weak_ciphers = True
    
    # Check security best practices
    has_hsts = False
    has_ocsp_stapling = False
    hsts_ok = False
    
    if result.security_check:
        has_hsts = result.security_check.hsts_enabled
        has_ocsp_stapling = result.security_check.ocsp_stapling_enabled
        if has_hsts and result.security_check.hsts_max_age and result.security_check.hsts_max_age >= 31536000:
            hsts_ok = True
    
    # Check certificate issues
    has_cert_failures = result.chain_check.severity == Severity.FAIL or \
                       result.hostname_check.severity == Severity.FAIL or \
                       result.validity_check.severity == Severity.FAIL
    
    # Check for certificate findings
    has_critical_findings = any(f.severity == Severity.FAIL for f in result.certificate_findings)
    
    # Rating logic
    
    # F: SSL protocols, critical vulns, or connection errors (already handled above)
    
    # E: Only TLS 1.0 or older, or only weak ciphers, or critical certificate issues
    if has_tls10 and not has_tls12 and not has_tls13:
        reasons.append("Only TLS 1.0 or older protocols are supported")
        return Rating.E, reasons
    if only_weak_ciphers:
        reasons.append("Only weak encryption algorithms are supported")
        return Rating.E, reasons
    if has_cert_failures or has_critical_findings:
        cert_issues = []
        if result.chain_check.severity == Severity.FAIL:
            cert_issues.append("Certificate chain invalid")
        if result.hostname_check.severity == Severity.FAIL:
            cert_issues.append("Hostname does not match")
        if result.validity_check.severity == Severity.FAIL:
            cert_issues.append("Certificate expired or not yet valid")
        if has_critical_findings:
            cert_issues.append("Critical certificate issues found")
        reasons.append(f"Critical certificate issues: {', '.join(cert_issues)}")
        return Rating.E, reasons
    
    # D: TLS 1.1 or TLS 1.0 with weak ciphers, no PFS
    if has_tls11 or has_tls10:
        if has_weak_ciphers or not has_pfs:
            if has_tls11:
                reasons.append("TLS 1.1 is supported (deprecated)")
            if has_tls10:
                reasons.append("TLS 1.0 is supported (deprecated)")
            if has_weak_ciphers:
                reasons.append("Weak encryption algorithms are supported")
            if not has_pfs:
                reasons.append("Perfect Forward Secrecy (PFS) is not supported")
            return Rating.D, reasons
        if has_tls11:
            reasons.append("TLS 1.1 is supported (deprecated)")
        if has_tls10:
            reasons.append("TLS 1.0 is supported (deprecated)")
        return Rating.C, reasons
    
    # C: TLS 1.2 only, with issues
    if has_tls12 and not has_tls13:
        if has_weak_ciphers:
            reasons.append("TLS 1.3 is not supported")
            reasons.append("Weak encryption algorithms are supported")
            return Rating.C, reasons
        if not has_pfs:
            reasons.append("TLS 1.3 is not supported")
            reasons.append("Perfect Forward Secrecy (PFS) is not supported")
            return Rating.C, reasons
        # TLS 1.2 only, but everything else is OK
        reasons.append("TLS 1.3 is not supported")
        return Rating.B, reasons
    
    # B: TLS 1.2+ with some issues
    if has_tls12 and not has_tls13:
        if not has_pfs:
            reasons.append("Perfect Forward Secrecy (PFS) is not supported")
            return Rating.B, reasons
        if has_weak_ciphers:
            reasons.append("Weak encryption algorithms are supported")
            return Rating.B, reasons
        # TLS 1.2 with good config, but no TLS 1.3
        reasons.append("TLS 1.3 is not supported")
        return Rating.A, reasons
    
    # A: TLS 1.3 supported, but with some issues
    if has_tls13:
        if not has_pfs:
            reasons.append("Perfect Forward Secrecy (PFS) is not supported")
            return Rating.A, reasons
        if has_weak_ciphers:
            reasons.append("Weak encryption algorithms are supported")
            return Rating.A, reasons
        # TLS 1.3 with PFS and no weak ciphers - continue to A+/A++ logic below
        # Note: HSTS and OCSP Stapling are informational only and do not affect rating
    
    # A+/A++: TLS 1.3, PFS, no weak ciphers
    if has_tls13 and has_pfs and not has_weak_ciphers:
        # Check for any warnings
        has_warnings = (
            result.chain_check.severity == Severity.WARN or
            result.hostname_check.severity == Severity.WARN or
            result.validity_check.severity == Severity.WARN or
            any(crl.severity == Severity.WARN for crl in result.crl_checks) or
            any(ocsp.severity == Severity.WARN for ocsp in result.ocsp_checks) or
            any(f.severity == Severity.WARN for f in result.certificate_findings) or
            (result.protocol_check and result.protocol_check.severity == Severity.WARN) or
            (result.cipher_check and result.cipher_check.severity == Severity.WARN) or
            (result.security_check and result.security_check.severity == Severity.WARN)
        )
        if has_warnings:
            warning_details = []
            if result.chain_check.severity == Severity.WARN:
                warning_details.append("Certificate chain warnings")
            if result.hostname_check.severity == Severity.WARN:
                warning_details.append("Hostname warnings")
            if result.validity_check.severity == Severity.WARN:
                warning_details.append("Validity check warnings")
            if any(crl.severity == Severity.WARN for crl in result.crl_checks):
                warning_details.append("CRL warnings")
            if any(ocsp.severity == Severity.WARN for ocsp in result.ocsp_checks):
                warning_details.append("OCSP warnings")
            if any(f.severity == Severity.WARN for f in result.certificate_findings):
                warning_details.append("Certificate warnings")
            if result.protocol_check and result.protocol_check.severity == Severity.WARN:
                warning_details.append("Protocol warnings")
            if result.cipher_check and result.cipher_check.severity == Severity.WARN:
                warning_details.append("Cipher warnings")
            if result.security_check and result.security_check.severity == Severity.WARN:
                warning_details.append("Security warnings")
            if warning_details:
                reasons.append(f"Warnings present: {', '.join(warning_details)}")
            return Rating.A_PLUS, reasons
        # Perfect configuration
        return Rating.A_PLUS_PLUS, reasons
    
    # Default fallback
    if has_tls12 and not has_tls13:
        reasons.append("Only TLS 1.2 or older protocols are supported")
        return Rating.B, reasons
    reasons.append("Unknown protocol configuration")
    return Rating.C, reasons


def calculate_overall_severity(result: CheckResult) -> Severity:
    """
    Calculate overall severity from all checks.

    Args:
        result: CheckResult

    Returns:
        Overall Severity (FAIL > WARN > OK)
    """
    severities = [
        result.chain_check.severity,
        result.hostname_check.severity,
        result.validity_check.severity,
    ]

    for crl_check in result.crl_checks:
        severities.append(crl_check.severity)

    for ocsp_check in result.ocsp_checks:
        severities.append(ocsp_check.severity)

    for finding in result.certificate_findings:
        severities.append(finding.severity)

    if result.protocol_check:
        severities.append(result.protocol_check.severity)

    if result.cipher_check:
        severities.append(result.cipher_check.severity)

    for vuln in result.vulnerability_checks:
        severities.append(vuln.severity)

    if result.security_check:
        severities.append(result.security_check.severity)

    if Severity.FAIL in severities:
        return Severity.FAIL
    elif Severity.WARN in severities:
        return Severity.WARN
    else:
        return Severity.OK


def _simplify_ssl_error(error_msg: str) -> str:
    """
    Simplify SSL error messages by extracting the core error.
    
    Args:
        error_msg: Original error message (may be nested)
    
    Returns:
        Simplified error message
    """
    import re
    
    # Extract common SSL error patterns
    patterns = [
        r"IP address mismatch[^']*'([^']+)'",
        r"certificate is not valid for '([^']+)'",
        r"hostname '([^']+)' doesn't match",
        r"certificate verify failed: ([^,]+)",
    ]
    
    for pattern in patterns:
        match = re.search(pattern, error_msg, re.IGNORECASE)
        if match:
            if len(match.groups()) > 0:
                # Extract the specific error
                if "IP address mismatch" in error_msg:
                    return f"IP address mismatch: certificate is not valid for '{match.group(1)}'"
                elif "hostname" in error_msg.lower():
                    return f"Hostname mismatch: certificate is not valid for '{match.group(1)}'"
                else:
                    return match.group(1).strip()
    
    # If no pattern matches, try to extract the last meaningful part
    # Remove nested parentheses and quotes
    simplified = error_msg
    # Remove outer parentheses if they wrap the entire message
    if simplified.startswith("(") and simplified.endswith(")"):
        simplified = simplified[1:-1]
    # Remove "TLS handshake failed:" prefix
    simplified = re.sub(r"^TLS handshake failed:\s*", "", simplified, flags=re.IGNORECASE)
    # Remove "SSL/TLS error:" prefix
    simplified = re.sub(r"^SSL/TLS error:\s*", "", simplified, flags=re.IGNORECASE)
    # Extract the core error message (usually after the last colon)
    if ":" in simplified:
        parts = simplified.split(":")
        if len(parts) > 1:
            # Take the last meaningful part
            simplified = parts[-1].strip()
            # Remove file references like "(_ssl.c:1006)"
            simplified = re.sub(r"\s*\([^)]*\)\s*$", "", simplified)
    
    return simplified.strip() or error_msg


def generate_summary(result: CheckResult) -> str:
    """
    Generate summary text for the check result.

    Args:
        result: CheckResult

    Returns:
        Summary string
    """
    issues = []

    if result.chain_check.skipped:
        issues.append("Chain validation skipped (--skip-chain)")
    elif result.chain_check.severity == Severity.FAIL:
        # Provide specific error message if available
        if result.chain_check.error:
            # Simplify SSL error messages for better readability
            error_msg = result.chain_check.error
            if "SSL" in error_msg or "TLS" in error_msg or "certificate verify failed" in error_msg:
                simplified_error = _simplify_ssl_error(error_msg)
                issues.append(f"Certificate chain validation failed: {simplified_error}")
            else:
                issues.append(f"Certificate chain validation failed: {error_msg}")
        else:
            issues.append("Certificate chain validation failed")
    elif result.chain_check.severity == Severity.WARN:
        # Provide specific warning message
        if not result.chain_check.chain_valid:
            if result.chain_check.error:
                issues.append(f"Certificate chain issue: {result.chain_check.error}")
            else:
                issues.append("Certificate chain structure invalid")
        elif not result.chain_check.trust_store_valid:
            root_ca_name = result.chain_check.root_cert.subject if result.chain_check.root_cert else "Root CA"
            issues.append(f"Root CA '{root_ca_name}' not found in system trust store (certifi bundle)")
        elif result.chain_check.missing_intermediates:
            issues.append(f"Missing intermediate certificate(s): {', '.join(result.chain_check.missing_intermediates)}")
        else:
            issues.append("Certificate chain has warnings")

    if result.hostname_check.skipped:
        issues.append("Hostname check skipped (--skip-hostname)")
    elif result.hostname_check.severity == Severity.FAIL:
        issues.append("Hostname does not match certificate")
    elif result.hostname_check.severity == Severity.WARN:
        issues.append("Hostname matching has warnings")

    # Only show validity issues when the certificate is actually expired
    # or not yet valid (not for connection errors, where is_expired=False)
    if result.validity_check.severity == Severity.FAIL:
        # For connection errors, is_expired=False, so don't show validity message
        if result.validity_check.is_expired:
            issues.append("Certificate is expired")
        elif not result.validity_check.is_expired and result.chain_check.error:
            # Check if it's a connection error (e.g., DNS error)
            # In this case, the error is already shown in the chain check summary
            # and we should not show an additional validity message
            connection_error_indicators = [
                "DNS resolution failed",
                "Connection error",
                "Connection timeout",
                "Could not resolve",
            ]
            if any(indicator in result.chain_check.error for indicator in connection_error_indicators):
                # Connection error - don't show validity message
                pass
            else:
                # Certificate is not yet valid (not a connection error)
                issues.append("Certificate is not yet valid")
        else:
            # Certificate is not yet valid
            issues.append("Certificate is not yet valid")
    elif result.validity_check.severity == Severity.WARN:
        issues.append(f"Certificate expires in {result.validity_check.days_until_expiry} days")

    # CRL: Check all WARNs and FAILs, include root cause (error message) for each CRL issue
    # RULE: All CRL problems must show root cause in summary
    failed_crls = [crl for crl in result.crl_checks if crl.severity in [Severity.WARN, Severity.FAIL]]
    if failed_crls:
        unreachable_crls = [crl for crl in failed_crls if not crl.reachable]
        reachable_crls_with_issues = [crl for crl in failed_crls if crl.reachable]
        
        if unreachable_crls:
            # Include root cause for unreachable CRLs
            for crl in unreachable_crls:
                if crl.error:
                    issues.append(f"CRL not reachable ({crl.url}): {crl.error}")
                else:
                    issues.append(f"CRL not reachable: {crl.url}")
        
        # Add reachable CRLs with issues (signature validation, issuer mismatch, revocation, etc.)
        for crl in reachable_crls_with_issues:
            if crl.error:
                # Include root cause in summary - this is the key information
                issues.append(f"CRL issue ({crl.url}): {crl.error}")
            else:
                # Fallback if no specific error message - should not happen but handle gracefully
                if crl.severity == Severity.FAIL:
                    issues.append(f"CRL validation failed: {crl.url}")
                else:
                    issues.append(f"CRL validation issue: {crl.url}")

    # OCSP: Check severity, not just reachable status
    # RULE: All OCSP problems must show root cause in summary
    failed_ocsps = [
        ocsp
        for ocsp in result.ocsp_checks
        if ocsp.severity == Severity.WARN
        or (ocsp.reachable and ocsp.status_code in [404, 405, 400])
    ]
    if failed_ocsps:
        unreachable_ocsps = [ocsp for ocsp in failed_ocsps if not ocsp.reachable]
        reachable_ocsps_with_issues = [ocsp for ocsp in failed_ocsps if ocsp.reachable]
        
        if unreachable_ocsps:
            # Include root cause for unreachable OCSP responders
            for ocsp in unreachable_ocsps:
                if ocsp.error:
                    issues.append(f"OCSP responder not reachable ({ocsp.url}): {ocsp.error}")
                else:
                    issues.append(f"OCSP responder not reachable: {ocsp.url}")
        
        # Add reachable OCSP responders with issues
        for ocsp in reachable_ocsps_with_issues:
            if ocsp.error:
                # Include root cause in summary
                issues.append(f"OCSP responder issue ({ocsp.url}): {ocsp.error}")
            elif ocsp.status_code:
                # Include HTTP status code as root cause
                issues.append(f"OCSP responder issue ({ocsp.url}): HTTP {ocsp.status_code}")
            else:
                # Fallback if no specific error message
                issues.append(f"OCSP responder issue: {ocsp.url}")

    # Certificate Findings
    for finding in result.certificate_findings:
        if finding.severity == Severity.FAIL:
            issues.append(f"Certificate finding ({finding.code}): {finding.message} (Subject: {finding.subject})")
        elif finding.severity == Severity.WARN:
            issues.append(f"Certificate finding ({finding.code}): {finding.message} (Subject: {finding.subject})")

    # Protocol Version Check
    if result.protocol_check:
        if result.protocol_check.severity == Severity.FAIL:
            if result.protocol_check.ssl_versions:
                issues.append(f"SSL protocols supported (CRITICAL): {', '.join(result.protocol_check.ssl_versions)}")
            elif result.protocol_check.deprecated_versions:
                issues.append(f"Only deprecated TLS versions supported: {', '.join(result.protocol_check.deprecated_versions)}")
            else:
                issues.append("No supported protocol versions found")
        elif result.protocol_check.severity == Severity.WARN:
            if result.protocol_check.deprecated_versions:
                issues.append(f"Deprecated TLS versions supported: {', '.join(result.protocol_check.deprecated_versions)}")

    # Cipher Suite Check
    if result.cipher_check:
        if result.cipher_check.severity == Severity.FAIL:
            if result.cipher_check.weak_ciphers and len(result.cipher_check.weak_ciphers) == len(result.cipher_check.supported_ciphers):
                issues.append(f"Only weak ciphers supported: {', '.join(result.cipher_check.weak_ciphers)}")
            else:
                issues.append("Cipher suite configuration has critical issues")
        elif result.cipher_check.severity == Severity.WARN:
            if result.cipher_check.weak_ciphers:
                issues.append(f"Weak ciphers supported: {', '.join(result.cipher_check.weak_ciphers)}")
            if not result.cipher_check.pfs_supported:
                issues.append("Perfect Forward Secrecy (PFS) not supported")

    # Cryptographic Vulnerabilities
    # Show all vulnerabilities with their status (OK/NICHT OK)
    if result.vulnerability_checks:
        vulnerable_found = [v for v in result.vulnerability_checks if v.vulnerable]
        if vulnerable_found:
            for vuln in vulnerable_found:
                if vuln.severity == Severity.FAIL:
                    issues.append(f"CRITICAL: {vuln.vulnerability_name} ({vuln.cve_id}) - {vuln.description}")
                elif vuln.severity == Severity.WARN:
                    issues.append(f"WARNING: {vuln.vulnerability_name} ({vuln.cve_id}) - {vuln.description}")
        
        # Add summary of all vulnerability checks with status
        vuln_statuses = []
        for vuln in result.vulnerability_checks:
            if vuln.vulnerable:
                status = "NICHT OK"
            elif "test skipped" in vuln.description.lower() or "nmap required" in vuln.description.lower():
                status = "ÜBERSPRUNGEN (nmap fehlt)"
            elif "test failed" in vuln.description.lower():
                status = "FEHLER"
            else:
                status = "OK"
            vuln_statuses.append(f"{vuln.vulnerability_name}: {status}")
        
        # Always show vulnerability check summary
        issues.append(f"Vulnerability Checks: {'; '.join(vuln_statuses)}")

    # Security Best Practices
    if result.security_check:
        if result.security_check.severity == Severity.FAIL:
            if result.security_check.tls_compression_enabled:
                issues.append("CRITICAL: TLS compression enabled (CRIME vulnerability)")
        # HSTS and OCSP Stapling are informational only - don't add to issues
        # They are best practices but not critical for SSL/TLS security

    # Note: Intermediate certificates fetched via AIA (informational, not an issue)
    notes = []
    if result.chain_check.intermediates_fetched_via_aia:
        count = result.chain_check.intermediates_fetched_count
        # Bei STARTTLS ist es sehr häufig, bei HTTPS auch nicht ungewöhnlich
        if result.service_type and result.service_type in ["SMTP", "IMAP", "POP3"]:
            notes.append(
                f"Note: {count} intermediate certificate(s) were fetched via AIA (Authority Information Access) "
                f"because the server did not send a complete certificate chain. "
                f"This is common for {result.service_type} STARTTLS connections."
            )
        else:
            notes.append(
                f"Note: {count} intermediate certificate(s) were fetched via AIA (Authority Information Access) "
                f"because the server did not send a complete certificate chain. "
                f"While servers should ideally send the complete chain, this is handled automatically via AIA."
            )

    if not issues:
        if notes:
            return "All checks passed successfully; " + "; ".join(notes)
        return "All checks passed successfully"

    summary = "; ".join(issues)
    if notes:
        summary += "; " + "; ".join(notes)
    return summary

