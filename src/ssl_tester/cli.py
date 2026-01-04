"""CLI entry point using Typer."""

import logging
import ssl
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

import typer

from ssl_tester.network import connect_tls
from ssl_tester.certificate import parse_certificate, check_hostname, check_validity, set_debug_warnings
from ssl_tester.chain import validate_chain, fetch_intermediates_via_aia, load_root_certs_from_trust_store
from ssl_tester.crl import check_crl_reachability
from ssl_tester.ocsp import check_ocsp_reachability
from ssl_tester.protocol import check_protocol_versions
from ssl_tester.cipher import check_cipher_suites
from ssl_tester.vulnerabilities import check_cryptographic_flaws
from ssl_tester.services import detect_service, get_default_port
from ssl_tester.security import check_security_best_practices
from ssl_tester.batch import read_targets_from_file, process_batch, BatchTarget
from ssl_tester.reporter import (
    generate_text_report,
    generate_json_report,
    calculate_overall_severity,
    generate_summary,
    calculate_rating,
    set_color_output,
)
from ssl_tester.reporter_html import generate_html_report
from ssl_tester.exporter import export_to_csv, export_to_pdf
from ssl_tester.models import (
    CheckResult,
    ChainCheckResult,
    HostnameCheckResult,
    ValidityCheckResult,
    CertificateInfo,
    CertificateFinding,
    ProtocolCheckResult,
    CipherCheckResult,
    SecurityCheckResult,
    Severity,
)

app = typer.Typer(help="SSL/TLS Certificate Checker CLI Tool")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
)


def perform_ssl_check(
    hostname: str,
    port: int,
    timeout: float = 10.0,
    insecure: bool = False,
    skip_chain: bool = False,
    skip_hostname: bool = False,
    skip_protocol: bool = False,
    skip_cipher: bool = False,
    vulnerabilities: bool = False,
    vulnerability_list: Optional[str] = None,
    skip_security: bool = False,
    only_checks: Optional[str] = None,
    ca_bundle: Optional[Path] = None,
    ipv6: bool = False,
    proxy: Optional[str] = None,
    no_redirects: bool = False,
    max_crl_bytes: int = 20 * 1024 * 1024,
    service: Optional[str] = None,
) -> CheckResult:
    """
    Perform SSL/TLS check for a single target.
    
    This is the core check function that can be used by both the check command
    and batch processing.
    
    Returns:
        CheckResult
    """
    logger = logging.getLogger(__name__)
    
    # Handle --only-checks parameter (exclusive mode: only run specified checks)
    # Handle Typer OptionInfo objects when function is called directly (not via CLI)
    if only_checks is not None:
        # Check if it's a Typer OptionInfo object
        if not isinstance(only_checks, str):
            # Try to get the default value from OptionInfo
            if hasattr(only_checks, 'default'):
                only_checks = only_checks.default if only_checks.default is not None else None
            elif hasattr(only_checks, 'value'):
                only_checks = only_checks.value if only_checks.value is not None else None
    
    only_checks_set: Optional[set] = None
    only_checks_list: Optional[List[str]] = None
    if only_checks and isinstance(only_checks, str):
        only_checks_list = [c.strip().lower() for c in only_checks.split(",") if c.strip()]
        
        # Valid available checks
        valid_checks = {"chain", "hostname", "crl", "ocsp", "protocol", "cipher", "vulnerabilities", "security"}
        
        # Validate check names
        invalid_checks = [c for c in only_checks_list if c not in valid_checks]
        if invalid_checks:
            logger.warning(f"Unknown check names: {', '.join(invalid_checks)}. Available: {', '.join(sorted(valid_checks))}")
            only_checks_list = [c for c in only_checks_list if c in valid_checks]
        
        if not only_checks_list:
            logger.error("No valid checks specified in --only-checks. Aborting.")
            raise ValueError("No valid checks specified in --only-checks")
        
        only_checks_set = set(only_checks_list)
        
        # CRL/OCSP require chain check (they need certificate information)
        if ("crl" in only_checks_set or "ocsp" in only_checks_set) and "chain" not in only_checks_set:
            logger.warning("CRL/OCSP checks require chain check. Adding 'chain' to checks.")
            only_checks_set.add("chain")
            only_checks_list.append("chain")
        
        # Set skip_* flags based on only_checks (inverse logic)
        skip_chain = "chain" not in only_checks_set
        skip_hostname = "hostname" not in only_checks_set
        skip_protocol = "protocol" not in only_checks_set
        skip_cipher = "cipher" not in only_checks_set
        skip_security = "security" not in only_checks_set
        
        # Vulnerability handling
        vulnerabilities = "vulnerabilities" in only_checks_set
        
        logger.info(f"Running only specified checks: {', '.join(sorted(only_checks_set))}")
    
    # Detect or set service type
    service_type: Optional[str] = None
    if service and isinstance(service, str):
        service_type = service.upper()
        logger.debug(f"Using specified service type: {service_type}")
    else:
        # Auto-detect service from port
        service_type = detect_service(port)
        if not service_type:
            service_type = "HTTPS"
    
    # Connect and get certificates
    logger.debug(f"Connecting to {hostname}:{port}...")
    
    connection_error: Optional[str] = None
    leaf_cert_der: Optional[bytes] = None
    chain_certs_der: List[bytes] = []
    leaf_cert_info: Optional[CertificateInfo] = None

    try:
        leaf_cert_der, chain_certs_der = connect_tls(
            hostname, port, timeout, insecure, ca_bundle, ipv6, service=service_type
        )
    except ssl.SSLError as e:
        error_msg = str(e)
        connection_error = f"SSL/TLS error: {error_msg}"
        logger.warning(f"SSL error during connection: {error_msg}")
        logger.debug("Attempting to retrieve certificate despite SSL error...")
        
        try:
            leaf_cert_der, chain_certs_der = connect_tls(
                hostname, port, timeout, insecure=True, ca_bundle=ca_bundle, ipv6=ipv6, ignore_hostname=True, service=service_type
            )
            logger.debug("Successfully retrieved certificate (validation bypassed for certificate extraction)")
        except Exception as e2:
            logger.error(f"Failed to retrieve certificate: {e2}")
            connection_error = f"{connection_error}; Certificate retrieval failed: {e2}"
    except Exception as e:
        connection_error = f"Connection error: {e}"
        logger.error(f"Connection failed: {e}")

    # If we don't have a certificate, create an error report
    if not leaf_cert_der:
        is_connection_error = connection_error and (
            "DNS resolution failed" in connection_error or
            "Connection error" in connection_error or
            "Connection timeout" in connection_error or
            "Could not resolve" in connection_error
        )
        
        dummy_cert_info = CertificateInfo(
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
        
        chain_check = ChainCheckResult(
            is_valid=False,
            chain_valid=False,
            leaf_cert=dummy_cert_info,
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=False,
            missing_intermediates=[],
            error=connection_error or "Failed to establish connection",
            severity=Severity.FAIL,
        )
        
        hostname_check = HostnameCheckResult(
            matches=False,
            expected_hostname=hostname,
            severity=Severity.FAIL,
        )
        
        validity_check = ValidityCheckResult(
            is_valid=False,
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow(),
            days_until_expiry=0,
            is_expired=False if is_connection_error else True,
            severity=Severity.FAIL,
        )
        
        result = CheckResult(
            target_host=hostname,
            target_port=port,
            timestamp=datetime.utcnow(),
            chain_check=chain_check,
            hostname_check=hostname_check,
            validity_check=validity_check,
            crl_checks=[],
            ocsp_checks=[],
            service_type=service_type,
            overall_severity=Severity.FAIL,
            summary=connection_error or "Failed to establish connection and retrieve certificate",
        )
        return result

    # Parse leaf certificate
    leaf_cert_info, leaf_findings = parse_certificate(leaf_cert_der)
    all_certificate_findings: List[CertificateFinding] = leaf_findings.copy()

    # If no chain was extracted, try AIA fetching
    intermediates_fetched_count = 0
    if not chain_certs_der and leaf_cert_info.ca_issuers_urls:
        logger.debug("No intermediate certificates in chain, attempting to fetch via AIA...")
        try:
            fetched_intermediates = fetch_intermediates_via_aia(leaf_cert_info, timeout, proxy=proxy)
            if fetched_intermediates:
                chain_certs_der.extend(fetched_intermediates)
                intermediates_fetched_count = len(fetched_intermediates)
                logger.debug(f"Fetched {intermediates_fetched_count} intermediate certificate(s) via AIA")
        except Exception as e:
            logger.warning(f"Failed to fetch intermediates via AIA: {e}")

    # Check hostname
    if skip_hostname:
        hostname_check = HostnameCheckResult(
            expected_hostname=hostname,
            matches=False,
            severity=Severity.OK,
            skipped=True,
        )
    elif insecure:
        # In insecure mode, skip hostname check (self-signed certs often have incorrect hostnames)
        hostname_check = HostnameCheckResult(
            expected_hostname=hostname,
            matches=False,  # We don't know if it matches, but we don't care in insecure mode
            severity=Severity.OK,
            skipped=False,  # Not explicitly skipped, but treated as OK
        )
    else:
        hostname_check = check_hostname(leaf_cert_info, hostname)
        if connection_error:
            hostname_check.severity = Severity.FAIL
            hostname_check.matches = False

    # Check validity
    validity_check = check_validity(leaf_cert_info)

    # Validate chain
    if skip_chain:
        chain_check = ChainCheckResult(
            is_valid=False,
            chain_valid=False,
            leaf_cert=leaf_cert_info,
            intermediate_certs=[],
            root_cert=None,
            trust_store_valid=False,
            missing_intermediates=[],
            error="Chain validation skipped (--skip-chain)",
            severity=Severity.OK,
            skipped=True,
            intermediates_fetched_via_aia=False,
            intermediates_fetched_count=0,
        )
    else:
        try:
            chain_check, chain_findings = validate_chain(leaf_cert_der, chain_certs_der, insecure, ca_bundle)
            # Set AIA fetching information
            chain_check.intermediates_fetched_via_aia = intermediates_fetched_count > 0
            chain_check.intermediates_fetched_count = intermediates_fetched_count
            all_certificate_findings.extend(chain_findings)
            if connection_error and not chain_check.error:
                chain_check.error = connection_error
                chain_check.severity = Severity.FAIL
                chain_check.is_valid = False
                chain_check.chain_valid = False
        except Exception as e:
            logger.error(f"Chain validation failed: {e}")
            chain_check = ChainCheckResult(
                is_valid=False,
                chain_valid=False,
                leaf_cert=leaf_cert_info,
                intermediate_certs=[],
                root_cert=None,
                trust_store_valid=False,
                missing_intermediates=[],
                error=f"Chain validation error: {e}",
                severity=Severity.FAIL,
            )

    # Collect all certificates for CRL checks
    all_cert_infos = [leaf_cert_info]
    for intermediate in chain_check.intermediate_certs:
        all_cert_infos.append(intermediate)
    if chain_check.root_cert:
        all_cert_infos.append(chain_check.root_cert)

    # Build maps for CRL validation
    cert_der_map: dict[str, bytes] = {leaf_cert_info.fingerprint_sha256: leaf_cert_der}
    issuer_map: dict[str, bytes] = {}
    
    for intermediate in chain_check.intermediate_certs:
        for cert_der in chain_certs_der:
            try:
                temp_cert_info, _ = parse_certificate(cert_der)
                if temp_cert_info.fingerprint_sha256 == intermediate.fingerprint_sha256:
                    cert_der_map[intermediate.fingerprint_sha256] = cert_der
                    issuer_map[intermediate.subject] = cert_der
                    break
            except Exception as e:
                logger.debug(f"Error parsing certificate for CRL validation map: {e}")
    
    if chain_check.root_cert:
        for cert_der in chain_certs_der:
            try:
                temp_cert_info, _ = parse_certificate(cert_der)
                if temp_cert_info.fingerprint_sha256 == chain_check.root_cert.fingerprint_sha256:
                    cert_der_map[chain_check.root_cert.fingerprint_sha256] = cert_der
                    issuer_map[chain_check.root_cert.subject] = cert_der
                    break
            except Exception as e:
                logger.debug(f"Error parsing root certificate for CRL validation map: {e}")
    
    if leaf_cert_info.issuer not in issuer_map:
        for cert_der in chain_certs_der:
            try:
                temp_cert_info, _ = parse_certificate(cert_der)
                if temp_cert_info.subject == leaf_cert_info.issuer:
                    issuer_map[leaf_cert_info.issuer] = cert_der
                    break
            except Exception as e:
                logger.debug(f"Error finding leaf issuer for CRL validation: {e}")

    if not insecure:
        try:
            root_certs_from_trust_store = load_root_certs_from_trust_store(ca_bundle=ca_bundle)
            for subject_dn, cert_der in root_certs_from_trust_store.items():
                if subject_dn not in issuer_map:
                    issuer_map[subject_dn] = cert_der
        except Exception as e:
            logger.warning(f"Failed to load root certificates from trust store: {e}")

    # Check CRL reachability
    crl_checks = []
    if not skip_chain and (only_checks_set is None or "crl" in only_checks_set):
        try:
            crl_checks = check_crl_reachability(
                all_cert_infos,
                timeout,
                max_redirects=5,
                max_crl_bytes=max_crl_bytes,
                no_redirects=no_redirects,
                proxy=proxy,
                cert_der_map=cert_der_map,
                issuer_map=issuer_map,
                leaf_cert_info=leaf_cert_info,
                intermediate_cert_infos=chain_check.intermediate_certs,
                root_cert_info=chain_check.root_cert,
            )
        except Exception as e:
            logger.warning(f"CRL check failed: {e}")

    # Check OCSP reachability
    ocsp_checks = []
    if not skip_chain and (only_checks_set is None or "ocsp" in only_checks_set):
        try:
            issuer_cert_der: Optional[bytes] = None
            
            if leaf_cert_info.issuer in issuer_map:
                issuer_cert_der = issuer_map[leaf_cert_info.issuer]
            else:
                for cert_der in chain_certs_der:
                    try:
                        temp_cert_info, _ = parse_certificate(cert_der)
                        if temp_cert_info.subject == leaf_cert_info.issuer:
                            issuer_cert_der = cert_der
                            break
                    except Exception as e:
                        logger.debug(f"Error parsing certificate while searching for OCSP issuer: {e}")
                
                if not issuer_cert_der:
                    for intermediate in chain_check.intermediate_certs:
                        if intermediate.subject == leaf_cert_info.issuer:
                            for cert_der in chain_certs_der:
                                try:
                                    temp_cert_info, _ = parse_certificate(cert_der)
                                    if temp_cert_info.fingerprint_sha256 == intermediate.fingerprint_sha256:
                                        issuer_cert_der = cert_der
                                        break
                                except Exception as e:
                                    logger.debug(f"Error parsing certificate while matching intermediate for OCSP: {e}")
                            if issuer_cert_der:
                                break
            
            ocsp_checks = check_ocsp_reachability(
                leaf_cert_info, 
                cert_der=leaf_cert_der, 
                issuer_cert_der=issuer_cert_der, 
                timeout=timeout, 
                proxy=proxy,
                crl_results=crl_checks,  # Pass CRL results as fallback
            )
        except Exception as e:
            logger.warning(f"OCSP check failed: {e}")

    # Check protocol versions
    protocol_check: Optional[ProtocolCheckResult] = None
    if not skip_protocol:
        try:
            protocol_check = check_protocol_versions(hostname, port, timeout, service=service_type)
        except Exception as e:
            logger.warning(f"Protocol check failed: {e}")

    # Check cipher suites
    cipher_check: Optional[CipherCheckResult] = None
    if not skip_cipher:
        try:
            cipher_check = check_cipher_suites(hostname, port, timeout, service=service_type)
        except Exception as e:
            logger.warning(f"Cipher check failed: {e}")

    # Check cryptographic vulnerabilities (only if --vulnerabilities is specified)
    # Handle Typer OptionInfo objects when function is called directly (not via CLI)
    if vulnerability_list is not None:
        # Check if it's a Typer OptionInfo object
        if not isinstance(vulnerability_list, str):
            # Try to get the default value from OptionInfo
            if hasattr(vulnerability_list, 'default'):
                vulnerability_list = vulnerability_list.default if vulnerability_list.default is not None else None
            elif hasattr(vulnerability_list, 'value'):
                vulnerability_list = vulnerability_list.value if vulnerability_list.value is not None else None
    
    vulnerability_checks: List = []
    if vulnerabilities:
        # Parse vulnerability list if provided, otherwise check all
        only_vulnerabilities: Optional[List[str]] = None
        if vulnerability_list and isinstance(vulnerability_list, str):
            # Parse comma-separated list
            only_vulnerabilities = [v.strip() for v in vulnerability_list.split(",") if v.strip()]
        
        try:
            vulnerability_checks = check_cryptographic_flaws(
                hostname, port, timeout, only_vulnerabilities=only_vulnerabilities
            )
        except Exception as e:
            logger.warning(f"Vulnerability check failed: {e}")

    # Check security best practices
    security_check: Optional[SecurityCheckResult] = None
    if not skip_security:
        try:
            security_check = check_security_best_practices(hostname, port, timeout, proxy, service=service_type)
        except Exception as e:
            logger.warning(f"Security check failed: {e}")

    # Build result
    result = CheckResult(
        target_host=hostname,
        target_port=port,
        timestamp=datetime.utcnow(),
        chain_check=chain_check,
        hostname_check=hostname_check,
        validity_check=validity_check,
        crl_checks=crl_checks,
        ocsp_checks=ocsp_checks,
        certificate_findings=all_certificate_findings,
        protocol_check=protocol_check,
        cipher_check=cipher_check,
        vulnerability_checks=vulnerability_checks,
        security_check=security_check,
        service_type=service_type,
        overall_severity=Severity.OK,  # Will be calculated
        summary="",  # Will be generated
        only_checks=only_checks_list,  # Store selected checks for report filtering
    )

    # Calculate overall severity, rating, and summary
    # Only calculate rating/summary if all checks were performed (not using --only-checks)
    if only_checks_list:
        # Partial check - only calculate severity for selected checks
        result.overall_severity = calculate_overall_severity(result)
        result.rating = None  # Rating doesn't make sense for partial checks
        result.rating_reasons = []
        result.summary = f"Partial check: Only {', '.join(sorted(set(only_checks_list)))} checks performed"
    else:
        # Full check - calculate everything
        result.overall_severity = calculate_overall_severity(result)
        result.rating, result.rating_reasons = calculate_rating(result)
        result.summary = generate_summary(result)

    return result


@app.command()
def check(
    target: str = typer.Argument(..., help="Hostname or URL (e.g., example.com or https://example.com)"),
    port: int = typer.Option(443, "--port", "-p", help="Port (default: 443)"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Timeout in seconds"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug logging"),
    no_redirects: bool = typer.Option(False, "--no-redirects", help="Do not follow redirects for CRL URLs"),
    max_crl_bytes: int = typer.Option(
        20 * 1024 * 1024, "--max-crl-bytes", help="Maximum CRL size in bytes (default: 20 MB)"
    ),
    insecure: bool = typer.Option(False, "--insecure", help="Accept private CAs / self-signed certificates"),
    skip_chain: bool = typer.Option(False, "--skip-chain", help="Skip chain and trust store validation. Useful for self-signed certificates. Combine with --skip-hostname to only check certificate validity."),
    skip_hostname: bool = typer.Option(False, "--skip-hostname", help="Skip hostname matching check. Can be combined with --skip-chain to only check certificate validity."),
    ca_bundle: Optional[Path] = typer.Option(None, "--ca-bundle", help="Custom CA bundle (PEM)"),
    ipv6: bool = typer.Option(False, "--ipv6", help="Prefer IPv6"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Proxy URL (e.g., http://proxy:8080)"),
    debug_warnings: bool = typer.Option(False, "--debug-warnings", help="Show original Python warnings in addition to Findings"),
    skip_protocol: bool = typer.Option(False, "--skip-protocol", help="Skip protocol version checks"),
    skip_cipher: bool = typer.Option(False, "--skip-cipher", help="Skip cipher suite checks"),
    vulnerabilities: bool = typer.Option(False, "--vulnerabilities", help="Enable vulnerability checks (checks all vulnerabilities)"),
    vulnerability_list: Optional[str] = typer.Option(
        None,
        "--vulnerability-list",
        help="Specify which vulnerabilities to check (comma-separated). Requires --vulnerabilities. Available: heartbleed, drown, poodle, ccs-injection, freak, logjam, ticketbleed, sweet32",
    ),
    skip_security: bool = typer.Option(False, "--skip-security", help="Skip security best practices checks"),
    only_checks: Optional[str] = typer.Option(
        None,
        "--only-checks",
        help="Only run specified checks (comma-separated). Available: chain, hostname, crl, ocsp, protocol, cipher, vulnerabilities, security. Example: --only-checks chain,hostname,protocol",
    ),
    service: Optional[str] = typer.Option(None, "--service", help="Service type (HTTPS, SMTP, IMAP, POP3, FTP, LDAP, XMPP, RDP, PostgreSQL, MySQL). Auto-detected from port if not specified."),
    html: Optional[Path] = typer.Option(None, "--html", help="Generate HTML report and save to file"),
    csv: Optional[Path] = typer.Option(None, "--csv", help="Generate CSV report and save to file"),
    color: bool = typer.Option(True, "--color/--no-color", help="Enable/disable colored output"),
    severity_filter: Optional[str] = typer.Option(None, "--severity", help="Only show checks with this severity or worse (OK/WARN/FAIL)"),
):
    """
    Check SSL/TLS certificate for an HTTPS server.
    """
    logger = logging.getLogger(__name__)
    
    # Set debug warnings mode
    set_debug_warnings(debug_warnings)
    
    # Set color output
    set_color_output(color)
    
    # Validate vulnerability options
    if vulnerability_list and not vulnerabilities:
        logger.warning("--vulnerability-list requires --vulnerabilities. Ignoring --vulnerability-list.")
        vulnerability_list = None
    
    # Parse severity filter
    # Handle both string and OptionInfo objects (when called directly vs via CLI)
    severity_filter_obj: Optional[Severity] = None
    if severity_filter:
        # Check if it's actually a string (not an OptionInfo object)
        if isinstance(severity_filter, str):
            try:
                severity_filter_obj = Severity[severity_filter.upper()]
            except KeyError:
                logger.error(f"Invalid severity filter: {severity_filter}. Must be OK, WARN, or FAIL")
                sys.exit(1)
        # If it's an OptionInfo object, it means it wasn't explicitly set, so treat as None
    
    # Set logging level
    if verbose:
        # Set root logger to DEBUG
        logging.getLogger().setLevel(logging.DEBUG)
        # Also set all ssl_tester loggers to DEBUG to ensure debug messages are shown
        logging.getLogger('ssl_tester').setLevel(logging.DEBUG)
        logging.getLogger('ssl_tester.crl').setLevel(logging.DEBUG)
        logging.getLogger('ssl_tester.chain').setLevel(logging.DEBUG)
        logging.getLogger('ssl_tester.certificate').setLevel(logging.DEBUG)
        logging.getLogger('ssl_tester.network').setLevel(logging.DEBUG)

    # Parse target (handle URLs)
    hostname = target
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        if parsed.port:
            port = parsed.port
        elif parsed.scheme == "https" and port == 443:
            pass  # Default HTTPS port
        elif parsed.scheme == "http" and port == 443:
            port = 80

    # Adjust service and port if needed
    if service and isinstance(service, str):
        service_type = service.upper()
        logger.info(f"Using specified service type: {service_type}")
        if port == 443 and service_type != "HTTPS":
            default_port = get_default_port(service_type)
            if default_port:
                port = default_port
                logger.info(f"Using default port for {service_type}: {port}")
    else:
        service_type = None  # Will be auto-detected in perform_ssl_check

    # Perform SSL check using the core function
    result = perform_ssl_check(
        hostname=hostname,
        port=port,
        timeout=timeout,
        insecure=insecure,
        skip_chain=skip_chain,
        skip_hostname=skip_hostname,
        skip_protocol=skip_protocol,
        skip_cipher=skip_cipher,
        vulnerabilities=vulnerabilities,
        vulnerability_list=vulnerability_list,
        skip_security=skip_security,
        only_checks=only_checks,
        ca_bundle=ca_bundle,
        ipv6=ipv6,
        proxy=proxy,
        no_redirects=no_redirects,
        max_crl_bytes=max_crl_bytes,
        service=service,
    )

    # Generate and output report
    # Handle OptionInfo objects when function is called directly (not via CLI)
    html_path = html if isinstance(html, (Path, type(None))) else None
    csv_path = csv if isinstance(csv, (Path, type(None))) else None
    
    if html_path:
        html_report = generate_html_report(result)
        html_path.parent.mkdir(parents=True, exist_ok=True)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_report)
        logger.info(f"HTML report saved to {html_path}")
    
    if csv_path:
        csv_content = export_to_csv([result], csv_path)
        logger.info(f"CSV report saved to {csv_path}")
    
    if json_output:
        report = generate_json_report(result)
        print(report)
    elif not html_path and not csv_path:
        # Only print text report if not generating HTML/CSV
        report = generate_text_report(result, severity_filter=severity_filter_obj)
        print(report)

    # Exit with appropriate code
    if result.overall_severity == Severity.FAIL:
        sys.exit(2)
    elif result.overall_severity == Severity.WARN:
        sys.exit(1)
    else:
        sys.exit(0)




@app.command()
def batch(
    file: Path = typer.Argument(..., help="File containing targets (one per line, format: hostname[:port])"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Timeout in seconds"),
    parallel: int = typer.Option(5, "--parallel", "-p", help="Number of parallel checks"),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", "-o", help="Output directory for reports"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
    skip_chain: bool = typer.Option(False, "--skip-chain", help="Skip chain validation"),
    skip_hostname: bool = typer.Option(False, "--skip-hostname", help="Skip hostname check"),
    skip_protocol: bool = typer.Option(False, "--skip-protocol", help="Skip protocol checks"),
    skip_cipher: bool = typer.Option(False, "--skip-cipher", help="Skip cipher checks"),
    vulnerabilities: bool = typer.Option(False, "--vulnerabilities", help="Enable vulnerability checks (checks all vulnerabilities)"),
    vulnerability_list: Optional[str] = typer.Option(
        None,
        "--vulnerability-list",
        help="Specify which vulnerabilities to check (comma-separated). Requires --vulnerabilities. Available: heartbleed, drown, poodle, ccs-injection, freak, logjam, ticketbleed, sweet32",
    ),
    only_checks: Optional[str] = typer.Option(
        None,
        "--only-checks",
        help="Only run specified checks (comma-separated). Available: chain, hostname, crl, ocsp, protocol, cipher, vulnerabilities, security. Example: --only-checks chain,hostname,protocol",
    ),
    insecure: bool = typer.Option(False, "--insecure", help="Accept self-signed certificates"),
    ca_bundle: Optional[Path] = typer.Option(None, "--ca-bundle", help="Custom CA bundle"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Proxy URL"),
):
    """
    Batch process multiple targets from a file.
    """
    try:
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
        
        # Read targets
        targets = read_targets_from_file(file)
        if not targets:
            logger.error(f"No valid targets found in {file}")
            sys.exit(1)
        
        logger.info(f"Found {len(targets)} target(s) in {file}")
        
        # Create check function wrapper
        def check_wrapper(hostname: str, port: int, service: Optional[str]) -> CheckResult:
            return perform_ssl_check(
                hostname=hostname,
                port=port,
                timeout=timeout,
                insecure=insecure,
                skip_chain=skip_chain,
                skip_hostname=skip_hostname,
                skip_protocol=skip_protocol,
                skip_cipher=skip_cipher,
                vulnerabilities=vulnerabilities,
                vulnerability_list=vulnerability_list,
                skip_security=skip_security,
                only_checks=only_checks,
                ca_bundle=ca_bundle,
                ipv6=False,  # Batch mode doesn't support IPv6 preference
                proxy=proxy,
                no_redirects=no_redirects,
                max_crl_bytes=max_crl_bytes,
                service=service,
            )
        
        # Process batch with progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        ) as progress:
            task = progress.add_task("Processing targets...", total=len(targets))
            
            def progress_callback(current: int, total: int):
                progress.update(task, completed=current)
            
            results = process_batch(
                targets,
                check_wrapper,
                max_workers=parallel,
                progress_callback=progress_callback,
            )
        
        # Generate reports
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            for i, result in enumerate(results):
                filename = f"{result.target_host}_{result.target_port}.{'json' if json_output else 'txt'}"
                output_path = output_dir / filename
                
                if json_output:
                    report = generate_json_report(result)
                else:
                    report = generate_text_report(result)
                
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(report)
                
                logger.info(f"Report saved: {output_path}")
        else:
            # Print summary
            for result in results:
                if json_output:
                    print(generate_json_report(result))
                else:
                    print(generate_text_report(result))
                    print("\n" + "=" * 70 + "\n")
        
        # Summary
        total = len(results)
        failed = sum(1 for r in results if r.overall_severity == Severity.FAIL)
        warnings = sum(1 for r in results if r.overall_severity == Severity.WARN)
        ok = sum(1 for r in results if r.overall_severity == Severity.OK)
        
        logger.info(f"Batch processing completed: {total} total, {ok} OK, {warnings} WARN, {failed} FAIL")
        
    except Exception as e:
        logger.error(f"Batch processing failed: {e}")
        sys.exit(1)


@app.command()
def compare(
    target1: str = typer.Argument(..., help="First target (hostname or URL)"),
    target2: str = typer.Argument(..., help="Second target (hostname or URL)"),
    port1: int = typer.Option(443, "--port1", "-p1", help="Port for first target"),
    port2: int = typer.Option(443, "--port2", "-p2", help="Port for second target"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Timeout in seconds"),
    insecure: bool = typer.Option(False, "--insecure", help="Accept self-signed certificates"),
    skip_chain: bool = typer.Option(False, "--skip-chain", help="Skip chain validation"),
    skip_hostname: bool = typer.Option(False, "--skip-hostname", help="Skip hostname check"),
    skip_protocol: bool = typer.Option(False, "--skip-protocol", help="Skip protocol checks"),
    skip_cipher: bool = typer.Option(False, "--skip-cipher", help="Skip cipher checks"),
    vulnerabilities: bool = typer.Option(False, "--vulnerabilities", help="Enable vulnerability checks (checks all vulnerabilities)"),
    vulnerability_list: Optional[str] = typer.Option(
        None,
        "--vulnerability-list",
        help="Specify which vulnerabilities to check (comma-separated). Requires --vulnerabilities. Available: heartbleed, drown, poodle, ccs-injection, freak, logjam, ticketbleed, sweet32",
    ),
    skip_security: bool = typer.Option(False, "--skip-security", help="Skip security checks"),
    html: Optional[Path] = typer.Option(None, "--html", help="Generate comparison HTML report"),
):
    """
    Compare SSL/TLS configuration between two targets.
    """
    logger = logging.getLogger(__name__)
    
    # Handle OptionInfo objects when function is called directly (not via CLI)
    html_path = html if isinstance(html, (Path, type(None))) else None
    
    from urllib.parse import urlparse
    
    # Parse targets
    def parse_target(target: str, default_port: int) -> tuple[str, int]:
        hostname = target
        port = default_port
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            hostname = parsed.hostname or target
            if parsed.port:
                port = parsed.port
        return hostname, port
    
    hostname1, port1 = parse_target(target1, port1)
    hostname2, port2 = parse_target(target2, port2)
    
    logger.info(f"Comparing {hostname1}:{port1} with {hostname2}:{port2}")
    
    # Perform checks
    result1 = perform_ssl_check(
        hostname=hostname1,
        port=port1,
        timeout=timeout,
        insecure=insecure,
        skip_chain=skip_chain,
        skip_hostname=skip_hostname,
        skip_protocol=skip_protocol,
        skip_cipher=skip_cipher,
        vulnerabilities=vulnerabilities,
        vulnerability_list=vulnerability_list,
        skip_security=skip_security,
        only_checks=only_checks,
        ca_bundle=None,
        ipv6=False,
        proxy=None,
        no_redirects=False,
        max_crl_bytes=20 * 1024 * 1024,
        service=None,
    )
    
    result2 = perform_ssl_check(
        hostname=hostname2,
        port=port2,
        timeout=timeout,
        insecure=insecure,
        skip_chain=skip_chain,
        skip_hostname=skip_hostname,
        skip_protocol=skip_protocol,
        skip_cipher=skip_cipher,
        vulnerabilities=vulnerabilities,
        vulnerability_list=vulnerability_list,
        skip_security=skip_security,
        only_checks=only_checks,
        ca_bundle=None,
        ipv6=False,
        proxy=None,
        no_redirects=False,
        max_crl_bytes=20 * 1024 * 1024,
        service=None,
    )
    
    # Generate comparison report
    lines = []
    lines.append("=" * 70)
    lines.append("SSL/TLS Configuration Comparison")
    lines.append("=" * 70)
    lines.append(f"Target 1: {hostname1}:{port1}")
    lines.append(f"Target 2: {hostname2}:{port2}")
    lines.append("")
    
    # Compare ratings
    lines.append("Security Rating:")
    lines.append(f"  Target 1: {result1.rating.value if result1.rating else 'N/A'}")
    lines.append(f"  Target 2: {result2.rating.value if result2.rating else 'N/A'}")
    lines.append("")
    
    # Compare protocols
    if result1.protocol_check and result2.protocol_check:
        lines.append("Protocol Versions:")
        lines.append(f"  Target 1: {result1.protocol_check.best_version}")
        lines.append(f"  Target 2: {result2.protocol_check.best_version}")
        lines.append("")
    
    # Compare ciphers
    if result1.cipher_check and result2.cipher_check:
        lines.append("Cipher Suites:")
        lines.append(f"  Target 1: {len(result1.cipher_check.supported_ciphers)} ciphers, PFS: {result1.cipher_check.pfs_supported}")
        lines.append(f"  Target 2: {len(result2.cipher_check.supported_ciphers)} ciphers, PFS: {result2.cipher_check.pfs_supported}")
        lines.append("")
    
    # Compare vulnerabilities
    if result1.vulnerability_checks and result2.vulnerability_checks:
        vuln1_count = len([v for v in result1.vulnerability_checks if v.vulnerable])
        vuln2_count = len([v for v in result2.vulnerability_checks if v.vulnerable])
        lines.append("Vulnerabilities:")
        lines.append(f"  Target 1: {vuln1_count} vulnerable")
        lines.append(f"  Target 2: {vuln2_count} vulnerable")
        lines.append("")
    
    # Compare security
    if result1.security_check and result2.security_check:
        lines.append("Security Best Practices:")
        lines.append(f"  Target 1: HSTS={result1.security_check.hsts_enabled}, OCSP Stapling={result1.security_check.ocsp_stapling_enabled}")
        lines.append(f"  Target 2: HSTS={result2.security_check.hsts_enabled}, OCSP Stapling={result2.security_check.ocsp_stapling_enabled}")
        lines.append("")
    
    lines.append("=" * 70)
    
    comparison_text = "\n".join(lines)
    
    if html_path:
        # Generate comparison HTML report
        html_content = f"""<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <title>SSL/TLS Comparison Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #667eea; color: white; }}
        .better {{ background-color: #d1fae5; }}
        .worse {{ background-color: #fee2e2; }}
    </style>
</head>
<body>
    <h1>SSL/TLS Configuration Comparison</h1>
    <pre>{comparison_text}</pre>
    <h2>Detailed Comparison</h2>
    <table>
        <tr>
            <th>Check</th>
            <th>Target 1 ({hostname1}:{port1})</th>
            <th>Target 2 ({hostname2}:{port2})</th>
        </tr>
        <tr>
            <td>Rating</td>
            <td>{result1.rating.value if result1.rating else 'N/A'}</td>
            <td>{result2.rating.value if result2.rating else 'N/A'}</td>
        </tr>
        <tr>
            <td>Best Protocol</td>
            <td>{result1.protocol_check.best_version if result1.protocol_check else 'N/A'}</td>
            <td>{result2.protocol_check.best_version if result2.protocol_check else 'N/A'}</td>
        </tr>
        <tr>
            <td>PFS Supported</td>
            <td>{result1.cipher_check.pfs_supported if result1.cipher_check else 'N/A'}</td>
            <td>{result2.cipher_check.pfs_supported if result2.cipher_check else 'N/A'}</td>
        </tr>
        <tr>
            <td>HSTS Enabled</td>
            <td>{result1.security_check.hsts_enabled if result1.security_check else 'N/A'}</td>
            <td>{result2.security_check.hsts_enabled if result2.security_check else 'N/A'}</td>
        </tr>
    </table>
</body>
</html>"""
        html_path.parent.mkdir(parents=True, exist_ok=True)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.info(f"Comparison HTML report saved to {html_path}")
    else:
        print(comparison_text)


if __name__ == "__main__":
    app()

