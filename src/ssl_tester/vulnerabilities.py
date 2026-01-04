"""Cryptographic vulnerability detection."""

import logging
from typing import List, Optional, Callable

from ssl_tester.models import VulnerabilityCheckResult, Severity
from ssl_tester.nmap_helper import (
    ensure_nmap_available,
    run_nmap_script,
    parse_nmap_output,
    get_nmap_path,
)

logger = logging.getLogger(__name__)


def check_heartbleed(host: str, port: int, timeout: float = 10.0) -> VulnerabilityCheckResult:
    """
    Check for Heartbleed vulnerability (CVE-2014-0160).
    
    Heartbleed is a vulnerability in OpenSSL's heartbeat extension that allows
    reading memory from the server.
    
    Requires nmap to be installed. Returns a result indicating test was skipped
    if nmap is not available.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        VulnerabilityCheckResult
    """
    logger.debug(f"Checking Heartbleed vulnerability for {host}:{port}")
    
    nmap_path = get_nmap_path()
    if not nmap_path:
        logger.warning("nmap not available - Heartbleed test skipped")
        return VulnerabilityCheckResult(
            vulnerability_name="Heartbleed",
            cve_id="CVE-2014-0160",
            vulnerable=False,
            severity=Severity.OK,
            description="OpenSSL Heartbeat Extension vulnerability that allows reading server memory (test skipped - nmap required)",
            recommendation="Install nmap to enable Heartbleed testing",
        )
    
    try:
        success, stdout, stderr = run_nmap_script(
            host, port, "ssl-heartbleed", timeout
        )
        if not success:
            logger.warning(f"nmap Heartbleed check failed: {stderr}")
            return VulnerabilityCheckResult(
                vulnerability_name="Heartbleed",
                cve_id="CVE-2014-0160",
                vulnerable=False,
                severity=Severity.OK,
                description="OpenSSL Heartbeat Extension vulnerability that allows reading server memory (test failed - nmap error)",
                recommendation="Check nmap installation and network connectivity",
            )
        
        parsed = parse_nmap_output(stdout, "ssl-heartbleed")
        vulnerable = parsed["vulnerable"]
        details = " ".join(parsed["details"]) if parsed["details"] else ""
        
        description = (
            "OpenSSL Heartbeat Extension vulnerability that allows reading server memory"
        )
        if details:
            description += f" - {details}"
        if parsed["state"] == "UNKNOWN":
            description += " (nmap check completed, no vulnerability detected)"
        
        return VulnerabilityCheckResult(
            vulnerability_name="Heartbleed",
            cve_id="CVE-2014-0160",
            vulnerable=vulnerable,
            severity=Severity.FAIL if vulnerable else Severity.OK,
            description=description,
            recommendation="Update OpenSSL to version 1.0.1g or later" if vulnerable else None,
        )
    except Exception as e:
        logger.error(f"Error running nmap Heartbleed check: {e}")
        return VulnerabilityCheckResult(
            vulnerability_name="Heartbleed",
            cve_id="CVE-2014-0160",
            vulnerable=False,
            severity=Severity.OK,
            description="OpenSSL Heartbeat Extension vulnerability that allows reading server memory (test failed)",
            recommendation="Check nmap installation",
        )


def check_poodle(host: str, port: int, timeout: float = 10.0) -> VulnerabilityCheckResult:
    """
    Check for POODLE vulnerability (CVE-2014-3566).
    
    POODLE (Padding Oracle On Downgraded Legacy Encryption) is a vulnerability
    in SSL 3.0 that allows decryption of encrypted data.
    
    Requires nmap to be installed. Returns a result indicating test was skipped
    if nmap is not available.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        VulnerabilityCheckResult
    """
    logger.debug(f"Checking POODLE vulnerability for {host}:{port}")
    
    nmap_path = get_nmap_path()
    if not nmap_path:
        logger.warning("nmap not available - POODLE test skipped")
        return VulnerabilityCheckResult(
            vulnerability_name="POODLE",
            cve_id="CVE-2014-3566",
            vulnerable=False,
            severity=Severity.OK,
            description="SSL 3.0 Padding Oracle vulnerability that allows decryption of encrypted data (test skipped - nmap required)",
            recommendation="Install nmap to enable POODLE testing",
        )
    
    try:
        success, stdout, stderr = run_nmap_script(
            host, port, "ssl-poodle", timeout
        )
        if not success:
            logger.warning(f"nmap POODLE check failed: {stderr}")
            return VulnerabilityCheckResult(
                vulnerability_name="POODLE",
                cve_id="CVE-2014-3566",
                vulnerable=False,
                severity=Severity.OK,
                description="SSL 3.0 Padding Oracle vulnerability that allows decryption of encrypted data (test failed - nmap error)",
                recommendation="Check nmap installation and network connectivity",
            )
        
        parsed = parse_nmap_output(stdout, "ssl-poodle")
        vulnerable = parsed["vulnerable"]
        details = " ".join(parsed["details"]) if parsed["details"] else ""
        
        description = "SSL 3.0 Padding Oracle vulnerability that allows decryption of encrypted data"
        if details:
            description += f" - {details}"
        if parsed["state"] == "UNKNOWN":
            description += " (nmap check completed, no vulnerability detected)"
        
        return VulnerabilityCheckResult(
            vulnerability_name="POODLE",
            cve_id="CVE-2014-3566",
            vulnerable=vulnerable,
            severity=Severity.FAIL if vulnerable else Severity.OK,
            description=description,
            recommendation="Disable SSL 3.0 support" if vulnerable else None,
        )
    except Exception as e:
        logger.error(f"Error running nmap POODLE check: {e}")
        return VulnerabilityCheckResult(
            vulnerability_name="POODLE",
            cve_id="CVE-2014-3566",
            vulnerable=False,
            severity=Severity.OK,
            description="SSL 3.0 Padding Oracle vulnerability that allows decryption of encrypted data (test failed)",
            recommendation="Check nmap installation",
        )


def check_freak(host: str, port: int, timeout: float = 10.0) -> VulnerabilityCheckResult:
    """
    Check for FREAK vulnerability (CVE-2015-0204).
    
    FREAK (Factoring Attack on RSA-EXPORT Keys) is a vulnerability that allows
    man-in-the-middle attacks by forcing servers to use weak export-grade RSA keys.
    
    Requires nmap to be installed. Returns a result indicating test was skipped
    if nmap is not available.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        VulnerabilityCheckResult
    """
    logger.debug(f"Checking FREAK vulnerability for {host}:{port}")
    
    nmap_path = get_nmap_path()
    if not nmap_path:
        logger.warning("nmap not available - FREAK test skipped")
        return VulnerabilityCheckResult(
            vulnerability_name="FREAK",
            cve_id="CVE-2015-0204",
            vulnerable=False,
            severity=Severity.OK,
            description="Export-grade RSA key vulnerability that allows man-in-the-middle attacks (test skipped - nmap required)",
            recommendation="Install nmap to enable FREAK testing",
        )
    
    try:
        success, stdout, stderr = run_nmap_script(
            host, port, "ssl-freak", timeout
        )
        if not success:
            logger.warning(f"nmap FREAK check failed: {stderr}")
            return VulnerabilityCheckResult(
                vulnerability_name="FREAK",
                cve_id="CVE-2015-0204",
                vulnerable=False,
                severity=Severity.OK,
                description="Export-grade RSA key vulnerability that allows man-in-the-middle attacks (test failed - nmap error)",
                recommendation="Check nmap installation and network connectivity",
            )
        
        parsed = parse_nmap_output(stdout, "ssl-freak")
        vulnerable = parsed["vulnerable"]
        details = " ".join(parsed["details"]) if parsed["details"] else ""
        
        description = "Export-grade RSA key vulnerability that allows man-in-the-middle attacks"
        if details:
            description += f" - {details}"
        if parsed["state"] == "UNKNOWN":
            description += " (nmap check completed, no vulnerability detected)"
        
        return VulnerabilityCheckResult(
            vulnerability_name="FREAK",
            cve_id="CVE-2015-0204",
            vulnerable=vulnerable,
            severity=Severity.FAIL if vulnerable else Severity.OK,
            description=description,
            recommendation="Disable export-grade cipher suites" if vulnerable else None,
        )
    except Exception as e:
        logger.error(f"Error running nmap FREAK check: {e}")
        return VulnerabilityCheckResult(
            vulnerability_name="FREAK",
            cve_id="CVE-2015-0204",
            vulnerable=False,
            severity=Severity.OK,
            description="Export-grade RSA key vulnerability that allows man-in-the-middle attacks (test failed)",
            recommendation="Check nmap installation",
        )


def check_drown(host: str, port: int, timeout: float = 10.0) -> VulnerabilityCheckResult:
    """
    Check for DROWN vulnerability (CVE-2016-0800).
    
    DROWN (Decrypting RSA with Obsolete and Weakened eNcryption) is a vulnerability
    that allows decryption of TLS connections by exploiting SSLv2.
    
    Requires nmap to be installed. Returns a result indicating test was skipped
    if nmap is not available.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        VulnerabilityCheckResult
    """
    logger.debug(f"Checking DROWN vulnerability for {host}:{port}")
    
    nmap_path = get_nmap_path()
    if not nmap_path:
        logger.warning("nmap not available - DROWN test skipped")
        return VulnerabilityCheckResult(
            vulnerability_name="DROWN",
            cve_id="CVE-2016-0800",
            vulnerable=False,
            severity=Severity.OK,
            description="SSLv2 vulnerability that allows decryption of TLS connections (test skipped - nmap required)",
            recommendation="Install nmap to enable DROWN testing",
        )
    
    try:
        success, stdout, stderr = run_nmap_script(
            host, port, "ssl-drown", timeout
        )
        if not success:
            logger.warning(f"nmap DROWN check failed: {stderr}")
            return VulnerabilityCheckResult(
                vulnerability_name="DROWN",
                cve_id="CVE-2016-0800",
                vulnerable=False,
                severity=Severity.OK,
                description="SSLv2 vulnerability that allows decryption of TLS connections (test failed - nmap error)",
                recommendation="Check nmap installation and network connectivity",
            )
        
        parsed = parse_nmap_output(stdout, "ssl-drown")
        vulnerable = parsed["vulnerable"]
        details = " ".join(parsed["details"]) if parsed["details"] else ""
        
        description = "SSLv2 vulnerability that allows decryption of TLS connections"
        if details:
            description += f" - {details}"
        if parsed["state"] == "UNKNOWN":
            description += " (nmap check completed, no vulnerability detected)"
        
        return VulnerabilityCheckResult(
            vulnerability_name="DROWN",
            cve_id="CVE-2016-0800",
            vulnerable=vulnerable,
            severity=Severity.FAIL if vulnerable else Severity.OK,
            description=description,
            recommendation="Disable SSLv2 support completely" if vulnerable else None,
        )
    except Exception as e:
        logger.error(f"Error running nmap DROWN check: {e}")
        return VulnerabilityCheckResult(
            vulnerability_name="DROWN",
            cve_id="CVE-2016-0800",
            vulnerable=False,
            severity=Severity.OK,
            description="SSLv2 vulnerability that allows decryption of TLS connections (test failed)",
            recommendation="Check nmap installation",
        )


def check_sweet32(host: str, port: int, timeout: float = 10.0) -> VulnerabilityCheckResult:
    """
    Check for Sweet32 vulnerability (CVE-2016-2183).
    
    Sweet32 is a vulnerability in 64-bit block ciphers (3DES, Blowfish) that allows
    birthday attacks on CBC mode encryption.
    
    Requires nmap to be installed. Returns a result indicating test was skipped
    if nmap is not available.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        VulnerabilityCheckResult
    """
    logger.debug(f"Checking Sweet32 vulnerability for {host}:{port}")
    
    nmap_path = get_nmap_path()
    if not nmap_path:
        logger.warning("nmap not available - Sweet32 test skipped")
        return VulnerabilityCheckResult(
            vulnerability_name="Sweet32",
            cve_id="CVE-2016-2183",
            vulnerable=False,
            severity=Severity.OK,
            description="64-bit block cipher vulnerability that allows birthday attacks on CBC mode (test skipped - nmap required)",
            recommendation="Install nmap to enable Sweet32 testing",
        )
    
    try:
        success, stdout, stderr = run_nmap_script(
            host, port, "ssl-enum-ciphers", timeout
        )
        if not success:
            logger.warning(f"nmap Sweet32 check failed: {stderr}")
            return VulnerabilityCheckResult(
                vulnerability_name="Sweet32",
                cve_id="CVE-2016-2183",
                vulnerable=False,
                severity=Severity.OK,
                description="64-bit block cipher vulnerability that allows birthday attacks on CBC mode (test failed - nmap error)",
                recommendation="Check nmap installation and network connectivity",
            )
        
        # Check for 3DES, DES, or Blowfish in cipher list
        vulnerable = False
        output_upper = stdout.upper()
        if "3DES" in output_upper or "DES-CBC" in output_upper or "BLOWFISH" in output_upper:
            vulnerable = True
        
        description = "64-bit block cipher vulnerability that allows birthday attacks on CBC mode"
        if vulnerable:
            description += " - 3DES/DES/Blowfish ciphers detected"
        else:
            description += " (nmap check completed, no 64-bit block ciphers detected)"
        
        return VulnerabilityCheckResult(
            vulnerability_name="Sweet32",
            cve_id="CVE-2016-2183",
            vulnerable=vulnerable,
            severity=Severity.WARN if vulnerable else Severity.OK,
            description=description,
            recommendation="Disable 3DES and other 64-bit block ciphers" if vulnerable else None,
        )
    except Exception as e:
        logger.error(f"Error running nmap Sweet32 check: {e}")
        return VulnerabilityCheckResult(
            vulnerability_name="Sweet32",
            cve_id="CVE-2016-2183",
            vulnerable=False,
            severity=Severity.OK,
            description="64-bit block cipher vulnerability that allows birthday attacks on CBC mode (test failed)",
            recommendation="Check nmap installation",
        )


def check_ticketbleed(host: str, port: int, timeout: float = 10.0) -> VulnerabilityCheckResult:
    """
    Check for Ticketbleed vulnerability (CVE-2016-9244).
    
    Ticketbleed is a vulnerability in TLS session ticket handling that allows
    reading memory from the server.
    
    Requires nmap to be installed. Returns a result indicating test was skipped
    if nmap is not available.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        VulnerabilityCheckResult
    """
    logger.debug(f"Checking Ticketbleed vulnerability for {host}:{port}")
    
    nmap_path = get_nmap_path()
    if not nmap_path:
        logger.warning("nmap not available - Ticketbleed test skipped")
        return VulnerabilityCheckResult(
            vulnerability_name="Ticketbleed",
            cve_id="CVE-2016-9244",
            vulnerable=False,
            severity=Severity.OK,
            description="TLS session ticket handling vulnerability that allows reading server memory (test skipped - nmap required)",
            recommendation="Install nmap to enable Ticketbleed testing",
        )
    
    try:
        success, stdout, stderr = run_nmap_script(
            host, port, "ssl-ticketbleed", timeout
        )
        if not success:
            logger.warning(f"nmap Ticketbleed check failed: {stderr}")
            return VulnerabilityCheckResult(
                vulnerability_name="Ticketbleed",
                cve_id="CVE-2016-9244",
                vulnerable=False,
                severity=Severity.OK,
                description="TLS session ticket handling vulnerability that allows reading server memory (test failed - nmap error)",
                recommendation="Check nmap installation and network connectivity",
            )
        
        parsed = parse_nmap_output(stdout, "ssl-ticketbleed")
        vulnerable = parsed["vulnerable"]
        details = " ".join(parsed["details"]) if parsed["details"] else ""
        
        description = "TLS session ticket handling vulnerability that allows reading server memory"
        if details:
            description += f" - {details}"
        if parsed["state"] == "UNKNOWN":
            description += " (nmap check completed, no vulnerability detected)"
        
        return VulnerabilityCheckResult(
            vulnerability_name="Ticketbleed",
            cve_id="CVE-2016-9244",
            vulnerable=vulnerable,
            severity=Severity.FAIL if vulnerable else Severity.OK,
            description=description,
            recommendation="Update F5 BIG-IP firmware or disable session tickets" if vulnerable else None,
        )
    except Exception as e:
        logger.error(f"Error running nmap Ticketbleed check: {e}")
        return VulnerabilityCheckResult(
            vulnerability_name="Ticketbleed",
            cve_id="CVE-2016-9244",
            vulnerable=False,
            severity=Severity.OK,
            description="TLS session ticket handling vulnerability that allows reading server memory (test failed)",
            recommendation="Check nmap installation",
        )


def check_logjam(host: str, port: int, timeout: float = 10.0) -> VulnerabilityCheckResult:
    """
    Check for Logjam vulnerability (CVE-2015-4000).
    
    Logjam is a vulnerability in Diffie-Hellman key exchange that allows
    man-in-the-middle attacks when using weak DH parameters.
    
    Requires nmap to be installed. Returns a result indicating test was skipped
    if nmap is not available.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        VulnerabilityCheckResult
    """
    logger.debug(f"Checking Logjam vulnerability for {host}:{port}")
    
    nmap_path = get_nmap_path()
    if not nmap_path:
        logger.warning("nmap not available - Logjam test skipped")
        return VulnerabilityCheckResult(
            vulnerability_name="Logjam",
            cve_id="CVE-2015-4000",
            vulnerable=False,
            severity=Severity.OK,
            description="Weak Diffie-Hellman parameters vulnerability that allows man-in-the-middle attacks (test skipped - nmap required)",
            recommendation="Install nmap to enable Logjam testing",
        )
    
    try:
        success, stdout, stderr = run_nmap_script(
            host, port, "ssl-dh-params", timeout
        )
        if not success:
            logger.warning(f"nmap Logjam check failed: {stderr}")
            return VulnerabilityCheckResult(
                vulnerability_name="Logjam",
                cve_id="CVE-2015-4000",
                vulnerable=False,
                severity=Severity.OK,
                description="Weak Diffie-Hellman parameters vulnerability that allows man-in-the-middle attacks (test failed - nmap error)",
                recommendation="Check nmap installation and network connectivity",
            )
        
        parsed = parse_nmap_output(stdout, "ssl-dh-params")
        vulnerable = parsed["vulnerable"]
        details = " ".join(parsed["details"]) if parsed["details"] else ""
        
        # Check for weak DH parameters in output
        if "1024" in stdout or "512" in stdout:
            vulnerable = True
        
        description = "Weak Diffie-Hellman parameters vulnerability that allows man-in-the-middle attacks"
        if details:
            description += f" - {details}"
        if parsed["state"] == "UNKNOWN":
            description += " (nmap check completed, no vulnerability detected)"
        
        return VulnerabilityCheckResult(
            vulnerability_name="Logjam",
            cve_id="CVE-2015-4000",
            vulnerable=vulnerable,
            severity=Severity.WARN if vulnerable else Severity.OK,
            description=description,
            recommendation="Use DH parameters >= 2048 bits or use ECDHE" if vulnerable else None,
        )
    except Exception as e:
        logger.error(f"Error running nmap Logjam check: {e}")
        return VulnerabilityCheckResult(
            vulnerability_name="Logjam",
            cve_id="CVE-2015-4000",
            vulnerable=False,
            severity=Severity.OK,
            description="Weak Diffie-Hellman parameters vulnerability that allows man-in-the-middle attacks (test failed)",
            recommendation="Check nmap installation",
        )


def check_ccs_injection(host: str, port: int, timeout: float = 10.0) -> VulnerabilityCheckResult:
    """
    Check for CCS Injection vulnerability (CVE-2014-0224).
    
    CCS (Change Cipher Spec) Injection is a vulnerability that allows
    man-in-the-middle attacks by injecting a ChangeCipherSpec message.
    
    Requires nmap to be installed. Returns a result indicating test was skipped
    if nmap is not available.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        VulnerabilityCheckResult
    """
    logger.debug(f"Checking CCS Injection vulnerability for {host}:{port}")
    
    nmap_path = get_nmap_path()
    if not nmap_path:
        logger.warning("nmap not available - CCS Injection test skipped")
        return VulnerabilityCheckResult(
            vulnerability_name="CCS Injection",
            cve_id="CVE-2014-0224",
            vulnerable=False,
            severity=Severity.OK,
            description="Change Cipher Spec injection vulnerability that allows man-in-the-middle attacks (test skipped - nmap required)",
            recommendation="Install nmap to enable CCS Injection testing",
        )
    
    try:
        success, stdout, stderr = run_nmap_script(
            host, port, "ssl-ccs-injection", timeout
        )
        if not success:
            logger.warning(f"nmap CCS Injection check failed: {stderr}")
            return VulnerabilityCheckResult(
                vulnerability_name="CCS Injection",
                cve_id="CVE-2014-0224",
                vulnerable=False,
                severity=Severity.OK,
                description="Change Cipher Spec injection vulnerability that allows man-in-the-middle attacks (test failed - nmap error)",
                recommendation="Check nmap installation and network connectivity",
            )
        
        parsed = parse_nmap_output(stdout, "ssl-ccs-injection")
        vulnerable = parsed["vulnerable"]
        details = " ".join(parsed["details"]) if parsed["details"] else ""
        
        description = "Change Cipher Spec injection vulnerability that allows man-in-the-middle attacks"
        if details:
            description += f" - {details}"
        if parsed["state"] == "UNKNOWN":
            description += " (nmap check completed, no vulnerability detected)"
        
        return VulnerabilityCheckResult(
            vulnerability_name="CCS Injection",
            cve_id="CVE-2014-0224",
            vulnerable=vulnerable,
            severity=Severity.FAIL if vulnerable else Severity.OK,
            description=description,
            recommendation="Update OpenSSL to version 1.0.1h or later" if vulnerable else None,
        )
    except Exception as e:
        logger.error(f"Error running nmap CCS Injection check: {e}")
        return VulnerabilityCheckResult(
            vulnerability_name="CCS Injection",
            cve_id="CVE-2014-0224",
            vulnerable=False,
            severity=Severity.OK,
            description="Change Cipher Spec injection vulnerability that allows man-in-the-middle attacks (test failed)",
            recommendation="Check nmap installation",
        )


def check_cryptographic_flaws(
    host: str,
    port: int,
    timeout: float = 10.0,
    only_vulnerabilities: Optional[List[str]] = None,
    progress_callback: Optional[Callable[[str, Optional[int], Optional[int]], None]] = None,
) -> List[VulnerabilityCheckResult]:
    """
    Check for all known cryptographic vulnerabilities.
    
    All tests require nmap to be installed. Tests are skipped if nmap is not available.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        only_vulnerabilities: Optional list of vulnerability names to check.
                            If None, all vulnerabilities are checked.
                            Valid names: heartbleed, drown, poodle, ccs-injection, freak, logjam, ticketbleed, sweet32
        
    Returns:
        List of VulnerabilityCheckResult
    """
    logger.info(f"Checking cryptographic vulnerabilities for {host}:{port}...")
    
    # Ensure nmap is available (will attempt download if not found)
    nmap_available, nmap_path = ensure_nmap_available()
    if nmap_available:
        logger.info(f"Using nmap for vulnerability scanning: {nmap_path}")
    else:
        logger.warning(
            "nmap not available - vulnerability tests will be skipped. "
            "Install nmap for vulnerability testing."
        )
    
    results = []
    
    # Mapping of vulnerability names to check functions (defined here after all functions)
    VULNERABILITY_CHECKS = {
        "heartbleed": check_heartbleed,
        "drown": check_drown,
        "poodle": check_poodle,
        "ccs-injection": check_ccs_injection,
        "ccs": check_ccs_injection,  # Alias
        "freak": check_freak,
        "logjam": check_logjam,
        "ticketbleed": check_ticketbleed,
        "sweet32": check_sweet32,
    }
    
    # Determine which vulnerabilities to check
    if only_vulnerabilities:
        # Normalize vulnerability names (lowercase, handle aliases)
        normalized_names = [name.lower().strip() for name in only_vulnerabilities]
        checks_to_run = []
        
        for name in normalized_names:
            if name in VULNERABILITY_CHECKS:
                checks_to_run.append(VULNERABILITY_CHECKS[name])
            else:
                logger.warning(f"Unknown vulnerability name: {name}. Skipping.")
                logger.info(f"Available vulnerabilities: {', '.join(VULNERABILITY_CHECKS.keys())}")
    else:
        # Check all vulnerabilities (default behavior)
        # Ordered by priority: Critical first, then important, then others
        checks_to_run = [
            check_heartbleed,  # Critical
            check_drown,  # Critical
            check_poodle,  # High
            check_ccs_injection,  # High
            check_freak,  # High
            check_logjam,  # Medium-High
            check_ticketbleed,  # Medium (F5 BIG-IP)
            check_sweet32,  # Low-Medium
        ]
    
    # Run selected checks
    total_checks = len(checks_to_run)
    for index, check_func in enumerate(checks_to_run, 1):
        try:
            if progress_callback and total_checks > 0:
                progress_callback("Checking security vulnerabilities...", index - 1, total_checks)
            results.append(check_func(host, port, timeout))
            if progress_callback and total_checks > 0:
                progress_callback("Checking security vulnerabilities...", index, total_checks)
        except Exception as e:
            logger.error(f"Error running {check_func.__name__}: {e}")
            # Create a failed result for this check
            vuln_name = check_func.__name__.replace("check_", "").replace("_", " ").title()
            results.append(
                VulnerabilityCheckResult(
                    vulnerability_name=vuln_name,
                    cve_id=None,
                    vulnerable=False,
                    severity=Severity.OK,
                    description=f"Test failed: {str(e)}",
                    recommendation="Check nmap installation and network connectivity",
                )
            )
            if progress_callback and total_checks > 0:
                progress_callback("Checking security vulnerabilities...", index, total_checks)
    
    return results
