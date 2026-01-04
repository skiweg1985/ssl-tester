"""OCSP responder reachability checks and validation."""

import logging
from typing import List, Optional, Tuple, Callable
import base64
import httpx
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from ssl_tester.models import CertificateInfo, OSPCheckResult, Severity, CRLCheckResult
from ssl_tester.http_client import create_http_client
from ssl_tester.certificate import _load_cert_with_cache

logger = logging.getLogger(__name__)


def check_ocsp_reachability(
    cert_info: CertificateInfo,
    cert_der: Optional[bytes] = None,
    issuer_cert_der: Optional[bytes] = None,
    timeout: float = 10.0,
    proxy: Optional[str] = None,
    crl_results: Optional[List[CRLCheckResult]] = None,
    progress_callback: Optional[Callable[[str, Optional[int], Optional[int]], None]] = None,
) -> List[OSPCheckResult]:
    """
    Check reachability and validate OCSP responders.

    Args:
        cert_info: Certificate to check (typically leaf)
        issuer_cert_der: Issuer certificate (DER) - required for OCSP request building
        timeout: HTTP request timeout in seconds
        crl_results: Optional list of CRL check results to use as fallback if OCSP fails

    Returns:
        List of OSPCheckResult for each OCSP URL
    """
    results: List[OSPCheckResult] = []

    # Check if CRL is available and successful for fallback
    crl_available = False
    crl_successful = False
    if crl_results:
        logger.debug(f"Checking {len(crl_results)} CRL results for fallback")
        # Check if any CRL check was successful (reachable and no errors)
        # Prefer CRL for leaf certificate, but any successful CRL is acceptable
        for crl_result in crl_results:
            logger.debug(f"CRL result: url={crl_result.url}, reachable={crl_result.reachable}, severity={crl_result.severity}, cert_type={crl_result.certificate_type}")
            if crl_result.reachable:
                crl_available = True
                # Check if this CRL is for the leaf certificate
                is_leaf_crl = (
                    crl_result.certificate_type == "Leaf" or
                    (crl_result.certificate_subject and cert_info.subject == crl_result.certificate_subject)
                )
                if crl_result.severity == Severity.OK:
                    crl_successful = True
                    logger.debug(f"Found successful CRL: {crl_result.url}, is_leaf={is_leaf_crl}")
                    # If this is leaf CRL and successful, we're done
                    if is_leaf_crl:
                        logger.debug(f"Found successful CRL for leaf certificate: {crl_result.url}")
                        break
        logger.debug(f"CRL fallback status: available={crl_available}, successful={crl_successful}")

    total_ocsp_urls = len(cert_info.ocsp_responder_urls) if cert_info.ocsp_responder_urls else 0
    current_index = 0
    
    for ocsp_url in cert_info.ocsp_responder_urls:
        if cert_der and issuer_cert_der:
            # Build proper OCSP request with POST
            result = _check_ocsp_with_request(
                cert_der, issuer_cert_der, ocsp_url, timeout, proxy, crl_available, crl_successful
            )
        else:
            # If we don't have cert_der/issuer_cert_der, we can't build proper OCSP request
            # This should not happen in normal flow, but log a warning
            logger.warning(f"Cannot build OCSP request for {ocsp_url}: missing certificate data")
            result = OSPCheckResult(
                url=ocsp_url,
                reachable=False,
                error="Cannot build OCSP request: missing certificate or issuer certificate",
                severity=Severity.WARN,
            )
        results.append(result)
        
        # Update progress
        current_index += 1
        if progress_callback and total_ocsp_urls > 0:
            progress_callback("Checking OCSP reachability...", current_index, total_ocsp_urls)

    return results


def _parse_ocsp_response(response_content: bytes) -> Tuple[Severity, Optional[str]]:
    """
    Parse OCSP response and determine severity and error message.

    Args:
        response_content: Raw OCSP response bytes

    Returns:
        Tuple of (severity, error_message)
    """
    try:
        ocsp_response = ocsp.load_der_ocsp_response(response_content)
        
        # Check response status
        response_status = ocsp_response.response_status
        if response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
            # Get certificate status
            cert_status = None
            revocation_time = None
            revocation_reason = None
            
            for single_response in ocsp_response.responses:
                cert_status = single_response.certificate_status
                # Extract revocation information if available
                if cert_status == ocsp.OCSPCertStatus.REVOKED:
                    revocation_time = single_response.revocation_time
                    revocation_reason = getattr(single_response, 'revocation_reason', None)
                break
            
            if cert_status == ocsp.OCSPCertStatus.GOOD:
                return Severity.OK, None
            elif cert_status == ocsp.OCSPCertStatus.REVOKED:
                error_msg = "Certificate is REVOKED according to OCSP"
                if revocation_time:
                    error_msg += f" (revoked at: {revocation_time})"
                if revocation_reason:
                    error_msg += f" (reason: {revocation_reason})"
                return Severity.FAIL, error_msg
            else:
                return Severity.WARN, f"OCSP certificate status: {cert_status}"
        elif response_status == ocsp.OCSPResponseStatus.UNAUTHORIZED:
            # UNAUTHORIZED means the responder is reachable but refuses to answer
            # This is often due to responder policies (e.g., requiring signed requests)
            # We cannot check revocation status via OCSP in this case
            # Note: This will be handled by the caller if CRL is available
            return Severity.WARN, (
                "OCSP responder returned UNAUTHORIZED - responder is reachable but "
                "refuses to answer (may require signed requests or have access restrictions). "
                "Revocation status cannot be verified via OCSP."
            )
        else:
            return Severity.WARN, f"OCSP response status: {response_status}"
    except Exception as e:
        logger.warning(f"Error parsing OCSP response: {e}")
        return Severity.WARN, f"OCSP response parsing failed: {e}"


def _check_ocsp_with_request(
    cert_der: bytes,
    issuer_cert_der: bytes,
    ocsp_url: str,
    timeout: float,
    proxy: Optional[str] = None,
    crl_available: bool = False,
    crl_successful: bool = False,
) -> OSPCheckResult:
    """
    Check OCSP responder with POST request, falling back to GET if POST returns UNAUTHORIZED.
    This mimics real-world client behavior per RFC 6960.
    If OCSP returns UNAUTHORIZED and CRL is available, severity is reduced to OK.

    Args:
        cert_der: Certificate to check (DER)
        issuer_cert_der: Issuer certificate (DER)
        ocsp_url: OCSP responder URL
        timeout: Request timeout
        crl_available: Whether CRL is available as fallback
        crl_successful: Whether CRL check was successful

    Returns:
        OSPCheckResult with validation status
    """
    try:
        # Parse certificates
        cert, _ = _load_cert_with_cache(cert_der, pem=False)
        issuer_cert, _ = _load_cert_with_cache(issuer_cert_der, pem=False)

        # Build OCSP request
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer_cert, hashes.SHA256())
        request = builder.build()
        request_der = request.public_bytes(serialization.Encoding.DER)

        client = create_http_client(proxy=proxy, timeout=timeout, follow_redirects=False)
        try:
            # First, try POST request (preferred method per RFC 6960)
            response = client.post(
                ocsp_url,
                content=request_der,
                headers={
                    "Content-Type": "application/ocsp-request",
                    "User-Agent": "ssl-tester/0.1.0",
                },
            )

            status_code = response.status_code
            severity = Severity.WARN
            error: Optional[str] = None

            if status_code == 200:
                # Parse OCSP response to check if it's UNAUTHORIZED
                try:
                    ocsp_response = ocsp.load_der_ocsp_response(response.content)
                    response_status = ocsp_response.response_status
                    
                    # If POST returned UNAUTHORIZED, try GET as fallback (like real clients do)
                    if response_status == ocsp.OCSPResponseStatus.UNAUTHORIZED:
                        logger.debug(f"OCSP POST returned UNAUTHORIZED for {ocsp_url}, trying GET fallback")
                        # Build GET URL with Base64-encoded request (RFC 6960 format)
                        # Remove padding and replace +/ with -_ for URL-safe encoding
                        request_b64 = base64.urlsafe_b64encode(request_der).decode('ascii').rstrip('=')
                        get_url = f"{ocsp_url.rstrip('/')}/{request_b64}"
                        
                        try:
                            get_response = client.get(
                                get_url,
                                headers={
                                    "User-Agent": "ssl-tester/0.1.0",
                                },
                            )
                            
                            if get_response.status_code == 200:
                                severity, error = _parse_ocsp_response(get_response.content)
                                logger.debug(f"OCSP GET fallback succeeded for {ocsp_url}")
                                # Check if GET also returned UNAUTHORIZED
                                if error and "UNAUTHORIZED" in error:
                                    if crl_successful:
                                        severity = Severity.OK
                                        error = (
                                            "OCSP responder returned UNAUTHORIZED (both POST and GET), but CRL is available and successful. "
                                            "Revocation status is verified via CRL instead."
                                        )
                                    elif crl_available:
                                        error = (
                                            f"{error} CRL is available as fallback for revocation checking."
                                        )
                            else:
                                severity, error = _parse_ocsp_response(response.content)  # Use original POST response
                                # If CRL is available and successful, reduce severity
                                if error and "UNAUTHORIZED" in error:
                                    if crl_successful:
                                        severity = Severity.OK
                                        error = (
                                            "OCSP responder returned UNAUTHORIZED, but CRL is available and successful. "
                                            "Revocation status is verified via CRL instead."
                                        )
                                        logger.debug(f"OCSP UNAUTHORIZED but CRL successful, setting severity to OK")
                                    elif crl_available:
                                        error = (
                                            f"{error} CRL is available as fallback for revocation checking."
                                        )
                                    else:
                                        error = f"OCSP POST returned UNAUTHORIZED, GET fallback returned HTTP {get_response.status_code}"
                        except Exception as get_error:
                            logger.debug(f"OCSP GET fallback failed: {get_error}")
                            severity, error = _parse_ocsp_response(response.content)  # Use original POST response
                            # If CRL is available and successful, reduce severity
                            if error and "UNAUTHORIZED" in error:
                                if crl_successful:
                                    severity = Severity.OK
                                    error = (
                                        "OCSP responder returned UNAUTHORIZED, but CRL is available and successful. "
                                        "Revocation status is verified via CRL instead."
                                    )
                                    logger.debug(f"OCSP UNAUTHORIZED but CRL successful, setting severity to OK")
                                elif crl_available:
                                    error = (
                                        f"{error} CRL is available as fallback for revocation checking."
                                    )
                                else:
                                    error = f"OCSP POST returned UNAUTHORIZED, GET fallback failed: {get_error}"
                    else:
                        # Normal response parsing
                        severity, error = _parse_ocsp_response(response.content)
                        # If UNAUTHORIZED and CRL is available, adjust severity
                        if error and "UNAUTHORIZED" in error:
                            logger.debug(f"OCSP returned UNAUTHORIZED, crl_available={crl_available}, crl_successful={crl_successful}")
                            if crl_successful:
                                severity = Severity.OK
                                error = (
                                    "OCSP responder returned UNAUTHORIZED, but CRL is available and successful. "
                                    "Revocation status is verified via CRL instead."
                                )
                                logger.debug(f"OCSP UNAUTHORIZED but CRL successful, setting severity to OK")
                            elif crl_available:
                                error = (
                                    f"{error} CRL is available as fallback for revocation checking."
                                )
                except Exception as parse_error:
                    # If we can't parse the response, treat it as a parsing error
                    logger.warning(f"Error parsing OCSP response: {parse_error}")
                    severity = Severity.WARN
                    error = f"OCSP response parsing failed: {parse_error}"
            elif status_code == 405:
                # Method Not Allowed - try GET as fallback
                logger.debug(f"OCSP POST returned 405 for {ocsp_url}, trying GET fallback")
                request_b64 = base64.urlsafe_b64encode(request_der).decode('ascii').rstrip('=')
                get_url = f"{ocsp_url.rstrip('/')}/{request_b64}"
                
                try:
                    get_response = client.get(
                        get_url,
                        headers={
                            "User-Agent": "ssl-tester/0.1.0",
                        },
                    )
                    
                    if get_response.status_code == 200:
                        severity, error = _parse_ocsp_response(get_response.content)
                        status_code = 200  # Update status code to reflect successful GET
                        logger.debug(f"OCSP GET fallback succeeded for {ocsp_url}")
                    else:
                        severity = Severity.WARN
                        error = f"OCSP responder returned HTTP 405 (Method Not Allowed), GET fallback returned HTTP {get_response.status_code}"
                except Exception as get_error:
                    logger.debug(f"OCSP GET fallback failed: {get_error}")
                    severity = Severity.WARN
                    error = f"OCSP responder returned HTTP 405 (Method Not Allowed), GET fallback failed: {get_error}"
            elif status_code == 404:
                # Not Found - this is what we get with HEAD/GET, but shouldn't happen with POST
                severity = Severity.WARN
                error = "OCSP responder returned HTTP 404 (Not Found) - this may indicate a misconfigured OCSP endpoint"
            else:
                severity = Severity.WARN
                error = f"OCSP responder returned HTTP {status_code}"

            return OSPCheckResult(
                url=ocsp_url,
                reachable=True,
                status_code=status_code,
                severity=severity,
                error=error,
            )
        finally:
            client.close()

    except httpx.TimeoutException:
        return OSPCheckResult(
            url=ocsp_url,
            reachable=False,
            error=f"Request timeout after {timeout}s",
            severity=Severity.WARN,
        )
    except httpx.RequestError as e:
        return OSPCheckResult(
            url=ocsp_url,
            reachable=False,
            error=str(e),
            severity=Severity.WARN,
        )
    except Exception as e:
        logger.exception(f"Unexpected error checking OCSP {ocsp_url}: {e}")
        return OSPCheckResult(
            url=ocsp_url,
            reachable=False,
            error=f"Unexpected error: {e}",
            severity=Severity.WARN,
        )



