"""CRL Distribution Point reachability checks."""

import logging
import warnings
from typing import List, Optional
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ssl_tester.models import CertificateInfo, CRLCheckResult, Severity
from ssl_tester.http_client import create_http_client
from ssl_tester.certificate import _load_cert_with_cache, parse_certificate

logger = logging.getLogger(__name__)


def check_crl_reachability(
    cert_infos: List[CertificateInfo],
    timeout: float = 10.0,
    max_redirects: int = 5,
    max_crl_bytes: int = 20 * 1024 * 1024,
    no_redirects: bool = False,
    proxy: Optional[str] = None,
    cert_der_map: Optional[dict[str, bytes]] = None,
    issuer_map: Optional[dict[str, bytes]] = None,
    leaf_cert_info: Optional[CertificateInfo] = None,
    intermediate_cert_infos: Optional[List[CertificateInfo]] = None,
    root_cert_info: Optional[CertificateInfo] = None,
) -> List[CRLCheckResult]:
    """
    Check reachability of all CRL Distribution Points and validate them.

    Args:
        cert_infos: List of certificates to check (leaf + intermediates)
        timeout: HTTP request timeout in seconds
        max_redirects: Maximum number of redirects to follow
        max_crl_bytes: Maximum CRL size to download
        no_redirects: Do not follow redirects
        cert_der_map: Map of certificate fingerprint to DER bytes
        issuer_map: Map of issuer DN to issuer certificate DER bytes

    Returns:
        List of CRLCheckResult for each CRL URL
    """
    results: List[CRLCheckResult] = []
    # Don't skip duplicate URLs - we need to check each certificate's CRL URLs
    # to detect misconfigurations (e.g., leaf cert pointing to root CA CRL)

    for cert_info in cert_infos:
        # Determine certificate type
        cert_type = None
        is_intermediate = False
        if leaf_cert_info and cert_info.fingerprint_sha256 == leaf_cert_info.fingerprint_sha256:
            cert_type = "Leaf"
        elif root_cert_info and cert_info.fingerprint_sha256 == root_cert_info.fingerprint_sha256:
            cert_type = "Root"
        elif intermediate_cert_infos:
            for intermediate in intermediate_cert_infos:
                if cert_info.fingerprint_sha256 == intermediate.fingerprint_sha256:
                    cert_type = "Intermediate"
                    is_intermediate = True
                    break
        
        # Check CRL URLs from the certificate itself (for certificates issued by this cert)
        # CRITICAL: For intermediate CAs, the CDP should contain the Root CA CRL URL to check
        # if the intermediate CA itself is revoked. The Root CA CRL URL comes from the
        # intermediate CA's CDP, not from the root CA certificate.
        for crl_url in cert_info.crl_distribution_points:
            logger.debug(f"Checking CRL URL '{crl_url}' for certificate with Subject='{cert_info.subject}', Issuer='{cert_info.issuer}'")

            # Find issuer certificate for this cert
            issuer_cert_der = None
            if issuer_map:
                issuer_cert_der = issuer_map.get(cert_info.issuer)
                if issuer_cert_der:
                    logger.debug(f"Found issuer certificate for CRL verification: cert issuer='{cert_info.issuer}'")
                else:
                    logger.debug(f"Issuer certificate not found in issuer_map for: '{cert_info.issuer}' (available keys: {list(issuer_map.keys())[:3]}...)")

            # For intermediate CAs: Also check if this CRL is signed by the Root CA
            # If so, check if the intermediate CA itself is revoked in this CRL
            root_cert_der = None
            if is_intermediate and root_cert_info:
                if issuer_map:
                    root_cert_der = issuer_map.get(root_cert_info.subject)
                    if not root_cert_der and cert_der_map and root_cert_info.fingerprint_sha256 in cert_der_map:
                        root_cert_der = cert_der_map[root_cert_info.fingerprint_sha256]

            logger.debug(f"Calling _check_single_crl with issuer_cert_der={'present' if issuer_cert_der else 'None'}, root_cert_der={'present' if root_cert_der else 'None'}")
            result = _check_single_crl(
                crl_url,
                timeout,
                max_redirects,
                max_crl_bytes,
                no_redirects,
                proxy,
                cert_info=cert_info,
                issuer_cert_der=issuer_cert_der,
                issuer_map=issuer_map,
                root_cert_info=root_cert_info if is_intermediate else None,
                root_cert_der=root_cert_der if is_intermediate else None,
                is_intermediate_ca=is_intermediate,
            )
            # Add certificate information to result
            result.certificate_subject = cert_info.subject
            result.certificate_type = cert_type
            results.append(result)

    return results


def _check_single_crl(
    url: str,
    timeout: float,
    max_redirects: int,
    max_crl_bytes: int,
    no_redirects: bool,
    proxy: Optional[str] = None,
    cert_info: Optional[CertificateInfo] = None,
    issuer_cert_der: Optional[bytes] = None,
    issuer_map: Optional[dict[str, bytes]] = None,
    root_cert_info: Optional[CertificateInfo] = None,
    root_cert_der: Optional[bytes] = None,
    is_intermediate_ca: bool = False,
) -> CRLCheckResult:
    """
    Check reachability of a single CRL URL and validate it against the certificate.

    Args:
        url: CRL URL to check
        timeout: Request timeout
        max_redirects: Max redirects
        max_crl_bytes: Max size
        no_redirects: Don't follow redirects
        cert_info: Certificate that references this CRL (for validation)
        issuer_cert_der: Issuer certificate DER (to verify CRL signature)
        root_cert_info: Root CA certificate info (for intermediate CA revocation check)
        root_cert_der: Root CA certificate DER (for intermediate CA revocation check)

    Returns:
        CRLCheckResult
    """
    # Handle LDAP URLs (not supported in MVP)
    if url.startswith("ldap://") or url.startswith("ldaps://"):
        logger.warning(f"LDAP CRL URL not supported: {url}")
        return CRLCheckResult(
            url=url,
            reachable=False,
            error="LDAP URLs not supported",
            severity=Severity.WARN,
        )

    # HTTP/HTTPS URLs
    redirect_chain: List[str] = []
    max_redirects_actual = 0 if no_redirects else max_redirects

    try:
        client = create_http_client(
            proxy=proxy,
            timeout=timeout,
            follow_redirects=not no_redirects,
            max_redirects=max_redirects_actual,
        )
        try:
            # Use stream=True to check size before downloading full content
            # Some CRL servers (e.g., Microsoft) require Accept header and specific User-Agent
            # Using curl-like User-Agent for better compatibility with CRL servers
            response = client.get(
                url,
                headers={
                    "User-Agent": "curl/7.0",
                    "Accept": "application/pkix-crl,application/x-pkcs7-crl,application/pkcs7-mime,*/*",
                },
                follow_redirects=not no_redirects,
            )

            # Track redirects
            if hasattr(response, "history"):
                redirect_chain = [str(r.url) for r in response.history]
            redirect_chain.append(str(response.url))

            status_code = response.status_code
            content_type = response.headers.get("Content-Type", "")

            # Check if it's a valid CRL content type
            valid_content_types = [
                "application/pkix-crl",
                "application/x-pkcs7-crl",
                "application/pkcs7-mime",
                "application/x-x509-ca-cert",  # Sometimes used
                "application/octet-stream",  # Some servers (e.g., Microsoft) use this for CRLs
                "binary/octet-stream",  # Some servers use this variant (non-standard but common)
            ]
            # Accept any content type containing "octet-stream" (flexible for various server implementations)
            is_valid_content_type = any(ct in content_type.lower() for ct in valid_content_types) or "octet-stream" in content_type.lower()

            # Get actual content size (from header or content)
            content_length = response.headers.get("Content-Length")
            size_bytes: Optional[int] = None
            
            # Read content with size limit
            content = b""
            if content_length:
                try:
                    size_bytes = int(content_length)
                    if size_bytes > max_crl_bytes:
                        return CRLCheckResult(
                            url=url,
                            reachable=True,
                            status_code=status_code,
                            content_type=content_type,
                            size_bytes=size_bytes,
                            redirect_chain=redirect_chain,
                            error=f"CRL too large: {size_bytes} bytes (max: {max_crl_bytes})",
                            severity=Severity.WARN,
                        )
                except ValueError:
                    pass

            # Read content in chunks to respect size limit
            try:
                for chunk in response.iter_bytes(chunk_size=8192):
                    content += chunk
                    if len(content) > max_crl_bytes:
                        return CRLCheckResult(
                            url=url,
                            reachable=True,
                            status_code=status_code,
                            content_type=content_type,
                            size_bytes=len(content),
                            redirect_chain=redirect_chain,
                            error=f"CRL too large: {len(content)} bytes (max: {max_crl_bytes})",
                            severity=Severity.WARN,
                        )
            except httpx.ReadTimeout:
                return CRLCheckResult(
                    url=url,
                    reachable=True,
                    status_code=status_code,
                    content_type=content_type,
                    error="Read timeout while downloading CRL",
                    redirect_chain=redirect_chain,
                    severity=Severity.WARN,
                )

            # Update size_bytes with actual content size
            if not size_bytes:
                size_bytes = len(content)

            # Try to validate CRL format and signature
            is_valid_crl_format = False
            crl = None
            crl_signature_valid = False
            revocation_status = None
            error_msg: Optional[str] = None
            
            if content and status_code == 200:
                try:
                    # Try DER format first
                    try:
                        crl = x509.load_der_x509_crl(content)
                        is_valid_crl_format = True
                        logger.debug(f"CRL from {url} is valid DER format")
                    except Exception as der_e:
                        logger.debug(f"Failed to load as DER: {der_e}")
                        # Try PEM format
                        try:
                            crl = x509.load_pem_x509_crl(content)
                            is_valid_crl_format = True
                            logger.debug(f"CRL from {url} is valid PEM format")
                        except Exception as pem_e:
                            logger.debug(f"Failed to load as PEM: {pem_e}")
                            logger.debug(f"CRL from {url} could not be parsed as DER or PEM")
                            crl = None  # Explicitly set to None if both fail
                    
                    # Validate CRL signature and check revocation status if we have the CRL
                    # Note: Signature verification is optional - we still check revocation status even if signature verification fails
                    # Use 'is not None' instead of truthiness check, as CRL objects may evaluate to False in boolean context
                    if crl is not None:
                        logger.debug(f"CRL check passed: crl is not None, proceeding with signature verification")
                        # Try to verify CRL signature
                        # IMPORTANT: The CRL is signed by the certificate whose subject matches the CRL issuer
                        # NOT by the certificate that issued the certificate we're checking
                        crl_signature_valid = False
                        signature_error = None
                        
                        # Get CRL issuer - this is who signed the CRL
                        crl_issuer = crl.issuer.rfc4514_string()
                        logger.debug(f"CRL issuer (who signed the CRL): '{crl_issuer}'")
                        
                        # CRITICAL: Check if CRL issuer matches certificate issuer or certificate subject
                        # The CRL should be signed by:
                        # 1. The certificate that issued the certificate we're checking (normal case)
                        # 2. The certificate itself (self-signed CRL - legitimate for intermediate CAs)
                        # If neither matches, this is a misconfiguration (e.g., leaf cert pointing to unrelated CA CRL)
                        crl_issuer_mismatch = False
                        matches_subject = False  # Initialize for later use
                        if cert_info:
                            # Check if CRL issuer matches certificate issuer (normal case)
                            matches_issuer = (crl_issuer == cert_info.issuer)
                            # Check if CRL issuer matches certificate subject (self-signed CRL - legitimate for intermediate CAs)
                            matches_subject = (crl_issuer == cert_info.subject)
                            
                            if not matches_issuer and not matches_subject:
                                crl_issuer_mismatch = True
                                logger.warning(
                                    f"CRL issuer '{crl_issuer}' does not match certificate issuer '{cert_info.issuer}' "
                                    f"nor certificate subject '{cert_info.subject}' "
                                    f"(CRL URL from certificate with subject '{cert_info.subject}') - MISCONFIGURATION"
                                )
                            elif matches_subject:
                                logger.info(
                                    f"CRL issuer '{crl_issuer}' matches certificate subject '{cert_info.subject}' "
                                    f"(self-signed CRL - legitimate for intermediate CAs)"
                                )
                        
                        # Find the certificate that signed the CRL (CRL issuer should match cert subject)
                        crl_signer_cert_der = None
                        if issuer_map:
                            crl_signer_cert_der = issuer_map.get(crl_issuer)
                            if crl_signer_cert_der:
                                logger.debug(f"Found CRL signer certificate from issuer_map for CRL issuer: '{crl_issuer}'")
                            else:
                                logger.debug(f"CRL signer certificate not found in issuer_map for CRL issuer: '{crl_issuer}' (available keys: {list(issuer_map.keys())[:3] if issuer_map else []}...)")
                        
                        # Fallback: if we don't have issuer_map or didn't find the cert, try the provided issuer_cert_der
                        # but only if it matches the CRL issuer
                        if not crl_signer_cert_der and issuer_cert_der:
                            try:
                                issuer_cert_info, _ = parse_certificate(issuer_cert_der)
                                if issuer_cert_info.subject == crl_issuer:
                                    crl_signer_cert_der = issuer_cert_der
                                    logger.debug(f"Using provided issuer_cert_der as CRL signer (subject matches CRL issuer)")
                                else:
                                    logger.debug(f"Provided issuer_cert_der subject '{issuer_cert_info.subject}' does not match CRL issuer '{crl_issuer}'")
                            except Exception as e:
                                logger.debug(f"Error checking issuer_cert_der: {e}")
                        
                        if crl_signer_cert_der:
                            logger.debug(f"Starting CRL signature verification with CRL signer certificate")
                            try:
                                crl_signer_cert, _ = _load_cert_with_cache(crl_signer_cert_der, pem=False)
                                crl_signer_cert_info, _ = parse_certificate(crl_signer_cert_der)
                                crl_signer_public_key = crl_signer_cert.public_key()
                                
                                logger.debug(f"CRL signer cert subject: '{crl_signer_cert_info.subject}'")
                                logger.debug(f"Certificate issuer (for reference): '{cert_info.issuer if cert_info else 'N/A'}'")
                                
                                # Try different verification methods based on cryptography version
                                # cryptography 45.0.0+ uses is_signature_valid(), older versions use verify_direct_signature()
                                if hasattr(crl, 'is_signature_valid'):
                                    # Newer API (cryptography 45.0.0+)
                                    crl_signature_valid = crl.is_signature_valid(crl_signer_public_key)
                                    logger.debug(f"is_signature_valid returned: {crl_signature_valid}")
                                    if not crl_signature_valid:
                                        # Include diagnostic info in error message
                                        signature_error = f"CRL signature is invalid (CRL issuer: '{crl_issuer}', CRL signer cert subject: '{crl_signer_cert_info.subject}')"
                                        logger.debug(f"Set signature_error: {signature_error}")
                                elif hasattr(crl, 'verify'):
                                    # Intermediate API (cryptography 41.0.0 - 44.x)
                                    try:
                                        crl.verify(crl_signer_public_key)
                                        crl_signature_valid = True
                                    except Exception as e:
                                        signature_error = f"CRL signature verification failed: {e}"
                                elif hasattr(crl, 'verify_direct_signature'):
                                    # Older API (pre-41.0.0)
                                    try:
                                        crl.verify_direct_signature(crl_signer_public_key)
                                        crl_signature_valid = True
                                    except Exception as e:
                                        signature_error = f"CRL signature verification failed: {e}"
                                else:
                                    signature_error = "CRL signature verification method not available"
                                
                                if crl_signature_valid:
                                    logger.debug(f"CRL signature verified successfully for {url}")
                                    # Note: CRL issuer mismatch is checked later (after revocation check)
                                elif signature_error:
                                    logger.debug(f"CRL signature verification failed for {url}: {signature_error}")
                            except Exception as e:
                                logger.debug(f"Error during CRL signature verification for {url}: {e}")
                                signature_error = f"Error verifying CRL signature: {e}"
                        else:
                            logger.debug(f"CRL signer certificate not available for signature verification (CRL issuer: '{crl_issuer}')")
                            if issuer_map:
                                signature_error = f"CRL signer certificate not found in issuer_map (CRL issuer: '{crl_issuer}')"
                            else:
                                signature_error = f"CRL signer certificate not available (CRL issuer: '{crl_issuer}', issuer_map not provided)"
                        
                        # CRITICAL: For intermediate CAs, FIRST check if this CRL is signed by the Root CA
                        # If so, this is the Root CA CRL from the intermediate CA's CDP, and we should
                        # check if the intermediate CA itself is revoked in this CRL BEFORE doing the normal check
                        intermediate_ca_revocation_checked = False
                        if root_cert_info and root_cert_der and cert_info:
                            try:
                                root_cert_info_parsed, _ = parse_certificate(root_cert_der)
                                # Check if CRL is signed by Root CA
                                if crl_issuer == root_cert_info_parsed.subject:
                                    logger.info(
                                        f"CRL from Intermediate CA CDP is signed by Root CA '{root_cert_info_parsed.subject}'. "
                                        f"Checking if Intermediate CA '{cert_info.subject}' (Serial: {cert_info.serial_number}) is revoked."
                                    )
                                    
                                    # Verify CRL signature with Root CA public key
                                    root_cert, _ = _load_cert_with_cache(root_cert_der, pem=False)
                                    root_public_key = root_cert.public_key()
                                    
                                    crl_signed_by_root = False
                                    if hasattr(crl, 'is_signature_valid'):
                                        crl_signed_by_root = crl.is_signature_valid(root_public_key)
                                    elif hasattr(crl, 'verify'):
                                        try:
                                            crl.verify(root_public_key)
                                            crl_signed_by_root = True
                                        except Exception:
                                            pass
                                    elif hasattr(crl, 'verify_direct_signature'):
                                        try:
                                            crl.verify_direct_signature(root_public_key)
                                            crl_signed_by_root = True
                                        except Exception:
                                            pass
                                    
                                    if crl_signed_by_root:
                                        logger.debug(f"CRL signature verified with Root CA public key")
                                        # Check if intermediate CA serial number is in this Root CA CRL
                                        try:
                                            intermediate_serial = int(cert_info.serial_number)
                                            revoked_serials = [entry.serial_number for entry in crl]
                                            if intermediate_serial in revoked_serials:
                                                # Find the revocation entry
                                                for entry in crl:
                                                    if entry.serial_number == intermediate_serial:
                                                        revocation_reason = None
                                                        try:
                                                            reason_ext = entry.extensions.get_extension_for_oid(
                                                                x509.oid.CRLEntryExtensionOID.CRL_REASON
                                                            )
                                                            revocation_reason = reason_ext.value
                                                        except x509.ExtensionNotFound:
                                                            pass
                                                        
                                                        reason_str = revocation_reason.reason.name if revocation_reason else "unspecified"
                                                        try:
                                                            revocation_date = entry.revocation_date_utc
                                                        except AttributeError:
                                                            revocation_date = entry.revocation_date
                                                        
                                                        logger.warning(
                                                            f"Intermediate CA serial {intermediate_serial} is REVOKED in Root CA CRL "
                                                            f"(reason: {reason_str}, date: {revocation_date})"
                                                        )
                                                        
                                                        # This is a FAIL - intermediate CA is revoked
                                                        return CRLCheckResult(
                                                            url=url,
                                                            reachable=True,
                                                            status_code=status_code,
                                                            content_type=content_type,
                                                            size_bytes=size_bytes,
                                                            redirect_chain=redirect_chain,
                                                            error=f"[Intermediate CA Revocation Check via Root CA CRL from CDP] Certificate is REVOKED (reason: {reason_str}, revoked on: {revocation_date})",
                                                            severity=Severity.FAIL,
                                                        )
                                                logger.debug(f"Intermediate CA serial {intermediate_serial} not found in Root CA CRL (not revoked)")
                                                # Mark that we checked intermediate CA revocation
                                                intermediate_ca_revocation_checked = True
                                                revocation_status = "not_revoked"
                                            else:
                                                logger.debug(f"Intermediate CA serial {intermediate_serial} not found in Root CA CRL revocation list (not revoked)")
                                                # Mark that we checked intermediate CA revocation
                                                intermediate_ca_revocation_checked = True
                                                revocation_status = "not_revoked"
                                        except (ValueError, AttributeError) as e:
                                            logger.debug(f"Could not check intermediate CA revocation status in Root CA CRL: {e}")
                                            intermediate_ca_revocation_checked = True
                                            revocation_status = "check_failed"
                                    else:
                                        logger.debug(f"CRL signature could not be verified with Root CA public key (CRL issuer: '{crl_issuer}', Root CA subject: '{root_cert_info_parsed.subject}')")
                            except Exception as e:
                                logger.debug(f"Error checking if CRL is signed by Root CA: {e}")
                        
                        # Check revocation status regardless of signature verification result
                        # This is the main goal: check if the certificate (host or intermediate) is revoked
                        # Skip this if we already checked intermediate CA revocation above
                        if cert_info and not intermediate_ca_revocation_checked:
                            try:
                                # Get certificate serial number
                                cert_serial = int(cert_info.serial_number)
                                
                                # Check if serial is in revoked list
                                revoked_serials = [entry.serial_number for entry in crl]
                                if cert_serial in revoked_serials:
                                    # Find the revocation entry
                                    for entry in crl:
                                        if entry.serial_number == cert_serial:
                                            revocation_reason = None
                                            try:
                                                reason_ext = entry.extensions.get_extension_for_oid(
                                                    x509.oid.CRLEntryExtensionOID.CRL_REASON
                                                )
                                                revocation_reason = reason_ext.value
                                            except x509.ExtensionNotFound:
                                                pass
                                            
                                            reason_str = revocation_reason.reason.name if revocation_reason else "unspecified"
                                            # Use UTC-aware method if available, fallback to deprecated method
                                            try:
                                                revocation_date = entry.revocation_date_utc
                                            except AttributeError:
                                                revocation_date = entry.revocation_date
                                            
                                            logger.warning(
                                                f"Certificate serial {cert_serial} is REVOKED in CRL "
                                                f"(reason: {reason_str}, date: {revocation_date})"
                                            )
                                            
                                            # This is a FAIL - certificate is revoked
                                            return CRLCheckResult(
                                                url=url,
                                                reachable=True,
                                                status_code=status_code,
                                                content_type=content_type,
                                                size_bytes=size_bytes,
                                                redirect_chain=redirect_chain,
                                                error=f"Certificate is REVOKED (reason: {reason_str}, revoked on: {revocation_date})",
                                                severity=Severity.FAIL,
                                            )
                                
                                logger.debug(f"Certificate serial {cert_serial} not found in CRL revocation list (not revoked)")
                                revocation_status = "not_revoked"
                            except (ValueError, AttributeError) as e:
                                logger.debug(f"Could not check revocation status: {e}")
                                # If revocation check fails, we still consider it OK if CRL is reachable and valid format
                                # The signature verification error will be shown as informational
                                revocation_status = "check_failed"
                        
                        # CRITICAL: Check for CRL issuer mismatch regardless of signature verification result
                        # This must be checked even if signature verification failed or wasn't performed
                        # IMPORTANT: This check happens AFTER signature verification, so we can use the result
                        if crl_issuer_mismatch:
                            # Always set error_msg for mismatch - this is a misconfiguration that must be reported
                            # If signature was valid but mismatch exists, we still report the mismatch
                            error_msg = (
                                f"CRL-Misconfiguration detected: The CRL is signed by '{crl_issuer}', "
                                f"but the certificate (Subject: '{cert_info.subject}') was issued by '{cert_info.issuer}'. "
                                f"The CRL should be signed either by '{cert_info.issuer}' (Certificate Issuer) "
                                f"or by '{cert_info.subject}' (Certificate Subject for self-signed CRL). "
                                f"This indicates a faulty CDP configuration."
                            )
                            logger.warning(error_msg)
                            # If signature was valid but mismatch exists, treat as invalid for severity calculation
                            if crl_signature_valid:
                                crl_signature_valid = False
                        
                        # Store signature error for reporting (but don't fail the check)
                        if signature_error and not error_msg:
                            error_msg = signature_error
                            logger.debug(f"Stored signature_error in error_msg: {signature_error}")
                        elif signature_error and error_msg:
                            # If we have both mismatch and signature error, combine them
                            error_msg = f"{error_msg} Additionally: {signature_error}"
                            logger.debug(f"Combined mismatch and signature errors")
                        else:
                            logger.debug(f"No signature_error to store (crl_signature_valid={crl_signature_valid})")
                    else:
                        logger.debug(f"After loading CRL: crl is None, is_valid_crl_format={is_valid_crl_format}")
                    
                    # If CRL was parsed but no issuer cert available for validation
                    if crl and not issuer_cert_der:
                        if cert_info and not error_msg:
                            error_msg = f"CRL signature validation skipped: issuer certificate not available (certificate issuer: '{cert_info.issuer}')"
                except Exception as e:
                    logger.debug(f"Error validating CRL format from {url}: {e}")
                    logger.debug(f"Exception type: {type(e)}, Exception args: {e.args}")
                    logger.debug(f"CRL state in exception handler: crl={'present' if crl else 'None'}")
                    if not error_msg:
                        error_msg = f"CRL format validation failed: {e}"
                    # Don't reset crl here - it might have been successfully loaded before the exception

            # Determine severity
            # Main goal: Check if certificate is revoked. Signature verification is important for trust.
            # CRITICAL: CRL issuer mismatch is always a FAIL, regardless of signature verification status
            if status_code == 200 and is_valid_content_type and is_valid_crl_format:
                # Check for CRL issuer mismatch first - this is always a FAIL
                if error_msg and "CRL-Misconfiguration" in error_msg:
                    severity = Severity.FAIL
                # If we successfully checked revocation status and certificate is not revoked
                elif revocation_status == "not_revoked":
                    if crl_signature_valid:
                        # Certificate is not revoked AND signature is valid - perfect
                        severity = Severity.OK
                        # Add info message for self-signed CRL if this is an intermediate CA
                        if is_intermediate_ca and cert_info and matches_subject and not error_msg:
                            error_msg = "[INFO] CRL is self-signed by the Intermediate CA. This is legitimate for CRLs of certificates issued by the Intermediate CA. To check if the Intermediate CA itself is revoked, a Root CA CRL URL should also be present in the CDP."
                    else:
                        # Certificate is not revoked BUT signature is invalid - this is a warning
                        # An invalid signature means we can't trust the CRL
                        severity = Severity.WARN
                        if not error_msg:
                            error_msg = "CRL signature verification failed: signature does not match issuer public key"
                elif revocation_status == "check_failed":
                    if crl_signature_valid:
                        # Revocation check failed but signature is valid - warning (can't verify revocation)
                        severity = Severity.WARN
                        if not error_msg:
                            error_msg = "Could not verify revocation status from CRL"
                    else:
                        # Both revocation check and signature verification failed - warning
                        severity = Severity.WARN
                        if not error_msg:
                            error_msg = "CRL signature verification failed and could not verify revocation status"
                elif crl_signature_valid:
                    # Signature valid but revocation status unknown (shouldn't happen, but handle it)
                    severity = Severity.OK
                else:
                    # Signature verification failed but CRL is reachable and valid format
                    # This is a warning - we can't trust the CRL without a valid signature
                    severity = Severity.WARN
                    # Keep error_msg for informational purposes (signature verification failed)
                    # Note: signature_error should already be in error_msg from line 336, but if not, use generic message
                    if not error_msg and issuer_cert_der:
                        logger.debug(f"error_msg is not set, using generic message (crl_signature_valid={crl_signature_valid}, revocation_status={revocation_status})")
                        error_msg = "CRL signature verification failed: signature does not match issuer public key"
                    elif not error_msg and not issuer_cert_der and cert_info:
                        error_msg = f"CRL signature validation skipped: issuer certificate not available (certificate issuer: '{cert_info.issuer}')"
            elif status_code == 200 and is_valid_content_type:
                if not error_msg:
                    error_msg = "CRL format validation failed: could not parse as DER or PEM"
                severity = Severity.WARN  # Valid content type but format validation failed
            elif status_code == 200:
                # Wenn die CRL erfolgreich geparst wurde, ist der Content-Type nicht kritisch
                if is_valid_crl_format:
                    # CRL wurde erfolgreich geparst - Content-Type ist nicht kritisch
                    if not error_msg:
                        error_msg = f"CRL has non-standard content type: '{content_type}' (but CRL is valid)"
                    severity = Severity.OK  # CRL ist gültig, Content-Type ist nur informativ
                else:
                    if not error_msg:
                        error_msg = f"CRL has wrong content type: '{content_type}' (expected: application/pkix-crl)"
                    severity = Severity.WARN  # Reachable but wrong content type
            else:
                if not error_msg:
                    error_msg = f"HTTP error: {status_code}"
                severity = Severity.WARN  # HTTP error

            return CRLCheckResult(
                url=url,
                reachable=True,
                status_code=status_code,
                content_type=content_type,
                size_bytes=size_bytes,
                redirect_chain=redirect_chain,
                error=error_msg,
                severity=severity,
            )
        finally:
            client.close()

    except httpx.TimeoutException:
        return CRLCheckResult(
            url=url,
            reachable=False,
            error=f"Request timeout after {timeout}s",
            severity=Severity.WARN,
        )
    except httpx.RequestError as e:
        return CRLCheckResult(
            url=url,
            reachable=False,
            error=str(e),
            severity=Severity.WARN,
        )
    except Exception as e:
        logger.exception(f"Unexpected error checking CRL {url}: {e}")
        return CRLCheckResult(
            url=url,
            reachable=False,
            error=f"Unexpected error: {e}",
            severity=Severity.WARN,
        )

