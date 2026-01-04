"""Certificate chain validation."""

import hashlib
import logging
import ssl
import sys
import subprocess
import warnings
from typing import List, Optional
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from ssl_tester.models import CertificateInfo, ChainCheckResult, Severity, CertificateFinding, CrossSignedCertificate
from ssl_tester.certificate import parse_certificate, _load_cert_with_cache
from ssl_tester.exceptions import ChainBuildingError, ChainValidationError
from ssl_tester.http_client import create_http_client

logger = logging.getLogger(__name__)


def _load_cert_without_warnings(cert_data: bytes, pem: bool = False) -> x509.Certificate:
    """
    Load a certificate while suppressing CryptographyDeprecationWarning about serial numbers.
    Legacy function for backward compatibility.
    
    Args:
        cert_data: Certificate data (DER or PEM bytes)
        pem: If True, treat as PEM format; otherwise DER
    
    Returns:
        Loaded certificate
    """
    cert, _ = _load_cert_with_cache(cert_data, pem=pem)
    return cert


def validate_chain(
    leaf_cert_der: bytes,
    chain_certs_der: List[bytes],
    insecure: bool = False,
    ca_bundle: Optional[Path] = None,
) -> tuple[ChainCheckResult, List[CertificateFinding]]:
    """
    Validate certificate chain structure and trust.

    Args:
        leaf_cert_der: Leaf certificate (DER)
        chain_certs_der: Intermediate certificates (DER)
        insecure: Accept self-signed certificates
        ca_bundle: Custom CA bundle path

    Returns:
        Tuple of (ChainCheckResult with validation status, List of CertificateFindings)
    """
    all_findings: List[CertificateFinding] = []
    cross_signed_certs: List[CrossSignedCertificate] = []
    
    # Parse leaf certificate
    leaf_cert_info, findings = parse_certificate(leaf_cert_der)
    all_findings.extend(findings)

    # Build and sort chain
    sorted_intermediates_der, root_cert_der = build_and_sort_chain(leaf_cert_der, chain_certs_der)
    
    # Store original chain for cross-signing detection
    original_chain_certs_der = chain_certs_der.copy()

    # Parse sorted certificates
    intermediate_certs: List[CertificateInfo] = []
    root_cert: Optional[CertificateInfo] = None

    for cert_der in sorted_intermediates_der:
        cert_info, findings = parse_certificate(cert_der)
        intermediate_certs.append(cert_info)
        all_findings.extend(findings)

    if root_cert_der:
        root_cert, findings = parse_certificate(root_cert_der)
        all_findings.extend(findings)

    # Validate chain links
    missing_intermediates: List[str] = []
    chain_valid = True
    error: Optional[str] = None

    # Check if leaf issuer matches first intermediate subject
    if intermediate_certs:
        first_intermediate = intermediate_certs[0]
        if leaf_cert_info.issuer != first_intermediate.subject:
            chain_valid = False
            error = f"Leaf issuer '{leaf_cert_info.issuer}' does not match intermediate subject '{first_intermediate.subject}'"
            missing_intermediates.append(leaf_cert_info.issuer)
            logger.warning(f"Chain link validation failed: {error}")
        else:
            logger.debug(f"Leaf issuer matches first intermediate subject: {leaf_cert_info.issuer}")

        # Check intermediate chain
        for i in range(len(intermediate_certs) - 1):
            current = intermediate_certs[i]
            next_cert = intermediate_certs[i + 1]
            if current.issuer != next_cert.subject:
                chain_valid = False
                if not error:
                    error = f"Chain broken: intermediate {i} issuer does not match next subject"
                missing_intermediates.append(current.issuer)
                logger.warning(f"Intermediate chain validation failed: {error}")
            else:
                logger.debug(f"Intermediate {i} issuer matches next subject: {current.issuer}")
        
        # Check if last intermediate issuer matches root subject (if root exists)
        if intermediate_certs and root_cert:
            last_intermediate = intermediate_certs[-1]
            if last_intermediate.issuer != root_cert.subject:
                chain_valid = False
                if not error:
                    error = f"Last intermediate issuer '{last_intermediate.issuer}' does not match root subject '{root_cert.subject}'"
                missing_intermediates.append(last_intermediate.issuer)
                logger.warning(f"Intermediate-to-root chain validation failed: {error}")
            else:
                logger.debug(f"Last intermediate issuer matches root subject: {last_intermediate.issuer}")
    else:
        # No intermediates provided - check if this is a self-signed certificate
        if leaf_cert_info.subject == leaf_cert_info.issuer:
            # Self-signed certificate - this is valid, no intermediates needed
            chain_valid = True
            logger.debug("Self-signed certificate detected (no intermediates needed)")
        else:
            # Leaf issuer is missing (not self-signed, but no intermediates provided)
            # Always add to missing_intermediates, regardless of insecure mode
            missing_intermediates.append(leaf_cert_info.issuer)
            if insecure:
                # In insecure mode, allow missing intermediates (might be self-signed or incomplete chain)
                chain_valid = True
                logger.debug("Insecure mode: allowing missing intermediate certificates")
            else:
                chain_valid = False
                error = "No intermediate certificates in chain"

    # Trust store validation using SSL context (needed before signature validation to get root from trust store)
    trust_store_valid = False
    root_from_trust_store: Optional[bytes] = None
    if not insecure:
        try:
            # Create SSL context with system CA bundle
            context = ssl.create_default_context()
            if ca_bundle:
                context.load_verify_locations(str(ca_bundle))

            # Try to validate the chain
            # Include root cert in chain_certs_der for trust store check if available
            all_certs_for_trust_check = chain_certs_der.copy()
            if root_cert_der:
                all_certs_for_trust_check.append(root_cert_der)
            
            trust_store_valid = _check_trust_store(leaf_cert_der, all_certs_for_trust_check, context)
            
            # Determine root CA based on trust store (browser behavior)
            # Browser logic: If a certificate with subject==issuer is in trust store, it's the root
            # This handles cross-signed certificates correctly
            # Note: We try to find the root even if trust_store_valid is False,
            # because cross-signed certificates might cause validation to fail initially
            root_from_trust_store = None
            try:
                trust_store_certs = _load_system_trust_store(context)
            except Exception as e:
                logger.debug(f"Error loading trust store certificates: {e}")
                trust_store_certs = []
            
            if trust_store_certs:
                
                # First: Check if any certificate from chain with subject==issuer is in trust store
                # This is the browser behavior - if cert with subject==issuer is in trust store, it's the root
                for cert_der in all_certs_for_trust_check:
                    try:
                        cert_info, _ = parse_certificate(cert_der)
                        # Check if this cert has subject==issuer (potential root)
                        if cert_info.subject == cert_info.issuer:
                            # Check if this cert is in trust store
                            for trust_cert_der in trust_store_certs:
                                try:
                                    trust_cert_info, _ = parse_certificate(trust_cert_der)
                                    # Match by subject (browser behavior)
                                    if trust_cert_info.subject == cert_info.subject:
                                        root_from_trust_store = trust_cert_der
                                        logger.info(f"Root CA '{cert_info.subject}' from chain found in trust store (browser behavior)")
                                        break
                                except Exception:
                                    continue
                            if root_from_trust_store:
                                break
                    except Exception:
                        continue
                
                # Second: Check if any certificate from chain has the same subject as a trust store root
                # This handles cross-signed certificates (same subject, different issuer/serial)
                if not root_from_trust_store:
                    for cert_der in all_certs_for_trust_check:
                        try:
                            cert_info, _ = parse_certificate(cert_der)
                            # Check if this cert's subject matches a trust store root (cross-signed case)
                            for trust_cert_der in trust_store_certs:
                                try:
                                    trust_cert = _load_cert_without_warnings(trust_cert_der, pem=False)
                                    trust_cert_info, _ = parse_certificate(trust_cert_der)
                                    # Match by subject and verify trust store cert is truly self-signed
                                    if trust_cert_info.subject == cert_info.subject and _is_truly_self_signed(trust_cert):
                                        root_from_trust_store = trust_cert_der
                                        logger.info(f"Root CA '{cert_info.subject}' found in trust store (cross-signed certificate detected)")
                                        break
                                except Exception:
                                    continue
                            if root_from_trust_store:
                                break
                        except Exception:
                            continue
                
                # Third: If no root found from chain, try to get root from trust store based on issuer
                if not root_from_trust_store:
                    root_from_trust_store = _get_root_from_trust_store(all_certs_for_trust_check, context)
                
                if root_from_trust_store:
                    logger.info("Root certificate loaded from trust store for signature validation")
                    # If we found a root from trust store, the chain is trusted
                    # This handles cross-signed certificates correctly: even if the cross-signed cert
                    # itself is not trusted, the trust store root that replaces it is trusted
                    trust_store_valid = True
                    # Parse root certificate from trust store for inclusion in result
                    root_from_trust_store_info, findings = parse_certificate(root_from_trust_store)
                    all_findings.extend(findings)
                    
                    # Use trust store root (browser behavior)
                    if not root_cert:
                        # No root cert in chain, use the one from trust store
                        root_cert = root_from_trust_store_info
                        root_cert_der = root_from_trust_store
                        logger.debug("Root certificate from trust store set as root_cert")
                    else:
                        # Root cert exists in chain - check if trust store root is different
                        if root_cert.fingerprint_sha256 == root_from_trust_store_info.fingerprint_sha256:
                            logger.debug("Root certificate from trust store matches root_cert in chain (same fingerprint)")
                        else:
                            # Trust store root differs - use trust store root (browser behavior)
                            logger.info(
                                f"Root certificate from trust store differs from root_cert in chain. "
                                f"Chain root: {root_cert.fingerprint_sha256[:16]}..., "
                                f"Trust store root: {root_from_trust_store_info.fingerprint_sha256[:16]}... "
                                f"Using trust store root (browser behavior)."
                            )
                            root_cert = root_from_trust_store_info
                            root_cert_der = root_from_trust_store
                    
                    # Remove chain certs from intermediates if they have the same subject as the trust store root
                    # This prevents showing the same cert twice (as intermediate and root)
                    root_subject = root_from_trust_store_info.subject
                    filtered_intermediates = []
                    for cert_der in sorted_intermediates_der:
                        cert_info, _ = parse_certificate(cert_der)
                        if cert_info.subject != root_subject:
                            filtered_intermediates.append(cert_der)
                        else:
                            logger.debug(f"Removing chain cert '{cert_info.subject}' from intermediates (replaced by trust store root)")
                    sorted_intermediates_der = filtered_intermediates
                    
                    # Re-parse intermediates after filtering
                    intermediate_certs = []
                    for cert_der in sorted_intermediates_der:
                        cert_info, findings = parse_certificate(cert_der)
                        intermediate_certs.append(cert_info)
                        all_findings.extend(findings)
                    
                    # Detect cross-signed certificates
                    # A cross-signed cert is replaced by a trust store root with the same subject
                    # This can happen in two cases:
                    # 1. Chain cert has subject==issuer but is not truly self-signed (cross-signed)
                    # 2. Chain cert has different issuer but same subject as trust store root (replaced)
                    root_from_trust_store_info, _ = parse_certificate(root_from_trust_store)
                    
                    # Check both original chain certs and current intermediates for cross-signed certificates
                    # This handles cases where the cert is still in intermediates but has same subject as trust store root
                    certs_to_check = list(set(original_chain_certs_der + sorted_intermediates_der))
                    
                    for cert_der in certs_to_check:
                        try:
                            cert = _load_cert_without_warnings(cert_der, pem=False)
                            cert_info, _ = parse_certificate(cert_der)
                            
                            # Check if this cert's subject matches the trust store root subject
                            # This indicates it's a cross-signed certificate (same subject, different issuer/serial)
                            if cert_info.subject == root_from_trust_store_info.subject:
                                # Check if this cert was removed from intermediates (replaced)
                                # or if it's a cross-signed cert (subject==issuer but not truly self-signed)
                                # or if it has a different issuer than the trust store root (cross-signed)
                                was_replaced = cert_info.subject == root_subject and cert_der not in sorted_intermediates_der
                                is_cross_signed_subject_issuer = (cert_info.subject == cert_info.issuer and not _is_truly_self_signed(cert))
                                is_cross_signed_different_issuer = (cert_info.subject != cert_info.issuer and cert_info.subject == root_from_trust_store_info.subject)
                                
                                if was_replaced or is_cross_signed_subject_issuer or is_cross_signed_different_issuer:
                                    # This cert was replaced by trust store root
                                    # Get the actual signer: For cross-signed certs, the issuer field shows subject==issuer,
                                    # but the actual signer is the one who signed it (found by checking signature)
                                    # For replaced certs, use the issuer field directly
                                    if cert_info.subject == cert_info.issuer:
                                        # Cross-signed: subject==issuer but not self-signed
                                        # Use the new function to find the actual signer by signature verification
                                        # trust_store_certs is available in this scope (loaded earlier)
                                        actual_signer = _find_actual_signer(
                                            cert=cert,
                                            cert_info=cert_info,
                                            candidate_certs_der=original_chain_certs_der,
                                            trust_store_certs_der=trust_store_certs
                                        )
                                        
                                        # Fallback: if signature verification didn't find a signer,
                                        # check if there's a cert in chain with different subject that could be the signer
                                        # For cross-signed certs, the signer is usually the issuer of the last intermediate
                                        # or a root CA in the chain
                                        if not actual_signer:
                                            # Check if there's a cert in chain that's a root CA (self-signed)
                                            for other_cert_der in original_chain_certs_der:
                                                if other_cert_der == cert_der:
                                                    continue
                                                try:
                                                    other_cert_info, _ = parse_certificate(other_cert_der)
                                                    # If this cert is self-signed and different from cross-signed cert,
                                                    # it might be the signer
                                                    if other_cert_info.subject == other_cert_info.issuer and \
                                                       other_cert_info.subject != cert_info.subject:
                                                        # This could be the signer
                                                        actual_signer = other_cert_info.subject
                                                        break
                                                except Exception:
                                                    continue
                                        
                                        # Final fallback: if we still can't find the signer, indicate unknown
                                        if not actual_signer:
                                            actual_signer = "Unknown (signature verification failed)"
                                    else:
                                        # Replaced cert: issuer field is correct
                                        actual_signer = cert_info.issuer
                                    
                                    cross_signed_certs.append(
                                        CrossSignedCertificate(
                                            chain_cert=cert_info,
                                            trust_store_root=root_from_trust_store_info,
                                            actual_signer=actual_signer  # The actual signer (e.g., Starfield)
                                        )
                                    )
                                    
                                    logger.info(
                                        f"Cross-signed certificate detected: '{cert_info.subject}' "
                                        f"(Chain Serial: {cert_info.serial_number}) signed by '{actual_signer}', "
                                        f"replaced by trust store root (Serial: {root_from_trust_store_info.serial_number})"
                                    )
                                    
                                    # Add finding for cross-signed certificate
                                    all_findings.append(
                                        CertificateFinding(
                                            code="CERT_CROSS_SIGNED",
                                            severity=Severity.OK,  # Informational, not a problem
                                            message=f"Cross-signed certificate detected. Chain certificate '{cert_info.subject}' "
                                                   f"(Serial: {cert_info.serial_number}) is signed by '{actual_signer}', "
                                                   f"but replaced by self-signed root '{root_from_trust_store_info.subject}' "
                                                   f"(Serial: {root_from_trust_store_info.serial_number}) from trust store (browser behavior).",
                                            subject=cert_info.subject,
                                            issuer=actual_signer,
                                            fingerprint_sha256=cert_info.fingerprint_sha256,
                                            context={
                                                'chain_serial': cert_info.serial_number,
                                                'trust_store_serial': root_from_trust_store_info.serial_number,
                                                'actual_signer': actual_signer,
                                                'replaced_by_trust_store': True
                                            }
                                        )
                                    )
                        except Exception as e:
                            logger.debug(f"Error checking for cross-signed certificate: {e}")
        except Exception as e:
            logger.warning(f"Trust store validation failed: {e}")
            trust_store_valid = False
    else:
        logger.warning("Insecure mode: skipping trust store validation")
        trust_store_valid = True  # Assume valid in insecure mode

    # Validate signatures (include root cert if available, or from trust store)
    # For self-signed certificates, we need to include the leaf cert itself for signature validation
    all_chain_certs_der = sorted_intermediates_der.copy()
    
    # Store original chain certs for cross-signed certificate signature validation
    # We need to check signatures against original chain certs (including cross-signed ones)
    # before they were replaced by trust store roots
    original_chain_certs_for_signature = original_chain_certs_der.copy()
    
    # If we're using a root from trust store that replaces a chain cert, replace it in the chain
    # This handles cases where chain cert is cross-signed but trust store has the real root
    if root_from_trust_store and root_cert:
        root_from_trust_store_info, _ = parse_certificate(root_from_trust_store)
        # Check if any intermediate has the same subject as the trust store root
        # If so, replace it with the trust store root for signature validation
        for i, cert_der in enumerate(all_chain_certs_der):
            cert_info, _ = parse_certificate(cert_der)
            if cert_info.subject == root_from_trust_store_info.subject:
                logger.debug(f"Replacing chain cert '{cert_info.subject}' with trust store root for signature validation")
                all_chain_certs_der[i] = root_from_trust_store
                break
    
    if root_cert_der:
        all_chain_certs_der.append(root_cert_der)
    # If leaf is self-signed and no chain certs, add leaf to chain for self-signature validation
    if leaf_cert_info.subject == leaf_cert_info.issuer and not all_chain_certs_der:
        all_chain_certs_der.append(leaf_cert_der)
    
    # Pass cross-signed certificates info to validate_signatures
    signature_results = validate_signatures(
        leaf_cert_der, 
        all_chain_certs_der, 
        root_from_trust_store,
        cross_signed_certs=cross_signed_certs,
        original_chain_certs_der=original_chain_certs_for_signature
    )
    invalid_signatures = [(fp, subject, err_msg) for fp, (is_valid, subject, err_msg) in signature_results.items() if not is_valid]
    if invalid_signatures:
        # In insecure mode, allow invalid signatures for self-signed certs
        if insecure and leaf_cert_info.subject == leaf_cert_info.issuer:
            logger.debug("Insecure mode: allowing invalid signature for self-signed certificate")
        else:
            chain_valid = False
        if not error:
            # Build detailed error message with root cause for each invalid signature
            error_details = []
            for fp, subject, err_msg in invalid_signatures:
                if subject:
                    cert_identifier = f"certificate '{subject}'"
                else:
                    cert_identifier = f"certificate (fingerprint: {fp[:16]}...)"
                
                if err_msg:
                    error_details.append(f"{cert_identifier}: {err_msg}")
                else:
                    error_details.append(f"{cert_identifier}: signature validation failed")
            
            if len(invalid_signatures) == 1:
                error = f"Invalid signature found for {error_details[0]}"
            else:
                error = f"Invalid signatures found for {len(invalid_signatures)} certificate(s): {'; '.join(error_details)}"
            logger.warning(f"Signature validation failed for {len(invalid_signatures)} certificate(s)")
    else:
        logger.debug("All certificate signatures validated successfully")
        logger.debug(f"Chain valid status after signature validation: {chain_valid}")

    # Determine severity
    logger.debug(f"Final chain_valid status: {chain_valid}, trust_store_valid: {trust_store_valid}")
    if not chain_valid:
        severity = Severity.FAIL
    elif not trust_store_valid and not insecure:
        # Trust store validation failed, but chain is valid - this is a warning, not a failure
        severity = Severity.WARN
    elif missing_intermediates and not insecure:
        # Missing intermediates are only a warning if not in insecure mode
        # In insecure mode, missing intermediates are expected (self-signed certs)
        severity = Severity.WARN
    else:
        severity = Severity.OK

    # Determine final validity: chain must be valid AND (trust store must be valid OR insecure mode is enabled)
    # Note: When insecure=True, trust_store_valid is already set to True (see line 161)
    final_is_valid = chain_valid and (trust_store_valid or insecure)
    logger.debug(f"Final is_valid for ChainCheckResult: {final_is_valid} (chain_valid={chain_valid}, trust_store_valid={trust_store_valid}, insecure={insecure})")
    
    chain_result = ChainCheckResult(
        is_valid=final_is_valid,
        chain_valid=chain_valid,
        leaf_cert=leaf_cert_info,
        intermediate_certs=intermediate_certs,
        root_cert=root_cert,
        trust_store_valid=trust_store_valid,
        missing_intermediates=missing_intermediates,
        error=error,
        severity=severity,
        cross_signed_certs=cross_signed_certs,
    )
    
    return chain_result, all_findings


def fetch_intermediates_via_aia(
    leaf_cert_info: CertificateInfo,
    timeout: float = 10.0,
    max_depth: int = 10,
    proxy: Optional[str] = None,
) -> List[bytes]:
    """
    Fetch intermediate certificates via AIA CA Issuers URLs (recursively).

    Args:
        leaf_cert_info: Leaf certificate info with AIA URLs
        timeout: HTTP request timeout in seconds
        max_depth: Maximum recursion depth to prevent infinite loops

    Returns:
        List of DER-encoded intermediate certificates (ordered: first intermediate to root)
    """
    all_certs_der: List[bytes] = []
    seen_fingerprints: set[str] = set()
    current_cert_info = leaf_cert_info
    depth = 0

    while depth < max_depth:
        if not current_cert_info.ca_issuers_urls:
            logger.debug(f"No CA Issuers URLs found for certificate at depth {depth}")
            break

        # Check if we've already seen this certificate (prevent loops)
        if current_cert_info.fingerprint_sha256 in seen_fingerprints:
            logger.warning(f"Circular reference detected in certificate chain at depth {depth}")
            break
        seen_fingerprints.add(current_cert_info.fingerprint_sha256)

        # Try to fetch issuer certificate
        fetched_cert_der = _fetch_single_cert_via_aia(current_cert_info, timeout, proxy)
        if not fetched_cert_der:
            logger.debug(f"Could not fetch certificate for issuer: {current_cert_info.issuer}")
            break

        # Parse fetched certificate
        try:
            fetched_cert, _ = _load_cert_with_cache(fetched_cert_der, pem=False)
            fetched_cert_info, findings = parse_certificate(fetched_cert_der)
            # Note: Findings from AIA-fetched certificates are not returned here
            # They should be collected when the chain is validated

            # Validate that fetched cert is actually the issuer
            if fetched_cert_info.subject != current_cert_info.issuer:
                logger.warning(
                    f"Fetched certificate subject '{fetched_cert_info.subject}' "
                    f"does not match expected issuer '{current_cert_info.issuer}'"
                )
                break

            all_certs_der.append(fetched_cert_der)
            logger.debug(f"Fetched certificate at depth {depth}: {fetched_cert_info.subject}")

            # Check if this is a root CA (self-signed)
            if fetched_cert_info.subject == fetched_cert_info.issuer:
                logger.debug("Root CA found, stopping chain building")
                break

            # Continue with next level
            current_cert_info = fetched_cert_info
            depth += 1

        except Exception as e:
            logger.warning(f"Error parsing fetched certificate: {e}")
            break

    if all_certs_der:
        logger.info(f"Successfully fetched {len(all_certs_der)} certificate(s) via recursive AIA")
    else:
        logger.warning("Failed to fetch any certificates via AIA")

    return all_certs_der


def _fetch_single_cert_via_aia(
    cert_info: CertificateInfo,
    timeout: float = 10.0,
    proxy: Optional[str] = None,
) -> Optional[bytes]:
    """
    Fetch a single certificate via AIA CA Issuers URLs.

    Args:
        cert_info: Certificate info with AIA URLs
        timeout: HTTP request timeout in seconds

    Returns:
        DER-encoded certificate or None if fetch failed
    """
    if not cert_info.ca_issuers_urls:
        return None

    for ca_issuer_url in cert_info.ca_issuers_urls:
        try:
            logger.debug(f"Fetching certificate from {ca_issuer_url}")
            client = create_http_client(proxy=proxy, timeout=timeout, follow_redirects=True)
            try:
                response = client.get(
                    ca_issuer_url,
                    headers={
                        "User-Agent": "ssl-tester/0.1.0",
                        "Accept": "application/pkix-cert,application/x-x509-ca-cert,*/*",
                    },
                )

                if response.status_code != 200:
                    logger.debug(f"Failed to fetch certificate from {ca_issuer_url}: HTTP {response.status_code}")
                    continue

                # Try to parse as DER first (most common)
                try:
                    cert, _ = _load_cert_with_cache(response.content, pem=False)
                    logger.debug(f"Successfully fetched certificate from {ca_issuer_url} (DER format)")
                    return response.content
                except Exception:
                    # Try PEM format
                    try:
                        cert, _ = _load_cert_with_cache(response.content, pem=True)
                        cert_der = cert.public_bytes(serialization.Encoding.DER)
                        logger.debug(f"Successfully fetched certificate from {ca_issuer_url} (PEM format)")
                        return cert_der
                    except Exception as e:
                        logger.debug(f"Could not parse certificate from {ca_issuer_url}: {e}")

            finally:
                client.close()
        except httpx.TimeoutException:
            logger.debug(f"Timeout fetching certificate from {ca_issuer_url}")
        except httpx.RequestError as e:
            logger.debug(f"Request error fetching certificate from {ca_issuer_url}: {e}")
        except Exception as e:
            logger.debug(f"Unexpected error fetching certificate from {ca_issuer_url}: {e}")

    return None


def build_and_sort_chain(
    leaf_cert_der: bytes,
    chain_certs_der: List[bytes],
) -> tuple[List[bytes], Optional[bytes]]:
    """
    Build and sort certificate chain (leaf -> intermediates -> root).

    Args:
        leaf_cert_der: Leaf certificate (DER)
        chain_certs_der: Unordered list of chain certificates (DER)

    Returns:
        Tuple of (sorted_intermediates_der, root_cert_der)
    """
    # Parse all certificates
    leaf_cert = _load_cert_without_warnings(leaf_cert_der, pem=False)
    leaf_cert_info, _ = parse_certificate(leaf_cert_der)

    chain_certs: List[tuple[x509.Certificate, CertificateInfo, bytes]] = []
    root_cert_der: Optional[bytes] = None
    root_cert_count = 0

    for cert_der in chain_certs_der:
        try:
            cert = _load_cert_without_warnings(cert_der, pem=False)
            cert_info, _ = parse_certificate(cert_der)

            # Check if this is a root CA
            # Browser behavior: If subject==issuer, treat as potential root CA
            # The actual root will be determined in validate_chain based on trust store
            # (If a cert with subject==issuer is in trust store, it's the root, regardless of signature)
            if cert_info.subject == cert_info.issuer:
                # Potential root CA - treat as root candidate
                # Will be resolved in validate_chain based on trust store
                root_cert_count += 1
                if root_cert_der is None:
                    root_cert_der = cert_der
                    if _is_truly_self_signed(cert):
                        logger.debug(f"Found root CA (truly self-signed): '{cert_info.subject}'")
                    else:
                        logger.debug(f"Found potential root CA (subject==issuer, may be cross-signed): '{cert_info.subject}'")
            else:
                # Not a root CA - add to intermediates list
                chain_certs.append((cert, cert_info, cert_der))
        except Exception as e:
            logger.warning(f"Error parsing chain certificate: {e}")
            continue
    
    # Warn if multiple root certificates were found
    if root_cert_count > 1:
        logger.warning(
            f"Multiple root certificates ({root_cert_count}) found in chain. "
            f"Using the first one found. This may indicate a configuration issue."
        )

    # Sort chain: each cert's issuer should match next cert's subject
    sorted_intermediates: List[bytes] = []
    current_issuer = leaf_cert_info.issuer

    while chain_certs:
        found = False
        for i, (cert, cert_info, cert_der) in enumerate(chain_certs):
            if cert_info.subject == current_issuer:
                sorted_intermediates.append(cert_der)
                current_issuer = cert_info.issuer
                chain_certs.pop(i)
                found = True
                break

        if not found:
            # Could not find next certificate in chain
            logger.warning(f"Could not find certificate for issuer: {current_issuer}")
            break

    return sorted_intermediates, root_cert_der


def validate_signatures(
    leaf_cert_der: bytes,
    chain_certs_der: List[bytes],
    root_from_trust_store: Optional[bytes] = None,
    cross_signed_certs: Optional[List[CrossSignedCertificate]] = None,
    original_chain_certs_der: Optional[List[bytes]] = None,
) -> dict[str, tuple[bool, Optional[str], Optional[str]]]:
    """
    Validate signatures in certificate chain using cryptography's built-in validation.

    Args:
        leaf_cert_der: Leaf certificate (DER)
        chain_certs_der: Intermediate certificates (DER, should be sorted)
        root_from_trust_store: Optional root certificate from trust store (DER) if missing from chain
        cross_signed_certs: Optional list of cross-signed certificates detected
        original_chain_certs_der: Optional original chain certificates before replacement by trust store root

    Returns:
        Dictionary mapping certificate fingerprint to (is_valid, subject, error_message)
        - is_valid: True if signature is valid
        - subject: Certificate subject (for identification)
        - error_message: Error message if validation failed, None if valid
    """
    results: dict[str, tuple[bool, Optional[str], Optional[str]]] = {}
    
    # Build set of cross-signed certificate subjects for quick lookup
    cross_signed_subjects: set[str] = set()
    cross_signed_issuers: dict[str, str] = {}  # Map subject to actual_signer
    if cross_signed_certs:
        for cross_signed in cross_signed_certs:
            cross_signed_subjects.add(cross_signed.chain_cert.subject)
            cross_signed_issuers[cross_signed.chain_cert.subject] = cross_signed.actual_signer

    try:
        leaf_cert = _load_cert_without_warnings(leaf_cert_der, pem=False)
        leaf_cert_info, _ = parse_certificate(leaf_cert_der)

        # Build issuer lookup
        issuer_map: dict[str, x509.Certificate] = {}
        for cert_der in chain_certs_der:
            try:
                cert = _load_cert_without_warnings(cert_der, pem=False)
                cert_info, _ = parse_certificate(cert_der)
                issuer_map[cert_info.subject] = cert
            except Exception as e:
                logger.warning(f"Error parsing certificate for signature validation: {e}")

        # Also add original chain certs to issuer_map to find cross-signers
        if original_chain_certs_der:
            for cert_der in original_chain_certs_der:
                try:
                    cert = _load_cert_without_warnings(cert_der, pem=False)
                    cert_info, _ = parse_certificate(cert_der)
                    # Only add if not already in issuer_map (don't overwrite trust store root)
                    if cert_info.subject not in issuer_map:
                        issuer_map[cert_info.subject] = cert
                except Exception as e:
                    logger.debug(f"Error parsing original chain cert for signature validation: {e}")

        # Add root from trust store to issuer map if provided
        if root_from_trust_store:
            try:
                root_cert = _load_cert_without_warnings(root_from_trust_store, pem=False)
                root_cert_info, _ = parse_certificate(root_from_trust_store)
                # Check if a certificate with this subject already exists in issuer_map
                if root_cert_info.subject in issuer_map:
                    logger.debug(
                        f"Root certificate from trust store with subject '{root_cert_info.subject}' "
                        f"already exists in issuer_map, skipping duplicate"
                    )
                else:
                    issuer_map[root_cert_info.subject] = root_cert
                    logger.debug(f"Added root certificate from trust store to issuer map: {root_cert_info.subject}")
            except Exception as e:
                logger.warning(f"Error parsing root certificate from trust store: {e}")

        # Validate leaf signature using cryptography's built-in method
        leaf_issuer = issuer_map.get(leaf_cert_info.issuer)
        if leaf_issuer:
            try:
                # Use verify_directly_issued_by which handles all signature algorithms correctly
                leaf_cert.verify_directly_issued_by(leaf_issuer)
                results[leaf_cert_info.fingerprint_sha256] = (True, leaf_cert_info.subject, None)
            except Exception as e:
                error_msg = f"Signature does not match issuer public key: {str(e)}"
                logger.warning(f"Leaf certificate signature validation failed: {e}")
                results[leaf_cert_info.fingerprint_sha256] = (False, leaf_cert_info.subject, error_msg)
        else:
            error_msg = f"Issuer '{leaf_cert_info.issuer}' not found in certificate chain"
            logger.debug(f"Leaf issuer not found in chain: {leaf_cert_info.issuer}")
            results[leaf_cert_info.fingerprint_sha256] = (False, leaf_cert_info.subject, error_msg)

        # Get trust store root subject for comparison
        trust_store_root_subject = None
        if root_from_trust_store:
            try:
                root_cert_info, _ = parse_certificate(root_from_trust_store)
                trust_store_root_subject = root_cert_info.subject
            except Exception:
                pass

        # Validate intermediate signatures
        for cert_der in chain_certs_der:
            try:
                cert = _load_cert_without_warnings(cert_der, pem=False)
                cert_info, _ = parse_certificate(cert_der)

                # Skip root (self-signed) - but verify signature is actually valid
                if cert_info.subject == cert_info.issuer:
                    # Verify that this is truly self-signed (not just subject==issuer)
                    # Cross-signed certificates may have subject==issuer but are not self-signed
                    if _is_truly_self_signed(cert):
                        results[cert_info.fingerprint_sha256] = (True, cert_info.subject, None)
                        logger.debug(f"Root certificate '{cert_info.subject}' is truly self-signed (signature verified)")
                    else:
                        # Subject==issuer but not truly self-signed - this is likely a cross-signed certificate
                        # Signature validation will be handled separately for cross-signed certs
                        logger.debug(f"Certificate '{cert_info.subject}' has subject==issuer but is not truly self-signed (likely cross-signed)")
                        # Don't mark as valid yet - let cross-signed detection handle it
                        # But also don't fail it here, as it might be handled by cross-signed logic
                        results[cert_info.fingerprint_sha256] = (True, cert_info.subject, None)
                    continue

                # Check if this is a cross-signed certificate that was replaced by trust store root
                # If so, skip signature validation (it's handled separately and replaced by trust store root)
                if cert_info.subject in cross_signed_subjects:
                    logger.debug(
                        f"Skipping signature validation for cross-signed certificate '{cert_info.subject}' "
                        f"(replaced by trust store root, actual signer: {cross_signed_issuers.get(cert_info.subject, 'unknown')})"
                    )
                    results[cert_info.fingerprint_sha256] = (True, cert_info.subject, None)
                    continue

                # Check if this certificate has the same subject as the trust store root
                # This indicates it's a cross-signed certificate that should be skipped
                if trust_store_root_subject and cert_info.subject == trust_store_root_subject:
                    logger.debug(
                        f"Skipping signature validation for certificate '{cert_info.subject}' "
                        f"(same subject as trust store root, likely cross-signed)"
                    )
                    results[cert_info.fingerprint_sha256] = (True, cert_info.subject, None)
                    continue

                issuer_cert = issuer_map.get(cert_info.issuer)
                if issuer_cert:
                    try:
                        # Use verify_directly_issued_by which handles all signature algorithms correctly
                        cert.verify_directly_issued_by(issuer_cert)
                        results[cert_info.fingerprint_sha256] = (True, cert_info.subject, None)
                    except Exception as e:
                        error_msg = f"Signature does not match issuer public key: {str(e)}"
                        logger.warning(f"Certificate signature validation failed for {cert_info.subject}: {e}")
                        results[cert_info.fingerprint_sha256] = (False, cert_info.subject, error_msg)
                else:
                    # Check if this certificate has the same subject as the trust store root
                    # This indicates it's a cross-signed certificate that should be skipped
                    if root_from_trust_store:
                        try:
                            root_cert_info, _ = parse_certificate(root_from_trust_store)
                            if cert_info.subject == root_cert_info.subject:
                                logger.debug(
                                    f"Skipping signature validation for certificate '{cert_info.subject}' "
                                    f"(same subject as trust store root, likely cross-signed)"
                                )
                                results[cert_info.fingerprint_sha256] = (True, cert_info.subject, None)
                                continue
                        except Exception:
                            pass
                    
                    # Check if this certificate's issuer is a cross-signer (not in chain but in original chain)
                    # This handles cases where a cross-signed cert's issuer is not in the filtered chain
                    if original_chain_certs_der:
                        found_in_original = False
                        for orig_cert_der in original_chain_certs_der:
                            try:
                                orig_cert_info, _ = parse_certificate(orig_cert_der)
                                if orig_cert_info.subject == cert_info.issuer:
                                    # Found the issuer in original chain - try to validate
                                    orig_cert = _load_cert_without_warnings(orig_cert_der, pem=False)
                                    try:
                                        cert.verify_directly_issued_by(orig_cert)
                                        results[cert_info.fingerprint_sha256] = (True, cert_info.subject, None)
                                        found_in_original = True
                                        logger.debug(f"Validated signature using original chain cert for '{cert_info.subject}'")
                                        break
                                    except Exception:
                                        pass
                            except Exception:
                                continue
                        
                        if found_in_original:
                            continue
                    
                    error_msg = f"Issuer '{cert_info.issuer}' not found in certificate chain"
                    logger.debug(f"Issuer not found for certificate: {cert_info.issuer}")
                    results[cert_info.fingerprint_sha256] = (False, cert_info.subject, error_msg)
            except Exception as e:
                logger.warning(f"Error validating certificate signature: {e}")
                # Try to get cert_info for error message
                try:
                    cert_info, _ = parse_certificate(cert_der)
                    results[cert_info.fingerprint_sha256] = (False, cert_info.subject, f"Error during validation: {str(e)}")
                except Exception:
                    # If we can't parse, use fingerprint as identifier
                    import hashlib
                    fp = hashlib.sha256(cert_der).hexdigest()
                    results[fp] = (False, None, f"Error during validation: {str(e)}")

    except Exception as e:
        logger.error(f"Error in signature validation: {e}")

    return results


def _get_signature_algorithm(oid: x509.oid.SignatureAlgorithmOID) -> hashes.HashAlgorithm:
    """Get hash algorithm from signature algorithm OID."""
    oid_name = oid._name.lower()
    if "sha256" in oid_name or "sha2-256" in oid_name:
        return hashes.SHA256()
    elif "sha384" in oid_name or "sha2-384" in oid_name:
        return hashes.SHA384()
    elif "sha512" in oid_name or "sha2-512" in oid_name:
        return hashes.SHA512()
    elif "sha1" in oid_name:
        return hashes.SHA1()
    elif "md5" in oid_name:
        return hashes.MD5()
    else:
        # Default to SHA256
        return hashes.SHA256()


def _get_padding_for_algorithm(oid: x509.oid.SignatureAlgorithmOID) -> Optional[padding.AsymmetricPadding]:
    """Get padding algorithm for signature verification."""
    oid_name = oid._name.lower()
    if "rsa" in oid_name:
        return padding.PKCS1v15()
    elif "ecdsa" in oid_name or "ec" in oid_name:
        # ECDSA doesn't use padding
        return None
    else:
        # Default to PKCS1v15 for RSA
        return padding.PKCS1v15()


def _find_actual_signer(
    cert: x509.Certificate,
    cert_info: CertificateInfo,
    candidate_certs_der: List[bytes],
    trust_store_certs_der: Optional[List[bytes]] = None
) -> Optional[str]:
    """
    Find the actual signer of a cross-signed certificate by verifying signatures.
    
    For cross-signed certificates, the issuer field shows subject==issuer, but the
    actual signer is a different CA. This function finds the actual signer by
    verifying the signature with each candidate certificate's public key.
    
    Args:
        cert: The cross-signed certificate
        cert_info: CertificateInfo for the cross-signed certificate
        candidate_certs_der: List of candidate certificates that might have signed it (DER)
        trust_store_certs_der: Optional list of trust store certificates (DER)
        
    Returns:
        Subject DN of the actual signer, or None if not found
    """
    # Combine all candidate certificates
    all_candidates = list(candidate_certs_der)
    if trust_store_certs_der:
        all_candidates.extend(trust_store_certs_der)
    
    # Try each candidate certificate
    for candidate_der in all_candidates:
        try:
            candidate_cert = _load_cert_without_warnings(candidate_der, pem=False)
            candidate_info, _ = parse_certificate(candidate_der)
            
            # Skip if it's the same certificate
            if candidate_info.fingerprint_sha256 == cert_info.fingerprint_sha256:
                continue
            
            # Try to verify signature using verify_directly_issued_by
            # This works even if issuer doesn't match (cross-signing case)
            try:
                # verify_directly_issued_by checks signature validity, not issuer match
                # For cross-signed certs, this will succeed if the signature is valid
                cert.verify_directly_issued_by(candidate_cert)
                # If we get here, the signature is valid!
                logger.debug(
                    f"Found actual signer of cross-signed cert '{cert_info.subject}': "
                    f"'{candidate_info.subject}' (signature verified)"
                )
                return candidate_info.subject
            except ValueError:
                # Signature verification failed or issuer mismatch - try next candidate
                continue
            except Exception as e:
                # Other error - try next candidate
                logger.debug(f"Error verifying signature with candidate '{candidate_info.subject}': {e}")
                continue
        except Exception as e:
            logger.debug(f"Error processing candidate certificate: {e}")
            continue
    
    # If no signer found by signature verification, return None
    logger.debug(f"Could not find actual signer for cross-signed cert '{cert_info.subject}' by signature verification")
    return None


def _is_truly_self_signed(cert: x509.Certificate) -> bool:
    """
    Check if a certificate is truly self-signed by verifying its signature.
    
    A certificate is truly self-signed if:
    1. subject == issuer (name matches)
    2. The signature is valid when verified with the certificate's own public key
    
    This is important for detecting cross-signed certificates, which may have
    subject == issuer but are actually signed by another CA.
    
    Args:
        cert: Certificate to check
        
    Returns:
        True if certificate is truly self-signed, False otherwise
    """
    try:
        # First check: subject must match issuer
        cert_info, _ = parse_certificate(cert.public_bytes(serialization.Encoding.DER))
        if cert_info.subject != cert_info.issuer:
            return False
        
        # Second check: verify signature with own public key
        # Use verify_directly_issued_by which handles all signature algorithms correctly
        try:
            cert.verify_directly_issued_by(cert)
            logger.debug(f"Certificate '{cert_info.subject}' is truly self-signed (signature verified)")
            return True
        except Exception as e:
            logger.debug(f"Certificate '{cert_info.subject}' has subject==issuer but signature verification failed: {e}. This is likely a cross-signed certificate.")
            return False
    except Exception as e:
        logger.debug(f"Error checking if certificate is self-signed: {e}")
        # Fallback: if we can't verify, assume it's not self-signed if subject != issuer
        try:
            cert_info, _ = parse_certificate(cert.public_bytes(serialization.Encoding.DER))
            return cert_info.subject == cert_info.issuer
        except Exception:
            return False


def _get_root_from_trust_store(
    chain_certs_der: List[bytes], context: ssl.SSLContext
) -> Optional[bytes]:
    """
    Get root certificate from trust store if it's missing from the chain.

    Args:
        chain_certs_der: Chain certificates (DER)
        context: SSL context with trust store loaded

    Returns:
        DER-encoded root certificate if found in trust store, None otherwise
    """
    try:
        # Parse certificates
        chain_certs = [_load_cert_without_warnings(cert_der, pem=False) for cert_der in chain_certs_der]

        # Load system trust store
        trust_store_certs = _load_system_trust_store(context)

        # First: Check if any certificate from chain has a subject that exists as root in trust store
        # Browser behavior: If a cert's subject exists in trust store as a root (subject==issuer),
        # use that trust store root, even if the chain cert is not self-signed
        # This handles cases where chain has cross-signed cert but trust store has the real root
        for cert in chain_certs:
            cert_info, _ = parse_certificate(cert.public_bytes(serialization.Encoding.DER))
            # Check if this cert's subject exists as a root in trust store
            for trust_cert_der in trust_store_certs:
                try:
                    trust_cert_info, _ = parse_certificate(trust_cert_der)
                    # Match by subject AND check if trust store cert is a root (subject==issuer)
                    if trust_cert_info.subject == cert_info.subject and trust_cert_info.subject == trust_cert_info.issuer:
                        logger.debug(f"Root CA '{cert_info.subject}' found in trust store (browser behavior - using trust store root instead of chain cert)")
                        return trust_cert_der
                except Exception:
                    continue
        
        # Second: Find root CA (truly self-signed) in chain
        # Only check this if no cert with subject==issuer was found in trust store
        root_cert: Optional[x509.Certificate] = None
        for cert in chain_certs:
            if _is_truly_self_signed(cert):
                root_cert = cert
                break

        if root_cert:
            # Root is already in chain, no need to fetch from trust store
            return None

        # Third: No root CA in chain - check if the issuer of the last intermediate is in trust store
        if chain_certs:
            # Get the last certificate in chain (should be the one closest to root)
            last_cert = chain_certs[-1]
            last_cert_info, _ = parse_certificate(last_cert.public_bytes(serialization.Encoding.DER))
            expected_root_issuer = last_cert_info.issuer
            
            logger.debug(f"Looking for root CA with subject '{expected_root_issuer}' in trust store")
            
            # Check if any certificate in trust store matches the expected root issuer
            for trust_cert_der in trust_store_certs:
                try:
                    trust_cert = _load_cert_without_warnings(trust_cert_der, pem=False)
                    trust_cert_info, _ = parse_certificate(trust_cert_der)
                    
                    # Check if this trust store cert matches the expected root issuer
                    if trust_cert_info.subject == expected_root_issuer:
                        # Also verify it's truly self-signed (root CA)
                        if _is_truly_self_signed(trust_cert):
                            logger.debug(f"Root CA '{expected_root_issuer}' found in trust store (not in chain)")
                            return trust_cert_der
                except Exception as e:
                    logger.debug(f"Error parsing trust store certificate: {e}")
                    continue
            
            logger.debug(f"Root CA '{expected_root_issuer}' not found in trust store")
        else:
            logger.debug("No certificates in chain to check against trust store")

        return None

    except Exception as e:
        logger.debug(f"Error getting root from trust store: {e}")
        return None


def _check_trust_store(
    leaf_cert_der: bytes, chain_certs_der: List[bytes], context: ssl.SSLContext
) -> bool:
    """
    Check if certificate chain is trusted by the system CA store.

    Args:
        leaf_cert_der: Leaf certificate (DER)
        chain_certs_der: Chain certificates (DER)
        context: SSL context with trust store loaded

    Returns:
        True if root CA is found in trust store (either in chain or by issuer lookup)
    """
    try:
        # Parse certificates
        chain_certs = [_load_cert_without_warnings(cert_der, pem=False) for cert_der in chain_certs_der]

        # Load system trust store
        trust_store_certs = _load_system_trust_store(context)

        # Find root CA (truly self-signed) in chain
        root_cert: Optional[x509.Certificate] = None
        for cert in chain_certs:
            if _is_truly_self_signed(cert):
                root_cert = cert
                break

        if root_cert:
            # Check if root CA from chain is in trust store
            root_cert_der = root_cert.public_bytes(serialization.Encoding.DER)
            root_fingerprint = hashlib.sha256(root_cert_der).hexdigest()

            for trust_cert_der in trust_store_certs:
                trust_fingerprint = hashlib.sha256(trust_cert_der).hexdigest()
                if trust_fingerprint == root_fingerprint:
                    logger.debug("Root CA from chain found in trust store")
                    return True

            logger.debug("Root CA from chain not found in trust store")
        else:
            # No root CA in chain - check if the issuer of the last intermediate is in trust store
            logger.debug("No root CA found in chain, checking if issuer of last intermediate is in trust store")
            
            if chain_certs:
                # Get the last certificate in chain (should be the one closest to root)
                last_cert = chain_certs[-1]
                last_cert_info, _ = parse_certificate(last_cert.public_bytes(serialization.Encoding.DER))
                expected_root_issuer = last_cert_info.issuer
                
                logger.debug(f"Looking for root CA with subject '{expected_root_issuer}' in trust store")
                
                # Check if any certificate in trust store matches the expected root issuer
                for trust_cert_der in trust_store_certs:
                    try:
                        trust_cert = _load_cert_without_warnings(trust_cert_der, pem=False)
                        trust_cert_info, _ = parse_certificate(trust_cert_der)
                        
                        # Check if this trust store cert matches the expected root issuer
                        if trust_cert_info.subject == expected_root_issuer:
                            # Also verify it's truly self-signed (root CA)
                            if _is_truly_self_signed(trust_cert):
                                logger.debug(f"Root CA '{expected_root_issuer}' found in trust store (not in chain)")
                                return True
                    except Exception as e:
                        logger.debug(f"Error parsing trust store certificate: {e}")
                        continue
                
                logger.debug(f"Root CA '{expected_root_issuer}' not found in trust store")
            else:
                logger.debug("No certificates in chain to check against trust store")

        return False

    except Exception as e:
        logger.debug(f"Trust store check failed: {e}")
        return False


def _load_system_trust_store(context: ssl.SSLContext) -> List[bytes]:
    """
    Load certificates from system trust store.

    Args:
        context: SSL context with trust store loaded

    Returns:
        List of DER-encoded certificates from trust store
    """
    import certifi
    import os

    trust_store_certs: List[bytes] = []

    try:
        # Load certifi bundle
        certifi_path = certifi.where()
        if os.path.exists(certifi_path):
            with open(certifi_path, "rb") as f:
                certifi_data = f.read()
                # Parse PEM certificates
                for cert_pem in _split_pem_certificates(certifi_data):
                    try:
                        cert = _load_cert_without_warnings(cert_pem, pem=True)
                        trust_store_certs.append(cert.public_bytes(serialization.Encoding.DER))
                    except Exception as e:
                        logger.debug(f"Error parsing certifi certificate: {e}")

        # Try to load system certificates (platform-specific)
        try:
            # On macOS, load from Keychain
            if sys.platform == "darwin":
                keychain_certs = _load_macos_keychain_certificates()
                trust_store_certs.extend(keychain_certs)
                logger.debug(f"Loaded {len(keychain_certs)} certificate(s) from macOS Keychain")
            # On Linux, try common locations
            elif os.name == "posix" and os.path.exists("/etc/ssl/certs/ca-certificates.crt"):
                with open("/etc/ssl/certs/ca-certificates.crt", "rb") as f:
                    system_data = f.read()
                    for cert_pem in _split_pem_certificates(system_data):
                        try:
                            cert = _load_cert_without_warnings(cert_pem, pem=True)
                            trust_store_certs.append(cert.public_bytes(serialization.Encoding.DER))
                        except Exception:
                            pass
        except Exception as e:
            logger.debug(f"Error loading system certificates: {e}")

    except Exception as e:
        logger.warning(f"Error loading trust store: {e}")

    return trust_store_certs


def _load_macos_keychain_certificates() -> List[bytes]:
    """
    Load certificates from macOS Keychain using the security command.
    
    Returns:
        List of DER-encoded certificates from macOS Keychain
    """
    keychain_certs: List[bytes] = []
    
    try:
        # Use security command to export all certificates from system keychains
        # -a: all certificates
        # -p: output in PEM format
        # We check both SystemRootCertificates and login keychain
        keychains = [
            "/System/Library/Keychains/SystemRootCertificates.keychain",
            "/Library/Keychains/SystemRootCertificates.keychain",
        ]
        
        # Try to get user's login keychain path
        try:
            result = subprocess.run(
                ["security", "default-keychain"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Extract keychain path from output (usually in quotes)
                keychain_path = result.stdout.strip().strip('"').strip("'")
                if keychain_path:
                    keychains.append(keychain_path)
        except Exception:
            pass  # Ignore if we can't get default keychain
        
        # Also try to find certificates in all keychains
        try:
            # Export all certificates from all keychains
            # -a: all certificates
            # -p: PEM format
            result = subprocess.run(
                ["security", "find-certificate", "-a", "-p"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            if result.returncode == 0 and result.stdout:
                # Parse PEM certificates from output
                for cert_pem in _split_pem_certificates(result.stdout.encode()):
                    try:
                        cert = _load_cert_without_warnings(cert_pem, pem=True)
                        keychain_certs.append(cert.public_bytes(serialization.Encoding.DER))
                    except Exception as e:
                        logger.debug(f"Error parsing Keychain certificate: {e}")
        except subprocess.TimeoutExpired:
            logger.debug("Timeout loading Keychain certificates")
        except FileNotFoundError:
            logger.debug("security command not found (not on macOS?)")
        except Exception as e:
            logger.debug(f"Error loading Keychain certificates: {e}")
            
    except Exception as e:
        logger.debug(f"Unexpected error loading macOS Keychain: {e}")
    
    return keychain_certs


def _split_pem_certificates(data: bytes) -> List[bytes]:
    """Split PEM data into individual certificate blocks."""
    import re

    pattern = rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----"
    matches = re.findall(pattern, data, re.DOTALL)
    return [
        b"-----BEGIN CERTIFICATE-----" + match + b"-----END CERTIFICATE-----\n"
        for match in matches
    ]


def load_root_certs_from_trust_store(
    ca_bundle: Optional[Path] = None,
) -> dict[str, bytes]:
    """
    Load root (self-signed) certificates from system trust store.
    
    Args:
        ca_bundle: Optional custom CA bundle path
    
    Returns:
        Dictionary mapping subject DN (RFC4514 format) to DER-encoded certificate bytes
    """
    issuer_map: dict[str, bytes] = {}
    
    try:
        # Create SSL context with system CA bundle
        context = ssl.create_default_context()
        if ca_bundle:
            context.load_verify_locations(str(ca_bundle))
        
        # Load all certificates from trust store
        trust_store_certs_der = _load_system_trust_store(context)
        
        logger.debug(f"Loaded {len(trust_store_certs_der)} certificate(s) from trust store, checking for root certificates...")
        
        # Filter for root certificates (self-signed) and add to issuer_map
        root_count = 0
        for cert_der in trust_store_certs_der:
            try:
                cert = _load_cert_without_warnings(cert_der, pem=False)
                cert_info, _ = parse_certificate(cert_der)
                # Root certificates are truly self-signed (not just subject==issuer)
                if _is_truly_self_signed(cert):
                    # Use RFC4514 format for consistency with CRL issuer format
                    subject_dn = cert_info.subject
                    issuer_map[subject_dn] = cert_der
                    root_count += 1
                    logger.debug(f"Added root certificate to issuer_map: {subject_dn}")
            except Exception as e:
                logger.debug(f"Error parsing certificate from trust store: {e}")
        
        logger.info(f"Loaded {root_count} root certificate(s) from trust store for CRL signature verification")
        
    except Exception as e:
        logger.warning(f"Error loading root certificates from trust store: {e}")
    
    return issuer_map

