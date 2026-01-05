"""Network operations for TLS connections."""

import socket
import ssl
import sys
import logging
import subprocess
from typing import Tuple, Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)


def _extract_chain_via_openssl(host: str, port: int, timeout: float, ignore_hostname: bool = False, server_name: Optional[str] = None) -> List[bytes]:
    """
    Extract certificate chain using OpenSSL command line tool.
    This is a fallback when getpeercert_chain() is not available.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        ignore_hostname: Ignore hostname verification
        server_name: SNI hostname (defaults to host if not specified)
    
    Returns:
        List of DER-encoded certificates (excluding leaf)
    """
    chain_certs_der: List[bytes] = []
    
    try:
        # Use openssl s_client to get the certificate chain
        openssl_cmd = [
            "openssl", "s_client",
            "-connect", f"{host}:{port}",
            "-showcerts",
        ]
        
        # SNI-Logik: Konsistent mit connect_tls()
        # Wenn server_name explizit gesetzt ist, diesen immer verwenden (auch bei ignore_hostname=True)
        # Wenn server_name nicht gesetzt ist und ignore_hostname=False, host als SNI verwenden
        # Nur wenn server_name nicht gesetzt ist UND ignore_hostname=True, kein SNI senden
        if server_name is not None:
            # Expliziter SNI-Wert wurde übergeben - immer verwenden (wichtig für korrekte Chain-Extraktion)
            openssl_cmd.extend(["-servername", server_name])
            logger.debug(f"Using SNI with hostname: {server_name} (OpenSSL fallback, explicit server_name)")
        elif not ignore_hostname:
            # Standard: hostname als SNI verwenden
            openssl_cmd.extend(["-servername", host])
            logger.debug(f"Using SNI with hostname: {host} (OpenSSL fallback)")
        else:
            # Nur wenn kein server_name UND ignore_hostname=True -> kein SNI
            logger.debug(f"SNI disabled for OpenSSL fallback (ignore_hostname=True, no explicit server_name)")
        
        # For ignore_hostname, we still want to get certificates even if validation fails
        # OpenSSL will output certificates regardless of validation status
        
        # Run openssl command
        try:
            result = subprocess.run(
                openssl_cmd,
                input=b"Q\n",  # Send quit command
                capture_output=True,
                timeout=timeout + 2,
                check=False,  # Don't raise on non-zero exit
            )
        except subprocess.TimeoutExpired:
            logger.debug("OpenSSL command timed out")
            return []
        except FileNotFoundError:
            logger.debug("OpenSSL command not found")
            return []
        
        # Parse the output to extract certificates
        # OpenSSL outputs certificates in PEM format between -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----
        output = result.stdout
        if not output:
            return []
        
        # Find all certificate blocks
        cert_start = b"-----BEGIN CERTIFICATE-----"
        cert_end = b"-----END CERTIFICATE-----"
        
        start_idx = 0
        while True:
            start_pos = output.find(cert_start, start_idx)
            if start_pos == -1:
                break
            
            end_pos = output.find(cert_end, start_pos)
            if end_pos == -1:
                break
            
            # Extract PEM certificate
            pem_cert = output[start_pos:end_pos + len(cert_end)]
            
            # Convert PEM to DER
            try:
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization
                
                from ssl_tester.certificate import _load_cert_with_cache
                cert, _ = _load_cert_with_cache(pem_cert, pem=True)
                cert_der = cert.public_bytes(serialization.Encoding.DER)
                chain_certs_der.append(cert_der)
            except Exception as e:
                logger.debug(f"Error parsing certificate from OpenSSL output: {e}")
            
            start_idx = end_pos + len(cert_end)
        
        # Remove the first certificate (leaf) - we already have it from getpeercert()
        if chain_certs_der:
            chain_certs_der = chain_certs_der[1:]
            logger.debug(f"Extracted {len(chain_certs_der)} intermediate certificate(s) via OpenSSL")
        
    except Exception as e:
        logger.debug(f"Error extracting chain via OpenSSL: {e}")
    
    return chain_certs_der


def _starttls_smtp(sock: socket.socket, timeout: float) -> None:
    """
    Perform SMTP STARTTLS handshake.
    
    Args:
        sock: Connected socket
        timeout: Socket timeout
        
    Raises:
        ConnectionError: If STARTTLS fails
    """
    sock.settimeout(timeout)
    
    # Read SMTP banner (e.g., "220 mail.example.com ESMTP")
    banner = sock.recv(4096).decode('utf-8', errors='ignore')
    if not banner.startswith('220'):
        raise ConnectionError(f"Unexpected SMTP banner: {banner[:100]}")
    
    # Send EHLO
    sock.sendall(b"EHLO localhost\r\n")
    response = sock.recv(4096).decode('utf-8', errors='ignore')
    
    # Check if STARTTLS is supported
    if 'STARTTLS' not in response.upper():
        raise ConnectionError("Server does not support STARTTLS")
    
    # Send STARTTLS command
    sock.sendall(b"STARTTLS\r\n")
    response = sock.recv(4096).decode('utf-8', errors='ignore')
    
    if not response.startswith('220'):
        raise ConnectionError(f"STARTTLS command failed: {response[:100]}")


def _starttls_imap(sock: socket.socket, timeout: float) -> None:
    """
    Perform IMAP STARTTLS handshake.
    
    Args:
        sock: Connected socket
        timeout: Socket timeout
        
    Raises:
        ConnectionError: If STARTTLS fails
    """
    sock.settimeout(timeout)
    
    # Read IMAP banner
    banner = sock.recv(4096).decode('utf-8', errors='ignore')
    
    # Send STARTTLS capability check
    sock.sendall(b"a001 CAPABILITY\r\n")
    response = sock.recv(4096).decode('utf-8', errors='ignore')
    
    if 'STARTTLS' not in response.upper():
        raise ConnectionError("Server does not support STARTTLS")
    
    # Send STARTTLS command
    sock.sendall(b"a002 STARTTLS\r\n")
    response = sock.recv(4096).decode('utf-8', errors='ignore')
    
    if not response.startswith('a002 OK'):
        raise ConnectionError(f"STARTTLS command failed: {response[:100]}")


def _starttls_pop3(sock: socket.socket, timeout: float) -> None:
    """
    Perform POP3 STARTTLS handshake.
    
    Args:
        sock: Connected socket
        timeout: Socket timeout
        
    Raises:
        ConnectionError: If STARTTLS fails
    """
    sock.settimeout(timeout)
    
    # Read POP3 banner (e.g., "+OK POP3 server ready")
    banner = sock.recv(4096).decode('utf-8', errors='ignore')
    if not banner.startswith('+OK'):
        raise ConnectionError(f"Unexpected POP3 banner: {banner[:100]}")
    
    # Send STLS command (POP3 uses STLS, not STARTTLS)
    sock.sendall(b"STLS\r\n")
    response = sock.recv(4096).decode('utf-8', errors='ignore')
    
    if not response.startswith('+OK'):
        raise ConnectionError(f"STLS command failed: {response[:100]}")


def _perform_starttls(sock: socket.socket, service: str, timeout: float) -> None:
    """
    Perform STARTTLS handshake for a given service.
    
    Args:
        sock: Connected socket
        service: Service type (SMTP, IMAP, POP3)
        timeout: Socket timeout
        
    Raises:
        ConnectionError: If STARTTLS fails
    """
    if service == "SMTP":
        _starttls_smtp(sock, timeout)
    elif service == "IMAP":
        _starttls_imap(sock, timeout)
    elif service == "POP3":
        _starttls_pop3(sock, timeout)
    else:
        raise ConnectionError(f"STARTTLS not implemented for service: {service}")


def connect_tls(
    host: str,
    port: int,
    timeout: float = 10.0,
    insecure: bool = False,
    ca_bundle: Optional[Path] = None,
    ipv6: bool = False,
    ignore_hostname: bool = False,
    service: Optional[str] = None,
    server_name: Optional[str] = None,
) -> Tuple[bytes, List[bytes], str]:
    """
    Establish TLS connection and extract certificate chain.
    
    Supports both direct TLS and STARTTLS for SMTP, IMAP, POP3.

    Args:
        host: Target hostname (for DNS resolution and connection)
        port: Target port
        timeout: Connection timeout in seconds
        insecure: Accept self-signed certificates
        ca_bundle: Custom CA bundle path
        ipv6: Prefer IPv6
        ignore_hostname: Ignore hostname verification (for error recovery)
        service: Service type (e.g., "SMTP", "IMAP", "POP3") - used to determine STARTTLS
        server_name: SNI hostname (defaults to host if not specified, None to disable SNI)

    Returns:
        Tuple of (leaf_certificate_der, chain_certificates_der_list, ip_address)

    Raises:
        ConnectionError: If connection fails
        ssl.SSLError: If TLS handshake fails
    """
    logger.debug(f"Connecting to {host}:{port} (timeout={timeout}s)")
    
    # Check if STARTTLS is needed
    needs_starttls = False
    if service:
        from ssl_tester.services import is_starttls_port
        needs_starttls = is_starttls_port(port, service)
    else:
        # Auto-detect service from port
        from ssl_tester.services import detect_service, is_starttls_port
        detected_service = detect_service(port)
        if detected_service:
            needs_starttls = is_starttls_port(port, detected_service)
            service = detected_service

    # Resolve address
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    ip_address: Optional[str] = None
    try:
        addr_info = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
        if not addr_info:
            raise ConnectionError(f"Could not resolve {host}:{port}")
        addr = addr_info[0][4]
        # IP-Adresse extrahieren (addr ist ein Tuple: (host, port) für IPv4 oder (host, port, flowinfo, scopeid) für IPv6)
        ip_address = addr[0] if isinstance(addr, tuple) else str(addr)
    except socket.gaierror as e:
        raise ConnectionError(f"DNS resolution failed for {host}: {e}")

    # Create socket
    sock = socket.socket(addr_info[0][0], socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        # Connect
        sock.connect(addr)
        logger.debug(f"TCP connection established to {addr}")

        # Perform STARTTLS handshake if needed
        if needs_starttls:
            logger.debug(f"Performing STARTTLS handshake for {service} on port {port}")
            if service == "SMTP":
                _starttls_smtp(sock, timeout)
            elif service == "IMAP":
                _starttls_imap(sock, timeout)
            elif service == "POP3":
                _starttls_pop3(sock, timeout)
            else:
                raise ConnectionError(f"STARTTLS not implemented for service: {service}")
            logger.debug("STARTTLS handshake completed")

        # Create SSL context
        context = ssl.create_default_context()
        if insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            logger.warning("Insecure mode enabled - certificate validation disabled")
        elif ignore_hostname:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED
            logger.debug("Hostname verification disabled for certificate extraction")

        if ca_bundle:
            context.load_verify_locations(str(ca_bundle))
            logger.debug(f"Using custom CA bundle: {ca_bundle}")

        # Wrap socket - SNI Logik:
        # Wenn server_name explizit gesetzt ist, diesen verwenden (auch bei ignore_hostname=True)
        # Wenn server_name None ist, aber host gesetzt ist, host verwenden (Standard-Verhalten)
        # Nur wenn server_name explizit auf None gesetzt wird UND ignore_hostname=True, kein SNI senden
        if server_name is not None:
            # Expliziter SNI-Wert wurde übergeben
            server_hostname = server_name
            logger.debug(f"Using explicit SNI hostname: {server_hostname} (connecting to IP: {ip_address})")
        elif ignore_hostname:
            # Kein expliziter SNI, aber ignore_hostname=True -> kein SNI (für Fehler-Recovery)
            server_hostname = None
            logger.debug(f"SNI disabled (ignore_hostname=True, no explicit server_name) - connecting to IP: {ip_address} (resolved from hostname: {host})")
        else:
            # Standard: hostname als SNI verwenden
            server_hostname = host
            logger.debug(f"Using SNI with hostname: {server_hostname} (connecting to IP: {ip_address})")
        ssl_sock = context.wrap_socket(sock, server_hostname=server_hostname)
        ssl_sock.do_handshake()
        logger.debug("TLS handshake completed")

        # Get leaf certificate
        leaf_cert_der = ssl_sock.getpeercert(binary_form=True)
        if not leaf_cert_der:
            raise ssl.SSLError("No certificate received from server")

        # Get certificate chain (Python 3.10+)
        # Note: getpeercert_chain() availability depends on the SSL backend used to compile Python,
        # not just the Python version. Some Python builds (especially on macOS) may not have this method.
        chain_certs_der: List[bytes] = []
        python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        ssl_version = ssl.OPENSSL_VERSION
        
        # Check if method is available
        if hasattr(ssl_sock, 'getpeercert_chain'):
            try:
                chain = ssl_sock.getpeercert_chain()
                if chain:
                    chain_certs_der = [cert for cert in chain if cert]
                    logger.debug(f"Received {len(chain_certs_der)} certificates in chain")
                else:
                    logger.warning("Server did not send certificate chain (only leaf)")
            except Exception as e:
                logger.debug(f"Error calling getpeercert_chain(): {e}")
        
        # Fallback: Try OpenSSL if getpeercert_chain() is not available or returned nothing
        if not chain_certs_der:
            if not hasattr(ssl_sock, 'getpeercert_chain'):
                logger.debug(
                    f"getpeercert_chain() not available in this Python build "
                    f"(Python {python_version}, {ssl_version}). "
                    "This is normal for some Python installations. Using OpenSSL fallback..."
                )
                logger.info("Extracting certificate chain via OpenSSL...")
            else:
                logger.info("No chain received via getpeercert_chain(), attempting to extract via OpenSSL...")
            
            # Close the current connection first
            try:
                ssl_sock.close()
            except Exception:
                pass
            
            # Try to extract chain via OpenSSL
            chain_certs_der = _extract_chain_via_openssl(host, port, timeout, ignore_hostname, server_name)
            
            if chain_certs_der:
                logger.info(f"Successfully extracted {len(chain_certs_der)} intermediate certificate(s) via OpenSSL")
            else:
                logger.warning("Could not extract certificate chain via OpenSSL. Will attempt to fetch intermediates via AIA if available.")

        return leaf_cert_der, chain_certs_der, ip_address

    except socket.timeout:
        raise ConnectionError(f"Connection timeout after {timeout}s")
    except ssl.SSLError as e:
        raise ssl.SSLError(f"TLS handshake failed: {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass

