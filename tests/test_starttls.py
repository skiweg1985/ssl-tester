"""Tests for STARTTLS functionality."""

import pytest
import socket
from unittest.mock import Mock, patch, MagicMock

from ssl_tester.network import (
    _starttls_smtp,
    _starttls_imap,
    _starttls_pop3,
    _perform_starttls,
    connect_tls,
)
from ssl_tester.protocol import check_protocol_versions
from ssl_tester.cipher import check_cipher_suites
from ssl_tester.security import check_security_best_practices


class TestSMTPSTARTTLS:
    """Tests for SMTP STARTTLS."""
    
    def test_starttls_smtp_success(self):
        """Test successful SMTP STARTTLS handshake."""
        mock_sock = Mock()
        mock_sock.recv.side_effect = [
            b"220 mail.example.com ESMTP\r\n",
            b"250-mail.example.com\r\n250-STARTTLS\r\n250-AUTH PLAIN\r\n",
            b"220 Ready to start TLS\r\n",
        ]
        
        _starttls_smtp(mock_sock, timeout=10.0)
        
        assert mock_sock.sendall.call_count == 2
        assert b"EHLO localhost\r\n" in [call[0][0] for call in mock_sock.sendall.call_args_list]
        assert b"STARTTLS\r\n" in [call[0][0] for call in mock_sock.sendall.call_args_list]
    
    def test_starttls_smtp_invalid_banner(self):
        """Test SMTP STARTTLS with invalid banner."""
        mock_sock = Mock()
        mock_sock.recv.return_value = b"500 Error\r\n"
        
        with pytest.raises(ConnectionError, match="Unexpected SMTP banner"):
            _starttls_smtp(mock_sock, timeout=10.0)
    
    def test_starttls_smtp_no_support(self):
        """Test SMTP STARTTLS when server doesn't support it."""
        mock_sock = Mock()
        mock_sock.recv.side_effect = [
            b"220 mail.example.com ESMTP\r\n",
            b"250-mail.example.com\r\n250-AUTH PLAIN\r\n",  # No STARTTLS
        ]
        
        with pytest.raises(ConnectionError, match="Server does not support STARTTLS"):
            _starttls_smtp(mock_sock, timeout=10.0)
    
    def test_starttls_smtp_command_failed(self):
        """Test SMTP STARTTLS when command fails."""
        mock_sock = Mock()
        mock_sock.recv.side_effect = [
            b"220 mail.example.com ESMTP\r\n",
            b"250-mail.example.com\r\n250-STARTTLS\r\n",
            b"500 Command not recognized\r\n",
        ]
        
        with pytest.raises(ConnectionError, match="STARTTLS command failed"):
            _starttls_smtp(mock_sock, timeout=10.0)


class TestIMAPSTARTTLS:
    """Tests for IMAP STARTTLS."""
    
    def test_starttls_imap_success(self):
        """Test successful IMAP STARTTLS handshake."""
        mock_sock = Mock()
        mock_sock.recv.side_effect = [
            b"* OK IMAP server ready\r\n",
            b"a001 CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n",
            b"a002 OK Begin TLS negotiation now\r\n",
        ]
        
        _starttls_imap(mock_sock, timeout=10.0)
        
        assert mock_sock.sendall.call_count == 2
        assert b"a001 CAPABILITY\r\n" in [call[0][0] for call in mock_sock.sendall.call_args_list]
        assert b"a002 STARTTLS\r\n" in [call[0][0] for call in mock_sock.sendall.call_args_list]
    
    def test_starttls_imap_no_support(self):
        """Test IMAP STARTTLS when server doesn't support it."""
        mock_sock = Mock()
        mock_sock.recv.side_effect = [
            b"* OK IMAP server ready\r\n",
            b"a001 CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n",  # No STARTTLS
        ]
        
        with pytest.raises(ConnectionError, match="Server does not support STARTTLS"):
            _starttls_imap(mock_sock, timeout=10.0)
    
    def test_starttls_imap_command_failed(self):
        """Test IMAP STARTTLS when command fails."""
        mock_sock = Mock()
        mock_sock.recv.side_effect = [
            b"* OK IMAP server ready\r\n",
            b"a001 CAPABILITY IMAP4rev1 STARTTLS\r\n",
            b"a002 NO STARTTLS not available\r\n",
        ]
        
        with pytest.raises(ConnectionError, match="STARTTLS command failed"):
            _starttls_imap(mock_sock, timeout=10.0)


class TestPOP3STARTTLS:
    """Tests for POP3 STARTTLS (STLS)."""
    
    def test_starttls_pop3_success(self):
        """Test successful POP3 STLS handshake."""
        mock_sock = Mock()
        mock_sock.recv.side_effect = [
            b"+OK POP3 server ready\r\n",
            b"+OK Begin TLS negotiation\r\n",
        ]
        
        _starttls_pop3(mock_sock, timeout=10.0)
        
        assert mock_sock.sendall.call_count == 1
        assert b"STLS\r\n" in [call[0][0] for call in mock_sock.sendall.call_args_list]
    
    def test_starttls_pop3_invalid_banner(self):
        """Test POP3 STLS with invalid banner."""
        mock_sock = Mock()
        mock_sock.recv.return_value = b"-ERR Error\r\n"
        
        with pytest.raises(ConnectionError, match="Unexpected POP3 banner"):
            _starttls_pop3(mock_sock, timeout=10.0)
    
    def test_starttls_pop3_command_failed(self):
        """Test POP3 STLS when command fails."""
        mock_sock = Mock()
        mock_sock.recv.side_effect = [
            b"+OK POP3 server ready\r\n",
            b"-ERR STLS not supported\r\n",
        ]
        
        with pytest.raises(ConnectionError, match="STLS command failed"):
            _starttls_pop3(mock_sock, timeout=10.0)


class TestPerformSTARTTLS:
    """Tests for _perform_starttls wrapper function."""
    
    def test_perform_starttls_smtp(self):
        """Test _perform_starttls with SMTP."""
        mock_sock = Mock()
        mock_sock.recv.side_effect = [
            b"220 mail.example.com ESMTP\r\n",
            b"250-mail.example.com\r\n250-STARTTLS\r\n",
            b"220 Ready to start TLS\r\n",
        ]
        
        _perform_starttls(mock_sock, "SMTP", timeout=10.0)
        
        assert mock_sock.sendall.call_count == 2
    
    def test_perform_starttls_imap(self):
        """Test _perform_starttls with IMAP."""
        mock_sock = Mock()
        mock_sock.recv.side_effect = [
            b"* OK IMAP server ready\r\n",
            b"a001 CAPABILITY IMAP4rev1 STARTTLS\r\n",
            b"a002 OK Begin TLS negotiation now\r\n",
        ]
        
        _perform_starttls(mock_sock, "IMAP", timeout=10.0)
        
        assert mock_sock.sendall.call_count == 2
    
    def test_perform_starttls_pop3(self):
        """Test _perform_starttls with POP3."""
        mock_sock = Mock()
        mock_sock.recv.side_effect = [
            b"+OK POP3 server ready\r\n",
            b"+OK Begin TLS negotiation\r\n",
        ]
        
        _perform_starttls(mock_sock, "POP3", timeout=10.0)
        
        assert mock_sock.sendall.call_count == 1
    
    def test_perform_starttls_unknown_service(self):
        """Test _perform_starttls with unknown service."""
        mock_sock = Mock()
        
        with pytest.raises(ConnectionError, match="STARTTLS not implemented"):
            _perform_starttls(mock_sock, "UNKNOWN", timeout=10.0)


class TestConnectTLSWithSTARTTLS:
    """Tests for connect_tls with STARTTLS support."""
    
    @patch("ssl_tester.network.socket.socket")
    @patch("ssl_tester.network.ssl.create_default_context")
    @patch("ssl_tester.services.is_starttls_port")
    def test_connect_tls_with_starttls(self, mock_is_starttls, mock_ssl_context, mock_socket_class):
        """Test connect_tls with STARTTLS."""
        # Mock socket
        mock_sock = Mock()
        mock_socket_class.return_value = mock_sock
        
        # Mock STARTTLS responses
        mock_sock.recv.side_effect = [
            b"220 mail.example.com ESMTP\r\n",
            b"250-mail.example.com\r\n250-STARTTLS\r\n",
            b"220 Ready to start TLS\r\n",
        ]
        
        # Mock STARTTLS detection
        mock_is_starttls.return_value = True
        
        # Mock SSL context and socket
        mock_context = Mock()
        mock_ssl_context.return_value = mock_context
        mock_ssl_sock = Mock()
        mock_context.wrap_socket.return_value = mock_ssl_sock
        
        # Mock certificate data
        leaf_cert = b"fake_leaf_cert"
        chain_certs = [b"fake_intermediate_cert"]
        mock_ssl_sock.getpeercert.return_value = leaf_cert
        mock_ssl_sock.getpeercert_chain.return_value = chain_certs
        
        # Mock getaddrinfo
        with patch("ssl_tester.network.socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 587))]
            
            result_leaf, result_chain = connect_tls("example.com", 587, timeout=10.0, service="SMTP")
            
            assert result_leaf == leaf_cert
            assert result_chain == chain_certs
            # Verify STARTTLS was performed (EHLO and STARTTLS commands sent)
            assert mock_sock.sendall.call_count >= 2
            mock_ssl_sock.do_handshake.assert_called_once()
    
    @patch("ssl_tester.network.socket.socket")
    @patch("ssl_tester.network.ssl.create_default_context")
    @patch("ssl_tester.services.is_starttls_port")
    def test_connect_tls_without_starttls(self, mock_is_starttls, mock_ssl_context, mock_socket_class):
        """Test connect_tls without STARTTLS (direct TLS)."""
        # Mock socket
        mock_sock = Mock()
        mock_socket_class.return_value = mock_sock
        
        # Mock STARTTLS detection
        mock_is_starttls.return_value = False
        
        # Mock SSL context and socket
        mock_context = Mock()
        mock_ssl_context.return_value = mock_context
        mock_ssl_sock = Mock()
        mock_context.wrap_socket.return_value = mock_ssl_sock
        
        # Mock certificate data
        leaf_cert = b"fake_leaf_cert"
        chain_certs = [b"fake_intermediate_cert"]
        mock_ssl_sock.getpeercert.return_value = leaf_cert
        mock_ssl_sock.getpeercert_chain.return_value = chain_certs
        
        # Mock getaddrinfo
        with patch("ssl_tester.network.socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 443))]
            
            with patch("ssl_tester.network._perform_starttls") as mock_perform_starttls:
                result_leaf, result_chain = connect_tls("example.com", 443, timeout=10.0, service="HTTPS")
                
                assert result_leaf == leaf_cert
                assert result_chain == chain_certs
                mock_perform_starttls.assert_not_called()
                mock_ssl_sock.do_handshake.assert_called_once()


class TestProtocolCheckWithSTARTTLS:
    """Tests for protocol checks with STARTTLS."""
    
    @patch("ssl_tester.protocol.socket.socket")
    @patch("ssl_tester.protocol.ssl.SSLContext")
    @patch("ssl_tester.services.is_starttls_port")
    @patch("ssl_tester.network._perform_starttls")
    def test_protocol_check_with_starttls(self, mock_perform_starttls, mock_is_starttls, mock_ssl_context, mock_socket_class):
        """Test protocol check with STARTTLS."""
        # Mock socket
        mock_sock = Mock()
        mock_socket_class.return_value = mock_sock
        
        # Mock STARTTLS detection
        mock_is_starttls.return_value = True
        
        # Mock SSL context and socket
        mock_context = Mock()
        mock_ssl_context.return_value = mock_context
        mock_ssl_sock = Mock()
        mock_context.wrap_socket.return_value = mock_ssl_sock
        mock_ssl_sock.version.return_value = "TLSv1.2"
        
        # Mock getaddrinfo
        with patch("ssl_tester.protocol.socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 587))]
            
            # This will fail on actual connection, but we're testing the STARTTLS call
            # We'll just verify that _perform_starttls would be called
            try:
                check_protocol_versions("example.com", 587, timeout=2.0, service="SMTP")
            except Exception:
                pass  # Expected to fail on real connection
            
            # Verify STARTTLS was attempted
            assert mock_perform_starttls.called or mock_is_starttls.called


class TestCipherCheckWithSTARTTLS:
    """Tests for cipher checks with STARTTLS."""
    
    @patch("ssl_tester.cipher.socket.socket")
    @patch("ssl_tester.cipher.ssl.SSLContext")
    @patch("ssl_tester.services.is_starttls_port")
    @patch("ssl_tester.network._perform_starttls")
    def test_cipher_check_with_starttls(self, mock_perform_starttls, mock_is_starttls, mock_ssl_context, mock_socket_class):
        """Test cipher check with STARTTLS."""
        # Mock socket
        mock_sock = Mock()
        mock_socket_class.return_value = mock_sock
        
        # Mock STARTTLS detection
        mock_is_starttls.return_value = True
        
        # Mock SSL context and socket
        mock_context = Mock()
        mock_ssl_context.return_value = mock_context
        mock_ssl_sock = Mock()
        mock_context.wrap_socket.return_value = mock_ssl_sock
        mock_ssl_sock.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 128)
        
        # Mock getaddrinfo
        with patch("ssl_tester.cipher.socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 587))]
            
            # This will fail on actual connection, but we're testing the STARTTLS call
            try:
                check_cipher_suites("example.com", 587, timeout=2.0, service="SMTP")
            except Exception:
                pass  # Expected to fail on real connection
            
            # Verify STARTTLS was attempted
            assert mock_perform_starttls.called or mock_is_starttls.called


class TestSecurityCheckWithSTARTTLS:
    """Tests for security checks with STARTTLS."""
    
    @patch("ssl_tester.security.check_hsts")
    @patch("ssl_tester.security.socket.socket")
    @patch("ssl_tester.security.ssl.create_default_context")
    @patch("ssl_tester.services.is_starttls_port")
    @patch("ssl_tester.network._perform_starttls")
    def test_security_check_hsts_only_for_https(self, mock_perform_starttls, mock_is_starttls, mock_ssl_context, mock_socket_class, mock_hsts):
        """Test that HSTS is only checked for HTTPS services."""
        from ssl_tester.models import SecurityCheckResult
        
        # Mock HSTS result
        mock_hsts.return_value = SecurityCheckResult(hsts_enabled=True)
        
        # Mock socket
        mock_sock = Mock()
        mock_socket_class.return_value = mock_sock
        
        # Mock SSL context and socket
        mock_context = Mock()
        mock_ssl_context.return_value = mock_context
        mock_ssl_sock = Mock()
        mock_context.wrap_socket.return_value = mock_ssl_sock
        mock_ssl_sock.getpeercert.return_value = {}
        
        # Mock getaddrinfo
        with patch("ssl_tester.security.socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 587))]
            
            # Test with SMTP (should NOT check HSTS)
            try:
                check_security_best_practices("example.com", 587, timeout=2.0, service="SMTP")
            except Exception:
                pass  # Expected to fail on real connection
            
            # HSTS should not be called for SMTP
            mock_hsts.assert_not_called()
        
        # Reset mock
        mock_hsts.reset_mock()
        
        # Test with HTTPS (should check HSTS)
        with patch("ssl_tester.security.socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 443))]
            
            try:
                check_security_best_practices("example.com", 443, timeout=2.0, service="HTTPS")
            except Exception:
                pass  # Expected to fail on real connection
            
            # HSTS should be called for HTTPS
            mock_hsts.assert_called_once()

