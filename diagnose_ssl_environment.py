#!/usr/bin/env python3
"""
Diagnose-Script für SSL/TLS Environment
Sammelt Informationen über Python, SSL-Backend, OpenSSL und System-Konfiguration
um Inkonsistenzen zwischen verschiedenen Macs zu identifizieren.
"""

import sys
import subprocess
import platform
import os
from pathlib import Path
from typing import Optional, Dict, List


def find_command(cmd_name: str) -> Optional[str]:
    """Finde Command im PATH oder bekannten Pfaden."""
    # Bekannte absolute Pfade für macOS
    known_paths = {
        "security": ["/usr/bin/security"],
        "openssl": ["/usr/bin/openssl", "/usr/local/bin/openssl", "/opt/homebrew/bin/openssl"],
    }
    
    # Prüfe bekannte Pfade zuerst
    if cmd_name in known_paths:
        for path in known_paths[cmd_name]:
            if Path(path).exists():
                return path
    
    # Prüfe PATH
    try:
        result = subprocess.run(
            ["which", cmd_name],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    
    return None


def run_command(cmd: List[str], timeout: int = 5) -> tuple[bool, str]:
    """Führe einen Command aus und gib Ergebnis zurück."""
    # Versuche zuerst mit gegebenem Command
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode == 0:
            return True, result.stdout.strip()
        # Wenn fehlgeschlagen, versuche absolute Pfad
        if cmd[0] in ["security", "openssl"]:
            abs_path = find_command(cmd[0])
            if abs_path:
                cmd_with_path = [abs_path] + cmd[1:]
                result = subprocess.run(
                    cmd_with_path,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
                if result.returncode == 0:
                    return True, result.stdout.strip()
        return False, result.stderr.strip() or result.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, f"Timeout nach {timeout}s"
    except FileNotFoundError:
        # Versuche absolute Pfad
        if cmd[0] in ["security", "openssl"]:
            abs_path = find_command(cmd[0])
            if abs_path:
                try:
                    cmd_with_path = [abs_path] + cmd[1:]
                    result = subprocess.run(
                        cmd_with_path,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        check=False,
                    )
                    return result.returncode == 0, result.stdout.strip()
                except Exception:
                    pass
        return False, "Command nicht gefunden"
    except Exception as e:
        return False, f"Fehler: {e}"


def check_file_exists(path: str) -> tuple[bool, Optional[str]]:
    """Prüfe ob Datei existiert und gib Größe zurück."""
    p = Path(path)
    if p.exists():
        size = p.stat().st_size
        return True, f"{size:,} bytes"
    return False, None


def main():
    print("=" * 80)
    print("SSL/TLS Environment Diagnose")
    print("=" * 80)
    print()
    
    # 1. System-Informationen
    print("1. SYSTEM-INFORMATIONEN")
    print("-" * 80)
    print(f"Betriebssystem: {platform.system()} {platform.release()}")
    print(f"Architektur: {platform.machine()}")
    print(f"Python Executable: {sys.executable}")
    print()
    
    # 2. Python Version
    print("2. PYTHON VERSION")
    print("-" * 80)
    print(f"Python Version: {sys.version}")
    print(f"Python Version Info: {sys.version_info}")
    print()
    
    # 3. SSL Backend Information
    print("3. SSL BACKEND INFORMATION")
    print("-" * 80)
    try:
        import ssl
        print(f"SSL Modul verfügbar: Ja")
        print(f"OpenSSL Version: {ssl.OPENSSL_VERSION}")
        print(f"OpenSSL Version Number: {ssl.OPENSSL_VERSION_NUMBER}")
        print(f"SSL Version: {ssl.PROTOCOL_TLS}")
        
        # Prüfe getpeercert_chain Verfügbarkeit
        has_getpeercert_chain = hasattr(ssl.SSLSocket, 'getpeercert_chain')
        print(f"getpeercert_chain() verfügbar: {'Ja ✓' if has_getpeercert_chain else 'Nein ✗'}")
        
        if not has_getpeercert_chain:
            print("  ⚠️  Warnung: getpeercert_chain() nicht verfügbar!")
            print("     Das Tool wird OpenSSL als Fallback verwenden müssen.")
        
        # Test SSL Context
        try:
            context = ssl.create_default_context()
            print(f"create_default_context() funktioniert: Ja ✓")
        except Exception as e:
            print(f"create_default_context() funktioniert: Nein ✗ ({e})")
            
    except ImportError as e:
        print(f"SSL Modul nicht verfügbar: {e}")
    print()
    
    # 4. OpenSSL Command Line Tool
    print("4. OPENSSL COMMAND LINE TOOL")
    print("-" * 80)
    openssl_path = find_command("openssl")
    if openssl_path:
        print(f"OpenSSL Pfad: {openssl_path}")
        openssl_available, openssl_version = run_command(["openssl", "version"])
        if openssl_available:
            print(f"OpenSSL verfügbar: Ja ✓")
            print(f"OpenSSL Version: {openssl_version}")
            
            # Prüfe ob s_client verfügbar ist (teste mit -connect statt -help)
            # LibreSSL verwendet andere Optionen als OpenSSL
            s_client_available, s_client_output = run_command(
                ["openssl", "s_client", "-connect", "example.com:443"],
                timeout=3
            )
            # s_client gibt normalerweise einen Fehler zurück, aber das bedeutet dass es existiert
            # Wir prüfen ob es "s_client" im Output gibt oder ob es "command not found" ist
            if "s_client" in s_client_output.lower() or "connect:" in s_client_output.lower() or openssl_available:
                print(f"openssl s_client verfügbar: Ja ✓")
            else:
                print(f"openssl s_client verfügbar: Unklar")
                print(f"  Output: {s_client_output[:150]}")
        else:
            print(f"OpenSSL verfügbar: Nein ✗")
            print(f"  Fehler: {openssl_version}")
    else:
        print(f"OpenSSL verfügbar: Nein ✗")
        print(f"  ⚠️  Warnung: OpenSSL nicht gefunden!")
        print(f"     Das Tool kann keine Zertifikatsketten extrahieren wenn getpeercert_chain() fehlt.")
    print()
    
    # 5. macOS Security Command (nur auf macOS)
    print("5. MACOS SECURITY COMMAND")
    print("-" * 80)
    if platform.system() == "Darwin":
        security_path = find_command("security")
        if security_path:
            print(f"security Command Pfad: {security_path}")
            # macOS security command unterstützt kein --version, teste direkt mit find-certificate
            security_available = Path(security_path).exists()
            if security_available:
                print(f"security Command verfügbar: Ja ✓")
                
                # Test Keychain-Zugriff
                keychain_test, keychain_output = run_command(
                    ["security", "find-certificate", "-a", "-p"],
                    timeout=10
                )
                if keychain_test:
                    cert_count = keychain_output.count("BEGIN CERTIFICATE")
                    print(f"Keychain-Zugriff: Erfolgreich ✓")
                    print(f"Zertifikate in Keychain: {cert_count}")
                else:
                    print(f"Keychain-Zugriff: Fehlgeschlagen ✗")
                    print(f"  Fehler: {keychain_output[:200]}")
            else:
                print(f"security Command verfügbar: Nein ✗")
                print(f"  Pfad existiert nicht: {security_path}")
        else:
            print(f"security Command verfügbar: Nein ✗")
            print(f"  ⚠️  Warnung: security Command nicht gefunden!")
            print(f"     Erwarteter Pfad: /usr/bin/security")
    else:
        print("Nicht auf macOS - übersprungen")
    print()
    
    # 6. Certifi CA Bundle
    print("6. CERTIFI CA BUNDLE")
    print("-" * 80)
    try:
        import certifi
        certifi_path = certifi.where()
        exists, size_info = check_file_exists(certifi_path)
        if exists:
            print(f"certifi verfügbar: Ja ✓")
            print(f"Certifi Bundle Pfad: {certifi_path}")
            print(f"Bundle Größe: {size_info}")
        else:
            print(f"certifi verfügbar: Ja, aber Bundle nicht gefunden ✗")
            print(f"Erwarteter Pfad: {certifi_path}")
    except ImportError:
        print(f"certifi verfügbar: Nein ✗")
        print(f"  ⚠️  Warnung: certifi nicht installiert!")
    print()
    
    # 7. Homebrew OpenSSL CA Bundle (macOS)
    print("7. HOMEBREW OPENSSL CA BUNDLES")
    print("-" * 80)
    if platform.system() == "Darwin":
        homebrew_paths = [
            "/usr/local/etc/openssl/cert.pem",  # Intel Mac
            "/opt/homebrew/etc/openssl/cert.pem",  # Apple Silicon
        ]
        found_any = False
        for path in homebrew_paths:
            exists, size_info = check_file_exists(path)
            if exists:
                print(f"✓ {path}: Gefunden ({size_info})")
                found_any = True
            else:
                print(f"✗ {path}: Nicht gefunden")
        
        if not found_any:
            print("Keine Homebrew OpenSSL CA Bundles gefunden")
    else:
        print("Nicht auf macOS - übersprungen")
    print()
    
    # 8. Python Dependencies
    print("8. PYTHON DEPENDENCIES")
    print("-" * 80)
    dependencies = {
        "cryptography": "Zertifikats-Parsing und Validierung",
        "httpx": "HTTP-Anfragen (AIA, OCSP, CRL)",
        "certifi": "CA-Bundle",
        "idna": "Hostname-Normalisierung",
    }
    
    for module_name, description in dependencies.items():
        try:
            mod = __import__(module_name)
            version = getattr(mod, "__version__", "Unbekannt")
            print(f"✓ {module_name}: {version} - {description}")
        except ImportError:
            print(f"✗ {module_name}: Nicht installiert - {description}")
    print()
    
    # 9. SSL Context Test
    print("9. SSL CONTEXT TEST")
    print("-" * 80)
    try:
        import ssl
        context = ssl.create_default_context()
        
        # Test CA Bundle Loading
        try:
            import certifi
            certifi_path = certifi.where()
            context.load_verify_locations(certifi_path)
            print(f"✓ Certifi Bundle kann geladen werden")
        except Exception as e:
            print(f"✗ Certifi Bundle kann nicht geladen werden: {e}")
        
        # Test Homebrew OpenSSL CA Bundle (macOS)
        if platform.system() == "Darwin":
            homebrew_paths = [
                "/usr/local/etc/openssl/cert.pem",
                "/opt/homebrew/etc/openssl/cert.pem",
            ]
            for path in homebrew_paths:
                if Path(path).exists():
                    try:
                        context.load_verify_locations(path)
                        print(f"✓ Homebrew CA Bundle kann geladen werden: {path}")
                    except Exception as e:
                        print(f"✗ Homebrew CA Bundle kann nicht geladen werden ({path}): {e}")
        
        # Test Keychain Loading (macOS)
        if platform.system() == "Darwin":
            try:
                from ssl_tester.chain import _load_macos_keychain_certificates
                keychain_certs = _load_macos_keychain_certificates()
                print(f"✓ Keychain-Zertifikate können geladen werden: {len(keychain_certs)} Zertifikate")
            except Exception as e:
                print(f"✗ Keychain-Zertifikate können nicht geladen werden: {e}")
        
    except Exception as e:
        print(f"✗ SSL Context Test fehlgeschlagen: {e}")
    print()
    
    # 10. Zusammenfassung und Empfehlungen
    print("10. ZUSAMMENFASSUNG")
    print("-" * 80)
    issues = []
    warnings = []
    
    # Prüfe kritische Komponenten
    try:
        import ssl
        if not hasattr(ssl.SSLSocket, 'getpeercert_chain'):
            warnings.append("getpeercert_chain() nicht verfügbar - OpenSSL Fallback wird benötigt")
    except:
        issues.append("SSL Modul nicht verfügbar")
    
    openssl_path = find_command("openssl")
    openssl_available = openssl_path is not None and Path(openssl_path).exists()
    if not openssl_available:
        try:
            import ssl
            has_getpeercert_chain = hasattr(ssl.SSLSocket, 'getpeercert_chain')
            if not has_getpeercert_chain:
                issues.append("OpenSSL nicht verfügbar UND getpeercert_chain() fehlt - Zertifikatsketten können nicht extrahiert werden")
            else:
                warnings.append("OpenSSL nicht verfügbar (nicht kritisch wenn getpeercert_chain() verfügbar)")
        except:
            pass
    
    if platform.system() == "Darwin":
        security_path = find_command("security")
        security_available = security_path is not None and Path(security_path).exists()
        if not security_available:
            warnings.append("security Command nicht verfügbar - Keychain-Zertifikate können nicht geladen werden")
    
    try:
        import certifi
    except ImportError:
        warnings.append("certifi nicht installiert - CA-Bundle kann fehlen")
    
    if issues:
        print("❌ KRITISCHE PROBLEME:")
        for issue in issues:
            print(f"   • {issue}")
        print()
    
    if warnings:
        print("⚠️  WARNUNGEN:")
        for warning in warnings:
            print(f"   • {warning}")
        print()
    
    if not issues and not warnings:
        print("✓ Alle Komponenten sind verfügbar und funktionieren korrekt!")
    else:
        print("💡 EMPFEHLUNGEN:")
        if "getpeercert_chain() nicht verfügbar" in str(warnings):
            print("   • Installieren Sie Python mit vollständigem SSL-Support")
            print("   • Oder stellen Sie sicher, dass OpenSSL im PATH verfügbar ist")
        if "OpenSSL nicht verfügbar" in str(issues + warnings):
            print("   • Installieren Sie OpenSSL: brew install openssl")
        if "security Command nicht verfügbar" in str(warnings):
            print("   • Sicherstellen Sie, dass Sie auf macOS sind")
            print("   • Prüfen Sie ob /usr/bin/security existiert")
        if "certifi nicht installiert" in str(warnings):
            print("   • Installieren Sie certifi: pip install certifi")
    
    print()
    print("=" * 80)
    print("Diagnose abgeschlossen")
    print("=" * 80)


if __name__ == "__main__":
    main()

