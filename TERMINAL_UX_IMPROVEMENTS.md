# Terminal UX Verbesserungen

## Übersicht

Die Terminal-UX wurde komplett überarbeitet, um Benutzern einen schnellen Überblick über den SSL/TLS-Status zu geben, ohne wichtige Details zu verlieren.

## Neue Features

### 1. At-a-glance Header

Am Anfang jedes Reports wird ein kompakter Header angezeigt mit:
- Gesamtstatus (OK/WARN/FAIL)
- Target und Port
- Security Rating (A++ bis F)
- TLS-Version
- Ablaufzeit (Tage bis Ablauf)
- Hostname-Match Status
- Revocation-Methode (CRL/OCSP)
- HSTS Status
- OCSP Stapling Status

**Beispiel:**
```
[OK ✓]  google.de:443  Rating: A++  TLS: TLSv1.3  Expiry: 51d  Hostname: OK  Revocation: CRL+OCSP  HSTS: Yes  Stapling: Yes
Timestamp: 2024-01-15 10:30:45 UTC
```

### 2. Findings-Sektion

Direkt nach dem Header werden alle wichtigen Findings gruppiert nach Severity angezeigt:
- **FAIL**: Kritische Probleme
- **WARN**: Warnungen
- **INFO**: Informative Meldungen (nur bei --verbose)

**Beispiel:**
```
Findings:
  FAIL:
    ✗ Certificate expired
    ✗ Hostname does not match certificate
  WARN:
    ⚠ Certificate expires in 30 days
    ⚠ CRL (http://crl.example.com/crl.crl): Not reachable
  Use --verbose or --debug to show full evidence
```

### 3. Phasen-Struktur

Der Report ist in 6 klar getrennte Phasen unterteilt:

#### Phase 1: Connectivity
- Verbindungsstatus
- HTTP-Redirect-Ergebnisse (falls geprüft)

#### Phase 2: Certificate Chain
- Chain-Validierung
- Trust-Path-Entscheidung
- Cross-Signing-Auflösung (kompakt)

#### Phase 3: Hostname Matching
- SAN/CN-Match-Status
- Erwarteter Hostname

#### Phase 4: Certificate Validity
- Gültigkeitszeitraum
- Tage bis Ablauf
- Ablaufstatus

#### Phase 5: Revocation Checks
- CRL-Status (erreichbar/nicht erreichbar)
- OCSP-Status
- Explizite Ergebnisse mit Soft-Fail/Hard-Fail-Semantik

#### Phase 6: TLS Configuration
- TLS-Versionen
- Cipher Suites
- Best Practices (HSTS, OCSP Stapling, etc.)

### 4. Verbesserte Cross-Signing-Darstellung

Cross-Signed-Zertifikate werden jetzt kompakt und klar dargestellt:

```
Cross-Signing Resolution (Info - not a security issue):
  Server chain root candidate: GTS Root R1 (cross-signed by GlobalSign Root CA)
  Trust anchor selected: GTS Root R1 (self-signed, from trust store)
  Reason: trust store contains self-signed root; RFC 4158 path building
```

Bei `--verbose` werden zusätzliche Details angezeigt:
- Chain cert issuer und serial number
- Trust root issuer und serial number

### 5. Verbosity-Kontrolle

#### Standard-Modus (kompakt)
- Zeigt nur die wichtigsten Informationen
- CN-Namen statt vollständiger DNs
- Zusammenfassungen statt vollständiger Listen

#### `--verbose` Modus
- Zeigt alle Details für jede Phase
- Vollständige DNs
- Alle Cipher Suites
- Vollständige Certificate Findings

#### `--quiet` Modus
- Zeigt nur den At-a-glance Header
- Finaler Status
- Rating und Downgrade-Gründe

#### `--debug` Modus
- Aktiviert Runtime-Logging
- Zeigt HTTP-Request-Traces
- Zeigt Debug-Ausgaben

### 6. Logging vs Report Trennung

- **Standard**: Nur der Report wird angezeigt, keine Runtime-Logs
- **--debug**: Runtime-Logs werden angezeigt (INFO/DEBUG Level)
- Logs werden nicht mehr mit dem Report vermischt

## Beispiel-Ausgaben

### Standard-Ausgabe (kompakt)

```
[OK ✓]  google.de:443  Rating: A++  TLS: TLSv1.3  Expiry: 51d  Hostname: OK  Revocation: CRL+OCSP  HSTS: Yes  Stapling: Yes
Timestamp: 2024-01-15 10:30:45 UTC

Findings:
  (keine kritischen Findings)

Phase 1: Connectivity
  Status: OK ✓
  
Phase 2: Certificate Chain
  Status: OK ✓
  Leaf: *.google.com
  Intermediates: 1 (GTS CA 1C3)
  Root: GTS Root R1
  
Phase 3: Hostname Matching
  Status: OK ✓
  Expected: google.de
  Matches: Yes
  
Phase 4: Certificate Validity
  Status: OK ✓
  Days Until Expiry: 51
  
Phase 5: Revocation Checks
  CRL Status: OK ✓
  CRLs: 2/2 reachable
  OCSP Status: OK ✓
  OCSP Responders: 1/1 reachable
  
Phase 6: TLS Configuration
  Protocol Status: OK ✓
  Best Version: TLSv1.3
  Cipher Status: OK ✓
  Ciphers: 15 supported
  PFS: Yes ✓
  Security Status: OK ✓
  HSTS: Yes ✓
  OCSP Stapling: Yes ✓

======================================================================
Summary:
  Security Rating: A++
  Overall Status: OK ✓
  All checks passed successfully
======================================================================
```

### Verbose-Ausgabe (`--verbose`)

```
[OK ✓]  google.de:443  Rating: A++  TLS: TLSv1.3  Expiry: 51d  Hostname: OK  Revocation: CRL+OCSP  HSTS: Yes  Stapling: Yes
Timestamp: 2024-01-15 10:30:45 UTC

Phase 1: Connectivity
  Status: OK ✓
  Connected to google.de:443
  Service Type: HTTPS
  
Phase 2: Certificate Chain
  Status: OK ✓
  Leaf Subject: CN=*.google.com, O=Google LLC, C=US
  Leaf Issuer: CN=GTS CA 1C3, O=Google Trust Services LLC, C=US
  Chain Valid: True
  Trust Store Valid: True
  Intermediates: 1
    1. CN=GTS CA 1C3, O=Google Trust Services LLC, C=US
  Root: CN=GTS Root R1, O=Google Trust Services LLC, C=US
  
  Cross-Signing Resolution (Info - not a security issue):
    Server chain root candidate: GTS Root R1 (cross-signed by GlobalSign Root CA)
    Trust anchor selected: GTS Root R1 (self-signed, from trust store)
    Reason: trust store contains self-signed root; RFC 4158 path building
    Details:
      Chain cert issuer: CN=GlobalSign Root CA, O=GlobalSign nv-sa, C=BE
      Chain cert serial: 1234567890
      Trust root issuer: CN=GTS Root R1, O=Google Trust Services LLC, C=US
      Trust root serial: 9876543210
  
Phase 3: Hostname Matching
  Status: OK ✓
  Expected: google.de
  Matches: True
  Matched SAN DNS: google.de
  
Phase 4: Certificate Validity
  Status: OK ✓
  Valid: True
  Not Before: 2024-01-01 00:00:00 UTC
  Not After: 2024-03-01 00:00:00 UTC
  Days Until Expiry: 51
  
Phase 5: Revocation Checks
  CRL Status: OK ✓
  Leaf Certificate CRLs:
    http://crl.pki.goog/gts1c3/gts1c3.crl: OK ✓
  Intermediate Certificate CRLs:
    http://crl.pki.goog/gtsr1/gtsr1.crl: OK ✓
  OCSP Status: OK ✓
    http://ocsp.pki.goog: OK ✓
  
Phase 6: TLS Configuration
  Protocol Status: OK ✓
  Supported Versions: TLSv1.2, TLSv1.3
  Best Version: TLSv1.3
  Cipher Status: OK ✓
  Supported Ciphers: 15
    - TLS_AES_128_GCM_SHA256
    - TLS_AES_256_GCM_SHA384
    - TLS_CHACHA20_POLY1305_SHA256
    ... and 12 more
  Perfect Forward Secrecy (PFS): Yes ✓
  Security Status: OK ✓
  HSTS Enabled: Yes ✓
  HSTS Max-Age: 31536000 seconds
  OCSP Stapling: Yes ✓
  TLS Compression: Disabled ✓

======================================================================
Summary:
  Security Rating: A++
  Overall Status: OK ✓
  All checks passed successfully
======================================================================
```

### Quiet-Ausgabe (`--quiet`)

```
[OK ✓]  google.de:443  Rating: A++  TLS: TLSv1.3  Expiry: 51d  Hostname: OK  Revocation: CRL+OCSP  HSTS: Yes  Stapling: Yes
Timestamp: 2024-01-15 10:30:45 UTC

======================================================================
Summary:
  Security Rating: A++
  Overall Status: OK ✓
  All checks passed successfully
======================================================================
```

## Migration

Die alte `generate_text_report()` Funktion bleibt für Rückwärtskompatibilität erhalten. Die neue `generate_terminal_report()` Funktion wird standardmäßig verwendet.

Um die alte Ausgabe zu verwenden, kann `generate_text_report()` direkt aufgerufen werden (z.B. in Skripten).

## CLI-Flags

- `--verbose` / `-v`: Zeigt vollständige Details für jede Phase
- `--quiet` / `-q`: Zeigt nur At-a-glance Header + Final Status
- `--debug`: Aktiviert Runtime-Logging (INFO/DEBUG Level)
- `--json`: Maschinenlesbare JSON-Ausgabe (unverändert)
- `--severity`: Filtert nach Severity (OK/WARN/FAIL)

## Design-Prinzipien

1. **At-a-glance**: Benutzer sehen sofort den Status
2. **Phasen-Struktur**: Klare Trennung der Check-Bereiche
3. **Kompakte Standard-Ausgabe**: Nur wichtige Informationen
4. **Verbose für Details**: Vollständige Informationen bei Bedarf
5. **Findings-First**: Wichtige Probleme werden sofort sichtbar
6. **Cross-Signing klar erklärt**: Keine Verwirrung bei Cross-Signed-Zertifikaten
7. **Saubere Logs**: Runtime-Logs stören den Report nicht

