# Technical Documentation - SSL/TLS Certificate Checker

This documentation contains detailed technical information for developers and advanced users.

## Table of Contents

- [Features in Detail](#features-in-detail)
- [Advanced Options](#advanced-options)
- [JSON Output](#json-output)
- [HTML Report](#html-report)
- [CSV Export](#csv-export)
- [Security Rating](#security-rating)
- [Protocol & Cipher Checks](#protocol--cipher-checks)
- [Cryptographic Vulnerabilities](#cryptographic-vulnerabilities)
- [Multi-Service Support](#multi-service-support)
- [Batch Processing](#batch-processing)
- [macOS Keychain Integration](#macos-keychain-integration)
- [CRL Signature Verification](#crl-signature-verification)
- [Trust Stores](#trust-stores)
- [RFC Compliance](#rfc-compliance)
- [Development](#development)
- [Troubleshooting](#troubleshooting)

## Features in Detail

### Certificate Chain Validation

- Full certificate chain validation including signature verification
- Automatic sorting and validation of the chain
- Support for missing intermediate certificates (AIA fetching)
- **AIA Fetching Tracking**: The tool tracks and reports when intermediate certificates must be fetched via AIA (Authority Information Access) because the server didn't send a complete certificate chain. This is reported as an informational note in the summary and text report (does not affect security rating). This helps identify configuration issues where servers should send complete certificate chains.
- Automatic loading of root certificates from trust store for CRL signature verification

### Hostname Matching

- RFC 6125-compliant check of SAN (Subject Alternative Names) and CN
- Wildcard support
- IP address support

### Validity Check

- Check of NotBefore/NotAfter
- Warning for upcoming expiration
- Days until expiration are displayed

### CRL Check

- Reachability of CRL Distribution Points
- Format validation (DER/PEM)
- **Signature Verification**: Automatic verification of CRL signature against CRL issuer
- Revocation status check (is the certificate marked as revoked?)
- Automatic loading of root certificates from trust store if CRL issuer is not present in chain

### OCSP Check

- Reachability of OCSP responders
- HTTP status check

### Certificate Findings

- Automatic detection and reporting of certificate problems
- Example: Deprecated serial number formats (non-positive serial numbers)

### Protocol & Cipher Checks

- **Protocol Version Tests**: Support for TLS 1.0-1.3, SSL 2.0/3.0
- **Cipher Suite Tests**: All supported cipher suites are listed
- **Vulnerability Detection**: RC4, MD5, DES, 3DES, Export ciphers
- **Perfect Forward Secrecy (PFS)**: Check for PFS support
- **Cipher Strength Classification**: Strong/Medium/Weak/Null

### Cryptographic Vulnerabilities

**By default, vulnerability checks are NOT performed.** Use `--vulnerabilities` to enable them.

The tool checks for known SSL/TLS vulnerabilities using nmap. All vulnerability tests require nmap to be installed.

**Nmap Integration:**
- The tool automatically detects if nmap is installed in the system PATH
- If nmap is not found, it attempts to install it via package managers (Homebrew on macOS, apt/yum/dnf/pacman on Linux)
- If automatic installation fails, tests are skipped with a warning message
- Nmap scripts used:
  - `ssl-heartbleed` - Heartbleed vulnerability detection
  - `ssl-poodle` - POODLE vulnerability detection
  - `ssl-drown` - DROWN vulnerability detection
  - `ssl-ccs-injection` - CCS Injection vulnerability detection
  - `ssl-freak` - FREAK vulnerability detection
  - `ssl-dh-params` - Logjam vulnerability detection (weak DH parameters)
  - `ssl-enum-ciphers` - Sweet32 detection (cipher enumeration)
  - `ssl-ticketbleed` - Ticketbleed vulnerability detection

**Vulnerability Checks:**

All vulnerability tests require nmap to be installed. Tests are skipped if nmap is not available.

**CLI Options:**
- `--vulnerabilities` - Enable vulnerability checks (checks all vulnerabilities by default)
- `--vulnerability-list <list>` - Specify which vulnerabilities to check (comma-separated). Requires `--vulnerabilities`.
  - Available: `heartbleed`, `drown`, `poodle`, `ccs-injection`, `freak`, `logjam`, `ticketbleed`, `sweet32`
  - Example: `--vulnerabilities --vulnerability-list heartbleed,drown`

- **Heartbleed** (CVE-2014-0160): Uses nmap `ssl-heartbleed` script for real heartbeat request testing.
- **DROWN** (CVE-2016-0800): Uses nmap `ssl-drown` script.
- **POODLE** (CVE-2014-3566): Uses nmap `ssl-poodle` script.
- **CCS Injection** (CVE-2014-0224): Uses nmap `ssl-ccs-injection` script.
- **FREAK** (CVE-2015-0204): Uses nmap `ssl-freak` script.
- **Logjam** (CVE-2015-4000): Uses nmap `ssl-dh-params` script to check DH parameter strength.
- **Ticketbleed** (CVE-2016-9244): Uses nmap `ssl-ticketbleed` script.
- **Sweet32** (CVE-2016-2183): Uses nmap `ssl-enum-ciphers` to check for 3DES/DES/Blowfish.

**Removed Tests:**
The following vulnerability tests have been removed as they only perform simplified checks that don't accurately detect vulnerabilities:
- **BEAST** (CVE-2011-3389): Would require checking all offered ciphers, not just the negotiated one.
- **Lucky13** (CVE-2013-0169): Requires timing attack tests with specialized tools.
- **ROBOT** (CVE-2017-13099): Requires padding oracle attack tests with specialized tools.

**Behavior when nmap is not available:**
- Tests are skipped and return a result indicating that nmap is required
- Results include a recommendation to install nmap
- Users are warned in logs when nmap is not available
- No false security is provided - tests are clearly marked as skipped

### Security Best Practices

- **HSTS**: HTTP Strict Transport Security header check
- **OCSP Stapling**: Check for OCSP Stapling support
- **TLS Compression**: Check for CRIME vulnerability
- **Session Resumption**: TLS Session Resumption status
- **Certificate Transparency**: SCT (Signed Certificate Timestamps) check

### Multi-Service Support

The tool supports various services with automatic detection:

- **HTTPS** (443)
- **SMTP** (25, 465, 587) - STARTTLS
- **IMAP** (143, 993) - STARTTLS
- **POP3** (110, 995) - STARTTLS
- **FTP** (21, 990) - FTPS/STARTTLS
- **LDAP** (389, 636) - STARTTLS
- **XMPP** (5222) - STARTTLS
- **RDP** (3389) - TLS
- **PostgreSQL** (5432) - TLS
- **MySQL** (3306) - TLS

### Batch Processing

- Parallel processing of multiple domains
- Progress bars with `rich` library
- Summary reports
- CSV export for batch results

## Advanced Options

### Timeout and Performance

```bash
# Custom Timeout (default: 10 seconds)
ssl-tester example.com --timeout 5.0

# Prefer IPv6
ssl-tester example.com --ipv6
```

### Proxy Support

```bash
# Use HTTP proxy
ssl-tester example.com --proxy http://proxy.example.com:8080

# Proxy is also used for CRL and OCSP requests
```

### Private CAs and Self-Signed Certificates

```bash
# Accept private CAs / self-signed certificates
ssl-tester internal.example.com --insecure

# Use custom CA bundle
ssl-tester example.com --ca-bundle /path/to/ca-bundle.pem
```

### CRL Options

```bash
# Don't follow redirects for CRL URLs
ssl-tester example.com --no-redirects

# Adjust maximum CRL size (default: 10MB)
ssl-tester example.com --max-crl-bytes 5242880
```

**Note:** The tool automatically validates CRL signatures against the CRL issuer. Signature verification is performed with the certificate whose subject matches the CRL issuer.

### Check Options

```bash
# Skip certain checks
ssl-tester example.com --skip-protocol

# Run only specific checks (exclusive mode)
ssl-tester example.com --only-checks chain,hostname,protocol
ssl-tester example.com --only-checks crl,ocsp
ssl-tester example.com --only-checks vulnerabilities --vulnerability-list heartbleed,drown
ssl-tester example.com --skip-cipher
ssl-tester example.com --skip-vulnerabilities
ssl-tester example.com --skip-security

# Explicitly specify service type
ssl-tester mail.example.com --port 587 --service SMTP
```

### Output Options

```bash
# Generate HTML report
ssl-tester example.com --html report.html

# CSV export
ssl-tester example.com --csv report.csv

# Control colored output
ssl-tester example.com --color      # Enabled (default)
ssl-tester example.com --no-color # Disabled

# Only show specific severity
ssl-tester example.com --severity WARN  # Only WARN and FAIL
```

### Batch Processing

```bash
# Check multiple domains from file
ssl-tester batch targets.txt --parallel 5 --output-dir reports/

# CSV export for batch results
ssl-tester batch targets.txt --csv batch-results.csv
```

### Server Comparison

```bash
# Compare two servers
ssl-tester compare server1.example.com server2.example.com

# With HTML report
ssl-tester compare server1.example.com server2.example.com --html comparison.html
```

## JSON Output

The JSON output contains all check results in structured form:

```json
{
  "target_host": "example.com",
  "target_port": 443,
  "timestamp": "2026-01-02T10:00:00Z",
  "rating": "A++",
  "rating_reasons": [],
  "overall_severity": "OK",
  "chain_check": {
    "intermediates_fetched_via_aia": false,
    "intermediates_fetched_count": 0,
    ...
  },
  "protocol_check": { ... },
  "cipher_check": { ... },
  "vulnerability_checks": [ ... ],
  "security_check": { ... }
}
```

**Note:** The `rating_reasons` field contains a list of strings with the reasons for rating downgrade. For a perfect rating (A++), this list is empty.

**AIA Fetching:** The `chain_check` object includes `intermediates_fetched_via_aia` (boolean) and `intermediates_fetched_count` (integer) fields that indicate when intermediate certificates were fetched via AIA because the server didn't send a complete chain. This information is also included in the summary text as an informational note.

## HTML Report

The HTML report provides a professional, interactive presentation of results:

- **Responsive Design**: Works on desktop and mobile
- **Color Coding**: OK/WARN/FAIL with visual indicators
- **Security Rating**: Prominent display of rating (A++ to F)
- **Downgrade Reasons**: Detailed list of rating downgrade reasons in a highlighted section
- **Structured Sections**: All checks in clear sections
- **CSS Styling**: Modern design with gradients and shadows

```bash
ssl-tester example.com --html report.html
```

## CSV Export

The CSV export is suitable for batch results and Excel analysis:

```bash
ssl-tester example.com --csv report.csv
ssl-tester batch targets.txt --csv batch-results.csv
```

The CSV file contains one row per target with all important metrics:
- Rating, Overall Severity
- Protocol versions, Cipher information
- Vulnerability count, Security flags
- CRL/OCSP status

## Security Rating

The tool uses a rating system to evaluate SSL/TLS security:

- **A++**: Perfect - TLS 1.3, strong ciphers, no vulnerabilities, HSTS, OCSP Stapling
- **A+**: Very good - TLS 1.3, good configuration, minimal warnings
- **A**: Good - TLS 1.2+, good configuration, some warnings
- **B**: Acceptable - TLS 1.2+, some issues
- **C**: Weak - TLS 1.1/1.0, weak ciphers
- **D**: Very weak - TLS 1.0, many issues
- **E**: Critical - Only TLS 1.0, critical vulnerabilities
- **F**: Completely insecure - SSL protocols, critical vulnerabilities

The rating is calculated based on all checks:
- Protocol versions
- Cipher suite configuration
- Cryptographic Vulnerabilities
- Security Best Practices
- Certificate validation

### Downgrade Reasons (Rating Reasons)

For each rating, detailed **downgrade reasons** are collected and displayed that explain why a particular rating was assigned. These reasons are available in all output formats:

**Text Report:**
```
Summary:
  Security Rating: B
  Downgrade Reasons:
    - TLS 1.3 is not supported
  Overall Status: OK ✓
```

**HTML Report:**
The downgrade reasons are displayed in a highlighted section directly below the rating badge.

**JSON Report:**
```json
{
  "rating": "B",
  "rating_reasons": [
    "TLS 1.3 is not supported"
  ],
  ...
}
```

**Typical Downgrade Reasons:**
- `"TLS 1.3 is not supported"` - Only older TLS versions available
- `"Perfect Forward Secrecy (PFS) is not supported"` - No PFS-capable cipher suites
- `"Weak encryption algorithms are supported"` - RC4, MD5, DES, etc.
- `"TLS 1.0 is supported (deprecated)"` - Deprecated protocols active
- `"TLS 1.1 is supported (deprecated)"` - Deprecated protocols active
- `"Critical security vulnerabilities found: Heartbleed, POODLE"` - Known vulnerabilities
- `"TLS compression is enabled (CRIME attack possible)"` - CRIME vulnerability
- `"Critical certificate issues: Certificate chain invalid"` - Certificate validation errors
- `"HSTS not enabled"` - Missing security best practices
- `"OCSP Stapling not enabled"` - Missing security best practices
- `"Warnings present: Certificate chain warnings, Hostname warnings"` - Various warnings

A rating of **A++** typically has no downgrade reasons (empty list), as it represents a perfect configuration.

## Protocol & Cipher Checks

### Protocol Version Tests

The tool tests all available TLS/SSL versions:
- TLS 1.3 (if available)
- TLS 1.2
- TLS 1.1 (deprecated)
- TLS 1.0 (deprecated)
- SSL 3.0 (FAIL)
- SSL 2.0 (FAIL)

### Cipher Suite Tests

- All supported cipher suites are listed
- Vulnerability detection: RC4, MD5, DES, 3DES, Export ciphers
- Perfect Forward Secrecy (PFS) check
- Cipher strength classification

## Cryptographic Vulnerabilities

Each known vulnerability is checked individually and marked with clear severity (OK/WARN/FAIL). Checks are performed locally without third-party services (privacy-first principle).

## Multi-Service Support

The tool supports various services with automatic detection based on port. STARTTLS is supported for SMTP, IMAP, POP3, FTP, and LDAP.

## Batch Processing

Batch mode enables parallel processing of multiple domains:

- **Threading**: Parallel processing with configurable worker count
- **Progress Bars**: Visual progress display with `rich`
- **Summary**: Overview of all results at the end
- **Export**: CSV export for all results

```bash
ssl-tester batch targets.txt --parallel 5 --output-dir reports/
```

## JSON Output (Legacy)

For automation and scripts, JSON output can be used:

```bash
ssl-tester example.com --json | jq '.chain_check.chain_valid'
```

The JSON structure contains all details:

- `chain_check`: Certificate chain information
- `hostname_check`: Hostname matching results
- `validity_check`: Validity check
- `crl_checks`: CRL checks (including signature verification)
- `ocsp_checks`: OCSP checks
- `certificate_findings`: Automatically detected certificate problems
- `overall_severity`: Overall status (OK/WARN/FAIL)

## macOS Keychain Integration

On macOS, certificates are automatically loaded from the Keychain:

- **System Keychains**: System root certificates
- **User Keychain**: User-specific certificates
- **Private CAs**: Automatically detected if installed in Keychain

No additional configuration required! The tool automatically finds private root CAs.

## CRL Signature Verification

CRL signature verification is an important part of certificate checking:

1. **CRL is downloaded** from the URL in the certificate
2. **CRL format is validated** (DER or PEM)
3. **CRL issuer is identified** (who signed the CRL)
4. **CRL issuer certificate is searched** in chain or issuer_map
5. **Root certificates are loaded from Trust Store** if CRL issuer not present in chain
6. **Signature is verified** against the public key of the CRL issuer
7. **Revocation status is checked** (is the certificate marked as revoked in the CRL?)

**Important:** The CRL is signed by the CRL issuer, not by the certificate issuer. These can be different!

The tool automatically loads root certificates from the system trust store (macOS Keychain, certifi bundle, Linux CA certificates) to verify CRL signatures, even if the signing root certificate is not included in the server certificate chain.

## Trust Stores

The tool checks certificates against:

1. **certifi Bundle**: Mozilla CA Bundle (Python package)
2. **macOS Keychain**: System and user keychains (automatic on macOS)
3. **Linux System CAs**: `/etc/ssl/certs/ca-certificates.crt` (on Linux)
4. **Custom CA Bundle**: Via `--ca-bundle` option

### Root Certificates for CRL Signature Verification

The tool automatically loads all root certificates (self-signed) from the trust store and adds them to the `issuer_map`. This enables verification of CRL signatures, even if the signing root certificate is not included in the server certificate chain.

## RFC Compliance

- **RFC 6125**: Hostname matching (SAN preferred, wildcard support)
- **RFC 5280**: Certificate validation
- **RFC 6960**: OCSP requests and responses

## Supported Features

- **Certificate Formats**: DER, PEM (automatic detection)
- **CRL Formats**: DER, PEM (automatic detection)
- **Signature Algorithms**: RSA, RSASSA-PSS, ECDSA, Ed25519, Ed448
- **Hash Algorithms**: SHA-1, SHA-256, SHA-384, SHA-512
- **Chain Building**: Automatic sorting and validation
- **AIA Fetching**: Recursive retrieval of intermediate certificates via Authority Information Access URLs. The tool tracks and reports when intermediate certificates must be fetched because the server didn't send a complete chain (informational note in summary and reports).
- **CRL Signature Verification**: Automatic signature verification against CRL issuer
- **Revocation Checking**: Check if certificates are marked as revoked in CRL

## Development

### Setup

```bash
# Clone repository
git clone git@github.com:benjamishirley/ssl-tester.git
cd ssl-tester

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"
```

### Run Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=ssl_tester --cov-report=html

# Specific tests
pytest tests/test_chain.py -v
```

### Code Quality

```bash
# Type checking
mypy src/

# Code formatting
black src/ tests/

# Linting
ruff check src/ tests/

# All checks
ruff check src/ tests/ && black --check src/ tests/ && mypy src/
```

### Test Coverage

```bash
# Tests with coverage report
pytest --cov=ssl_tester --cov-report=term-missing

# Generate HTML report
pytest --cov=ssl_tester --cov-report=html
# Open htmlcov/index.html in browser
```

## Troubleshooting

### "getpeercert_chain() not available"

This is a warning when Python < 3.10 is used. The tool automatically falls back to AIA fetching.

### "Root CA not found in system trust store"

- **macOS**: Certificate should be installed in Keychain (automatically loaded)
- **Linux**: Add certificate to `/etc/ssl/certs/` or use `--ca-bundle`
- **Alternative**: Use `--insecure` for private CAs

### "CRL signer certificate not found in issuer_map"

This error should no longer occur, as the tool automatically loads root certificates from the trust store. If it still appears:

- Check if the root certificate is present in the system trust store
- Use `--verbose` for detailed debug information
- Check if the root certificate is actually self-signed (subject == issuer)

### "CRL signature verification failed"

This means the CRL signature could not be verified against the CRL issuer. Possible causes:

- CRL issuer certificate not present in chain and not found in trust store
- Signature is actually invalid
- CRL issuer does not match certificate issuer (normal, as CRL is signed by CRL issuer)

**Note:** If CRL signature verification fails, the CRL check is marked as WARN, even if the CRL is reachable and the certificate is not marked as revoked. An invalid signature means the CRL is not trustworthy.

### Timeout Errors

- Increase timeout: `--timeout 30.0`
- Verbose mode for details: `--verbose`
- Check network connectivity

## Changelog / Changes

### Current Version

- **AIA Fetching Tracking**: The tool now tracks and reports when intermediate certificates must be fetched via AIA because the server didn't send a complete certificate chain. This is shown as an informational note in the summary and text report (does not affect security rating).
- **Root Certificates from Trust Store**: Automatic loading of root certificates for CRL signature verification
- **CRL Signature Verification**: Fixed bug where CRL objects evaluated to `False` in boolean context. Signature verification now works correctly.
- **Certificate Findings**: Automatic detection and reporting of certificate problems (e.g., deprecated serial number formats).
- **Improved Error Handling**: More detailed error messages for CRL and chain validation.

## Contributing

Contributions are welcome! Please create a Pull Request or open an Issue.
