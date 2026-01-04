# SSL/TLS Certificate Checker

A simple and fast CLI tool for checking SSL/TLS certificates on HTTPS web servers.

## Why use this tool?

This tool provides **comprehensive SSL/TLS certificate validation** with a focus on detailed checks that are essential for PKI operators and security professionals. It offers extensive validation capabilities that go far beyond basic expiration checks.

### Key Use Cases

**Operating Your Own PKI:**
When running your own Certificate Authority (CA) or managing internal certificates, you need detailed validation capabilities. This tool is especially valuable for:
- **CRL (Certificate Revocation List) Validation**: One of the most critical features - this tool performs comprehensive CRL checks including:
  - CRL reachability and accessibility
  - CRL signature verification against the CRL issuer
  - Revocation status checking (is your certificate actually revoked?)
  - CRL format validation (DER/PEM)
  - Automatic detection of CRL misconfigurations
  
  This comprehensive CRL validation helps ensure your PKI is properly configured and functioning correctly.

- **Certificate Chain Validation**: Full validation including signature verification, trust store validation, and automatic intermediate certificate fetching via AIA (Authority Information Access). The tool reports when intermediate certificates must be fetched because the server didn't send a complete chain (configuration issue).
- **Private CA Support**: Automatic detection and validation of certificates issued by private CAs (especially on macOS with Keychain integration)
- **Multi-Service Support**: Check certificates not just on HTTPS, but also on SMTP, IMAP, LDAP, and other TLS-enabled services

**Security Auditing:**
- Optional comprehensive vulnerability scanning (Heartbleed, POODLE, DROWN, etc.) using nmap
- Protocol and cipher suite analysis
- Security best practices validation (HSTS, OCSP Stapling, etc.)
- Detailed security rating system (A++ to F) with specific downgrade reasons

**Monitoring & Automation:**
- JSON output for integration with monitoring systems
- Batch processing for multiple domains
- CSV export for reporting and analysis
- Exit codes for automated alerting

**Troubleshooting:**
- Detailed error messages with root cause analysis
- Verbose mode for debugging certificate issues
- Clear reporting of what's wrong and why

Whether you're managing a corporate PKI, auditing SSL/TLS configurations, or troubleshooting certificate issues, this tool provides the detailed validation capabilities you need.

## Prerequisites

### Required

- **Python 3.10 or higher** (3.11 and 3.12 are also supported)
  - Check your Python version: `python3 --version`
  - If not installed: [python.org/downloads](https://www.python.org/downloads/)

- **pip** (Python Package Manager)
  - Usually included with Python
  - Check: `pip3 --version`

### Optional (but recommended)

- **nmap** (for comprehensive vulnerability scanning)
  - **Highly recommended** for accurate vulnerability detection
  - The tool will attempt to automatically install nmap if not found (requires package manager)
  - Manual installation:
    - macOS: `brew install nmap`
    - Linux: `sudo apt-get install nmap` (Debian/Ubuntu) or `sudo yum install nmap` (RHEL/CentOS)
    - Windows: Download from [nmap.org](https://nmap.org/download.html)
  - Check: `nmap --version`
  - **Note:** Vulnerability checks are disabled by default. Use `--vulnerabilities` to enable them. Without nmap, tests are skipped.

- **OpenSSL** (for fallback certificate chain extraction)
  - macOS: Usually pre-installed
  - Linux: `sudo apt-get install openssl` (Debian/Ubuntu) or `sudo yum install openssl` (RHEL/CentOS)
  - Windows: Part of Git for Windows or install separately
  - Check: `openssl version`

- **System CA Certificates** (for Trust Store validation)
  - macOS: Automatically loaded from Keychain
  - Linux: Usually in `/etc/ssl/certs/` or via `ca-certificates` package
  - Windows: From Windows Certificate Store

### Network

- Internet connection (for CRL/OCSP checks and AIA fetching)
- Optional: Proxy configuration if behind firewall/proxy

## Installation

### Step 1: Clone or download repository

```bash
# If from Git
git clone git@github.com:benjamishirley/ssl-tester.git
cd ssl-tester

# Or simply use the directory if already present
cd ssl-tester
```

### Step 2: Run installation

```bash
pip install -e .
```

**What happens during installation?**

1. **Dependencies are installed:**
   - `typer` (≥0.9.0) - CLI framework
   - `cryptography` (≥41.0.0) - Cryptographic operations for certificates
   - `httpx` (≥0.25.0) - HTTP client for CRL/OCSP/AIA requests
   - `certifi` (≥2023.0.0) - CA certificate bundle
   - `idna` (≥3.4) - Internationalized domain names

2. **The tool is registered as a CLI command:**
   - The `ssl-tester` command becomes available in your PATH
   - Installation is done in "editable mode" (`-e`), i.e., code changes take effect immediately

3. **Verification:**
   ```bash
   ssl-tester --help
   ```
   Should display help if installation was successful.

### Alternative: Installation without Editable Mode

If you don't want to develop the tool:

```bash
pip install .
```

**Note:** In this mode, you need to re-run the installation when making code changes.

### Development Environment (optional)

For development and testing:

```bash
pip install -e ".[dev]"
```

Installs additionally:
- `pytest` - Test framework
- `pytest-cov` - Coverage reports
- `mypy` - Type checking
- `black` - Code formatting
- `ruff` - Linting

### Troubleshooting Installation

**Problem: "pip: command not found"**
```bash
# macOS/Linux
python3 -m pip install -e .

# Windows
py -m pip install -e .
```

**Problem: "Permission denied"**
```bash
# Option 1: User installation (recommended)
pip install --user -e .

# Option 2: Virtual Environment (recommended for development)
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows
pip install -e .
```

**Problem: "No module named 'ssl_tester'"**
- Make sure you're in the correct directory
- Check if installation was successful: `pip list | grep ssl-tester`

## Quick Start

### Basic Usage

```bash
# Simple server check
ssl-tester example.com

# With URL
ssl-tester https://example.com

# JSON output for automation
ssl-tester example.com --json

# Verbose mode for details
ssl-tester example.com --verbose
```

## What does the tool offer?

The tool automatically checks:

### Certificate Checks
- **Certificate Chain**: Full validation including signature verification, trust store validation, and automatic intermediate certificate fetching via AIA when needed. The tool reports when intermediate certificates must be fetched because the server didn't send a complete chain (informational note, does not affect security rating).
- **Hostname**: RFC 6125-compliant check (SAN and CN)
- **Validity**: Expiration date and warning for upcoming expiration
- **CRL (Certificate Revocation List)**: Comprehensive CRL validation - a standout feature that's hard to find elsewhere:
  - CRL reachability and HTTP status checking
  - **CRL signature verification** against the CRL issuer certificate
  - **Revocation status checking** (is the certificate actually revoked?)
  - CRL format validation (DER/PEM automatic detection)
  - Detection of CRL misconfigurations (e.g., CRL signed by wrong issuer)
  - Automatic loading of root certificates from trust store for signature verification
  - Support for intermediate CA revocation checking
  - Detailed error reporting with root cause analysis
  
  This comprehensive CRL validation is essential for PKI operators who need to ensure their revocation infrastructure is working correctly.
- **OCSP**: Reachability of OCSP responders with fallback to CRL when OCSP is unavailable
- **Private CAs**: Automatic detection from macOS Keychain (no manual configuration needed)

### Protocol & Cipher Checks
- **Protocol Versions**: Support for TLS 1.0-1.3, SSL 2.0/3.0 (marked as FAIL)
- **Cipher Suites**: All supported cipher suites, vulnerability detection
- **Perfect Forward Secrecy (PFS)**: Check for PFS support
- **Weak Ciphers**: Detection of RC4, MD5, DES, 3DES, Export ciphers

### Cryptographic Vulnerabilities

**By default, vulnerability checks are NOT performed.** Use `--vulnerabilities` to enable them.

The tool checks for known SSL/TLS vulnerabilities using nmap. **All vulnerability tests require nmap to be installed.** Tests are skipped if nmap is not available.

Available vulnerability checks:
- **Heartbleed** (CVE-2014-0160) - Uses nmap `ssl-heartbleed` script
- **DROWN** (CVE-2016-0800) - Uses nmap `ssl-drown` script
- **POODLE** (CVE-2014-3566) - Uses nmap `ssl-poodle` script
- **CCS Injection** (CVE-2014-0224) - Uses nmap `ssl-ccs-injection` script
- **FREAK** (CVE-2015-0204) - Uses nmap `ssl-freak` script
- **Logjam** (CVE-2015-4000) - Uses nmap `ssl-dh-params` script
- **Ticketbleed** (CVE-2016-9244) - Uses nmap `ssl-ticketbleed` script
- **Sweet32** (CVE-2016-2183) - Uses nmap `ssl-enum-ciphers` script

**Usage:**
- `--vulnerabilities` - Enable all vulnerability checks
- `--vulnerabilities --vulnerability-list heartbleed,drown` - Check only specific vulnerabilities

**Important:** Vulnerability tests are only performed when nmap is installed. Without nmap, tests are skipped and results indicate that nmap is required.

### Security Best Practices
- **HSTS**: HTTP Strict Transport Security header check
- **OCSP Stapling**: Check for OCSP Stapling support
- **TLS Compression**: Check for CRIME vulnerability
- **Session Resumption**: TLS Session Resumption status

### Multi-Service Support
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

### Reporting & Export
- **Text Report**: Clear text output with severity display
- **JSON Report**: Machine-readable JSON for automation
- **HTML Report**: Professional HTML reports with CSS styling
- **CSV Export**: Batch results as CSV for Excel/Spreadsheets
- **PDF Export**: Optional with reportlab
- **Security Rating**: Rating system (A++ to F) based on all checks
  - **Downgrade Reasons**: Detailed list of reasons why a rating was downgraded

## Example Output

```
======================================================================
SSL/TLS Certificate Check Report
======================================================================
Target: example.com:443
Timestamp: 2026-01-02 10:00:00 UTC

Certificate Chain:
  Status: OK ✓
  Leaf Subject: CN=example.com
  Chain Valid: True
  Trust Store Valid: True

Hostname Matching:
  Status: OK ✓
  Expected: example.com
  Matches: True

Certificate Validity:
  Status: OK ✓
  Days Until Expiry: 47

Protocol Versions:
  Status: OK ✓
  Supported Versions: TLSv1.2, TLSv1.3
  Best Version: TLSv1.3

Cipher Suites:
  Status: OK ✓
  Supported Ciphers: 15
  Perfect Forward Secrecy (PFS): Yes ✓
  Weak Ciphers: None

Cryptographic Vulnerabilities:
  Status: OK ✓
  Vulnerable: 0 of 10

Security Best Practices:
  Status: OK ✓
  HSTS Enabled: Yes ✓
  OCSP Stapling: Yes ✓
  TLS Compression: Disabled ✓

======================================================================
Summary:
  Security Rating: A++
  Overall Status: OK ✓
  All checks passed successfully

Example with AIA fetching note:
======================================================================
Summary:
  Security Rating: A++
  Overall Status: OK ✓
  All checks passed successfully; Note: 2 intermediate certificate(s) were fetched via AIA (Authority Information Access) because the server did not send a complete certificate chain. This is a configuration issue - servers should send the complete chain.
======================================================================

Example with downgrade reasons:
======================================================================
Summary:
  Security Rating: B
  Downgrade Reasons:
    - TLS 1.3 is not supported
  Overall Status: WARN ⚠
  Certificate expires in 30 days
======================================================================
======================================================================
```

## Common Use Cases

### Monitoring / Automation

```bash
# JSON for monitoring systems
ssl-tester example.com --json > /var/log/ssl-check.json

# With exit code for alerts
ssl-tester example.com || send-alert.sh

# HTML report for dashboards
ssl-tester example.com --html /var/www/ssl-report.html

# CSV export for Excel
ssl-tester example.com --csv ssl-report.csv
```

### Batch Processing

```bash
# Check multiple domains from file
echo -e "example.com\ngoogle.com\ngithub.com" > targets.txt
ssl-tester batch targets.txt --parallel 5 --output-dir reports/

# CSV export for all results
ssl-tester batch targets.txt --csv batch-results.csv
```

### Server Comparison

```bash
# Compare two servers
ssl-tester compare server1.example.com server2.example.com

# With HTML report
ssl-tester compare server1.example.com server2.example.com --html comparison.html
```

### Private CAs / Internal Servers

```bash
# Private CA is automatically loaded from macOS Keychain
ssl-tester internal.example.com

# If not in Keychain: use --insecure
ssl-tester internal.example.com --insecure
```

### Multi-Service Support

```bash
# SMTP with STARTTLS
ssl-tester mail.example.com --port 587 --service SMTP

# IMAP
ssl-tester mail.example.com --port 993 --service IMAP

# LDAP
ssl-tester ldap.example.com --port 636 --service LDAP
```

### Debugging

```bash
# Verbose mode shows all details
ssl-tester problematic.example.com --verbose

# Only show specific severity
ssl-tester example.com --severity WARN

# Disable colored output
ssl-tester example.com --no-color
```

## Important Options

### Basic Options

```bash
# Adjust timeout (default: 10 seconds)
ssl-tester example.com --timeout 30.0

# Use proxy
ssl-tester example.com --proxy http://proxy.example.com:8080

# Custom CA bundle
ssl-tester example.com --ca-bundle /path/to/ca-bundle.pem

# Prefer IPv6
ssl-tester example.com --ipv6
```

### Check Options

```bash
# Skip certain checks
ssl-tester example.com --skip-protocol --skip-cipher

# Enable vulnerability checks (all vulnerabilities)
ssl-tester example.com --vulnerabilities

# Enable only specific vulnerability checks
ssl-tester example.com --vulnerabilities --vulnerability-list heartbleed,drown
```

### Output Options

```bash
# Generate HTML report
ssl-tester example.com --html report.html

# CSV export
ssl-tester example.com --csv report.csv

# JSON output
ssl-tester example.com --json

# Control colored output
ssl-tester example.com --color      # Enabled (default)
ssl-tester example.com --no-color   # Disabled

# Only show specific severity
ssl-tester example.com --severity WARN  # Only WARN and FAIL
```

### Service Options

```bash
# Explicitly specify service type
ssl-tester mail.example.com --port 587 --service SMTP

# Automatic service detection based on port
ssl-tester mail.example.com --port 993  # Automatically detects IMAP
```

## Exit Codes

For script integration:

- `0`: All checks successful (OK)
- `1`: Warnings present (WARN)
- `2`: Errors present (FAIL)

**Example:**
```bash
#!/bin/bash
if ssl-tester example.com; then
    echo "Certificate is valid!"
else
    exit_code=$?
    if [ $exit_code -eq 1 ]; then
        echo "Warnings found"
    elif [ $exit_code -eq 2 ]; then
        echo "Errors found!"
        exit 1
    fi
fi
```

## System-Specific Notes

### macOS

- **Keychain Integration**: Private CAs are automatically loaded from macOS Keychain
- **OpenSSL**: Usually pre-installed, check with `openssl version`
- **Python**: Often already installed, alternatively via Homebrew: `brew install python3`

### Linux

- **CA Certificates**: Make sure `ca-certificates` is installed:
  ```bash
  # Debian/Ubuntu
  sudo apt-get update && sudo apt-get install ca-certificates
  
  # RHEL/CentOS
  sudo yum install ca-certificates
  ```
- **OpenSSL**: Usually pre-installed, if not: `sudo apt-get install openssl`

### Windows

- **Python**: Download from [python.org](https://www.python.org/downloads/)
- **OpenSSL**: Part of Git for Windows or separately from [slproweb.com](https://slproweb.com/products/Win32OpenSSL.html)
- **CA Certificates**: Loaded from Windows Certificate Store

## Further Information

- **Technical Details**: See [TECHNICAL.md](TECHNICAL.md)
- **Development**: See [TECHNICAL.md](TECHNICAL.md#development)
- **Troubleshooting**: See [TECHNICAL.md](TECHNICAL.md#troubleshooting)

## License

MIT License
