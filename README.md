# OFXpwn - Open Financial Exchange Security Testing Framework

<div align="center">

**A comprehensive penetration testing toolkit for OFX (Open Financial Exchange) servers**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Author: Mike Piekarski](https://img.shields.io/badge/author-Mike%20Piekarski-blue)](https://github.com/pect0ral)

[Installation](#installation) • [Quick Start](#quick-start) • [Modules](#modules) • [Documentation](#documentation)

</div>

---

## Overview

OFXpwn is a modular penetration testing framework designed specifically for security assessments of OFX (Open Financial Exchange) servers. Born from real-world pentesting needs, this tool addresses the gap in publicly available security testing tools for financial protocols.

### What is OFX?

OFX is a unified specification for the electronic exchange of financial data between financial institutions, businesses, and consumers via the Internet. It's used by applications like Quicken, QuickBooks, Microsoft Money, and GnuCash to download transactions and account information.

### Why OFXpwn?

- **Specialized**: Purpose-built for OFX security testing
- **Modular**: Run individual tests or comprehensive scans
- **Flexible**: Config-driven with runtime overrides
- **Comprehensive**: Covers authentication, protocol fuzzing, info disclosure, and more
- **Professional**: Built by pentesters, for pentesters

### Key Features

**Authentication Testing**
- Default credential bruteforce
- SQL/LDAP injection testing
- Username enumeration
- Parameter fuzzing (CLIENTUID, FID, ORG, APPID/APPVER)
- Rate limiting and account lockout detection
- Custom credential lists

**Protocol Security**
- XXE (XML External Entity) attacks
- SGML/XML parser fuzzing
- Field overflow testing
- Encoding attacks

**Reconnaissance**
- Version fingerprinting
- Capability discovery (PROFRQ)
- Account enumeration (ACCTINFORQ)
- Server enumeration
- Technology detection

**Exploitation**
- IDOR (Insecure Direct Object Reference) testing
- SQL injection
- XSS testing
- Command injection
- Path traversal

**Infrastructure**
- SSL/TLS assessment
- HTTP header analysis
- Directory enumeration
- Security misconfiguration detection

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- (Optional) Burp Suite or similar proxy for traffic analysis

### Quick Install

```bash
# Clone the repository
git clone https://github.com/pect0ral/ofxpwn.git
cd ofxpwn

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install ofxpwn
pip install -e .
```

### Verify Installation

```bash
ofxpwn --version
ofxpwn --help
```

---

## Quick Start

### 1. Create Configuration File

```bash
# Copy example config
cp config.example.yaml myconfig.yaml

# Edit with your target details
nano myconfig.yaml
```

### 2. Run Your First Scan

```bash
# List available modules
ofxpwn list

# Run reconnaissance
ofxpwn run recon/fingerprint --config myconfig.yaml

# Run authentication testing
ofxpwn run auth/default_creds --config myconfig.yaml

# Run everything (YOLO mode)
ofxpwn all --config myconfig.yaml
```

### 3. Review Results

Results are saved to the `output/` directory:
- `output/logs/` - Detailed logs
- `output/reports/` - Test results
- `output/evidence/` - Request/response samples

---

## Modules

OFXpwn is organized into five categories of security tests:

### Authentication (`auth/`)

| Module | Description |
|--------|-------------|
| `auth/login` | Test authentication with user-supplied credentials |
| `auth/default_creds` | Test common default credentials |
| `auth/injection` | SQL/LDAP injection in authentication fields |
| `auth/bruteforce` | Credential brute-force with wordlists |
| `auth/param_fuzzer` | Systematically fuzz auth parameters (CLIENTUID, FID, ORG, APPID/APPVER) |
| `auth/rate_limiting` | **NEW** Test for rate limiting, account lockout, and brute force protection |

### Reconnaissance (`recon/`)

| Module | Description |
|--------|-------------|
| `recon/fingerprint` | Server version detection and OFX version enumeration |
| `recon/profile` | Unauthenticated profile information disclosure (PROFRQ) |
| `recon/accounts` | **NEW** Enumerate accessible accounts (ACCTINFORQ) |

### Exploitation (`exploit/`)

| Module | Description |
|--------|-------------|
| `exploit/xxe` | XML External Entity (XXE) vulnerability testing |
| `exploit/idor` | **NEW** IDOR testing via account ID manipulation and access control bypass |

### Fuzzing (`fuzz/`)

| Module | Description |
|--------|-------------|
| `fuzz/protocol` | OFX protocol fuzzing with malformed requests |
| `fuzz/fields` | Field overflow and edge case testing |

### Infrastructure (`infra/`)

| Module | Description |
|--------|-------------|
| `infra/ssl` | SSL/TLS configuration and certificate assessment |
| `infra/headers` | HTTP security header analysis |
| `infra/directories` | Common directory and file enumeration |

---

## Usage Examples

### Running Individual Modules

```bash
# Test for default credentials
ofxpwn run auth/default_creds --config myconfig.yaml

# With runtime overrides
ofxpwn run auth/default_creds \
  --config myconfig.yaml \
  --target https://ofx.example.com/ofx \
  --proxy http://127.0.0.1:8080 \
  --org "MYORG" \
  --fid "12345"

# Test for XXE vulnerabilities
ofxpwn run exploit/xxe --config myconfig.yaml --output /tmp/xxe-test

# Fingerprint the server
ofxpwn run recon/fingerprint --config myconfig.yaml --verbose
```

### Running Module Categories

```bash
# Run all authentication tests
ofxpwn scan --category auth --config myconfig.yaml

# Run all reconnaissance tests
ofxpwn scan --category recon --config myconfig.yaml

# Run all exploitation modules
ofxpwn scan --category exploit --config myconfig.yaml
```

### YOLO Mode (Run Everything)

```bash
# Run comprehensive security assessment
ofxpwn all --config myconfig.yaml

# With custom output directory
ofxpwn all --config myconfig.yaml --output /path/to/results

# Aggressive mode (faster, noisier)
ofxpwn all --config myconfig.yaml --aggressive
```

### Module-Specific Help

```bash
# Get help for specific commands
ofxpwn run --help
ofxpwn scan --help
ofxpwn all --help

# List available modules
ofxpwn list
ofxpwn list --category auth
```

---

## Configuration

OFXpwn uses YAML configuration files. See [`config.example.yaml`](config.example.yaml) for all options.

### Basic Configuration

```yaml
# Target OFX server
target:
  url: "https://ofx.example.com/OFXServer/ofxsrvr.dll"
  org: "ORGNAME"
  fid: "12345"

# HTTP proxy (optional)
proxy:
  enabled: true
  url: "http://127.0.0.1:8080"
  verify_ssl: false

# Output settings
output:
  directory: "./output"
  save_requests: true
  save_responses: true

# Testing configuration
testing:
  max_threads: 50
  timeout: 30
  rate_limit: 0  # requests per second, 0 = unlimited
```

### Runtime Overrides

All config values can be overridden at runtime:

```bash
ofxpwn auth/bruteforce \
  --target https://different.server.com/ofx \
  --proxy http://localhost:8080 \
  --threads 10 \
  --timeout 60
```

---

## Documentation

- [**Usage Guide**](docs/USAGE.md) - Detailed usage instructions
- [**Module Reference**](docs/MODULES.md) - Complete module documentation
- [**CLI Quick Reference**](CLI_QUICK_REFERENCE.md) - Command reference and examples

---

## Project Background

This tool was developed during a real-world penetration test of a financial system using the OFX protocol. I found a lack of comprehensive, modern security testing tools for OFX implementations and decided to create one to fill this gap.

### Research & Inspiration

- Security Innovation's 2018 OFX Direct Connect research
- OWASP Web Security Testing Guide
- Real-world penetration testing experience
- Community feedback and contributions

### Known OFX Vulnerabilities

Research has shown that many OFX implementations suffer from:
- Lack of multi-factor authentication (especially OFX 1.x)
- Information disclosure through verbose errors
- XML-based attacks (XXE in OFX 2.x)
- Weak input validation
- Missing security headers

OFXpwn helps identify these and other security issues.

---

## Useful Resources

### OFX Specification & Documentation
- [OFX Specification](https://www.ofx.net/downloads.html) - Official OFX protocol documentation
- [OFX Developer's Guide](https://www.ofx.net/developers.html) - Technical implementation guide

### Financial Institution Directory
- [Intuit FI Directory](https://ofx-prod-filist.intuit.com/qw2800/data/fidir.txt) - Comprehensive list of financial institutions with their FID, ORG, and OFX endpoints. Extremely useful for identifying correct FID values during testing.

### Security Research
- [Security Innovation: Your Bank's Digital Side Door](https://blog.securityinnovation.com/digital-side-door) - 2018 research on OFX Direct Connect vulnerabilities
- [ofxpostern](https://github.com/SecurityInnovation/ofxpostern) - Original OFX security scanner (inspiration for this tool)

---

## Legal & Ethical Use

**IMPORTANT**: This tool is designed for **authorized security testing only**.

### Acceptable Use

- Authorized penetration tests with written permission
- Security research in controlled environments
- Educational purposes with proper lab setup
- Bug bounty programs that explicitly allow testing

### Prohibited Use

- Unauthorized access to systems
- Testing without explicit permission
- Any illegal or malicious activity
- Violating terms of service

**You are responsible for obtaining proper authorization before testing any system.**

---

## Contributing

We welcome contributions!

### Ways to Contribute

- Report bugs and issues via [GitHub Issues](https://github.com/pect0ral/ofxpwn/issues)
- Suggest new modules or features
- Improve documentation
- Submit pull requests
- Share your OFX testing experiences

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/ofxpwn.git
cd ofxpwn

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e .
pip install pytest

# Run tests
pytest tests/
```

---

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## Author

**Mike Piekarski** - [pect0ral](https://github.com/pect0ral)

*Security Consultant at [Breach Craft](https://breachcraft.io)*

---

## Acknowledgments

- Security Innovation for their OFX research and ofxpostern tool
- The OFX specification authors
- Intuit for maintaining the financial institution directory
- The security research community
- All contributors to this project

---

## Disclaimer

This tool is provided "as-is" for educational and authorized testing purposes. The author is not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before testing any system.

---

<div align="center">

**Created by [Mike Piekarski](https://github.com/pect0ral) | [Breach Craft](https://breachcraft.io)**

[Report Bug](https://github.com/pect0ral/ofxpwn/issues) • [Request Feature](https://github.com/pect0ral/ofxpwn/issues) • [Documentation](docs/)

</div>
