# OFXpwn Module Reference

This document provides detailed information about all available modules in OFXpwn.

## Module Categories

OFXpwn organizes modules into five categories:

- **auth** - Authentication testing modules
- **recon** - Reconnaissance and fingerprinting modules  
- **exploit** - Exploitation modules for known vulnerabilities
- **fuzz** - Fuzzing modules for parser and protocol testing
- **infra** - Infrastructure and configuration testing modules

## Usage

List all available modules:
```bash
ofxpwn modules
```

Run a specific module:
```bash
ofxpwn run <category>/<module> --config config.yaml
```

Run all modules in a category:
```bash
ofxpwn scan --category <category> --config config.yaml
```

---

## Authentication Modules

### auth/default_creds

**Description:** Tests common default credentials against the OFX server.

**Purpose:** Identifies weak or default credentials that may provide unauthorized access.

**Test Cases:**
- 30+ common default username/password combinations
- Software-specific credentials (quicken, quickbooks, ofx, intuit)
- Generic admin accounts (admin:admin, test:test)
- Empty/null credentials

**Configuration Options:**
```yaml
auth:
  default_creds:
    file: "payloads/default_creds.txt"  # Custom credential list
    delay: 0.5  # Delay between attempts (seconds)
```

**Findings:**
- CRITICAL: Valid credentials discovered
- INFO: Authentication mechanism behavior

**Example:**
```bash
ofxpwn run auth/default_creds --config config.yaml
```

---

### auth/injection

**Description:** Tests for SQL and LDAP injection vulnerabilities in authentication fields.

**Purpose:** Identifies injection vulnerabilities that could lead to authentication bypass or information disclosure.

**Test Cases:**
- SQL injection payloads (' OR '1'='1, admin'--, UNION SELECT)
- LDAP injection payloads (*, admin)(|, *)(objectClass=*)
- Time-based blind SQL injection (SLEEP)
- Tests both username and password fields

**Detection Methods:**
- Different OFX status codes from baseline
- SQL/LDAP error messages in responses
- Timing anomalies for blind SQL injection
- Response size differences

**Findings:**
- CRITICAL: Time-based SQL injection confirmed
- HIGH: SQL/LDAP injection possible (status code anomaly)
- HIGH: SQL/LDAP error message disclosure
- MEDIUM: LDAP injection possible

**Example:**
```bash
ofxpwn run auth/injection --config config.yaml
```

---

### auth/bruteforce

**Description:** Performs systematic credential brute-forcing using custom wordlists.

**Purpose:** Comprehensive credential testing when default credentials fail.

**Attack Modes:**
- **default** - Smart combinations (same user:pass, common patterns, then cartesian product)
- **username_spray** - Try each password against all usernames (stealthier)
- **user_focused** - Try all passwords for each username (faster per-user)

**Configuration Options:**
```yaml
bruteforce:
  mode: "default"  # or "username_spray" or "user_focused"
  username_file: "payloads/usernames.txt"
  password_file: "payloads/passwords.txt"
  max_attempts: 1000  # Maximum combinations to test
  delay: 0.5  # Delay between attempts
```

**Features:**
- Anomaly detection for username enumeration
- Timing analysis for behavioral differences
- Account lockout detection
- Progress indicators for long-running attacks

**Findings:**
- CRITICAL: Valid credentials discovered
- MEDIUM: Possible account lockout triggered
- INFO: Timing or response anomalies (username enumeration)

**Example:**
```bash
ofxpwn run auth/bruteforce --config config.yaml --verbose
```

---

## Reconnaissance Modules

### recon/fingerprint

**Description:** Identifies supported OFX protocol versions and server technology.

**Purpose:** Maps the attack surface by determining supported versions and server details.

**Test Cases:**
- SGML versions: 102, 103, 151, 160
- XML versions: 200, 202, 211, 220
- Server technology detection from headers
- Application version identification

**Information Gathered:**
- Supported OFX versions
- Server software (IIS, Apache, etc.)
- Application frameworks
- Version-specific vulnerabilities

**Findings:**
- INFO: Supported OFX versions detected
- LOW: Information disclosure via headers
- MEDIUM: Outdated protocol version support

**Example:**
```bash
ofxpwn run recon/fingerprint --config config.yaml
```

---

### recon/profile

**Description:** Tests unauthenticated PROFRQ (Profile Request) to gather server capabilities.

**Purpose:** High-value reconnaissance that often works without authentication.

**Test Cases:**
- Unauthenticated profile requests
- Anonymous user profile requests
- Profile requests in both SGML and XML formats

**Information Gathered:**
- Financial institution details (FI name, ORG, FID)
- Supported message sets and versions
- Server capabilities and features
- Transaction type support

**Findings:**
- MEDIUM: Profile information accessible without authentication
- INFO: Server capabilities disclosed

**Example:**
```bash
ofxpwn run recon/profile --config config.yaml
```

---

## Exploitation Modules

### exploit/xxe

**Description:** Tests for XML External Entity (XXE) injection vulnerabilities.

**Purpose:** Identifies XXE vulnerabilities that could lead to file disclosure or SSRF.

**Test Cases:**
- File disclosure attacks (/etc/passwd, win.ini, web.config)
- XXE in different OFX XML fields
- Out-of-band XXE detection (when applicable)
- Recursive entity expansion (billion laughs)

**Target Files:**
- Unix: /etc/passwd, /etc/hosts
- Windows: c:/windows/win.ini, c:/inetpub/wwwroot/web.config
- Application: config files, connection strings

**Findings:**
- CRITICAL: XXE file disclosure successful
- HIGH: XXE vulnerability confirmed (out-of-band)
- MEDIUM: XML parser accepts external entities

**Example:**
```bash
ofxpwn run exploit/xxe --config config.yaml
```

---

## Fuzzing Modules

### fuzz/protocol

**Description:** Fuzzes OFX protocol with malformed requests to test parser robustness.

**Purpose:** Identifies parser vulnerabilities, crashes, and error handling issues.

**Test Cases:**
- Missing closing tags
- Duplicate tags
- Invalid nesting
- Extremely long tag names (10,000 chars)
- Invalid characters in tags
- Empty OFX body
- Invalid OFX versions
- Missing OFX header
- Complete garbage data

**Findings:**
- HIGH: Parser timeout/hang (DoS vulnerability)
- HIGH: HTTP 500 error on malformed input (crash)
- MEDIUM: Unexpected HTTP status codes
- INFO: Error handling behavior

**Example:**
```bash
ofxpwn run fuzz/protocol --config config.yaml
```

---

### fuzz/fields

**Description:** Tests OFX fields with oversized, malformed, and edge-case inputs.

**Purpose:** Identifies buffer overflows, format string bugs, and input validation issues.

**Test Cases:**
- Buffer overflows (1,000 to 10,000 character fields)
- Format string attacks (%s%s%s, %n%n%n)
- Special characters (null bytes, unicode, high ASCII)
- Control characters (newlines, tabs)
- Path traversal (../, ..\)
- Numeric edge cases (negative, zero, very large)
- Script injection (<script>, <img>)
- Empty and whitespace-only values

**Fields Tested:**
- USERID (username)
- USERPASS (password)
- ORG (organization)
- FID (financial institution ID)
- CLIENTUID (client unique ID)

**Findings:**
- CRITICAL: Server connection lost (crash)
- HIGH: Parser timeout/hang
- HIGH: HTTP 500 error on field overflow
- MEDIUM: Input reflection (XSS risk)
- LOW: Timing anomalies

**Example:**
```bash
ofxpwn run fuzz/fields --config config.yaml
```

---

## Infrastructure Modules

### infra/headers

**Description:** Analyzes HTTP security headers and identifies missing protections.

**Purpose:** Assesses server security posture through HTTP header configuration.

**Headers Checked:**

**Security Headers:**
- Strict-Transport-Security (HSTS) - Forces HTTPS
- X-Content-Type-Options - Prevents MIME-sniffing
- X-Frame-Options - Prevents clickjacking
- Content-Security-Policy (CSP) - Controls resource loading
- X-XSS-Protection - XSS filter

**Information Disclosure:**
- Server - Web server version
- X-Powered-By - Technology stack
- X-AspNet-Version - ASP.NET version
- X-AspNetMvc-Version - MVC version

**Additional Checks:**
- CORS configuration (Access-Control-Allow-Origin)
- Cache control headers

**Findings:**
- MEDIUM: Missing HSTS or CSP
- MEDIUM: Overly permissive CORS
- LOW: Missing security headers
- LOW: Information disclosure headers
- LOW: Missing cache control

**Example:**
```bash
ofxpwn run infra/headers --config config.yaml
```

---

### infra/ssl

**Description:** Assesses SSL/TLS configuration and certificate security.

**Purpose:** Identifies weak cryptographic configurations and certificate issues.

**Tests Performed:**

**Protocol Versions:**
- SSLv2 (CRITICAL if enabled)
- SSLv3 (CRITICAL if enabled)
- TLSv1.0 (HIGH if enabled)
- TLSv1.1 (MEDIUM if enabled)
- TLSv1.2 (Recommended)
- TLSv1.3 (Best)

**Certificate Checks:**
- Subject and issuer information
- Validity dates
- Subject Alternative Names (SAN)
- Hostname matching
- Self-signed detection

**Cipher Suite Analysis:**
- Negotiated cipher strength
- Weak cipher detection (NULL, ANON, EXPORT, DES, MD5, RC4)

**Findings:**
- CRITICAL: SSLv2/SSLv3 enabled
- HIGH: TLSv1.0 enabled or weak ciphers
- MEDIUM: TLSv1.1 enabled or certificate hostname mismatch
- LOW: Self-signed certificate

**Example:**
```bash
ofxpwn run infra/ssl --config config.yaml
```

---

### infra/directories

**Description:** Enumerates common directories and files on the web server.

**Purpose:** Discovers accessible resources that may contain sensitive information or provide additional attack surface.

**Paths Tested:**

**Admin Interfaces:**
- /admin, /administrator, /manager, /console

**Documentation:**
- /docs, /api, /swagger, /openapi.json

**Configuration Files:**
- /web.config, /.env, /config.xml

**Common Files:**
- /robots.txt, /.git/config, /crossdomain.xml

**Backup Files:**
- /backup.zip, /db.sql, /database.sql

**Server Files:**
- /server-status, /phpinfo.php

**OFX Specific:**
- /OFXServer/help, /OFXServer/admin

**Findings:**
- CRITICAL: Backup files accessible
- CRITICAL: Configuration files accessible
- MEDIUM: Directory listing enabled
- HIGH: Sensitive information in accessible files
- INFO: Resource enumeration

**Example:**
```bash
ofxpwn run infra/directories --config config.yaml
```

---

## Running Multiple Modules

**Run all modules in a category:**
```bash
ofxpwn scan --category auth --config config.yaml
ofxpwn scan --category recon --config config.yaml
ofxpwn scan --category infra --config config.yaml
```

**Run all modules (YOLO mode):**
```bash
ofxpwn all --config config.yaml
```

**Run with custom settings:**
```bash
ofxpwn run auth/bruteforce \
  --config config.yaml \
  --target https://ofx.example.com/OFXServer/ofxsrvr.dll \
  --proxy http://127.0.0.1:8080 \
  --verbose
```

---

## Module Development

To create a new module:

1. Create a new file in the appropriate category directory
2. Inherit from `BaseModule`
3. Implement required methods:
   - `get_description()` - Class method returning module description
   - `run(config, logger)` - Main execution method

**Example:**
```python
from ofxpwn.core.base_module import BaseModule
from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger

class MyModule(BaseModule):
    @classmethod
    def get_description(cls) -> str:
        return "Description of what this module does"
    
    def run(self, config: Config, logger: Logger) -> Dict[str, Any]:
        logger.info("Running my module...")
        
        # Use self.log_finding() to record security findings
        self.log_finding(
            'HIGH',
            'Finding Title',
            'Description of the issue',
            'Recommendation for remediation'
        )
        
        return {'results': 'data'}
```

4. Add to category's `__init__.py`
5. Test with `ofxpwn run <category>/<module>`

---

## Interpreting Results

**Log Files:**
- `logs/main_<timestamp>.log` - Main execution log
- `logs/requests_<timestamp>.log` - All HTTP requests
- `logs/responses_<timestamp>.log` - All HTTP responses
- `logs/findings_<timestamp>.log` - Security findings only

**Evidence Files:**
- `evidence/<timestamp>_<module>_request.txt` - Request bodies
- `evidence/<timestamp>_<module>_response.txt` - Response bodies

**Severity Levels:**
- **CRITICAL** - Immediate security risk (valid creds, RCE, file disclosure)
- **HIGH** - Serious vulnerability (injection, weak crypto)
- **MEDIUM** - Configuration weakness (missing headers, disclosure)
- **LOW** - Minor issue (info disclosure, low-impact misconfig)
- **INFO** - Informational finding (version detection, capabilities)

---

## Best Practices

1. **Start with reconnaissance** - Run `recon/*` modules first to understand the target
2. **Test carefully** - Use `--verbose` to monitor behavior
3. **Review logs** - Check findings log for all discovered issues
4. **Save evidence** - Evidence files provide proof for reports
5. **Rate limiting** - Adjust delays if triggering lockouts
6. **Use Burp** - Enable proxy to inspect and modify traffic
7. **Targeted testing** - Run specific modules rather than "all" when possible

