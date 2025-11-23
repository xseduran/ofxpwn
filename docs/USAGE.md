# OFXpwn Usage Guide

Complete guide to using OFXpwn for OFX server security testing.

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Basic Usage](#basic-usage)
- [Common Workflows](#common-workflows)
- [Advanced Usage](#advanced-usage)
- [Proxy Integration](#proxy-integration)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Optional: Burp Suite for traffic inspection

### Install from Source

```bash
git clone https://github.com/pect0ral/ofxpwn.git
cd ofxpwn
pip install -r requirements.txt
pip install -e .
```

### Verify Installation

```bash
ofxpwn --help
```

---

## Configuration

### Create Configuration File

Copy the example configuration:

```bash
cp config.example.yaml myconfig.yaml
```

Edit `myconfig.yaml` with your target details:

```yaml
target:
  url: "https://ofx.example.com/OFXServer/ofxsrvr.dll"
  org: "BANKORG"      # Organization code
  fid: "12345"        # Financial Institution ID

proxy:
  enabled: false      # Set to true to use Burp
  url: "http://127.0.0.1:8080"
  verify_ssl: false   # Disable for testing with Burp

credentials:
  username: ""        # Leave empty for unauthenticated testing
  password: ""

output:
  logs_dir: "logs"
  evidence_dir: "evidence"
  verbose: false
```

### Finding ORG and FID

Many OFX servers require the correct ORG and FID values. You can find these in:

1. **Intuit FI Directory:**
   - https://ofx-prod-filist.intuit.com/qw2800/data/fidir.txt
   - Search for your target institution
   - Extract FID and ORG values

2. **Financial Institution's Website:**
   - Look for "OFX Setup" or "Direct Connect" documentation
   - Often listed in support articles

3. **Trial and Error:**
   - Use `recon/profile` module with common values
   - Server may reveal correct values in error messages

### Configuration Tips

- **Keep sensitive configs outside git repo:** Use `myconfig.yaml` (gitignored)
- **Never commit real credentials:** Use `config.example.yaml` for templates only
- **Use absolute paths:** For wordlists and custom payloads
- **Enable verbose logging:** For initial testing and troubleshooting

---

## Basic Usage

### List Available Modules

```bash
ofxpwn modules
```

Output shows all available modules by category.

### Run a Single Module

```bash
ofxpwn run <category>/<module> --config myconfig.yaml
```

Examples:
```bash
ofxpwn run recon/fingerprint --config myconfig.yaml
ofxpwn run auth/default_creds --config myconfig.yaml
ofxpwn run exploit/xxe --config myconfig.yaml
```

### Run All Modules in a Category

```bash
ofxpwn scan --category <category> --config myconfig.yaml
```

Examples:
```bash
ofxpwn scan --category recon --config myconfig.yaml
ofxpwn scan --category auth --config myconfig.yaml
ofxpwn scan --category infra --config myconfig.yaml
```

### Run All Modules (YOLO Mode)

```bash
ofxpwn all --config myconfig.yaml
```

**Warning:** This runs ALL modules and may take significant time. Use carefully on production systems.

---

## Common Workflows

### Workflow 1: Initial Reconnaissance

Start with information gathering modules:

```bash
# Step 1: Fingerprint the server
ofxpwn run recon/fingerprint --config myconfig.yaml

# Step 2: Try unauthenticated profile request
ofxpwn run recon/profile --config myconfig.yaml

# Step 3: Check HTTP security headers
ofxpwn run infra/headers --config myconfig.yaml

# Step 4: Assess SSL/TLS configuration
ofxpwn run infra/ssl --config myconfig.yaml
```

Review logs to understand:
- Supported OFX versions
- Server technology stack
- Security posture
- Whether authentication is required

### Workflow 2: Authentication Testing

If you need valid credentials:

```bash
# Step 1: Test default credentials (fast)
ofxpwn run auth/default_creds --config myconfig.yaml

# Step 2: Test for injection vulnerabilities
ofxpwn run auth/injection --config myconfig.yaml

# Step 3: Brute-force with wordlists (if needed)
ofxpwn run auth/bruteforce --config myconfig.yaml
```

**Important:** Monitor for account lockouts. Adjust delays if needed.

### Workflow 3: Vulnerability Assessment

Test for common vulnerabilities:

```bash
# Test for XXE (if server uses XML)
ofxpwn run exploit/xxe --config myconfig.yaml

# Fuzz the protocol parser
ofxpwn run fuzz/protocol --config myconfig.yaml

# Test field overflow vulnerabilities
ofxpwn run fuzz/fields --config myconfig.yaml

# Enumerate directories
ofxpwn run infra/directories --config myconfig.yaml
```

Review findings log for discovered vulnerabilities.

### Workflow 4: Comprehensive Assessment

Run all tests systematically:

```bash
# All reconnaissance
ofxpwn scan --category recon --config myconfig.yaml

# All infrastructure testing
ofxpwn scan --category infra --config myconfig.yaml

# All authentication testing (be careful with rate)
ofxpwn scan --category auth --config myconfig.yaml

# All exploitation tests
ofxpwn scan --category exploit --config myconfig.yaml

# All fuzzing tests
ofxpwn scan --category fuzz --config myconfig.yaml
```

---

## Advanced Usage

### Runtime Parameter Overrides

Override config file settings at runtime:

```bash
# Override target URL
ofxpwn run recon/fingerprint \
  --config myconfig.yaml \
  --target https://different-server.com/ofx

# Enable proxy for this run
ofxpwn run auth/injection \
  --config myconfig.yaml \
  --proxy http://127.0.0.1:8080

# Override ORG and FID
ofxpwn run recon/profile \
  --config myconfig.yaml \
  --org NEWORG \
  --fid 99999

# Increase verbosity
ofxpwn run auth/bruteforce \
  --config myconfig.yaml \
  --verbose

# Change output directory
ofxpwn run exploit/xxe \
  --config myconfig.yaml \
  --output /path/to/custom/output
```

### Custom Wordlists

Use custom username/password lists for brute-forcing:

Edit your config file:
```yaml
bruteforce:
  username_file: "/path/to/custom/usernames.txt"
  password_file: "/path/to/custom/passwords.txt"
  mode: "username_spray"  # or "user_focused" or "default"
  max_attempts: 5000
  delay: 1.0  # Slower to avoid lockout
```

Then run:
```bash
ofxpwn run auth/bruteforce --config myconfig.yaml
```

### Multiple Targets

Test multiple targets with different configs:

```bash
# Target 1
ofxpwn run recon/fingerprint --config target1.yaml

# Target 2
ofxpwn run recon/fingerprint --config target2.yaml

# Or override at runtime
ofxpwn run recon/fingerprint \
  --config base.yaml \
  --target https://target1.com/ofx \
  --org TARGET1 \
  --fid 11111

ofxpwn run recon/fingerprint \
  --config base.yaml \
  --target https://target2.com/ofx \
  --org TARGET2 \
  --fid 22222
```

---

## Proxy Integration

### Using Burp Suite

OFXpwn integrates seamlessly with Burp Suite for traffic inspection and manipulation.

**Setup:**

1. Start Burp Suite with proxy listener on `127.0.0.1:8080`

2. Enable proxy in config:
```yaml
proxy:
  enabled: true
  url: "http://127.0.0.1:8080"
  verify_ssl: false  # Required for Burp's SSL interception
```

3. Run modules:
```bash
ofxpwn run recon/fingerprint --config myconfig.yaml
```

4. View traffic in Burp's Proxy → HTTP history

**Or enable at runtime:**
```bash
ofxpwn run auth/injection \
  --config myconfig.yaml \
  --proxy http://127.0.0.1:8080
```

### Benefits of Using Burp

- **Traffic inspection:** See all OFX requests/responses
- **Manual testing:** Repeat and modify interesting requests
- **Intruder:** Use Burp Intruder for custom fuzzing
- **Scanner:** Run Burp Scanner on OFX endpoints
- **Evidence:** Export specific requests for reports

### Other Proxies

OFXpwn works with any HTTP proxy:

```yaml
proxy:
  enabled: true
  url: "http://localhost:8888"  # ZAP
  verify_ssl: false
```

---

## Understanding Output

### Log Files

After running modules, check the `logs/` directory:

```
logs/
├── main_20251123_143022.log       # Main execution log
├── requests_20251123_143022.log   # All requests sent
├── responses_20251123_143022.log  # All responses received
└── findings_20251123_143022.log   # Security findings only
```

**Key log to review:**
- `findings_*.log` - Contains all security issues discovered

**Sample finding:**
```
[2025-11-23 14:30:45] [CRITICAL] Valid Credentials Found
Description: Successfully authenticated: admin:admin
Recommendation: OFX Status: 0
---
```

### Evidence Files

Module-specific evidence saved to `evidence/`:

```
evidence/
├── 20251123_143022_default_creds_request.txt
├── 20251123_143022_default_creds_response.txt
├── 20251123_143050_xxe_test_request.txt
└── 20251123_143050_xxe_test_response.txt
```

Use these for:
- Report proof
- Manual analysis
- Reproducing findings

### Console Output

OFXpwn uses color-coded console output:

- **Green (SUCCESS):** Positive findings or successful operations
- **Yellow (WARNING):** Potential issues or interesting responses
- **Red (ERROR):** Errors or critical findings
- **Blue (INFO):** General information

### Severity Levels

Findings are categorized by severity:

- **CRITICAL:** Immediate security risk (credentials, RCE, data exposure)
- **HIGH:** Serious vulnerability (injection, weak crypto)
- **MEDIUM:** Configuration weakness (missing headers)
- **LOW:** Minor issue (info disclosure)
- **INFO:** Informational (version detection)

---

## Troubleshooting

### Connection Issues

**Problem:** "Connection refused" or "Could not connect"

**Solutions:**
- Verify target URL is correct and accessible
- Check network connectivity
- Verify server is running
- Try with different OFX versions (fingerprint module)
- Check firewall rules

### SSL Certificate Errors

**Problem:** "SSL certificate verify failed"

**Solutions:**
- Add to config:
```yaml
proxy:
  verify_ssl: false
```
- Or use `--verify-ssl false` flag
- Check if server uses self-signed cert (infra/ssl module)

### Invalid ORG/FID

**Problem:** "2000 - General error" or "15500 - Signon invalid"

**Solutions:**
- Verify ORG and FID from Intuit directory
- Try profile request without credentials first
- Check institution's OFX documentation
- Server may reveal correct values in error messages

### No Modules Found

**Problem:** "No modules available" or import errors

**Solutions:**
- Reinstall: `pip install -e .`
- Check Python path: `echo $PYTHONPATH`
- Verify installation: `pip list | grep ofxpwn`

### Rate Limiting / Account Lockout

**Problem:** "Possible account lockout" warning

**Solutions:**
- Increase delay in config:
```yaml
bruteforce:
  delay: 2.0  # Increase from default 0.5
```
- Use username_spray mode instead of user_focused
- Reduce max_attempts
- Wait before resuming testing
- Contact client if production account locked

### Empty Responses

**Problem:** Server returns 200 but empty response

**Solutions:**
- Check if ORG/FID are correct
- Try different OFX versions (102, 103, 151, 160)
- Verify SGML syntax with Burp
- Check server error logs if available

### Slow Performance

**Problem:** Modules take very long to complete

**Solutions:**
- Reduce max_attempts for brute-force
- Increase delays if server is slow to respond
- Run specific modules instead of "all"
- Use faster attack mode (username_spray)
- Check timeout settings

---

## Tips and Best Practices

### Security Testing Guidelines

1. **Get Authorization:** Only test systems you have permission to test
2. **Understand Impact:** Authentication testing may trigger lockouts
3. **Save Evidence:** Keep all logs and evidence files
4. **Document Findings:** Note context for each discovered issue
5. **Rate Limiting:** Use appropriate delays to avoid DoS
6. **Communication:** Keep client informed of testing activities

### Effective Testing

1. **Start Light:** Begin with recon, then escalate
2. **Use Proxy:** Always run through Burp for visibility
3. **Read Logs:** Review findings log after each run
4. **Iterate:** Use findings to inform next tests
5. **Manual Testing:** Follow up interesting automated findings
6. **Save Configs:** Keep working configs for different targets

### Reporting

1. **Severity:** Use framework's severity ratings
2. **Evidence:** Include request/response from evidence files
3. **Reproduction:** Document exact commands and config used
4. **Impact:** Explain business impact of findings
5. **Remediation:** Provide specific fix recommendations

---

## Example Scenarios

### Scenario 1: Finding Valid Credentials

```bash
# Try defaults first
ofxpwn run auth/default_creds --config myconfig.yaml

# Check findings log
cat logs/findings_*.log | grep CRITICAL

# If found, test access
# Update config with discovered credentials
# Run authenticated modules
```

### Scenario 2: Discovering XXE

```bash
# Run XXE module
ofxpwn run exploit/xxe --config myconfig.yaml

# If successful, check evidence
ls -lh evidence/*xxe*response.txt

# Look for file contents in response
grep -A5 "root:" evidence/*xxe*response.txt

# Document in report with evidence file
```

### Scenario 3: Complete Assessment

```bash
# Full assessment of new target
ofxpwn all --config target.yaml --verbose

# Review all findings
cat logs/findings_*.log

# Focus on CRITICAL and HIGH
grep -E "CRITICAL|HIGH" logs/findings_*.log

# Manual follow-up on interesting findings
# Use Burp to explore further
```

---

## Getting Help

- **Module Help:** See `docs/MODULES.md` for module-specific documentation
- **Issues:** Report bugs at https://github.com/pect0ral/ofxpwn/issues
- **OFX Protocol:** See `docs/PROTOCOL.md` for protocol details (if available)
- **Command Help:** Run `ofxpwn --help` or `ofxpwn run --help`

