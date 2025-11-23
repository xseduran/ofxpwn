# OFXpwn CLI Quick Reference

## Help

Get help anywhere with `-h` or `--help`:

```bash
ofxpwn -h                    # Main help
ofxpwn run -h               # Help for run command
ofxpwn list -h              # Help for list command
ofxpwn scan -h              # Help for scan command
ofxpwn all -h               # Help for all command
```

## Listing & Discovery

### List Categories

```bash
ofxpwn list categories
```

Output:
```
Available Categories:

  auth            - 5 modules
  recon           - 2 modules
  exploit         - 1 modules
  fuzz            - 2 modules
  infra           - 3 modules
```

### List All Modules

```bash
ofxpwn list                 # Default: list modules
ofxpwn list modules         # Explicit
ofxpwn modules              # Legacy (still works)
```

### List Modules by Category

```bash
ofxpwn list --category auth
ofxpwn list -c recon
ofxpwn list -c infra
```

### List Everything

```bash
ofxpwn list all
```

Shows both categories and all modules.

## Running Modules

### Single Module

```bash
ofxpwn run <category>/<module> --config <config.yaml>

# Examples:
ofxpwn run recon/fingerprint -c config.yaml
ofxpwn run auth/default_creds -c config.yaml
ofxpwn run exploit/xxe -c config.yaml
```

### With Runtime Overrides

```bash
ofxpwn run recon/fingerprint \
  -c config.yaml \
  --target https://other-server.com/ofx \
  --proxy http://127.0.0.1:8080 \
  --verbose

# Short options:
ofxpwn run auth/injection \
  -c config.yaml \
  -t https://ofx.example.com \
  -p http://127.0.0.1:8080 \
  -v
```

### Category Scan

Run all modules in a category:

```bash
ofxpwn scan --category recon -c config.yaml
ofxpwn scan --category auth -c config.yaml
ofxpwn scan --category infra -c config.yaml -v
```

### YOLO Mode (All Modules)

```bash
ofxpwn all -c config.yaml

# With options:
ofxpwn all -c config.yaml --aggressive --verbose
ofxpwn all -c config.yaml -o /tmp/results
```

## Common Workflows

### Initial Reconnaissance

```bash
# 1. See what modules are available
ofxpwn list categories

# 2. List recon modules
ofxpwn list -c recon

# 3. Run fingerprinting
ofxpwn run recon/fingerprint -c config.yaml

# 4. Run profile test
ofxpwn run recon/profile -c config.yaml

# 5. Run all recon
ofxpwn scan --category recon -c config.yaml
```

### Authentication Testing

```bash
# See available auth modules
ofxpwn list -c auth

# Test with known credentials
ofxpwn run auth/login -c config.yaml -u username -p password

# Test defaults
ofxpwn run auth/default_creds -c config.yaml

# Test injection
ofxpwn run auth/injection -c config.yaml

# Full brute-force
ofxpwn run auth/bruteforce -c config.yaml -v

# Parameter fuzzing (CLIENTUID, FID, ORG, APPID/APPVER)
ofxpwn run auth/param_fuzzer -c config.yaml -u username -p password

# All auth tests
ofxpwn scan --category auth -c config.yaml
```

### Vulnerability Assessment

```bash
# List exploit modules
ofxpwn list -c exploit

# Test XXE
ofxpwn run exploit/xxe -c config.yaml

# List fuzz modules
ofxpwn list -c fuzz

# Protocol fuzzing
ofxpwn run fuzz/protocol -c config.yaml
ofxpwn run fuzz/fields -c config.yaml
```

### Infrastructure Testing

```bash
# List infra modules
ofxpwn list -c infra

# HTTP headers
ofxpwn run infra/headers -c config.yaml

# SSL/TLS
ofxpwn run infra/ssl -c config.yaml

# Directories
ofxpwn run infra/directories -c config.yaml

# All infra
ofxpwn scan --category infra -c config.yaml
```

## Runtime Overrides

All run commands support these overrides:

```bash
-c, --config PATH     Config file path [required]
-t, --target TEXT     Override target URL
-p, --proxy TEXT      Override proxy URL
--org TEXT            Override organization name
--fid TEXT            Override FID
-o, --output PATH     Override output directory
--threads INT         Override max threads
--timeout INT         Override timeout (seconds)
-v, --verbose         Verbose output
```

## Examples

### Test Different Target

```bash
ofxpwn run recon/fingerprint \
  -c config.yaml \
  -t https://different-server.com/ofx
```

### Enable Burp Proxy

```bash
ofxpwn run auth/injection \
  -c config.yaml \
  -p http://127.0.0.1:8080
```

### Change Output Location

```bash
ofxpwn all \
  -c config.yaml \
  -o /tmp/ofx-scan-$(date +%Y%m%d)
```

### Verbose Mode

```bash
ofxpwn run exploit/xxe -c config.yaml -v
```

## Tips

1. **Always use `-h` when unsure:**
   ```bash
   ofxpwn -h
   ofxpwn run -h
   ```

2. **List before running:**
   ```bash
   ofxpwn list categories      # See what's available
   ofxpwn list -c auth         # See modules in category
   ```

3. **Test one module first:**
   ```bash
   ofxpwn run recon/fingerprint -c config.yaml
   ```

4. **Then run category scans:**
   ```bash
   ofxpwn scan --category recon -c config.yaml
   ```

5. **Finally, comprehensive scan:**
   ```bash
   ofxpwn all -c config.yaml
   ```

## Command Summary

| Command | Purpose | Example |
|---------|---------|---------|
| `ofxpwn -h` | Show help | `ofxpwn -h` |
| `ofxpwn --version` | Show version | `ofxpwn --version` |
| `ofxpwn list` | List modules | `ofxpwn list` |
| `ofxpwn list categories` | List categories | `ofxpwn list categories` |
| `ofxpwn list -c <cat>` | List category modules | `ofxpwn list -c auth` |
| `ofxpwn run <mod> -c <cfg>` | Run single module | `ofxpwn run recon/fingerprint -c config.yaml` |
| `ofxpwn scan --category <cat> -c <cfg>` | Run category | `ofxpwn scan --category auth -c config.yaml` |
| `ofxpwn all -c <cfg>` | Run everything | `ofxpwn all -c config.yaml` |

