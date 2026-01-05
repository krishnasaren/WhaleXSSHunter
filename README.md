# WhaleXSSHunter
Ad advance XSS hunter


# 🚀 Advanced XSS Scanner

A comprehensive, production-ready XSS vulnerability scanner that detects Reflected, Stored, DOM, and Blind XSS vulnerabilities through URL-based scanning.

## 📋 Features

- **Complete XSS Detection**: Reflected, Stored, DOM, and Blind XSS
- **URL-Based Scanning**: No project folder needed - scan any website
- **Advanced Analysis**: AST parsing, taint analysis, source-to-sink tracking
- **Multi-Format Reports**: JSON, HTML, and console output
- **Smart Crawling**: Configurable depth and page limits
- **Performance Optimized**: Concurrent scanning with configurable threads
- **WAF Detection**: Automatic Web Application Firewall detection
- **Technology Fingerprinting**: Framework and technology stack detection

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone <repository-url>
cd xss-scanner

# Install dependencies
pip install -r requirements.txt

# Additional dependencies (optional but recommended)
pip install selenium beautifulsoup4 js2py aiohttp
```

### Basic Usage

```bash
# Scan a website
python xss_scanner.py https://example.com

# Scan with HTML report
python xss_scanner.py https://example.com --format html

# Full scan with maximum coverage
python xss_scanner.py https://example.com --full --format both
```

## 📊 Complete Command Line Reference

### Required Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `url` | Target URL to scan (required) | `https://example.com` |

### Scan Mode Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--quick`, `-q` | Flag | `False` | Quick scan mode (reduced coverage) |
| `--full` | Flag | `False` | Full scan mode (maximum coverage) |
| `--no-selenium` | Flag | `False` | Disable Selenium for DOM XSS testing |

#### Scan Mode Details:

**Quick Mode (`--quick`):**
- `max_pages = 10` (instead of 50)
- `payload_count = 20` (instead of 50)
- `scan_types = ['reflected', 'dom']` (skips stored/blind)

**Full Mode (`--full`):**
- `max_pages = 100`
- `payload_count = 100`
- `scan_types = ['reflected', 'stored', 'dom', 'blind']`

**No Selenium (`--no-selenium`):**
- Disables browser automation
- DOM XSS detection will be limited
- Useful when Chrome/ChromeDriver is not available

### Crawling & Discovery Arguments

| Argument | Type | Default | Range | Description |
|----------|------|---------|-------|-------------|
| `--depth`, `-d` | Integer | `3` | 1-10 | How many link levels to crawl |
| `--pages`, `-p` | Integer | `50` | 1-500 | Maximum total pages to scan |

#### Depth & Pages Explained:

**Depth (`--depth`):**
- **Depth 1**: Scan only the provided URL
- **Depth 2**: Scan URL + all pages linked from it
- **Depth 3**: Scan URL + linked pages + their linked pages
- **Depth 5**: Deep scanning (5 clicks away from start)

**Pages (`--pages`):**
- Limits total pages scanned regardless of depth
- Prevents infinite crawling on large sites
- Use with depth to control coverage vs performance

**Example Structures:**
```
# Flat site structure (blog):
Home → [Post1, Post2, Post3]  # Depth 1 covers all

# Deep site structure (e-commerce):
Home → Categories → Products → Details → Reviews  # Needs depth 4-5
```

### Performance & Testing Arguments

| Argument | Type | Default | Range | Description |
|----------|------|---------|-------|-------------|
| `--concurrent`, `-c` | Integer | `10` | 1-50 | Simultaneous requests |
| `--timeout`, `-t` | Integer | `30` | 5-300 | Request timeout in seconds |
| `--payloads` | Integer | `50` | 1-200 | Payloads to test per parameter |

#### Performance Guidelines:

**Concurrent Requests:**
- **1-5**: Conservative (less likely to trigger rate limiting)
- **5-15**: Balanced (recommended for most scans)
- **15-30**: Aggressive (may get blocked by WAF)
- **30+**: Very aggressive (only for internal testing)

**Timeout Values:**
- **15-30**: Fast sites, local networks
- **30-60**: Typical web applications
- **60+**: Slow sites, behind proxies, high-latency connections

**Payload Count:**
- **20**: Quick testing, basic coverage
- **50**: Standard testing (default)
- **100**: Comprehensive testing
- **150+**: Thorough security audit

### Output & Reporting Arguments

| Argument | Type | Default | Choices | Description |
|----------|------|---------|---------|-------------|
| `--format`, `-f` | Choice | `json` | `json`, `html`, `both` | Report output format |
| `--output`, `-o` | String | Auto-generated | Any path | Output file name/path |
| `--verbose`, `-v` | Flag | `False` | - | Show detailed progress |
| `--debug` | Flag | `False` | - | Enable debug logging |

#### Report Formats:

**JSON (`--format json`):**
- Machine-readable format
- Complete raw data
- Easy to process programmatically
- Good for CI/CD integration
- File: `xss_report_[scan_id].json`

**HTML (`--format html`):**
- Visual dashboard with charts
- Color-coded severity levels
- Expandable vulnerability details
- Clickable links to vulnerable pages
- Good for presentations/reports
- File: `xss_report_[scan_id].html`

**Both (`--format both`):**
- Generates both JSON and HTML reports
- Best for comprehensive reporting

#### Output File Examples:
```bash
# Auto-generated names
python xss_scanner.py https://example.com --format both
# Creates: xss_report_20250105123456_abc123.json
# Creates: xss_report_20250105123456_abc123.html

# Custom names
python xss_scanner.py https://example.com --output my_report --format both
# Creates: my_report.json and my_report.html

# Specific paths
python xss_scanner.py https://example.com --output /reports/scan.html --format html
# Creates: /reports/scan.html
```

### Advanced & Debugging Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--proxy` | String | `None` | Route traffic through proxy |
| `--verbose`, `-v` | Flag | `False` | Show detailed progress |
| `--debug` | Flag | `False` | Enable debug logging with stack traces |

#### Proxy Usage:
```bash
# With Burp Suite / OWASP ZAP
python xss_scanner.py https://example.com --proxy http://127.0.0.1:8080

# With authentication
python xss_scanner.py https://example.com --proxy http://user:pass@proxy.company.com:8080

# For debugging requests
python xss_scanner.py https://example.com --proxy http://127.0.0.1:8080 --verbose
```

## 🎯 Common Usage Patterns

### Standard Professional Scan
```bash
python xss_scanner.py https://example.com \
  --full \
  --format both \
  --depth 3 \
  --pages 100 \
  --concurrent 10 \
  --output professional_scan \
  --verbose
```

### Quick Security Assessment
```bash
python xss_scanner.py https://example.com \
  --quick \
  --format html \
  --depth 2 \
  --pages 20 \
  --concurrent 5 \
  --verbose
```

### Penetration Testing Setup (with Proxy)
```bash
python xss_scanner.py https://example.com \
  --full \
  --format both \
  --depth 4 \
  --pages 150 \
  --concurrent 8 \
  --proxy http://127.0.0.1:8080 \
  --verbose
```

### Development/CI Pipeline Scan
```bash
python xss_scanner.py http://localhost:3000 \
  --no-selenium \
  --depth 2 \
  --pages 30 \
  --concurrent 5 \
  --format json \
  --output ci_report.json
```

### Maximum Aggressive Scan
```bash
python xss_scanner.py https://example.com \
  --full \
  --format both \
  --depth 5 \
  --pages 200 \
  --concurrent 15 \
  --payloads 100 \
  --timeout 60 \
  --verbose \
  --debug
```

### Local Testing
```bash
python xss_scanner.py http://127.0.0.1:8080 \
  --full \
  --format both \
  --depth 3 \
  --pages 50 \
  --concurrent 8 \
  --output local_scan \
  --verbose
```

The issue is that your scanner is only scanning 1 page (just the initial URL). You need to enable crawling to discover more pages. Here are the commands for comprehensive scanning with multiple reports:

## **Command for Maximum Coverage:**

```bash
# Best command for thorough scanning with both report types
python xss_scanner.py http://127.0.0.1/xs.php \
  --full \
  --format both \
  --depth 5 \
  --pages 100 \
  --concurrent 10 \
  --timeout 30 \
  --payloads 100 \
  --output xss_scan_report \
  --verbose
```

## **Explanation of Parameters:**

| Parameter | What it does | Recommended Value |
|-----------|--------------|-------------------|
| `--full` | Enables all scan types (reflected, stored, DOM, blind) | Always use |
| `--format both` | Generates both JSON and HTML reports | `both` |
| `--depth 5` | How many links deep to crawl | 3-5 |
| `--pages 100` | Maximum pages to scan | 50-200 |
| `--concurrent 10` | Simultaneous requests | 5-15 |
| `--timeout 30` | Request timeout in seconds | 30 |
| `--payloads 100` | Payloads per test | 50-100 |
| `--output` | Base name for reports | Your choice |
| `--verbose` | Show detailed progress | Optional |

## **Alternative Commands:**

### **1. Quick but Comprehensive:**
```bash
python xss_scanner.py http://127.0.0.1/xs.php \
  --full \
  --format both \
  --depth 3 \
  --pages 50 \
  --concurrent 8
```

### **2. Maximum Aggressive Scan:**
```bash
python xss_scanner.py http://127.0.0.1/xs.php \
  --full \
  --format both \
  --depth 10 \
  --pages 500 \
  --concurrent 20 \
  --payloads 200 \
  --timeout 60 \
  --output full_scan_report
```

### **3. For Local Testing (Fast):**
```bash
python xss_scanner.py http://127.0.0.1/ \
  --full \
  --format both \
  --depth 2 \
  --pages 20 \
  --concurrent 5 \
  --no-selenium \
  --output local_scan
```

## **What Each Report Contains:**

### **JSON Report (`xss_scan_report.json`):**
- Machine-readable format
- Complete raw data
- Easy to process programmatically
- All vulnerability details
- Good for CI/CD integration

### **HTML Report (`xss_scan_report.html`):**
- Visual dashboard with charts
- Color-coded severity levels
- Expandable vulnerability details
- Clickable links to vulnerable pages
- Executive summary
- Good for presentations/reports

## **If Still Getting Only 1 Page:**

If you're still only scanning 1 page, there might be an issue with the crawler. Try this debugging approach:

```bash
# Enable debug mode to see what's happening
python xss_scanner.py http://127.0.0.1/xs.php \
  --full \
  --depth 3 \
  --pages 50 \
  --debug \
  --verbose
```

## **Common Issues and Solutions:**

### **1. Crawler not finding links:**
- Target site might use JavaScript for navigation
- Links might be relative or broken
- Site might require authentication

**Fix:** Add Selenium for JavaScript rendering:
```bash
# Make sure selenium is installed and ChromeDriver is available
pip install selenium webdriver-manager
```

### **2. Too many false positives with 70 vulnerabilities:**
```bash
# Reduce payload count for cleaner results
python xss_scanner.py http://127.0.0.1/xs.php \
  --full \
  --format both \
  --payloads 30 \
  --depth 3 \
  --pages 30
```

### **3. Scan taking too long:**
```bash
# Quick scan with basic coverage
python xss_scanner.py http://127.0.0.1/xs.php \
  --format both \
  --depth 2 \
  --pages 10 \
  --concurrent 5 \
  --payloads 20
```

## **To Monitor Progress:**

Add this to your scanner code (in the `scan` method of `AdvancedXSSScanner`):

```python
def scan(self, target_url: str) -> ScanResult:
    # ... existing code ...
    
    # Phase 1: Crawling and discovery
    logging.info(f"Phase 1: Crawling target (depth: {self.config.max_depth}, max pages: {self.config.max_pages})...")
    pages = self.crawler.crawl(target_url)
    self.results.pages = pages
    self.results.pages_scanned = len(pages)
    logging.info(f"✓ Found {len(pages)} pages to scan")
    
    # Phase 2: Vulnerability detection
    logging.info(f"Phase 2: Testing {len(pages)} pages for XSS...")
    # ... rest of the code ...
```

## **Expected Output Structure:**

After running with `--format both`, you should get:
```
📁 Current Directory/
├── xss_scan_report.json      # JSON report
├── xss_scan_report.html      # HTML report (open in browser)
├── xss_scan_[scan_id].log    # Log file
└── screenshots/              # If screenshots are enabled
```

## **Final Recommendation:**

For your local test on `http://127.0.0.1/xs.php`, use:

```bash
python xss_scanner.py http://127.0.0.1/xs.php \
  --full \
  --format both \
  --depth 4 \
  --pages 100 \
  --concurrent 8 \
  --payloads 50 \
  --output xs_vulnerability_report \
  --verbose
```

This will:
1. Crawl up to 100 pages within 4 links depth
2. Use 8 simultaneous requests for speed
3. Test 50 payloads per parameter
4. Generate both JSON and HTML reports
5. Show detailed progress with `--verbose`

The key to scanning more than 1 page is the `--depth` and `--pages` parameters. If those don't work, there might be an issue with the crawler implementation or the target website structure.




## ⚡ Performance Optimization

### Time Estimation Formula
```
Approximate Time ≈ (Pages × Parameters × Payloads × Request Time) / Concurrent

Example:
50 pages × 5 parameters × 50 payloads × 1 second = 12,500 seconds
With 10 concurrent threads: ≈ 1,250 seconds (21 minutes)
```

### Recommended Settings by Site Size

| Site Size | Pages | Depth | Concurrent | Payloads | Est. Time |
|-----------|-------|-------|------------|----------|-----------|
| Small (10 pages) | 10-20 | 2-3 | 5-8 | 30-50 | 5-15 min |
| Medium (100 pages) | 30-50 | 3-4 | 8-12 | 50-80 | 30-60 min |
| Large (500+ pages) | 50-100 | 3-5 | 10-15 | 50-100 | 1-3 hours |

### For Fast Results
```bash
# Fast scan with basic coverage
python xss_scanner.py https://example.com \
  --quick \
  --no-selenium \
  --depth 2 \
  --pages 10 \
  --concurrent 3 \
  --timeout 15
```

## 🛠️ Troubleshooting

### Common Issues & Solutions

#### Issue: Scanner only scans 1 page
**Solution:**
```bash
# Increase depth and pages
python xss_scanner.py https://example.com --depth 3 --pages 30 --verbose
```

#### Issue: Scan is too slow
**Solution:**
```bash
# Reduce payloads and increase concurrency
python xss_scanner.py https://example.com \
  --payloads 20 \
  --concurrent 15 \
  --no-selenium
```

#### Issue: Getting blocked by WAF/rate limiting
**Solution:**
```bash
# Be more conservative
python xss_scanner.py https://example.com \
  --concurrent 2 \
  --timeout 60 \
  --proxy http://127.0.0.1:8080
```

#### Issue: Missing Selenium/ChromeDriver
**Solution:**
```bash
# Disable Selenium or install ChromeDriver
python xss_scanner.py https://example.com --no-selenium

# Install ChromeDriver:
# Linux: sudo apt-get install chromium-chromedriver
# Mac: brew install chromedriver
# Windows: Download from https://chromedriver.chromium.org/
```

#### Issue: SSL/TLS certificate errors with proxy
**Solution:**
```bash
# The scanner automatically disables SSL verification when using proxy
# If you need proper SSL, export proxy CA certificate and configure it
```

### Debug Mode
```bash
# Enable debug logging for troubleshooting
python xss_scanner.py https://example.com --debug --verbose

# Check log file
tail -f xss_scan_*.log
```

## 📁 Output Files

After a scan completes, you'll typically see:

```
📁 Current Directory/
├── xss_report_[scan_id].json      # JSON report (if --format json/both)
├── xss_report_[scan_id].html      # HTML report (if --format html/both)
├── xss_scan_[scan_id].log         # Log file with detailed operations
└── screenshots/                   # Screenshots of vulnerable pages (if enabled)
```

### Report Contents

**JSON Report Includes:**
- Complete vulnerability details
- HTTP requests/responses
- Confidence scores and severity levels
- CWE classifications
- Scan metadata and statistics

**HTML Report Includes:**
- Visual dashboard with summary statistics
- Color-coded vulnerability cards
- Expandable details for each finding
- Technology stack detection
- WAF detection status
- Timeline and scan metadata

## 🔧 Advanced Configuration

### Environment Variables
```bash
# Set default values (optional)
export XSS_SCANNER_CONCURRENT=15
export XSS_SCANNER_TIMEOUT=45
export XSS_SCANNER_PROXY=http://127.0.0.1:8080
```

### Configuration File Support
Create a `config.json` file:
```json
{
    "max_depth": 3,
    "max_pages": 100,
    "max_concurrent": 10,
    "timeout": 30,
    "payload_count": 50,
    "use_selenium": true,
    "verify_ssl": false,
    "user_agent": "Mozilla/5.0 (XSS Scanner)"
}
```
Use with:
```bash
python xss_scanner.py https://example.com --config config.json
```

## 📚 Examples by Use Case

### Example 1: Single Page Application
```bash
python xss_scanner.py https://spa.example.com \
  --full \
  --depth 1 \
  --pages 5 \
  --concurrent 5 \
  --format both \
  --verbose
```

### Example 2: E-commerce Site
```bash
python xss_scanner.py https://shop.example.com \
  --full \
  --depth 4 \
  --pages 80 \
  --concurrent 8 \
  --payloads 80 \
  --format html \
  --output ecommerce_scan
```

### Example 3: API Testing
```bash
python xss_scanner.py https://api.example.com \
  --no-selenium \
  --depth 1 \
  --pages 10 \
  --concurrent 3 \
  --format json \
  --output api_scan.json
```

### Example 4: Internal Network Scan
```bash
python xss_scanner.py http://192.168.1.100 \
  --full \
  --depth 3 \
  --pages 40 \
  --concurrent 6 \
  --timeout 15 \
  --format both \
  --verbose
```

## ⚠️ Legal & Ethical Usage

**IMPORTANT**: Only scan websites that you own or have explicit permission to test. Unauthorized scanning is illegal and unethical.

### Responsible Disclosure
1. Always get written permission before scanning
2. Respect robots.txt and rate limits
3. Use the `--proxy` flag to monitor traffic
4. Report findings responsibly to the site owner
5. Never exploit vulnerabilities you discover

### For Educational Purposes
```bash
# Use test environments
python xss_scanner.py http://testphp.vulnweb.com
python xss_scanner.py http://dvwa.local
python xss_scanner.py http://bwapp
```

## 🔄 Updates & Support

### Checking for Updates
```bash
git pull origin main
pip install -r requirements.txt --upgrade
```

### Getting Help
```bash
# Show all options
python xss_scanner.py --help

# Show examples
python xss_scanner.py --help | grep -A5 "Examples:"
```

### Reporting Issues
1. Check the log file: `xss_scan_*.log`
2. Run with `--debug` and `--verbose` flags
3. Capture the full command and output
4. Include target URL (if it's a test site)

---

**Happy Scanning!** 🎯

Remember: With great power comes great responsibility. Always scan ethically and responsibly.
