# =============================================================================
# modules/deep_analyzer.py  —  DeepAnalyzer (Dynamic / Runtime Analysis)
# =============================================================================
# BUG FIX:
#   _trace_redirects() called requests.get(..., verify=False) without
#   suppressing the resulting urllib3.exceptions.InsecureRequestWarning.
#   This flooded the server logs with a warning on every redirect hop for
#   any HTTPS URL.  Added urllib3.disable_warnings() scoped to the
#   InsecureRequestWarning category, called once at module load.
# =============================================================================

import logging
import os
import time
import base64
import re
import json
import ipaddress
import socket as _socket
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import requests
import urllib3

# BUG FIX: suppress the InsecureRequestWarning produced by verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


# ── SSRF Protection ────────────────────────────────────────────────────────────
# Block requests to private/loopback/link-local addresses.  This prevents
# an attacker from using /deep-analyze to probe internal services or
# cloud-metadata endpoints (e.g. 169.254.169.254 AWS IMDS).

_SSRF_BLOCKED_NETWORKS = [
    ipaddress.ip_network(r) for r in (
        '10.0.0.0/8',      # RFC 1918 private
        '172.16.0.0/12',   # RFC 1918 private
        '192.168.0.0/16',  # RFC 1918 private
        '127.0.0.0/8',     # loopback
        '169.254.0.0/16',  # link-local + AWS/GCP/Azure IMDS
        '100.64.0.0/10',   # shared address space (RFC 6598)
        '::1/128',         # IPv6 loopback
        'fc00::/7',        # IPv6 unique local
        'fe80::/10',       # IPv6 link-local
    )
]


def _is_safe_to_fetch(hostname: str) -> bool:
    """Return True only if the hostname resolves to a public IP address.

    Uses stdlib socket + ipaddress — no new dependencies.
    Fails closed: an unresolvable hostname returns False.
    """
    if not hostname:
        return False
    try:
        results = _socket.getaddrinfo(hostname, None, type=_socket.SOCK_STREAM)
        for *_, sockaddr in results:
            try:
                ip = ipaddress.ip_address(sockaddr[0])
                if any(ip in net for net in _SSRF_BLOCKED_NETWORKS):
                    logger.warning('SSRF blocked: %s resolves to private IP %s', hostname, ip)
                    return False
            except ValueError:
                continue
        return bool(results)
    except _socket.gaierror:
        return False  # fail-closed: unresolvable = block

# ── Optional heavy dependencies (graceful degradation if not installed) ────────
try:
    import whois as python_whois
    _WHOIS_AVAILABLE = True
except ImportError:
    _WHOIS_AVAILABLE = False
    logger.warning('python-whois not installed; domain-age checks disabled.')

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.common.by import By
    from selenium.common.exceptions import WebDriverException, TimeoutException
    from webdriver_manager.chrome import ChromeDriverManager
    _SELENIUM_AVAILABLE = True
except ImportError:
    _SELENIUM_AVAILABLE = False
    logger.warning('selenium/webdriver-manager not installed; headless browser disabled.')


# ── Constants ─────────────────────────────────────────────────────────────────
MAX_REDIRECTS   = 10
REQUEST_TIMEOUT = 10
BROWSER_TIMEOUT = 20
NEW_DOMAIN_DAYS = 30
BITB_OVERLAP_PX = 80

BITB_KEYWORDS = [
    'google.com/accounts', 'microsoft.com/login', 'apple.com/sign',
    'facebook.com/login', 'accounts.google', 'login.live.com',
]


class DeepAnalyzer:
    """
    Performs dynamic, runtime analysis of a URL using a headless browser
    and HTTP redirect tracing.
    """

    def analyze(self, url: str) -> dict:
        result = {
            'url':            url,
            'redirect_chain': [],
            'final_url':      url,
            'domain_age':     None,
            'domain_age_days': None,
            'newly_registered': False,
            'has_login_form':  False,
            'has_password_field': False,
            'hidden_iframes':  0,
            'bitb_detected':   False,
            'bitb_detail':     '',
            'screenshot_b64':  None,
            'dom_signals':     [],
            'deep_risk_score': 0,
            'deep_flags':      [],
            'selenium_available': _SELENIUM_AVAILABLE,
            'whois_available':    _WHOIS_AVAILABLE,
            'error':           '',
        }

        # ── Step 1: Trace redirect chain ──────────────────────────────────────
        try:
            redirect_result = self._trace_redirects(url)
            result['redirect_chain'] = redirect_result['chain']
            result['final_url']      = redirect_result['final_url']

            if redirect_result['changed_domain']:
                result['deep_flags'].append({
                    'flag':     'domain_changed_after_redirect',
                    'severity': 'high',
                    'detail':   (
                        f"URL redirected to a different domain. "
                        f"Original: {urlparse(url).netloc} → "
                        f"Final: {urlparse(redirect_result['final_url']).netloc}"
                    ),
                })
                result['deep_risk_score'] += 3

            if len(redirect_result['chain']) > 3:
                result['deep_flags'].append({
                    'flag':     'excessive_redirects',
                    'severity': 'medium',
                    'detail':   f"{len(redirect_result['chain'])} redirects detected. "
                                "Long redirect chains are used to obscure final destinations.",
                })
                result['deep_risk_score'] += 1

        except Exception as exc:
            logger.warning('Redirect tracing failed: %s', exc)
            result['error'] += f'redirect_trace_error: {exc}; '

        # ── Step 2: WHOIS domain age check ────────────────────────────────────
        try:
            final_domain = urlparse(result['final_url']).netloc.split(':')[0]
            age_result   = self._check_domain_age(final_domain)
            result['domain_age']       = age_result['registration_date']
            result['domain_age_days']  = age_result['age_days']
            result['newly_registered'] = age_result['newly_registered']

            if age_result['newly_registered']:
                result['deep_flags'].append({
                    'flag':     'newly_registered_domain',
                    'severity': 'high',
                    'detail':   (
                        f"Domain '{final_domain}' was registered "
                        f"{age_result['age_days']} days ago (< {NEW_DOMAIN_DAYS} days). "
                        "Newly registered domains are a strong phishing indicator."
                    ),
                })
                result['deep_risk_score'] += 4

        except Exception as exc:
            logger.warning('WHOIS check failed: %s', exc)
            result['error'] += f'whois_error: {exc}; '

        # ── Step 3: Headless browser analysis ─────────────────────────────────
        try:
            browser_result = self._browser_analyze(result['final_url'])
            result['has_login_form']     = browser_result['has_login_form']
            result['has_password_field'] = browser_result['has_password_field']
            result['hidden_iframes']     = browser_result['hidden_iframes']
            result['bitb_detected']      = browser_result['bitb_detected']
            result['bitb_detail']        = browser_result['bitb_detail']
            result['screenshot_b64']     = browser_result['screenshot_b64']
            result['dom_signals']        = browser_result['dom_signals']

            if browser_result['bitb_detected']:
                result['deep_flags'].append({
                    'flag':     'bitb_attack',
                    'severity': 'high',
                    'detail':   browser_result['bitb_detail'],
                })
                result['deep_risk_score'] += 5

            if browser_result['has_password_field'] and browser_result['has_login_form']:
                result['deep_flags'].append({
                    'flag':     'credential_harvesting_form',
                    'severity': 'high',
                    'detail':   'Page contains a login form with a password field. '
                                'Credentials entered here may be stolen.',
                })
                result['deep_risk_score'] += 2

            if browser_result['hidden_iframes'] > 0:
                result['deep_flags'].append({
                    'flag':     'hidden_iframes',
                    'severity': 'medium',
                    'detail':   f"{browser_result['hidden_iframes']} hidden/zero-size "
                                "iframes detected. These are used to load malicious "
                                "content invisibly.",
                })
                result['deep_risk_score'] += 1

        except Exception as exc:
            logger.warning('Browser analysis failed: %s', exc)
            result['error'] += f'browser_error: {exc}; '

        # ── Step 5: Zero Trust Validation (DNS + TLS) ─────────────────────────
        # FIX: _zero_trust_validate() moved here from analyzer.py Fast Path to
        # eliminate the 10-second DNS+TLS latency on every /analyze call.
        # It now runs only on the Deep Path where long runtimes are expected.
        try:
            result['zero_trust'] = self._zero_trust_validate(url)
            if not result['zero_trust']['passed']:
                result['deep_flags'].append({
                    'flag':     'zero_trust_failed',
                    'severity': 'high',
                    'detail':   'URL failed Zero Trust DNS/TLS validation.',
                })
                result['deep_risk_score'] += 2
        except Exception as exc:
            logger.warning('Zero Trust validation error: %s', exc)
            result['zero_trust'] = {
                'passed': None, 'ssl_valid': None, 'dns_resolved': None,
                'checks': [{'check': 'error', 'passed': False, 'detail': str(exc)}],
            }

        return result

    # ── Private: Redirect Tracing ──────────────────────────────────────────────

    def _trace_redirects(self, url: str) -> dict:
        chain           = []
        current         = url
        original_netloc = urlparse(url).netloc.lower()

        session = requests.Session()
        session.headers['User-Agent'] = (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36'
        )

        for hop in range(MAX_REDIRECTS):
            parsed_hop = urlparse(current)
            if not _is_safe_to_fetch(parsed_hop.hostname or ''):
                chain.append({
                    'hop':         hop + 1,
                    'url':         current,
                    'status_code': 'ssrf_blocked',
                })
                break
            try:
                resp = session.get(
                    current,
                    allow_redirects=False,
                    timeout=REQUEST_TIMEOUT,
                    verify=False,   # InsecureRequestWarning suppressed at module level
                )
                chain.append({
                    'hop':         hop + 1,
                    'url':         current,
                    'status_code': resp.status_code,
                })

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get('Location', '')
                    if not location:
                        break
                    if location.startswith('/'):
                        parsed   = urlparse(current)
                        location = f'{parsed.scheme}://{parsed.netloc}{location}'
                    current = location
                else:
                    break

            except requests.exceptions.SSLError:
                chain.append({'hop': hop + 1, 'url': current, 'status_code': 'ssl_error'})
                break
            except requests.exceptions.ConnectionError:
                chain.append({'hop': hop + 1, 'url': current, 'status_code': 'connection_error'})
                break
            except Exception as exc:
                chain.append({'hop': hop + 1, 'url': current, 'status_code': f'error: {exc}'})
                break

        final_netloc   = urlparse(current).netloc.lower()
        changed_domain = (final_netloc != original_netloc and bool(final_netloc))

        return {
            'chain':          chain,
            'final_url':      current,
            'changed_domain': changed_domain,
        }

    # ── Private: Domain Age (WHOIS) ───────────────────────────────────────────

    def _check_domain_age(self, domain: str) -> dict:
        base_result = {
            'registration_date': None,
            'age_days':          None,
            'newly_registered':  False,
        }

        if not _WHOIS_AVAILABLE:
            return base_result

        try:
            w             = python_whois.whois(domain)
            creation_date = w.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date is None:
                return base_result

            now = datetime.now(timezone.utc)
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)

            age_days = (now - creation_date).days
            return {
                'registration_date': creation_date.isoformat(),
                'age_days':          age_days,
                'newly_registered':  age_days < NEW_DOMAIN_DAYS,
            }

        except Exception as exc:
            logger.debug('WHOIS query failed for %s: %s', domain, exc)
            return base_result

    # ── Private: Headless Browser Analysis ────────────────────────────────────

    def _browser_analyze(self, url: str) -> dict:
        result = {
            'has_login_form':     False,
            'has_password_field': False,
            'hidden_iframes':     0,
            'bitb_detected':      False,
            'bitb_detail':        '',
            'screenshot_b64':     None,
            'dom_signals':        [],
        }

        # ── SSRF Guard ────────────────────────────────────────────────────────
        parsed_url = urlparse(url)
        if not _is_safe_to_fetch(parsed_url.hostname or ''):
            result['dom_signals'].append('ssrf_blocked')
            return result

        if not _SELENIUM_AVAILABLE:
            result['dom_signals'].append('selenium_not_available')
            return result

        options = ChromeOptions()
        options.add_argument('--headless=new')
        # --no-sandbox is only added when explicitly requested via env var.
        # It disables Chrome's entire process sandbox and should never be used
        # when visiting untrusted pages unless the container runtime provides
        # its own isolation (e.g. gVisor / Kata Containers).
        # Enable user-namespace sandboxing instead (see backend/setup.sh).
        if os.getenv('CHROME_NO_SANDBOX', '').strip() == '1':
            options.add_argument('--no-sandbox')
        options.add_argument('--disable-setuid-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--window-size=1280,800')
        options.add_argument('--disable-extensions')
        options.add_argument('--ignore-certificate-errors')
        options.add_argument(
            '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36'
        )

        driver = None
        try:
            service = ChromeService(ChromeDriverManager().install())
            driver  = webdriver.Chrome(service=service, options=options)
            driver.set_page_load_timeout(BROWSER_TIMEOUT)
            driver.set_script_timeout(10)

            driver.get(url)
            time.sleep(2)

            try:
                screenshot_bytes         = driver.get_screenshot_as_png()
                result['screenshot_b64'] = base64.b64encode(screenshot_bytes).decode()
            except Exception:
                pass  # Screenshot failure is non-fatal

            try:
                password_fields = driver.find_elements(By.CSS_SELECTOR, 'input[type="password"]')
                login_forms     = driver.find_elements(
                    By.XPATH,
                    '//form[.//input[@type="password"] or .//input[@type="text"]]'
                )
                result['has_password_field'] = len(password_fields) > 0
                result['has_login_form']     = len(login_forms) > 0

                if result['has_login_form']:
                    result['dom_signals'].append('login_form_present')
            except Exception:
                pass

            try:
                iframes       = driver.find_elements(By.TAG_NAME, 'iframe')
                hidden_count  = 0
                bitb_detected = False
                bitb_detail   = ''

                for iframe in iframes:
                    location = iframe.location
                    size     = iframe.size
                    src      = iframe.get_attribute('src') or ''
                    style    = iframe.get_attribute('style') or ''

                    if size['width'] == 0 or size['height'] == 0:
                        hidden_count += 1
                        continue
                    if 'display:none' in style.replace(' ', '') or \
                       'visibility:hidden' in style.replace(' ', ''):
                        hidden_count += 1
                        continue

                    top_y  = location.get('y', 9999)
                    width  = size.get('width', 0)
                    height = size.get('height', 0)

                    is_large       = width > 400 and height > 300
                    is_near_top    = top_y < BITB_OVERLAP_PX
                    src_suspicious = any(kw in src for kw in BITB_KEYWORDS)

                    if is_large and (is_near_top or src_suspicious):
                        bitb_detected = True
                        bitb_detail   = (
                            f"Iframe at y={top_y}px (size {width}×{height}) "
                            f"appears to simulate a browser window "
                            f"{'containing a known auth URL' if src_suspicious else 'near page top'}. "
                            "This is a Browser-in-the-Browser (BiTB) attack pattern."
                        )
                        result['dom_signals'].append('bitb_iframe_detected')

                result['hidden_iframes'] = hidden_count
                result['bitb_detected']  = bitb_detected
                result['bitb_detail']    = bitb_detail
            except Exception:
                pass

            try:
                body_text     = driver.find_element(By.TAG_NAME, 'body').text.lower()
                urgency_words = [
                    'verify your account', 'confirm your identity', 'suspended',
                    'unusual activity', 'click here immediately', 'expires in',
                    'your account has been', 'limited access',
                ]
                for phrase in urgency_words:
                    if phrase in body_text:
                        result['dom_signals'].append(f'urgency_language: "{phrase}"')
            except Exception:
                pass

        except TimeoutException:
            result['dom_signals'].append('page_load_timeout')
        except WebDriverException as exc:
            # Log and return gracefully — do not re-raise; the caller handles
            # the absence of browser data safely via the safe fallback dict.
            logger.warning('_browser_analyze WebDriverException for %s: %s', url, exc)
            result['dom_signals'].append(f'webdriver_error: {type(exc).__name__}')
        except Exception as exc:
            logger.warning('_browser_analyze unexpected error for %s: %s', url, exc)
            result['dom_signals'].append(f'browser_error: {type(exc).__name__}')
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass

        return result

    # ── Private: Zero Trust Validation ────────────────────────────────────────
    # FIX: moved from URLAnalyzer._zero_trust_validate() in analyzer.py.
    # Performs DNS resolution (ZT-1) and SSL/TLS certificate check (ZT-2).
    # Called from analyze() above; kept as a @staticmethod so it can be tested
    # independently without instantiating DeepAnalyzer.

    @staticmethod
    def _zero_trust_validate(url: str) -> dict:
        """
        Zero Trust pre-flight validation (DNS + TLS).

        ZT-1  DNS Resolution  — hostname must resolve to a valid IP.
        ZT-2  SSL/TLS Validity — for HTTPS, certificate chain must be valid.

        Returns:
            {
              'passed':       bool,
              'ssl_valid':    bool,
              'dns_resolved': bool,
              'checks':       list[dict]
            }
        """
        import ssl
        import socket
        from urllib.parse import urlparse as _urlparse

        parsed   = _urlparse(url)
        hostname = parsed.netloc.split(':')[0]
        checks: list[dict] = []

        # ── ZT-1: DNS Resolution ──────────────────────────────────────────────
        try:
            socket.getaddrinfo(
                hostname, None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
            dns_resolved = True
            checks.append({
                'check':  'dns_resolution',
                'passed': True,
                'detail': f"'{hostname}' resolves to a valid IP address.",
            })
        except socket.gaierror as exc:
            dns_resolved = False
            checks.append({
                'check':  'dns_resolution',
                'passed': False,
                'detail': f"DNS resolution failed for '{hostname}': {exc}",
            })

        # ── ZT-2: SSL/TLS Certificate Validity ───────────────────────────────
        if parsed.scheme == 'https':
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(
                    socket.socket(socket.AF_INET),
                    server_hostname=hostname,
                ) as ssock:
                    ssock.settimeout(5)
                    ssock.connect((hostname, 443))
                ssl_valid = True
                checks.append({
                    'check':  'ssl_certificate',
                    'passed': True,
                    'detail': f"SSL/TLS certificate for '{hostname}' is valid.",
                })
            except (ssl.SSLError, socket.timeout, OSError) as exc:
                ssl_valid = False
                checks.append({
                    'check':  'ssl_certificate',
                    'passed': False,
                    'detail': f"SSL/TLS validation failed for '{hostname}': {exc}",
                })
        else:
            ssl_valid = False
            checks.append({
                'check':  'ssl_certificate',
                'passed': False,
                'detail': "No TLS — URL uses plain HTTP.",
            })

        return {
            'passed':       dns_resolved and ssl_valid,
            'ssl_valid':    ssl_valid,
            'dns_resolved': dns_resolved,
            'checks':       checks,
        }
