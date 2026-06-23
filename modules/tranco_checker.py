# =============================================================================
# modules/tranco_checker.py  —  TrancoChecker
# =============================================================================
# FIXES APPLIED IN THIS VERSION:
#
#   BUG-02 (Wrong File Path) — _LIST_PATH pointed at 'tranco_top100k.txt'
#     which does not exist on disk. The actual file is 'data/tranco.csv'.
#     With the wrong path os.path.exists() returned False and _load() silently
#     fell back to the 34-domain hardcoded _FALLBACK_WHITELIST, meaning
#     99,966 domains were NEVER loaded.
#     Fix: changed the filename in _LIST_PATH from
#       'tranco_top100k.txt'  →  'tranco.csv'
#
#   Previously fixed (retained):
#   • Critical subdomain whitelist bypass: is_whitelisted() now checks the
#     EXACT hostname rather than the registered-domain strip, preventing
#     "evil.paypal.com" from being classified as safe.
# =============================================================================

import os
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_FALLBACK_WHITELIST: set[str] = {
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'linkedin.com', 'wikipedia.org', 'amazon.com', 'apple.com', 'microsoft.com',
    'github.com', 'stackoverflow.com', 'reddit.com', 'netflix.com', 'yahoo.com',
    'whatsapp.com', 'tiktok.com', 'snapchat.com', 'pinterest.com', 'ebay.com',
    'paypal.com', 'dropbox.com', 'spotify.com', 'adobe.com', 'salesforce.com',
    'shopify.com', 'cloudflare.com', 'wordpress.com', 'bbc.co.uk', 'cnn.com',
    'nytimes.com', 'theguardian.com', 'reuters.com', 'bloomberg.com',
    'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citibank.com',
}

_DATA_DIR  = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')

# BUG-02 FIX: was 'tranco_top100k.txt' — file is 'tranco.csv'.
# Also reads TRANCO_PATH env var so the path can be overridden without code changes.
_LIST_PATH = os.getenv(
    'TRANCO_PATH',
    os.path.join(_DATA_DIR, 'tranco.csv'),
)


class TrancoChecker:
    """
    Loads the Tranco top-100k domain list and provides O(1) membership lookup.
    """

    def __init__(self):
        self._domains: set[str] = set()
        self._source: str = ''
        self._load()

    # ── Public API ─────────────────────────────────────────────────────────────

    def is_whitelisted(self, url_or_domain: str) -> dict:
        """
        Check whether the domain from *url_or_domain* is in the top-100k list.

        Only the EXACT extracted hostname (or its www.-stripped form) is checked.
        Arbitrary subdomains of trusted brands are NOT automatically safe
        (e.g. "evil.paypal.com" is NOT whitelisted even though "paypal.com" is).

        Parameters
        ----------
        url_or_domain : str  Either a full URL or a bare domain name.

        Returns
        -------
        dict:
            whitelisted  bool  – True only if the exact domain is in the list.
            domain       str   – The extracted domain that was checked.
            rank         str   – "top_100k" if whitelisted, else "unranked".
            source       str   – "tranco_file" or "fallback_set".
        """
        domain = self._extract_domain(url_or_domain)

        # Check exact match first
        if domain in self._domains:
            hit = True
        else:
            # Allow www. prefix variant: "www.paypal.com" <-> "paypal.com"
            if domain.startswith('www.'):
                hit = domain[4:] in self._domains
            else:
                hit = ('www.' + domain) in self._domains

        return {
            'whitelisted': hit,
            'domain':      domain,
            'rank':        'top_100k' if hit else 'unranked',
            'source':      self._source,
        }

    @property
    def size(self) -> int:
        """Number of domains currently loaded."""
        return len(self._domains)

    # ── Private helpers ────────────────────────────────────────────────────────

    def _load(self):
        """Load domains from the Tranco CSV file, falling back to the hardcoded set."""
        if os.path.exists(_LIST_PATH):
            try:
                with open(_LIST_PATH, 'r', encoding='utf-8') as fh:
                    for line in fh:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split(',')
                            # tranco.csv format: rank,domain  (e.g. "1,google.com")
                            domain = parts[-1].strip().lower()
                            if domain:
                                self._domains.add(domain)
                self._source = 'tranco_file'
                logger.info('TrancoChecker: loaded %d domains from %s',
                            len(self._domains), _LIST_PATH)
                return
            except Exception as exc:
                logger.warning('TrancoChecker: failed to read file (%s), '
                               'falling back to hardcoded set.', exc)

        self._domains = set(_FALLBACK_WHITELIST)
        self._source  = 'fallback_set'
        logger.info('TrancoChecker: using fallback set (%d domains)',
                    len(self._domains))

    @staticmethod
    def _extract_domain(url_or_domain: str) -> str:
        """Return lowercase domain from a URL or bare hostname."""
        s = url_or_domain.strip().lower()
        if '://' in s:
            parsed = urlparse(s)
            host = parsed.netloc or s
        else:
            host = s
        return host.split(':')[0]

    @staticmethod
    def _registered_domain(domain: str) -> str:
        """
        Naively strip subdomains to get the registered domain.
        NOTE: Retained for reference but NO LONGER used by is_whitelisted().
        Using it for whitelist decisions caused the subdomain bypass bug.
        """
        parts = domain.split('.')
        if len(parts) > 2:
            return '.'.join(parts[-2:])
        return domain
