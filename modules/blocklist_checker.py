# =============================================================================
# modules/blocklist_checker.py  —  Real-Time Phishing Blocklist Lookup
# =============================================================================
# Queries the Google Safe Browsing Lookup API v4 to check whether a URL is
# present in Google's constantly-updated phishing / malware blocklists.
#
# WHY THIS MATTERS:
#   The ML+heuristic pipeline can miss novel phishing pages that were only
#   registered minutes ago.  Google Safe Browsing maintains real-time lists
#   of confirmed malicious URLs.  A blocklist hit gives 100% precision for
#   known-bad URLs with virtually zero false-positive rate.
#
# CONFIGURATION:
#   Set GOOGLE_SAFE_BROWSING_KEY in your .env file.
#   Get a free key (10,000 req/day) at:
#     https://developers.google.com/safe-browsing/v4/get-started
#   Leave the variable empty or unset to run in disabled mode (no external
#   calls; all URLs return is_blocked=False, source='disabled').
#
# THREAT TYPES CHECKED:
#   • SOCIAL_ENGINEERING  — phishing pages impersonating trusted sites
#   • MALWARE             — pages that distribute malware
#   • UNWANTED_SOFTWARE   — deceptive software install pages
#
# TIMEOUT:
#   Hard-coded to 3 seconds.  A timeout is treated as a non-block (fail-open)
#   so that a slow API never blocks the main analysis response.
# =============================================================================

import os
import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

_THREAT_TYPES = [
    'SOCIAL_ENGINEERING',
    'MALWARE',
    'UNWANTED_SOFTWARE',
]

_DISABLED_RESULT: dict = {
    'is_blocked':  False,
    'source':      'disabled',
    'threat_type': None,
}

_ERROR_RESULT: dict = {
    'is_blocked':  False,
    'source':      'error',
    'threat_type': None,
}


class BlocklistChecker:
    """
    Checks a URL against Google Safe Browsing v4.

    Instantiated once as a singleton in URLAnalyzer.__init__().
    When GOOGLE_SAFE_BROWSING_KEY is absent the instance operates in
    disabled mode and all check() calls return immediately without
    making any network request.
    """

    def __init__(self, api_key: Optional[str] = None):
        self._api_key: str = (
            api_key
            or os.getenv('GOOGLE_SAFE_BROWSING_KEY', '')
        ).strip()

        if self._api_key:
            logger.info('BlocklistChecker: Google Safe Browsing enabled.')
        else:
            logger.info(
                'BlocklistChecker: GOOGLE_SAFE_BROWSING_KEY not set — '
                'running in disabled mode.  Set the env var to enable '
                'real-time blocklist lookups.'
            )

    @property
    def enabled(self) -> bool:
        return bool(self._api_key)

    def check(self, url: str) -> dict:
        """
        Query Google Safe Browsing for *url*.

        Returns
        -------
        dict with keys:
            is_blocked  bool   — True if the URL matched a threat entry.
            source      str    — 'google_safe_browsing' | 'disabled' | 'error'.
            threat_type str|None — e.g. 'SOCIAL_ENGINEERING', or None.
        """
        if not self.enabled:
            return _DISABLED_RESULT

        payload = {
            'client': {
                'clientId':      'clicksafe',
                'clientVersion': '2.0',
            },
            'threatInfo': {
                'threatTypes':      _THREAT_TYPES,
                'platformTypes':    ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries':    [{'url': url}],
            },
        }

        try:
            resp = requests.post(
                f'{_API_URL}?key={self._api_key}',
                json=payload,
                timeout=3,
            )
            resp.raise_for_status()
            data = resp.json()

            matches = data.get('matches', [])
            if matches:
                threat_type = matches[0].get('threatType', 'UNKNOWN')
                logger.warning(
                    'BlocklistChecker: BLOCKED — %s  threat=%s',
                    url, threat_type,
                )
                return {
                    'is_blocked':  True,
                    'source':      'google_safe_browsing',
                    'threat_type': threat_type,
                }

            return {
                'is_blocked':  False,
                'source':      'google_safe_browsing',
                'threat_type': None,
            }

        except requests.exceptions.Timeout:
            logger.warning('BlocklistChecker: request timed out for %s — failing open.', url)
            return _ERROR_RESULT
        except requests.exceptions.RequestException as exc:
            logger.warning('BlocklistChecker: request failed (%s) — failing open.', exc)
            return _ERROR_RESULT
        except Exception as exc:
            logger.error('BlocklistChecker: unexpected error (%s) — failing open.', exc)
            return _ERROR_RESULT
