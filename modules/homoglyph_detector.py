# =============================================================================
# modules/homoglyph_detector.py  —  HomoglyphDetector
# =============================================================================
# BUG FIX:
#   _extract_sld() used `hostname.lower().lstrip('www.')` which calls Python's
#   str.lstrip() with a *character set*, not a prefix string.  lstrip('www.')
#   strips any leading character that appears in the set {'w', '.'},  so a
#   domain like 'wwexample.com' would become 'example.com' (strips 'w','w')
#   and 'www.wwe.com' would become 'e.com' (strips w,w,.,w,w,.) — both wrong.
#   Fixed to use str.startswith() + slicing, which is the correct idiom.
# =============================================================================

import unicodedata
import re
from typing import Optional


HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic look-alikes
    '\u0430': 'a',
    '\u0435': 'e',
    '\u043e': 'o',
    '\u0440': 'r',
    '\u0441': 'c',
    '\u0443': 'u',
    '\u0445': 'x',
    '\u0456': 'i',
    '\u0458': 'j',
    '\u0455': 's',
    '\u0501': 'd',
    '\u0570': 'h',
    # Greek look-alikes
    '\u03bf': 'o',
    '\u03c1': 'p',
    '\u03b1': 'a',
    '\u03b5': 'e',
    '\u03b9': 'i',
    '\u03bd': 'v',
    # Latin extended look-alikes
    '\u00e0': 'a',
    '\u00e1': 'a',
    '\u00e2': 'a',
    '\u00e4': 'a',
    '\u00e8': 'e',
    '\u00e9': 'e',
    '\u00ec': 'i',
    '\u00ed': 'i',
    '\u00f2': 'o',
    '\u00f3': 'o',
    '\u00f9': 'u',
    '\u00fa': 'u',
    # Zero-width and confusing punctuation
    '\u2019': "'",
    '\u2018': "'",
    '\uff0e': '.',
    '\u3002': '.',
}

DIGIT_SUB_MAP: dict[str, str] = {
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '6': 'g',
    '7': 't',
    '8': 'b',
    '9': 'g',
    '@': 'a',
    '$': 's',
    '!': 'i',
}

KNOWN_BRANDS: set[str] = {
    'google', 'gmail', 'youtube', 'facebook', 'instagram', 'twitter',
    'microsoft', 'apple', 'amazon', 'netflix', 'paypal', 'ebay',
    'linkedin', 'whatsapp', 'tiktok', 'snapchat', 'pinterest',
    'dropbox', 'spotify', 'airbnb', 'uber', 'netflix',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'barclays',
    'hsbc', 'santander', 'lloyds', 'natwest',
    'icloud', 'outlook', 'yahoo', 'hotmail', 'live',
    'adobe', 'salesforce', 'shopify', 'wordpress', 'github',
}


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(
                prev[j + 1] + 1,
                curr[j] + 1,
                prev[j] + (c1 != c2),
            ))
        prev = curr
    return prev[-1]


def _normalise_homoglyphs(text: str) -> str:
    result = [HOMOGLYPH_MAP.get(ch, ch) for ch in text]
    return unicodedata.normalize('NFKC', ''.join(result))


def _normalise_digits(text: str) -> str:
    return ''.join(DIGIT_SUB_MAP.get(ch, ch) for ch in text)


class HomoglyphDetector:

    def check(self, hostname: str) -> dict:
        sld = self._extract_sld(hostname)
        if not sld:
            return self._clean_result(sld)

        # ── Technique 1: Homoglyph character substitution ─────────────────
        normalised_hg = _normalise_homoglyphs(sld)
        if normalised_hg != sld and normalised_hg.lower() in KNOWN_BRANDS:
            return {
                'is_suspicious':        True,
                'technique':            'homoglyph_substitution',
                'matched_brand':        normalised_hg.lower(),
                'normalised':           normalised_hg,
                'levenshtein_distance': 0,
                'detail': (
                    f"The domain '{hostname}' contains Unicode look-alike "
                    f"characters. When normalised, it reads '{normalised_hg}' "
                    f"— impersonating the brand '{normalised_hg.lower()}'."
                ),
            }

        # ── Technique 2: Digit substitution (l33t-speak) ──────────────────
        normalised_ds = _normalise_digits(sld.lower())
        if normalised_ds != sld.lower() and normalised_ds in KNOWN_BRANDS:
            return {
                'is_suspicious':        True,
                'technique':            'digit_substitution',
                'matched_brand':        normalised_ds,
                'normalised':           normalised_ds,
                'levenshtein_distance': 0,
                'detail': (
                    f"The domain '{hostname}' uses digit/symbol substitutions "
                    f"(e.g. '0' for 'o', '1' for 'l'). Normalised: '{normalised_ds}' "
                    f"— impersonating '{normalised_ds}'."
                ),
            }

        # ── Technique 3: Levenshtein distance to known brands ─────────────
        sld_clean  = sld.lower()
        best_brand: Optional[str] = None
        best_dist  = 999
        for brand in KNOWN_BRANDS:
            if abs(len(sld_clean) - len(brand)) > 3:
                continue
            dist = _levenshtein(sld_clean, brand)
            if dist < best_dist:
                best_dist  = dist
                best_brand = brand

        if best_dist <= 2 and best_dist > 0 and best_brand:
            return {
                'is_suspicious':        True,
                'technique':            'levenshtein_typosquatting',
                'matched_brand':        best_brand,
                'normalised':           sld_clean,
                'levenshtein_distance': best_dist,
                'detail': (
                    f"The domain '{sld_clean}' is very similar to the well-known "
                    f"brand '{best_brand}' (edit distance: {best_dist}). "
                    "This is a classic typosquatting pattern."
                ),
            }

        return self._clean_result(sld)

    @staticmethod
    def _extract_sld(hostname: str) -> str:
        """
        Extract the second-level domain (the main brand name part).
        'login.paypal.com' → 'paypal'
        'google.co.uk'     → 'google'

        BUG FIX: original used hostname.lower().lstrip('www.') which calls
        str.lstrip() with a character *set* {'w', '.'}, not a prefix strip.
        This corrupted domains like 'wwexample.com' → 'example.com' and
        'www.wwe.com' → 'e.com'.  Fixed to use startswith() + slicing.
        """
        host = hostname.lower()
        if host.startswith('www.'):
            host = host[4:]
        parts = host.split('.')
        if len(parts) >= 2:
            return parts[-2]
        return host

    @staticmethod
    def _clean_result(sld: str) -> dict:
        return {
            'is_suspicious':        False,
            'technique':            'none',
            'matched_brand':        '',
            'normalised':           sld,
            'levenshtein_distance': -1,
            'detail':               '',
        }
