# =============================================================================
# modules/ml_engine.py  —  MLEngine (Feature Extraction + Prediction)
# =============================================================================
# CHANGES IN v2 (19 features):
#
#   Five new features appended — indices [14-18] — so existing feature
#   indices [0-13] are unchanged and backward-compatible with any cached
#   analysis results.  After running train_model.py the new model.pkl
#   expects 19 features; the old 14-feature pkl must NOT be used.
#
#   [14] has_suspicious_tld    — TLD in a known-abused free registry
#   [15] hostname_digit_ratio  — digit fraction in hostname (0.0–1.0)
#   [16] vowel_ratio           — vowel fraction in hostname (0.0–1.0)
#   [17] has_non_standard_port — non-standard port flag (bool int)
#   [18] http_count_in_url     — embedded 'http' occurrences past the scheme
#
#   LABEL THRESHOLD FIX:
#     predict() now uses 0.7 (not 0.5) for the 'phishing' label, matching
#     the combined-verdict threshold in analyzer.py and AppConfig.dart.
#     Using 0.5 caused the label to say "phishing" when the final verdict
#     was "suspicious", confusing UI consumers.
#
#   BUG FIXES RETAINED:
#   • num_special_chars: broad 30-char set matching train_model.py.
#   • num_slashes: full URL count matching train_model.py.
# =============================================================================

import math
import re
import os
from urllib.parse import urlparse, parse_qs

import joblib
import numpy as np


class MLEngine:
    """Loads a pre-trained 19-feature classifier and scores URLs."""

    MODEL_PATH = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "models", "model.pkl",
    )

    _RE_IP         = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$")
    _SPECIAL_CHARS = set("!@#$%^&*()_+-=[]{};':\"|,.<>/?")
    _SUSPICIOUS_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click',
        'link', 'win', 'download', 'ru', 'cn', 'pw', 'cc', 'biz',
    }
    _VOWELS         = set('aeiou')
    _STANDARD_PORTS = {80, 443, 8080, 8443}

    # Feature order — must stay in sync with train_model.py FEATURE_NAMES.
    _FEATURE_ORDER = [
        "url_length", "hostname_length", "path_length",
        "num_dots", "num_hyphens", "num_underscores",
        "num_slashes", "num_query_params", "num_special_chars",
        "has_ip_host", "has_https", "has_at_sign",
        "subdomain_count", "url_entropy",
        "has_suspicious_tld", "hostname_digit_ratio", "vowel_ratio",
        "has_non_standard_port", "http_count_in_url",
    ]

    def __init__(self):
        if not os.path.exists(self.MODEL_PATH):
            raise FileNotFoundError(
                f"Model file not found at {self.MODEL_PATH}. "
                "Please run train_model.py first."
            )
        self.model = joblib.load(self.MODEL_PATH)

        # Guard against stale model.pkl trained on a different feature count.
        expected = len(self._FEATURE_ORDER)
        actual   = self.model.n_features_in_
        if actual != expected:
            raise ValueError(
                f"model.pkl expects {actual} features but MLEngine extracts "
                f"{expected}.  Re-run train_model.py to regenerate the model."
            )

    # ── Feature Extraction ─────────────────────────────────────────────────────

    def extract_features(self, url: str) -> dict:
        """
        Returns a dict of 19 numerical features for *url*.
        Keys must match _FEATURE_ORDER exactly.
        """
        parsed   = urlparse(url)
        hostname = parsed.netloc.lower().split(":")[0]
        path     = parsed.path
        query    = parsed.query

        # ── Features [0-13] ───────────────────────────────────────────────────
        url_length        = len(url)
        hostname_length   = len(hostname)
        path_length       = len(path)
        num_dots          = url.count(".")
        num_hyphens       = url.count("-")
        num_underscores   = url.count("_")
        num_slashes       = url.count("/")          # full URL (matches training)
        num_query_params  = len(parse_qs(query))
        num_special_chars = sum(1 for c in url if c in self._SPECIAL_CHARS)
        has_ip_host       = int(bool(self._RE_IP.match(parsed.netloc)))
        has_https         = int(parsed.scheme == "https")
        has_at_sign       = int("@" in url)
        clean_host        = hostname[4:] if hostname.startswith("www.") else hostname
        subdomain_count   = max(0, len(clean_host.split(".")) - 2)
        url_entropy       = round(self._shannon_entropy(url), 6)

        # ── Feature [14]: has_suspicious_tld ──────────────────────────────────
        tld               = hostname.split(".")[-1].lower() if "." in hostname else ""
        has_suspicious_tld = int(tld in self._SUSPICIOUS_TLDS)

        # ── Feature [15]: hostname_digit_ratio ────────────────────────────────
        hostname_digit_ratio = round(
            sum(c.isdigit() for c in hostname) / max(len(hostname), 1), 6
        )

        # ── Feature [16]: vowel_ratio (of hostname) ───────────────────────────
        vowel_ratio = round(
            sum(c in self._VOWELS for c in hostname.lower()) / max(len(hostname), 1), 6
        )

        # ── Feature [17]: has_non_standard_port ───────────────────────────────
        port = parsed.port
        has_non_standard_port = int(bool(port) and port not in self._STANDARD_PORTS)

        # ── Feature [18]: http_count_in_url ───────────────────────────────────
        http_count_in_url = max(0, url.lower().count("http") - 1)

        return {
            "url_length":           url_length,
            "hostname_length":      hostname_length,
            "path_length":          path_length,
            "num_dots":             num_dots,
            "num_hyphens":          num_hyphens,
            "num_underscores":      num_underscores,
            "num_slashes":          num_slashes,
            "num_query_params":     num_query_params,
            "num_special_chars":    num_special_chars,
            "has_ip_host":          has_ip_host,
            "has_https":            has_https,
            "has_at_sign":          has_at_sign,
            "subdomain_count":      subdomain_count,
            "url_entropy":          url_entropy,
            "has_suspicious_tld":   has_suspicious_tld,
            "hostname_digit_ratio": hostname_digit_ratio,
            "vowel_ratio":          vowel_ratio,
            "has_non_standard_port": has_non_standard_port,
            "http_count_in_url":    http_count_in_url,
        }

    # ── Prediction ─────────────────────────────────────────────────────────────

    def predict(self, features: dict) -> dict:
        X = np.array([[features[k] for k in self._FEATURE_ORDER]])

        proba         = self.model.predict_proba(X)[0]
        phishing_prob = float(proba[1])

        # LABEL THRESHOLD FIX: use 0.7, matching the combined-verdict threshold
        # in analyzer.py and AppConfig.mlPhishingThreshold in Flutter.
        # The old 0.5 threshold made the label disagree with the final verdict.
        label = "phishing" if phishing_prob >= 0.7 else "safe"

        return {
            "label":       label,
            "probability": round(phishing_prob, 4),
        }

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        n    = len(text)
        freq: dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        return -sum((count / n) * math.log2(count / n) for count in freq.values())
