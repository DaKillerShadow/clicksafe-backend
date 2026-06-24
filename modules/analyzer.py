# =============================================================================
# modules/analyzer.py  —  URLAnalyzer (Enhanced Hybrid Orchestrator)
# =============================================================================
# FIXES IN THIS VERSION:
#
#   VERDICT BUG FIX (Critical):
#     The previous code recomputed base_rule_score as
#     sum(rule.get('score', 0) for rule in triggered_rules), which was always
#     0 because no rule dict contained a 'score' key.  The verdict logic now
#     preserves the accumulated rule_score (built up correctly through the
#     analyze() pipeline) and only adds the zero-day delta on top.
#     Rule dicts now include a 'score' key matching rule_engine.py's output.
#
#   ML RULE CORROBORATION (New):
#     Added a strict rule corroboration requirement in Stage 8. If a URL is
#     not in the Tranco whitelist, the ML model alone cannot trigger a
#     `suspicious` or `likely_phishing` verdict unless its probability is
#     >= 0.85, or a high severity rule is also triggered.
#
#   DEAD CODE REMOVED:
#     _zero_trust_validate() static method has been removed from URLAnalyzer.
#     It was moved to DeepAnalyzer in deep_analyzer.py and was unreachable here.
#     The fast path returns a 'deferred' placeholder; the deep path runs the
#     real check via DeepAnalyzer._zero_trust_validate().
#
#   SCORE KEYS ON MANUAL RULE APPENDS:
#     The shortener (+2), homoglyph (+5), link-masking (+3), blocklist (+8),
#     and zero-day rule injections all now include a 'score' key so Flutter
#     can display per-rule points and the verdict aggregation is consistent.
#
#   PREVIOUSLY FIXED (retained):
#   • BLOCKLIST INTEGRATION: BlocklistChecker called after Tranco whitelist.
#   • 19-FEATURE SUPPORT: _FEATURE_IMPORTANCE_APPROX etc. updated.
#   • BUG-01: _build_xai() returns high_severity_rules + top_risk_features.
#   • ML-01: try/except FileNotFoundError around MLEngine(); heuristic-only.
#   • ZERO-DAY (Stage 6.5): rule_engine.check_zero_day() with inflation cap.
# =============================================================================

import logging

from .validator          import URLValidator
from .rule_engine        import RuleEngine
from .ml_engine          import MLEngine
from .tranco_checker     import TrancoChecker
from .homoglyph_detector import HomoglyphDetector
from .blocklist_checker  import BlocklistChecker

logger = logging.getLogger(__name__)

# ── Feature importance fallback values (from retrained 19-feature model) ──────
_FEATURE_IMPORTANCE_APPROX: dict[str, float] = {
    'path_length':          0.324062,
    'num_slashes':          0.313584,
    'num_special_chars':    0.132997,
    'url_entropy':          0.081047,
    'subdomain_count':      0.033798,
    'num_dots':             0.032261,
    'url_length':           0.027813,
    'hostname_length':      0.025456,
    'has_https':            0.012593,
    'num_hyphens':          0.009436,
    'vowel_ratio':          0.002556,
    'hostname_digit_ratio': 0.001920,
    'num_query_params':     0.001909,
    'num_underscores':      0.000528,
    'has_suspicious_tld':   0.000040,
    'has_ip_host':          0.0,
    'has_at_sign':          0.0,
    'has_non_standard_port': 0.0,
    'http_count_in_url':    0.0,
}

_FEATURE_DESCRIPTIONS: dict[str, str] = {
    'url_length':           'Total URL length — phishing URLs are typically much longer',
    'url_entropy':          'Character randomness — high entropy suggests generated/obfuscated URLs',
    'num_special_chars':    'Special characters (@, %, =, ?) — used to confuse URL parsers',
    'hostname_length':      'Hostname length — long hostnames often embed brand names as decoys',
    'path_length':          'Path depth — deep paths hide malicious payloads',
    'num_dots':             'Dot count — many dots indicate excessive subdomain nesting',
    'subdomain_count':      'Subdomain depth — e.g. "secure.login.paypal.evil.com"',
    'num_slashes':          'Slash count — extra slashes enable redirect tricks',
    'has_https':            'HTTPS presence — absence of TLS is a weak but real signal',
    'num_hyphens':          'Hyphen count — hyphens used in typosquatting (pay-pal.com)',
    'has_ip_host':          'IP as host — raw IP addresses avoid domain registration',
    'num_query_params':     'Query parameter count — many params suggest tracking/redirect',
    'has_at_sign':          '@ symbol — browsers ignore everything before @ in a URL',
    'num_underscores':      'Underscore count — underscores are uncommon in legitimate domains',
    'has_suspicious_tld':   'Suspicious TLD (.tk, .ml, .xyz…) — free/abused registries',
    'hostname_digit_ratio': 'Digit fraction in hostname — machine-generated domains have high ratios',
    'vowel_ratio':          'Vowel fraction in hostname — gibberish domains deviate from natural language',
    'has_non_standard_port': 'Non-standard port — legitimate sites use 80/443; unusual ports are red flags',
    'http_count_in_url':    'Embedded HTTP in URL — proxy for URL-in-URL redirect chain tricks',
}

LABEL_MAP = {
    'safe':            '✅  Safe',
    'suspicious':      '⚠️  Suspicious',
    'likely_phishing': '🚨  Likely Phishing',
}

_NULL_ML_RESULT = {'label': 'safe', 'probability': 0.0}
_NULL_FEATURES  = {}


class URLAnalyzer:
    """
    Enhanced hybrid orchestrator: Tranco whitelist → Google Safe Browsing
    blocklist → Zero Trust validation → homoglyph detection → link masking
    → heuristic rules → Zero-Day check → ML.
    """

    def __init__(self):
        self.validator         = URLValidator()
        self.rule_engine       = RuleEngine()
        self.tranco            = TrancoChecker()
        self.homoglyph         = HomoglyphDetector()
        self.blocklist         = BlocklistChecker()
        self.SHORTENER_DOMAINS = {
            'tinyurl.com', 'bit.ly', 't.co', 'rb.gy', 'goo.gl', 'is.gd', 'ow.ly',
        }

        # Domains that are Tranco-whitelisted yet host arbitrary user content.
        self.SHARED_INFRASTRUCTURE = {
            'ipfs.io', 'dweb.link', 'cloudflare-ipfs.com',
            'nftstorage.link', 'w3s.link',
            'firebaseapp.com', 'web.app',
            'storage.googleapis.com', 'appspot.com',
            'workers.dev', 'pages.dev',
            'azurewebsites.net', 'blob.core.windows.net',
            'notion.site', 'sites.google.com',
        }

        # OAuth / SSO endpoints whose URLs are legitimately long.
        self.TRUSTED_OAUTH_DOMAINS = {
            'accounts.google.com',
            'login.microsoftonline.com',
            'login.live.com',
            'appleid.apple.com',
            'auth.amazon.com',
        }

        # ML-01: graceful degradation when model.pkl is absent
        try:
            self.ml_engine = MLEngine()
            logger.info('MLEngine loaded — %d features.', self.ml_engine.model.n_features_in_)
        except (FileNotFoundError, ValueError) as exc:
            self.ml_engine = None
            logger.warning('MLEngine unavailable — heuristic-only mode. (%s)', exc)

    # ── Private ML guards ──────────────────────────────────────────────────────

    def _extract_features(self, url: str) -> dict:
        if self.ml_engine is None:
            return _NULL_FEATURES
        return self.ml_engine.extract_features(url)

    def _predict(self, features: dict) -> dict:
        if self.ml_engine is None or not features:
            return _NULL_ML_RESULT
        return self.ml_engine.predict(features)

    # ── Public API ─────────────────────────────────────────────────────────────

    def analyze(self, raw_url: str, visible_text: str = '') -> dict:
        """Full pipeline: validate → whitelist → blocklist → Zero Trust →
        rules + Zero-Day → ML → verdict."""

        # ── Stage 1: Validate & Normalise ────────────────────────────────────
        validation = self.validator.validate(raw_url)
        if not validation['is_valid']:
            return {
                'success': False, 'error': validation['error'], 'url': raw_url,
                'verdict': None, 'verdict_label': None, 'triggered_rules': [],
                'rule_risk_score': 0, 'ml_result': None, 'features': None,
                'explanation': '', 'whitelist': None, 'homoglyph': None,
                'link_masking': None, 'xai': None, 'combined_score': 0,
                'blocklist': None,
                'zero_trust': None,
                'zero_day':   None,
            }

        url = validation['url']

        # ── Stage 2: Tranco Whitelist (Shortener + Shared-Infrastructure Bypass) ─
        whitelist_result = self.tranco.is_whitelisted(url)
        domain = whitelist_result.get('domain', '').lower()

        is_shared = any(
            domain == si or domain.endswith('.' + si)
            for si in self.SHARED_INFRASTRUCTURE
        )

        if whitelist_result['whitelisted'] and domain not in self.SHORTENER_DOMAINS and not is_shared:
            return {
                'success':         True,
                'error':           '',
                'url':             url,
                'verdict':         'safe',
                'verdict_label':   LABEL_MAP['safe'],
                'triggered_rules': [],
                'rule_risk_score': 0,
                'ml_result':       {'label': 'safe', 'probability': 0.02},
                'features':        self._extract_features(url) or None,
                'explanation':     (
                    f"Domain '{whitelist_result['domain']}' is in the Tranco "
                    f"Top-1M list — a globally recognised, legitimate website."
                ),
                'whitelist':       whitelist_result,
                'homoglyph':       {'is_suspicious': False, 'technique': 'none', 'detail': '',
                                    'matched_brand': '', 'normalised': '', 'levenshtein_distance': -1},
                'link_masking':    self._check_link_masking(url, visible_text),
                'xai':             None,
                'combined_score':  0.2,
                'blocklist':       {'is_blocked': False, 'source': 'skipped_whitelist'},
                'zero_trust': {
                    'passed':       True,
                    'ssl_valid':    True,
                    'dns_resolved': True,
                    'checks': [{
                        'check':  'skipped_whitelist',
                        'passed': True,
                        'detail': (
                            'Domain is in the Tranco Top-1M list — '
                            'Zero Trust checks are pre-satisfied for globally '
                            'recognised, audited domains.'
                        ),
                    }],
                },
                'zero_day': {
                    'is_zero_day':    False,
                    'zero_day_score': 0,
                    'indicators':     [],
                },
            }

        # ── Stage 3: Real-Time Blocklist (Google Safe Browsing) ───────────────
        blocklist_result = self.blocklist.check(url)

        # ── Stage 3d: Trusted OAuth / SSO Fast-Return ────────────────────────
        from urllib.parse import urlparse as _up
        _oauth_host  = _up(url).netloc.lower().split(':')[0]
        _oauth_clean = _oauth_host[4:] if _oauth_host.startswith('www.') else _oauth_host
        _is_trusted_oauth = any(
            _oauth_clean == d or _oauth_clean.endswith('.' + d)
            for d in self.TRUSTED_OAUTH_DOMAINS
        )
        if _is_trusted_oauth and not blocklist_result['is_blocked']:
            return {
                'success':         True,
                'error':           '',
                'url':             url,
                'verdict':         'safe',
                'verdict_label':   LABEL_MAP['safe'],
                'triggered_rules': [],
                'rule_risk_score': 0,
                'ml_result':       {'label': 'safe', 'probability': 0.01},
                'features':        self._extract_features(url) or None,
                'explanation': (
                    f"Domain '{_oauth_host}' is a trusted OAuth/SSO identity "
                    f"provider. Long redirect URLs with percent-encoded parameters "
                    f"are expected and safe on this endpoint."
                ),
                'whitelist':    {'whitelisted': True, 'domain': _oauth_host,
                                 'source': 'trusted_oauth'},
                'homoglyph':    {
                    'is_suspicious':        False,
                    'technique':            'none',
                    'matched_brand':        '',
                    'normalised':           '',
                    'levenshtein_distance': -1,
                    'detail':               '',
                },
                'link_masking': self._check_link_masking(url, visible_text),
                'xai':          None,
                'combined_score': 0.1,
                'blocklist':    blocklist_result,
                'zero_trust': {
                    'passed':       True,
                    'ssl_valid':    True,
                    'dns_resolved': True,
                    'checks': [{'check': 'skipped_trusted_oauth', 'passed': True,
                                'detail': 'Domain is a trusted OAuth/SSO provider.'}],
                },
                'zero_day': {
                    'is_zero_day':    False,
                    'zero_day_score': 0,
                    'indicators':     [],
                },
            }

        # ── Stage 3.5: Zero Trust — deferred to Deep Path ────────────────────
        zero_trust_result = {
            'passed':       None,
            'ssl_valid':    None,
            'dns_resolved': None,
            'checks': [{
                'check':  'deferred_to_deep_path',
                'passed': None,
                'detail': (
                    'Zero Trust validation deferred to Deep Path '
                    '(DNS + TLS checks skipped on Fast Path for latency).'
                ),
            }],
        }

        # ── Stage 4: Feature Extraction ───────────────────────────────────────
        from urllib.parse import urlparse, unquote, urlunparse
        _parsed_for_ml = urlparse(url)
        _ml_url = urlunparse(_parsed_for_ml._replace(
            query=unquote(_parsed_for_ml.query),
            fragment=unquote(_parsed_for_ml.fragment or ''),
        ))
        features = self._extract_features(_ml_url)
        hostname  = _parsed_for_ml.netloc.lower().split(':')[0]

        # ── Stage 5: Homoglyph & Link Masking ─────────────────────────────────
        homoglyph_result    = self.homoglyph.check(hostname)
        link_masking_result = self._check_link_masking(url, visible_text)

        # ── Stage 6: Heuristic Rule Engine ────────────────────────────────────
        rule_result     = self.rule_engine.analyze(url)
        rule_score      = rule_result['risk_score']
        triggered_rules = rule_result['triggered_rules']

        if domain in self.SHORTENER_DOMAINS:
            triggered_rules.append({
                'name':        'URL Shortener (Analysis Required)',
                'description': 'Known URL shortener detected. Forcing deeper inspection.',
                'severity':    'medium',
                'score':       2,
            })
            rule_score += 2

        if homoglyph_result['is_suspicious']:
            triggered_rules.append({
                'name':        'Homoglyph / Typosquatting Attack',
                'description': homoglyph_result['detail'],
                'severity':    'high',
                'score':       5,
            })
            rule_score += 5

        if link_masking_result['is_masked']:
            triggered_rules.append({
                'name':        'Link Masking Detected',
                'description': link_masking_result['detail'],
                'severity':    'high',
                'score':       3,
            })
            rule_score += 3

        # ── Blocklist hit: inject rule + escalate score ────────────────────────
        if blocklist_result['is_blocked']:
            threat = blocklist_result.get('threat_type', 'UNKNOWN')
            triggered_rules.insert(0, {
                'name': 'Confirmed Threat (Google Safe Browsing)',
                'description': (
                    f"This URL is listed in Google Safe Browsing as a confirmed "
                    f"threat ({threat}). Do not open this link."
                ),
                'severity': 'high',
                'score':    8,
            })
            rule_score = max(rule_score + 8, 8)

        # ── Stage 6.5: Zero-Day Threat Check ──────────────────────────────────
        zero_day_result = self.rule_engine.check_zero_day(url)

        if zero_day_result['is_zero_day']:
            indicator_summary = '; '.join(
                i['detail'] for i in zero_day_result['indicators'][:2]
            )
            zd_rule = {
                'name': 'Zero-Day Threat Indicators Detected',
                'description': (
                    f"{len(zero_day_result['indicators'])} zero-day signal(s): "
                    f"{indicator_summary}"
                ),
                'severity': 'high',
                'score':    zero_day_result['zero_day_score'],
            }
            triggered_rules.append(zd_rule)

        # ── Stage 7: ML Prediction ────────────────────────────────────────────
        ml_result = self._predict(features)

        # ── Stage 8: Combined Verdict ─────────────────────────────────────────
        has_high_rule = any(r.get('severity') == 'high' for r in triggered_rules)
        zd_score      = zero_day_result.get('zero_day_score', 0) if zero_day_result else 0

        if zero_day_result['is_zero_day']:
            if rule_score < 4 and not has_high_rule:
                # Low base: cap total so ZD alone can't trigger phishing verdict.
                rule_score = min(rule_score + zd_score, 3)
            else:
                rule_score += zd_score

        prob = ml_result.get('probability', 0.0)
        is_whitelisted = whitelist_result.get('whitelisted', False)

        # Rule corroboration requirement: ML alone cannot trigger verdict if not whitelisted
        ml_corroborated = is_whitelisted or has_high_rule or (prob >= 0.85)

        # Verdict: blocklist always wins; otherwise use combined thresholds.
        if blocklist_result.get('is_blocked'):
            verdict = 'likely_phishing'
        elif rule_score >= 8 or (prob >= 0.7 and ml_corroborated):
            if rule_score >= 4 or has_high_rule:
                verdict = 'likely_phishing'
            else:
                verdict = 'suspicious'
        elif rule_score >= 4 or (prob >= 0.4 and ml_corroborated):
            verdict = 'suspicious'
        else:
            verdict = 'safe'

        combined_score = round((prob * 10) + (rule_score * 0.5), 2)

        return {
            'success':         True,
            'error':           '',
            'url':             url,
            'verdict':         verdict,
            'verdict_label':   LABEL_MAP[verdict],
            'triggered_rules': triggered_rules,
            'rule_risk_score': rule_score,
            'ml_result':       ml_result,
            'features':        features if features else None,
            'explanation':     self._build_explanation(
                                   verdict, rule_score, ml_result,
                                   homoglyph_result, link_masking_result,
                                   whitelist_result, blocklist_result,
                               ),
            'whitelist':       whitelist_result,
            'homoglyph':       homoglyph_result,
            'link_masking':    link_masking_result,
            'xai':             self._build_xai(features, ml_result, triggered_rules, verdict),
            'combined_score':  combined_score,
            'blocklist':       blocklist_result,
            'zero_trust':      zero_trust_result,
            'zero_day':        zero_day_result,
        }

    def get_feature_importances(self) -> list[dict]:
        """Return sorted feature importances for all 19 ML features."""
        feature_order = [
            'url_length', 'hostname_length', 'path_length', 'num_dots',
            'num_hyphens', 'num_underscores', 'num_slashes', 'num_query_params',
            'num_special_chars', 'has_ip_host', 'has_https', 'has_at_sign',
            'subdomain_count', 'url_entropy',
            'has_suspicious_tld', 'hostname_digit_ratio', 'vowel_ratio',
            'has_non_standard_port', 'http_count_in_url',
        ]

        if self.ml_engine is None:
            return sorted(
                [
                    {
                        'feature':     n,
                        'importance':  _FEATURE_IMPORTANCE_APPROX.get(n, 0.0),
                        'description': _FEATURE_DESCRIPTIONS.get(n, ''),
                    }
                    for n in feature_order
                ],
                key=lambda x: x['importance'], reverse=True,
            )

        try:
            importances = self.ml_engine.model.feature_importances_
            result = [
                {
                    'feature':     n,
                    'importance':  round(float(imp), 6),
                    'description': _FEATURE_DESCRIPTIONS.get(n, ''),
                }
                for n, imp in zip(feature_order, importances)
            ]
            return sorted(result, key=lambda x: x['importance'], reverse=True)
        except Exception:
            return sorted(
                [
                    {
                        'feature':     n,
                        'importance':  _FEATURE_IMPORTANCE_APPROX.get(n, 0.0),
                        'description': _FEATURE_DESCRIPTIONS.get(n, ''),
                    }
                    for n in feature_order
                ],
                key=lambda x: x['importance'], reverse=True,
            )

    # ── Static helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _check_link_masking(url: str, visible_text: str) -> dict:
        if not visible_text or not visible_text.strip():
            return {'checked': False, 'is_masked': False, 'detail': 'No visible text provided.'}

        from urllib.parse import urlparse
        import re

        visible     = visible_text.strip().lower()
        href_domain = urlparse(url).netloc.lower().split(':')[0]
        pattern     = re.compile(r'([a-z0-9\-]+\.[a-z]{2,})', re.IGNORECASE)
        visible_domains = pattern.findall(visible)

        if not visible_domains:
            return {'checked': True, 'is_masked': False, 'detail': 'No domain in visible text.'}

        for vd in visible_domains:
            vd_lower = vd.lower()
            vd_clean = vd_lower[4:] if vd_lower.startswith('www.') else vd_lower
            hd_clean = href_domain[4:] if href_domain.startswith('www.') else href_domain
            if vd_clean not in hd_clean and hd_clean not in vd_clean:
                return {
                    'checked':        True,
                    'is_masked':      True,
                    'visible_domain': vd,
                    'actual_domain':  href_domain,
                    'detail':         f"Link masking: {vd} vs {href_domain}",
                }
        return {'checked': True, 'is_masked': False, 'detail': 'Domains match.'}

    @staticmethod
    def _build_xai(features: dict, ml_result: dict, triggered_rules: list, verdict: str) -> dict:
        """Build XAI breakdown. Returns all keys expected by XaiResult.fromJson()."""
        FEATURE_RANGES = {
            'url_length':           (10, 200),
            'hostname_length':      (3, 80),
            'path_length':          (0, 120),
            'num_dots':             (1, 15),
            'num_hyphens':          (0, 10),
            'num_underscores':      (0, 6),
            'num_slashes':          (1, 20),
            'num_query_params':     (0, 12),
            'num_special_chars':    (0, 15),
            'has_ip_host':          (0, 1),
            'has_https':            (0, 1),
            'has_at_sign':          (0, 1),
            'subdomain_count':      (0, 8),
            'url_entropy':          (2, 6),
            'has_suspicious_tld':   (0, 1),
            'hostname_digit_ratio': (0.0, 0.6),
            'vowel_ratio':          (0.0, 0.6),
            'has_non_standard_port': (0, 1),
            'http_count_in_url':    (0, 4),
        }

        feature_contributions = []
        for fname, fval in features.items():
            lo, hi = FEATURE_RANGES.get(fname, (0, 10))
            span   = hi - lo if hi != lo else 1
            normalised = (
                1.0 - (fval - lo) / span
                if fname == 'has_https'
                else min(1.0, max(0.0, (fval - lo) / span))
            )
            importance = _FEATURE_IMPORTANCE_APPROX.get(fname, 0.001)
            feature_contributions.append({
                'feature':      fname,
                'value':        fval,
                'normalised':   round(normalised, 3),
                'importance':   importance,
                'contribution': round(normalised * importance, 6),
                'description':  _FEATURE_DESCRIPTIONS.get(fname, ''),
                'risk_level':   'high' if normalised > 0.7 else ('medium' if normalised > 0.4 else 'low'),
            })
        feature_contributions.sort(key=lambda x: x['contribution'], reverse=True)

        high_severity_rules: int = sum(
            1 for r in triggered_rules if r.get('severity') == 'high'
        )
        top_risk_features: list[str] = [
            f['feature'] for f in feature_contributions if f['normalised'] > 0.5
        ][:3]

        return {
            'why_summary': (
                f"Top indicators: {', '.join(f['feature'] for f in feature_contributions[:2])}"
                if feature_contributions
                else f"Heuristic-only mode — {len(triggered_rules)} rule(s) fired."
            ),
            'feature_contributions': feature_contributions,
            'ml_probability_pct':    round(ml_result.get('probability', 0.0) * 100, 1),
            'rule_count':            len(triggered_rules),
            'high_severity_rules':   high_severity_rules,
            'top_risk_features':     top_risk_features,
        }

    @staticmethod
    def _build_explanation(
        verdict: str, rule_score: int, ml_result: dict,
        homoglyph: dict, link_masking: dict,
        whitelist: dict, blocklist: dict,
    ) -> str:
        parts = [f"Hybrid scan complete. Verdict: {verdict.replace('_', ' ').title()}."]

        if blocklist.get('is_blocked'):
            parts.append(
                f"⛔ Confirmed threat via Google Safe Browsing "
                f"({blocklist.get('threat_type', 'unknown')})."
            )

        prob = ml_result.get('probability', 0.0)
        if prob > 0.0:
            parts.append(
                f"ML engine: {prob*100:.1f}% phishing probability. "
                f"Rule engine: {rule_score} points."
            )
        else:
            parts.append(f"Rule engine: {rule_score} points (ML running in heuristic-only mode).")

        if homoglyph.get('is_suspicious'):
            parts.append(f"⚠️ Homoglyph attack: impersonating '{homoglyph.get('matched_brand', '?')}'.")

        if link_masking.get('is_masked'):
            parts.append(f"⚠️ Link masking: displayed as '{link_masking.get('visible_domain', '?')}'.")

        if not whitelist.get('whitelisted'):
            parts.append("Domain is NOT in the global Tranco whitelist.")

        return ' '.join(parts)
