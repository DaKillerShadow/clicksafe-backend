# =============================================================================
# modules/__init__.py  —  Public API of the ClickSafe modules package
# =============================================================================
# Three classes are the public entry points consumed by app.py:
#
#   URLAnalyzer   — main hybrid pipeline (validate → whitelist → blocklist
#                   → homoglyph → rules → ML → verdict).  Instantiate once
#                   at startup; it owns all sub-components internally.
#
#   DeepAnalyzer  — slow-path dynamic analysis (redirect tracing, WHOIS
#                   domain-age check, headless browser, BiTB detection).
#                   Called only from the /deep-analyze endpoint.
#
#   IntelLoop     — signature ingestion and incremental model retraining.
#                   Called from /intel-loop/ingest and /intel-loop/stats.
#
# The remaining classes (RuleEngine, MLEngine, TrancoChecker, etc.) are
# internal to URLAnalyzer and are not imported here to keep the public
# surface minimal and avoid circular-import risk.
# =============================================================================

from .analyzer      import URLAnalyzer
from .deep_analyzer import DeepAnalyzer
from .intel_loop    import IntelLoop

__all__ = [
    'URLAnalyzer',
    'DeepAnalyzer',
    'IntelLoop',
]
