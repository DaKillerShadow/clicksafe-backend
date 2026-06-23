# =============================================================================
# app.py  —  IsThisSafe Enhanced Flask API
# =============================================================================
# ENDPOINTS:
#   GET  /health                → Liveness/readiness probe
#   POST /analyze               → Fast Path (static lexical + ML)
#   POST /deep-analyze          → Deep Path (Selenium + WHOIS + BiTB)
#   POST /intel-loop/ingest     → Ingest new phishing signatures
#   GET  /intel-loop/stats      → Signature database statistics
#   GET  /feature-importances   → XAI: Random Forest feature importance list
#
# SECURITY:
#   • INTEL_API_KEY compared with hmac.compare_digest() (constant-time).
#   • INTEL_API_KEY must be set via env var; startup raises if absent.
#   • Stdlib sliding-window rate limiter: 30 req/min on /analyze,
#     5 req/min on /deep-analyze, per client IP.
#   • MAX_CONTENT_LENGTH = 64 KB (prevents oversized request DoS).
#   • CORS origins restricted via ALLOWED_ORIGINS env var.
# =============================================================================

import hmac as _hmac
import os
import logging

from flask        import Flask, request, jsonify
from flask_cors   import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from modules.analyzer      import URLAnalyzer, LABEL_MAP
from modules.deep_analyzer import DeepAnalyzer
from modules.intel_loop    import IntelLoop

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
)
logger = logging.getLogger(__name__)

# ── App init ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024   # 64 KB — blocks oversized request bodies
CORS(app, resources={r'/*': {'origins': os.getenv('ALLOWED_ORIGINS', '*')}})

# ── Rate Limiting (Flask-Limiter) ─────────────────────────────────────────────
# storage_uri="memory://" is correct for a single-worker Gunicorn deployment.
# For multi-worker deployments switch to Redis: storage_uri="redis://localhost:6379"
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri='memory://',
    default_limits=[],      # no global default — set per-route below
)

# ── Singletons ────────────────────────────────────────────────────────────────
logger.info('Loading URLAnalyzer (ML model + Tranco list)...')
analyzer      = URLAnalyzer()
deep_analyzer = DeepAnalyzer()
intel_loop    = IntelLoop(ml_engine_ref=analyzer.ml_engine)
logger.info('All engines ready.')

# ── Intel API key — must be set; refuse to start with empty string ────────────
INTEL_API_KEY = os.getenv('INTEL_API_KEY', '').strip()
if not INTEL_API_KEY:
    raise RuntimeError(
        'INTEL_API_KEY environment variable is not set or empty. '
        'Generate a strong key with:\n'
        '  python -c "import secrets; print(secrets.token_hex(32))"\n'
        'Then add INTEL_API_KEY=<key> to your .env file.'
    )


# =============================================================================
# Helpers
# =============================================================================

def _require_intel_key() -> bool:
    """Constant-time comparison using hmac.compare_digest to prevent timing attacks."""
    provided = request.headers.get('X-Intel-Key', '')
    return _hmac.compare_digest(provided.encode(), INTEL_API_KEY.encode())

def _bad_request(msg: str):
    return jsonify({'success': False, 'error': msg}), 400

def _unauthorised():
    return jsonify({'success': False, 'error': 'Invalid or missing X-Intel-Key header.'}), 401

# Flask-Limiter returns 429 automatically; this handler customises the JSON body.
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'success': False, 'error': f'Rate limit exceeded: {e.description}'}), 429


# =============================================================================
# Routes
# =============================================================================

@app.route('/', methods=['GET'])
def root():
    """Root health ping — returns online status for uptime monitors."""
    return jsonify({'status': 'online'})


@app.route('/health', methods=['GET'])
def health():
    """Liveness probe — Flutter app polls this on startup."""
    return jsonify({
        'status':            'ok',
        'tranco_domains':    analyzer.tranco.size,
        'model_loaded':      analyzer.ml_engine is not None,
        'blocklist_enabled': analyzer.blocklist.enabled,
        'intel_sigs':        intel_loop.get_stats()['total_signatures'],
    })


@app.route('/analyze', methods=['POST'])
@limiter.limit('30 per minute')
def analyze():
    """
    Fast Path — static lexical + ML analysis.
    Body: { "url": "...", "visible_text": "..." (optional) }
    Rate-limited: 30 requests/minute per IP via Flask-Limiter.
    """
    data = request.get_json(silent=True)
    if not data or 'url' not in data:
        return _bad_request('Missing required field: url')
    raw_url      = data.get('url', '').strip()
    visible_text = data.get('visible_text', '')
    if not raw_url:
        return _bad_request('url field is empty')
    result = analyzer.analyze(raw_url, visible_text=visible_text)
    return jsonify(result)


@app.route('/deep-analyze', methods=['POST'])
@limiter.limit('5 per minute')
def deep_analyze():
    """
    Deep Path — redirect tracing, WHOIS, Selenium, BiTB, screenshot.
    Body: { "url": "...", "visible_text": "..." (optional) }
    Rate-limited: 5 requests/minute per IP via Flask-Limiter.
    """
    data = request.get_json(silent=True)
    if not data or 'url' not in data:
        return _bad_request('Missing required field: url')
    raw_url = data.get('url', '').strip()
    if not raw_url:
        return _bad_request('url field is empty')

    visible_text = data.get('visible_text', '')
    fast_result = analyzer.analyze(raw_url, visible_text=visible_text)
    if not fast_result.get('success'):
        return _bad_request(f"Invalid URL: {fast_result.get('error', 'unknown error')}")

    normalised_url = fast_result['url']
    deep_result    = deep_analyzer.analyze(normalised_url)

    # Escalate verdict if the deep path uncovers additional risk.
    verdict = fast_result.get('verdict', 'safe')
    if deep_result['bitb_detected'] or deep_result['newly_registered']:
        verdict = 'likely_phishing'
    elif deep_result['deep_risk_score'] >= 6 and verdict != 'likely_phishing':
        verdict = 'likely_phishing'
    elif deep_result['deep_risk_score'] >= 3 and verdict == 'safe':
        verdict = 'suspicious'

    return jsonify({
        'success':             True,
        'fast_path':           fast_result,
        'deep_path':           deep_result,
        'final_verdict':       verdict,
        'final_verdict_label': LABEL_MAP.get(verdict, verdict),
    })


@app.route('/intel-loop/ingest', methods=['POST'])
def intel_ingest():
    """
    Ingest new confirmed phishing URLs to update the Random Forest model.
    Requires X-Intel-Key header.
    Body: { "urls": [...], "label": 1, "source": "manual" }
    """
    if not _require_intel_key():
        return _unauthorised()
    data = request.get_json(silent=True)
    if not data or 'urls' not in data:
        return _bad_request('Missing required field: urls (list of URL strings)')
    urls   = data.get('urls', [])
    source = str(data.get('source', 'api'))
    if not isinstance(urls, list) or not urls:
        return _bad_request('urls must be a non-empty list of strings')
    try:
        label = int(data.get('label', 1))
    except (TypeError, ValueError):
        return _bad_request('label must be the integer 0 (safe) or 1 (phishing)')
    if label not in (0, 1):
        return _bad_request('label must be 0 (safe) or 1 (phishing)')
    result = intel_loop.ingest(urls=urls, label=label, source=source)
    return jsonify(result)


@app.route('/intel-loop/stats', methods=['GET'])
def intel_stats():
    """Return phishing signature database statistics."""
    if not _require_intel_key():
        return _unauthorised()
    return jsonify(intel_loop.get_stats())


@app.route('/feature-importances', methods=['GET'])
def feature_importances():
    """Return Random Forest feature importances for XAI visualisation."""
    importances = analyzer.get_feature_importances()
    return jsonify({'success': True, 'importances': importances})


# =============================================================================
# Error Handlers
# =============================================================================

@app.errorhandler(404)
def not_found(_):
    return jsonify({'success': False, 'error': 'Endpoint not found.'}), 404

@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({'success': False, 'error': 'Method not allowed.'}), 405

@app.errorhandler(413)
def request_entity_too_large(_):
    return jsonify({'success': False, 'error': 'Request body too large (max 64 KB).'}), 413

@app.errorhandler(500)
def internal_error(exc):
    logger.exception('Unhandled server error: %s', exc)
    return jsonify({'success': False, 'error': 'Internal server error.'}), 500


# =============================================================================
# Entry Point
# =============================================================================
if __name__ == '__main__':
    port  = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    logger.info('Starting IsThisSafe API on port %d (debug=%s)', port, debug)
    app.run(debug=debug, host='0.0.0.0', port=port)
