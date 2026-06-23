# =============================================================================
# modules/intel_loop.py  —  IntelLoop (Continuous Model Update)
# =============================================================================
# BUG FIX:
#   ingest() accepted an `api_key` parameter that was never used inside the
#   method (authentication is correctly handled in app.py via _require_intel_key).
#   The dead parameter has been removed to avoid confusion about where auth
#   is enforced.
# =============================================================================

import os
import json
import logging
import time
import threading
from datetime import datetime, timezone
from typing import Optional

import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier

logger = logging.getLogger(__name__)

_BASE_DIR    = os.path.dirname(os.path.dirname(__file__))
_MODEL_PATH  = os.path.join(_BASE_DIR, 'models', 'model.pkl')
_SIGS_PATH   = os.path.join(_BASE_DIR, 'data', 'phishing_signatures.json')
_MIN_SAMPLES = 50   # raised from 10 — prevents retraining on statistically insignificant batches

# Module-level lock: prevents concurrent _retrain() calls from racing on model.pkl.
_retrain_lock = threading.Lock()

_FEATURE_ORDER = [
    # ── Features [0-13]: original 14-feature set ────────────────────────────
    'url_length', 'hostname_length', 'path_length',
    'num_dots', 'num_hyphens', 'num_underscores',
    'num_slashes', 'num_query_params', 'num_special_chars',
    'has_ip_host', 'has_https', 'has_at_sign',
    'subdomain_count', 'url_entropy',
    # ── Features [14-18]: v2 additions — MUST match ml_engine._FEATURE_ORDER ─
    # BUG FIX: this list was frozen at 14 entries from before v2.  The retrained
    # model.pkl now expects 19 features; _retrain() was raising ValueError on
    # every call because X_new had shape (n, 14) while the model expected (n, 19).
    'has_suspicious_tld', 'hostname_digit_ratio', 'vowel_ratio',
    'has_non_standard_port', 'http_count_in_url',
]


class IntelLoop:
    """
    Manages ingestion of new phishing signatures and incremental model updates.
    """

    def __init__(self, ml_engine_ref=None):
        self._ml_engine  = ml_engine_ref
        self._signatures: list[dict] = []
        os.makedirs(os.path.join(_BASE_DIR, 'data'), exist_ok=True)
        self._load_signatures()

    # ── Public API ─────────────────────────────────────────────────────────────

    def ingest(self, urls: list[str], label: int = 1, source: str = 'manual') -> dict:
        """
        Ingest a batch of URLs as new labelled training samples.

        Parameters
        ----------
        urls   : list[str]  New phishing (label=1) or safe (label=0) URLs.
        label  : int        Ground truth: 1 = phishing, 0 = safe.
        source : str        Where did this intel come from? (audit trail)

        BUG FIX: removed the unused `api_key` parameter — authentication is
        enforced in app.py before this method is ever called.

        Returns
        -------
        dict — ingestion report including whether retraining was triggered.
        """
        if not urls:
            return {'success': False, 'error': 'No URLs provided.', 'retrained': False}

        from .ml_engine import MLEngine
        engine = self._ml_engine or MLEngine()

        ingested = 0
        skipped  = 0
        for url in urls:
            try:
                features = engine.extract_features(url)
                sig = {
                    'url':       url,
                    'label':     label,
                    'features':  features,
                    'source':    source,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                }
                self._signatures.append(sig)
                ingested += 1
            except Exception as exc:
                logger.warning('Failed to extract features for %s: %s', url, exc)
                skipped += 1

        self._save_signatures()
        logger.info('IntelLoop: ingested %d new signatures (label=%d)', ingested, label)

        retrained      = False
        retrain_detail = ''
        new_sigs_count = len(self._signatures)

        if new_sigs_count >= _MIN_SAMPLES:
            try:
                retrain_result = self._retrain()
                retrained      = True
                retrain_detail = retrain_result['detail']
            except Exception as exc:
                logger.error('Retraining failed: %s', exc)
                retrain_detail = f'Retraining failed: {exc}'

        return {
            'success':          True,
            'ingested':         ingested,
            'skipped':          skipped,
            'total_signatures': new_sigs_count,
            'retrained':        retrained,
            'retrain_detail':   retrain_detail,
            'min_for_retrain':  _MIN_SAMPLES,
        }

    def get_stats(self) -> dict:
        """Return statistics about the current signature database."""
        label_counts: dict[int, int] = {0: 0, 1: 0}
        sources: dict[str, int] = {}
        for sig in self._signatures:
            label_key = sig.get('label', 1)
            if label_key in label_counts:
                label_counts[label_key] += 1
            src = sig.get('source', 'unknown')
            sources[src] = sources.get(src, 0) + 1

        return {
            'total_signatures': len(self._signatures),
            'phishing_count':   label_counts[1],
            'safe_count':       label_counts[0],
            'sources':          sources,
            'model_path':       _MODEL_PATH,
            'model_exists':     os.path.exists(_MODEL_PATH),
        }

    # ── Private helpers ────────────────────────────────────────────────────────

    def _retrain(self) -> dict:
        # ── Guard 1: require both classes ─────────────────────────────────────
        labels = [s.get('label') for s in self._signatures]
        if len(set(labels)) < 2:
            raise ValueError(
                f'Retraining requires samples from both classes (0=safe and 1=phishing). '
                f'Current labels: {dict((l, labels.count(l)) for l in set(labels))}. '
                'Ingest URLs from the missing class before retraining.'
            )

        with _retrain_lock:
            t0 = time.time()

            X_new = np.array([
                [sig['features'][k] for k in _FEATURE_ORDER]
                for sig in self._signatures
            ])
            y_new = np.array([sig['label'] for sig in self._signatures])

            if not os.path.exists(_MODEL_PATH):
                raise FileNotFoundError(
                    f'Base model not found at {_MODEL_PATH}. '
                    'Run train_model.py first.'
                )

            model: RandomForestClassifier = joblib.load(_MODEL_PATH)

            old_n = model.n_estimators
            new_n = old_n + max(10, len(self._signatures) // 5)
            model.set_params(warm_start=True, n_estimators=new_n)
            model.fit(X_new, y_new)
            model.set_params(warm_start=False)

            # ── Atomic write: write to .tmp then os.replace ────────────────────
            # os.replace is atomic on POSIX — readers never see a partial file.
            tmp_path = _MODEL_PATH + '.tmp'
            try:
                joblib.dump(model, tmp_path)
                os.replace(tmp_path, _MODEL_PATH)
            except Exception:
                # Clean up temp file if rename fails.
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                raise

            # ── Update the in-memory model reference ───────────────────────────
            # Done inside the lock so concurrent predict() calls see consistent state.
            if self._ml_engine is not None:
                self._ml_engine.model = model

            elapsed = time.time() - t0
            detail  = (
                f'Model retrained in {elapsed:.2f}s. '
                f'Trees: {old_n} → {new_n}. '
                f'New samples: {len(self._signatures)} '
                f'(phishing={sum(s["label"]==1 for s in self._signatures)}, '
                f'safe={sum(s["label"]==0 for s in self._signatures)}).'
            )
            logger.info('IntelLoop: %s', detail)
            return {'detail': detail}

    def _load_signatures(self):
        if os.path.exists(_SIGS_PATH):
            try:
                with open(_SIGS_PATH, 'r', encoding='utf-8') as fh:
                    self._signatures = json.load(fh)
                logger.info('IntelLoop: loaded %d existing signatures',
                            len(self._signatures))
            except Exception as exc:
                logger.warning('IntelLoop: could not load signatures: %s', exc)
                self._signatures = []
        else:
            self._signatures = []

    def _save_signatures(self):
        try:
            with open(_SIGS_PATH, 'w', encoding='utf-8') as fh:
                json.dump(self._signatures, fh, indent=2)
        except Exception as exc:
            logger.error('IntelLoop: failed to save signatures: %s', exc)
