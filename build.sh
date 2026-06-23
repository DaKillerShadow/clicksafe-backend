#!/usr/bin/env bash
# =============================================================================
# build.sh — ClickSafe Backend Build Script (Render Free Tier)
# =============================================================================
# Runs during every Render deploy.
#
# Free web services have no persistent disk, so anything written here is
# wiped before the next build — there's no point in the old "skip if
# already on disk" caching logic, since there's no disk to check.
#
# Order:
#   1. Install Python deps
#   2. Install Chrome (required by deep_analyzer.py / Selenium)
#   3. Download a fresh Tranco whitelist (small + fast — fine to redo
#      on every deploy; TrancoChecker falls back to a built-in list if
#      this fails, so it won't break the build either way)
#   4. Use the model.pkl committed in the repo (models/model.pkl) as-is.
#      No training happens by default. Set FORCE_RETRAIN=1 in your Render
#      env vars if you want this build to download fresh PhishTank data
#      and retrain instead (slower, and depends on PhishTank's API being
#      reachable at build time).
#
# To ship a new model: train it locally with train_model.py, then commit
# the updated models/model.pkl. That's the source of truth now — not a
# build-time retrain.
# =============================================================================
set -euo pipefail

# ── 1. Python dependencies ────────────────────────────────────────────────────
echo "[1/4] Installing Python dependencies..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo "      Done."

# ── 2. Google Chrome (required for Selenium deep analysis) ───────────────────
echo "[2/4] Checking Google Chrome..."
if command -v google-chrome &>/dev/null; then
    echo "      Already installed: $(google-chrome --version)"
else
    echo "      Installing Chrome Stable..."
    wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - 2>/dev/null
    echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" \
        > /etc/apt/sources.list.d/google-chrome.list
    apt-get update -qq
    apt-get install -y google-chrome-stable -qq
    echo "      Installed: $(google-chrome --version)"
fi

# ── 3. Tranco whitelist ───────────────────────────────────────────────────────
# No disk to cache this on — download it fresh every deploy. A failure here
# is non-fatal: TrancoChecker falls back to its built-in whitelist.
echo "[3/4] Downloading Tranco top-100k whitelist..."
python setup_tranco.py || echo "      Tranco download failed — app will use its built-in fallback list."

# ── 4. Model ───────────────────────────────────────────────────────────────────
if [[ "${FORCE_RETRAIN:-0}" == "1" ]]; then
    echo "[4/4] FORCE_RETRAIN=1 — downloading PhishTank data and retraining..."
    if [[ -n "${PHISHTANK_API_KEY:-}" ]]; then
        python load_phishtank.py --download --build --api-key "${PHISHTANK_API_KEY}"
    else
        python load_phishtank.py --download --build
    fi
    python augment_training_data.py
    python train_model.py
    echo "      Done. model.pkl retrained for this build."
elif [[ -f models/model.pkl ]]; then
    echo "[4/4] Using bundled models/model.pkl from the repo — skipping training."
else
    echo "[4/4] models/model.pkl not found in the repo — training now (~1-2 minutes)..."
    if [[ -n "${PHISHTANK_API_KEY:-}" ]]; then
        python load_phishtank.py --download --build --api-key "${PHISHTANK_API_KEY}"
    else
        python load_phishtank.py --download --build
    fi
    python augment_training_data.py
    python train_model.py
    echo "      Done."
fi

echo ""
echo "Build complete. Starting Gunicorn..."
