#!/usr/bin/env bash
# =============================================================================
# build.sh — ClickSafe Backend Build Script (Render)
# =============================================================================
# Runs during every Render deploy (web service + cron jobs).
# Order matters:
#   1. Install Python deps
#   2. Install Chrome (required by deep_analyzer.py / Selenium)
#   3. Link persistent-disk dirs into the expected src paths
#   4. Download Tranco list (if not already cached on disk)
#   5. Download PhishTank data (if not already cached on disk)
#   6. Train model (if model.pkl is missing from disk)
# =============================================================================
set -euo pipefail

SRC="/opt/render/project/src"
DISK="${SRC}/data-persist"         # persistent disk mount path (render.yaml)
MODEL_DIR="${DISK}/models"
DATA_DIR="${DISK}/data"

# ── 1. Python dependencies ────────────────────────────────────────────────────
echo "[1/6] Installing Python dependencies..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo "      Done."

# ── 2. Google Chrome (required for Selenium deep analysis) ───────────────────
echo "[2/6] Checking Google Chrome..."
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

# ── 3. Link persistent disk dirs ─────────────────────────────────────────────
# The persistent disk survives deploys; the src/ tree does not.
# We create symlinks so all existing code that references models/ and data/
# transparently reads/writes to the persistent disk without any code changes.
echo "[3/6] Linking persistent disk directories..."
mkdir -p "${MODEL_DIR}" "${DATA_DIR}"

# Remove the ephemeral src dirs and replace with symlinks to the disk.
rm -rf "${SRC}/models" && ln -sfn "${MODEL_DIR}" "${SRC}/models"
rm -rf "${SRC}/data"   && ln -sfn "${DATA_DIR}"  "${SRC}/data"
echo "      models/ → ${MODEL_DIR}"
echo "      data/   → ${DATA_DIR}"

# ── 4. Tranco whitelist ───────────────────────────────────────────────────────
TRANCO_CSV="${DATA_DIR}/tranco.csv"
if [[ -f "${TRANCO_CSV}" ]]; then
    AGE_DAYS=$(( ( $(date +%s) - $(stat -c %Y "${TRANCO_CSV}") ) / 86400 ))
    echo "[4/6] Tranco list exists (${AGE_DAYS} days old) — skipping download."
else
    echo "[4/6] Downloading Tranco top-100k whitelist..."
    python setup_tranco.py
    echo "      Done."
fi

# ── 5. PhishTank training data ────────────────────────────────────────────────
TRAINING_CSV="${DATA_DIR}/training_data.csv"
if [[ -f "${TRAINING_CSV}" ]]; then
    ROWS=$(wc -l < "${TRAINING_CSV}")
    echo "[5/6] Training data exists (${ROWS} rows) — skipping PhishTank download."
else
    echo "[5/6] Downloading PhishTank data and building training_data.csv..."
    if [[ -n "${PHISHTANK_API_KEY:-}" ]]; then
        python load_phishtank.py --download --build --api-key "${PHISHTANK_API_KEY}"
    else
        python load_phishtank.py --download --build
    fi
    echo "      Done."
fi

# ── 6. Train model ────────────────────────────────────────────────────────────
MODEL_PKL="${MODEL_DIR}/model.pkl"
if [[ -f "${MODEL_PKL}" ]]; then
    echo "[6/6] model.pkl exists on persistent disk — skipping training."
    echo "      (Delete it from the disk to force a retrain on next deploy.)"
else
    echo "[6/6] model.pkl not found — training now (this takes ~1-2 minutes)..."
    python train_model.py
    echo "      Done. model.pkl saved to persistent disk."
fi

echo ""
echo "Build complete. Starting Gunicorn..."
