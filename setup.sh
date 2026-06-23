#!/usr/bin/env bash
# =============================================================================
# backend/setup.sh — ClickSafe Backend Environment Setup
# =============================================================================
# Installs all system-level dependencies required to run the ClickSafe backend,
# including Google Chrome Stable (required by the Selenium deep-path analyzer).
#
# Tested on: Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, Debian 12
# Run as:    bash setup.sh
#            (no sudo needed if already root inside a container;
#             otherwise prefix individual apt-get commands with sudo)
#
# After this script:
#   1. Copy .env.example → .env and fill in your API keys.
#   2. Run: python setup_tranco.py          (download Tranco whitelist)
#   3. Run: python load_phishtank.py --download --build  (build training data)
#   4. Run: python train_model.py           (train the Random Forest model)
#   5. Run: gunicorn -w 1 -b 0.0.0.0:5000 app:app
#
# CHROME SANDBOX NOTE
# ───────────────────
# This script installs Chrome for use WITHOUT --no-sandbox (the flag has been
# removed from deep_analyzer.py for security).  To run without root privileges
# inside a container, configure a user-namespace sandbox:
#
#   # Allow unprivileged user namespaces (required for Chrome sandbox):
#   echo 'kernel.unprivileged_userns_clone=1' | sudo tee -a /etc/sysctl.conf
#   sudo sysctl -p
#
# If you are in a restricted environment where user namespaces cannot be
# enabled (e.g. some CI systems), set CHROME_NO_SANDBOX=1 in your .env and
# the application will detect it and add --no-sandbox only then.
# =============================================================================

set -euo pipefail

BOLD='\033[1m'; RESET='\033[0m'; GREEN='\033[32m'; RED='\033[31m'
step() { echo -e "\n${BOLD}[$(date +%H:%M:%S)] $*${RESET}"; }
ok()   { echo -e "  ${GREEN}✔${RESET}  $*"; }
fail() { echo -e "  ${RED}✘${RESET}  $*" >&2; exit 1; }

# ── 0. Preflight ──────────────────────────────────────────────────────────────
step "Preflight checks"
[[ "$(uname -s)" == "Linux" ]] || fail "This script is for Linux only."
command -v python3 >/dev/null  || fail "python3 not found. Install it first."
command -v pip3    >/dev/null  || apt-get install -y python3-pip
ok "python3 $(python3 --version)"

# ── 1. System packages ────────────────────────────────────────────────────────
step "Installing system packages"
apt-get update -qq
apt-get install -y --no-install-recommends \
    wget curl ca-certificates gnupg \
    fonts-liberation libappindicator3-1 libasound2 libatk-bridge2.0-0 \
    libatk1.0-0 libcups2 libdbus-1-3 libgbm1 libgtk-3-0 \
    libnspr4 libnss3 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libxss1 libxtst6 lsb-release xdg-utils
ok "System packages installed."

# ── 2. Google Chrome Stable ───────────────────────────────────────────────────
step "Installing Google Chrome Stable"

if command -v google-chrome >/dev/null 2>&1; then
    ok "Chrome already present: $(google-chrome --version)"
else
    ARCH=$(dpkg --print-architecture)
    if [[ "$ARCH" != "amd64" ]]; then
        fail "Chrome is only available for amd64. Current arch: $ARCH"
    fi

    CHROME_DEB=$(mktemp --suffix=.deb)
    CHROME_URL="https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"

    echo "  Downloading from $CHROME_URL …"
    wget -q --show-progress -O "$CHROME_DEB" "$CHROME_URL"

    apt-get install -y "$CHROME_DEB"
    rm -f "$CHROME_DEB"

    CHROME_VER=$(google-chrome --version)
    ok "Chrome installed: $CHROME_VER"
fi

# ChromeDriver is NOT installed here — selenium's webdriver-manager downloads
# the correct ChromeDriver version at runtime automatically.

# ── 3. Python dependencies ────────────────────────────────────────────────────
step "Installing Python dependencies (requirements.txt)"

cd "$(dirname "$0")"   # ensure we're in the backend directory

if [[ ! -f requirements.txt ]]; then
    fail "requirements.txt not found. Run this script from the backend/ directory."
fi

pip3 install --upgrade pip --quiet
pip3 install -r requirements.txt
ok "Python packages installed."

# ── 4. Environment configuration ─────────────────────────────────────────────
step "Environment configuration"

if [[ -f .env ]]; then
    ok ".env already exists — skipping copy."
else
    if [[ -f .env.example ]]; then
        cp .env.example .env
        echo "  .env created from .env.example."
        echo "  ⚠️  Edit .env now and set INTEL_API_KEY and GOOGLE_SAFE_BROWSING_KEY."
    else
        fail ".env.example not found. Cannot create .env."
    fi
fi

# ── 5. Data directory ─────────────────────────────────────────────────────────
step "Preparing data directory"
mkdir -p data models
ok "data/ and models/ directories ready."

# ── 6. User-namespace sandbox check ──────────────────────────────────────────
step "Checking Chrome sandbox configuration"

USERNS=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo "unknown")
if [[ "$USERNS" == "1" ]]; then
    ok "Unprivileged user namespaces enabled — Chrome sandbox will work."
elif [[ "$USERNS" == "0" ]]; then
    echo "  ⚠️  Unprivileged user namespaces are DISABLED."
    echo "     Chrome will fail without --no-sandbox.  To fix:"
    echo "       echo 'kernel.unprivileged_userns_clone=1' | sudo tee -a /etc/sysctl.conf"
    echo "       sudo sysctl -p"
    echo "     Or, set CHROME_NO_SANDBOX=1 in your .env as a fallback."
else
    ok "User namespace check skipped (non-standard kernel — check manually)."
fi

# ── 7. Next steps ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Setup complete. Next steps:${RESET}"
echo "  1. Edit backend/.env  →  set INTEL_API_KEY and GOOGLE_SAFE_BROWSING_KEY"
echo "  2. python setup_tranco.py"
echo "  3. python load_phishtank.py --download --build"
echo "  4. python train_model.py"
echo "  5. gunicorn -w 1 -b 0.0.0.0:5000 app:app"
