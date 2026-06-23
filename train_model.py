# =============================================================================
# train_model.py  —  ML Model Training Script (v2 — 19 features)
# =============================================================================
# CHANGES VS v1 (14 features):
#   Five new features appended at the end of the feature vector so that
#   existing feature indices [0-13] are unchanged and the expansion is additive:
#
#   [14] has_suspicious_tld    — TLD in a known-abused registry (.tk, .xyz…)
#   [15] hostname_digit_ratio  — fraction of digits in the hostname; machine-
#                                generated domains have abnormally high ratios
#   [16] vowel_ratio           — fraction of vowels in hostname; gibberish
#                                domains deviate from natural language patterns
#   [17] has_non_standard_port — non-standard port (not 80, 443, 8080, 8443)
#   [18] http_count_in_url     — number of embedded 'http' occurrences beyond
#                                the scheme itself; proxy for redirect-chain URLs
# =============================================================================

import os
import re
import math
import urllib.parse
import numpy as np
import pandas as pd
from sklearn.ensemble        import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics         import classification_report, accuracy_score
import joblib

# ── Reproducibility ───────────────────────────────────────────────────────────
RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)

# ── Output path ───────────────────────────────────────────────────────────────
MODEL_DIR  = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "model.pkl")
os.makedirs(MODEL_DIR, exist_ok=True)

# ── Shared constants (must stay in sync with ml_engine.py) ───────────────────
_SPECIAL_CHARS   = set("!@#$%^&*()_+-=[]{};':\"|,.<>/?")
_SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click',
    'link', 'win', 'download', 'ru', 'cn', 'pw', 'cc', 'biz',
}
_VOWELS          = set('aeiou')
_STANDARD_PORTS  = {80, 443, 8080, 8443}

# =============================================================================
# 1. FEATURE EXTRACTION  (19 features — must match ml_engine.extract_features)
# =============================================================================

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0.0
    for ch in set(text):
        p = text.count(ch) / len(text)
        entropy -= p * math.log2(p)
    return entropy


def extract_features(url: str) -> list:
    """
    Returns a list of 19 numerical features for *url*.
    Feature order MUST stay in sync with ml_engine.py's feature_order list.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed   = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        path     = parsed.path or ""
        query    = parsed.query or ""

        # ── Features [0-13]: unchanged from v1 ───────────────────────────────
        url_length        = len(url)
        hostname_length   = len(hostname)
        path_length       = len(path)
        num_dots          = url.count('.')
        num_hyphens       = url.count('-')
        num_underscores   = url.count('_')
        num_slashes       = url.count('/')
        num_query_params  = len(urllib.parse.parse_qs(query)) if query else 0
        num_special_chars = sum(1 for c in url if c in _SPECIAL_CHARS)
        has_ip_host       = 1 if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", hostname) else 0
        has_https         = 1 if parsed.scheme == "https" else 0
        has_at_sign       = 1 if "@" in url else 0
        subdomain_count   = max(0, len(hostname.split('.')) - 2) if hostname else 0
        url_entropy       = calculate_entropy(url)

        # ── Feature [14]: has_suspicious_tld ─────────────────────────────────
        tld               = hostname.split('.')[-1].lower() if '.' in hostname else ''
        has_suspicious_tld = int(tld in _SUSPICIOUS_TLDS)

        # ── Feature [15]: hostname_digit_ratio ────────────────────────────────
        hostname_digit_ratio = round(
            sum(c.isdigit() for c in hostname) / max(len(hostname), 1), 6
        )

        # ── Feature [16]: vowel_ratio (of hostname) ───────────────────────────
        vowel_ratio = round(
            sum(c in _VOWELS for c in hostname.lower()) / max(len(hostname), 1), 6
        )

        # ── Feature [17]: has_non_standard_port ───────────────────────────────
        port = parsed.port
        has_non_standard_port = int(bool(port) and port not in _STANDARD_PORTS)

        # ── Feature [18]: http_count_in_url ───────────────────────────────────
        # Subtract 1 for the scheme itself; remaining hits = embedded redirects
        http_count_in_url = max(0, url.lower().count('http') - 1)

        return [
            url_length, hostname_length, path_length, num_dots, num_hyphens,
            num_underscores, num_slashes, num_query_params, num_special_chars,
            has_ip_host, has_https, has_at_sign, subdomain_count, url_entropy,
            has_suspicious_tld, hostname_digit_ratio, vowel_ratio,
            has_non_standard_port, http_count_in_url,
        ]

    except Exception:
        return [0] * 19


# Named list — used for the feature importance report only.
FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length",
    "num_dots", "num_hyphens", "num_underscores",
    "num_slashes", "num_query_params", "num_special_chars",
    "has_ip_host", "has_https", "has_at_sign",
    "subdomain_count", "url_entropy",
    "has_suspicious_tld", "hostname_digit_ratio", "vowel_ratio",
    "has_non_standard_port", "http_count_in_url",
]


print("─" * 60)
print("  Phishing URL Detector — Model Training (v2, 19 features)")
print("─" * 60)

# =============================================================================
# 2. LOAD DATA & EXTRACT FEATURES
# =============================================================================
print("\n[1/5] Loading dataset and extracting features …")
DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "training_data.csv")

if not os.path.exists(DATA_PATH):
    raise FileNotFoundError(
        f"Dataset not found at {DATA_PATH}. "
        "Add training_data.csv or run load_phishtank.py first."
    )

df   = pd.read_csv(DATA_PATH)
urls = df["url"].tolist()
y    = df["label"].values

X_list = [extract_features(u) for u in urls]
X      = np.array(X_list)

print(
    f"    Samples: {len(y):,}  |  "
    f"Legitimate: {(y==0).sum():,}  |  "
    f"Phishing: {(y==1).sum():,}  |  "
    f"Features: {X.shape[1]}"
)

# =============================================================================
# 3. TRAIN / TEST SPLIT
# =============================================================================
print("\n[2/5] Splitting 80% train / 20% test …")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y,
)
print(f"    Train: {len(X_train):,}   Test: {len(X_test):,}")

# =============================================================================
# 4. MODEL TRAINING
# =============================================================================
print("\n[3/5] Training Random Forest …")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    min_samples_leaf=5,
    random_state=RANDOM_SEED,
    n_jobs=-1,
)
model.fit(X_train, y_train)
print("    Training complete.")

# =============================================================================
# 5. EVALUATION
# =============================================================================
print("\n[4/5] Evaluating on held-out test set …")
y_pred = model.predict(X_test)
acc    = accuracy_score(y_test, y_pred)
print(f"\n    Accuracy: {acc*100:.2f}%\n")
print("    Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

importances = sorted(
    zip(FEATURE_NAMES, model.feature_importances_),
    key=lambda x: x[1], reverse=True,
)
print("    Top 5 most important features:")
for name, imp in importances[:5]:
    bar = "█" * int(imp * 100)
    print(f"      {name:<26} {imp:.4f}  {bar}")

# =============================================================================
# 6. SAVE MODEL
# =============================================================================
print(f"\n[5/5] Saving model to {MODEL_PATH} …")
joblib.dump(model, MODEL_PATH)
print(f"    ✔  model.pkl saved  ({model.n_features_in_} features)\n")
print("─" * 60)
print("  Start the Flask server:  python app.py")
print("─" * 60)
