"""
load_phishtank.py — PhishTank data loader + optional auto-downloader.

Usage (one-time data setup):
    # 1. Download Tranco whitelist (writes data/tranco.csv):
    python setup_tranco.py

    # 2. Download PhishTank phishing URLs (writes data/verified_online.csv):
    python load_phishtank.py --download
    # With an API key (removes 5-min rate limit):
    python load_phishtank.py --download --api-key YOUR_PHISHTANK_API_KEY

    # 3. Build training_data.csv (reads both CSV files above):
    python load_phishtank.py --build

    # Steps 2+3 in one go:
    python load_phishtank.py --download --build

Get a free PhishTank API key at: https://www.phishtank.com/api_register.php
"""

from __future__ import annotations

import argparse
import io
import os
import sys
import urllib.request
import zipfile

import pandas as pd

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_DATA_DIR          = os.environ.get('DATA_DIR') or os.path.join(os.path.dirname(__file__), 'data')
_PHISHTANK_PATH    = os.path.join(_DATA_DIR, 'verified_online.csv')
_TRANCO_PATH       = os.path.join(_DATA_DIR, 'tranco.csv')
_TRAINING_PATH     = os.path.join(_DATA_DIR, 'training_data.csv')

# PhishTank data endpoint.
# Without a key the server enforces one download per 5 minutes per IP.
# With a key the limit is removed; register at phishtank.com/api_register.php
_PHISHTANK_PUBLIC_URL = 'https://data.phishtank.com/data/online-valid.csv'
_PHISHTANK_KEYED_URL  = 'https://data.phishtank.com/data/{api_key}/online-valid.csv'

# PhishTank also distributes a zipped version — used as fallback for speed.
_PHISHTANK_ZIP_URL    = 'https://data.phishtank.com/data/online-valid.csv.zip'


# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------

def download_phishtank(api_key: str = '', output_path: str = _PHISHTANK_PATH) -> None:
    """Download the PhishTank verified phishing URL database.

    Parameters
    ----------
    api_key:
        Optional PhishTank API key.  Without it, one download per 5 min per IP
        is allowed.  Register at https://www.phishtank.com/api_register.php
    output_path:
        Destination CSV path.  Defaults to data/verified_online.csv.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    if api_key:
        url = _PHISHTANK_KEYED_URL.format(api_key=api_key.strip())
        print(f'Downloading PhishTank data (authenticated) …')
    else:
        url = _PHISHTANK_PUBLIC_URL
        print('Downloading PhishTank data (public — max 1 request / 5 min) …')
        print('Tip: use --api-key to skip the rate limit.')

    headers = {
        'User-Agent': 'clicksafe-trainer/2.0 (https://github.com/clicksafe)'
    }
    req = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            sys.exit(
                'ERROR: PhishTank rate limit hit (HTTP 429). '
                'Wait 5 minutes or register for a free API key.'
            )
        sys.exit(f'ERROR: HTTP {exc.code} from PhishTank — {exc.reason}')
    except urllib.error.URLError as exc:
        sys.exit(f'ERROR: Network failure — {exc.reason}')

    # The endpoint may return a ZIP or plain CSV depending on the URL used.
    if raw[:2] == b'PK':
        print('Response is a ZIP archive — extracting …')
        zf   = zipfile.ZipFile(io.BytesIO(raw))
        name = zf.namelist()[0]
        raw  = zf.read(name)

    with open(output_path, 'wb') as fh:
        fh.write(raw)

    line_count = raw.count(b'\n')
    print(f'Saved {line_count:,} lines → {output_path}')


# ---------------------------------------------------------------------------
# Data-loading helpers (used by train_model.py and augment_training_data.py)
# ---------------------------------------------------------------------------

def load_phishtank(csv_path: str = _PHISHTANK_PATH) -> pd.DataFrame:
    """Load a PhishTank CSV and return a clean DataFrame with url + label columns.

    PhishTank's export has many columns; we only need 'url'.  All rows are
    labelled 1 (phishing) by definition.

    Parameters
    ----------
    csv_path:
        Path to verified_online.csv (downloaded by download_phishtank()).
    """
    try:
        df = pd.read_csv(csv_path, usecols=['url'], low_memory=False)
    except ValueError:
        # Some exports use 'phish_detail_url' or column ordering varies —
        # fall back to reading all columns and grabbing the first one named 'url'.
        df_full = pd.read_csv(csv_path, low_memory=False)
        url_cols = [c for c in df_full.columns if 'url' in c.lower() and 'detail' not in c.lower()]
        if not url_cols:
            raise ValueError(
                f"Could not find a 'url' column in {csv_path}. "
                f"Columns present: {list(df_full.columns)}"
            )
        df = df_full[[url_cols[0]]].rename(columns={url_cols[0]: 'url'})

    df = df.dropna(subset=['url'])
    df = df[df['url'].str.startswith(('http://', 'https://'), na=False)]
    df['label'] = 1  # all PhishTank entries are phishing
    df = df.reset_index(drop=True)
    return df[['url', 'label']]


def load_tranco(tranco_path: str = _TRANCO_PATH, limit: int = 50_000) -> pd.DataFrame:
    """Load Tranco top domains as legitimate URLs.

    Expected format: rank,domain  (CSV, no header — as written by setup_tranco.py).

    Parameters
    ----------
    tranco_path:
        Path to tranco.csv downloaded by setup_tranco.py.
    limit:
        Maximum number of rows to load (class balancing).
    """
    df = pd.read_csv(tranco_path, header=None, names=['rank', 'domain'])
    df = df.head(limit)
    df['url']   = 'https://' + df['domain'].str.strip()
    df['label'] = 0  # legitimate
    return df[['url', 'label']].reset_index(drop=True)


def build_dataset(
    phishtank_csv: str = _PHISHTANK_PATH,
    tranco_csv:    str = _TRANCO_PATH,
    output_path:   str = _TRAINING_PATH,
    random_state:  int = 42,
) -> pd.DataFrame:
    """Build a balanced, shuffled training dataset and save it to CSV.

    Loads PhishTank phishing URLs and an equal number of Tranco legitimate
    URLs, shuffles them, and writes the result to *output_path*.

    Returns the combined DataFrame.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    print('[1/3] Loading PhishTank phishing URLs …')
    phish = load_phishtank(phishtank_csv)
    print(f'      → {len(phish):,} phishing URLs loaded.')

    print('[2/3] Loading Tranco legitimate URLs …')
    legit = load_tranco(tranco_csv, limit=len(phish))
    print(f'      → {len(legit):,} legitimate URLs loaded.')

    print('[3/3] Shuffling and saving training_data.csv …')
    combined = (
        pd.concat([phish, legit], ignore_index=True)
        .sample(frac=1, random_state=random_state)
        .reset_index(drop=True)
    )
    combined.to_csv(output_path, index=False)

    phishing_n = int(combined['label'].sum())
    legit_n    = len(combined) - phishing_n
    print(
        f'      → {len(combined):,} rows written to {output_path} '
        f'({phishing_n:,} phishing, {legit_n:,} legitimate).'
    )
    return combined


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description='ClickSafe data pipeline — download PhishTank data and build training_data.csv.',
    )
    p.add_argument(
        '--download',
        action='store_true',
        help='Download PhishTank verified phishing URLs to data/verified_online.csv.',
    )
    p.add_argument(
        '--api-key',
        default=os.getenv('PHISHTANK_API_KEY', ''),
        metavar='KEY',
        help='PhishTank API key (also reads PHISHTANK_API_KEY env var). '
             'Register free at https://www.phishtank.com/api_register.php',
    )
    p.add_argument(
        '--build',
        action='store_true',
        help='Build data/training_data.csv from verified_online.csv + tranco.csv.',
    )
    p.add_argument(
        '--phishtank-path',
        default=_PHISHTANK_PATH,
        metavar='PATH',
        help=f'Path to PhishTank CSV. Default: {_PHISHTANK_PATH}',
    )
    p.add_argument(
        '--tranco-path',
        default=_TRANCO_PATH,
        metavar='PATH',
        help=f'Path to Tranco CSV. Default: {_TRANCO_PATH}',
    )
    p.add_argument(
        '--output-path',
        default=_TRAINING_PATH,
        metavar='PATH',
        help=f'Destination training CSV. Default: {_TRAINING_PATH}',
    )
    return p.parse_args()


if __name__ == '__main__':
    args = _parse_args()

    if not args.download and not args.build:
        print(
            'No action specified.  Use --download, --build, or both.\n'
            'Run with --help for usage details.'
        )
        sys.exit(0)

    if args.download:
        download_phishtank(api_key=args.api_key, output_path=args.phishtank_path)

    if args.build:
        if not os.path.exists(args.phishtank_path):
            sys.exit(
                f'ERROR: PhishTank data not found at {args.phishtank_path}.\n'
                'Run with --download first, or manually place verified_online.csv there.'
            )
        if not os.path.exists(args.tranco_path):
            sys.exit(
                f'ERROR: Tranco whitelist not found at {args.tranco_path}.\n'
                'Run: python setup_tranco.py'
            )
        build_dataset(
            phishtank_csv=args.phishtank_path,
            tranco_csv=args.tranco_path,
            output_path=args.output_path,
        )

    print('\nDone.')
