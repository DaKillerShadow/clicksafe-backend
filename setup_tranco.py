#!/usr/bin/env python3
"""
setup_tranco.py — Download the Tranco Top-100k domain list.

Run once before starting the Flask backend:
    python setup_tranco.py

The list is saved to data/tranco_top100k.txt (one domain per line).
If the download fails, TrancoChecker will fall back to its embedded
hardcoded whitelist of ~40 universally known safe domains.

Reference: https://tranco-list.eu/
"""

import os
import sys
import urllib.request
import zipfile
import io

DATA_DIR   = os.environ.get('DATA_DIR') or os.path.join(os.path.dirname(__file__), 'data')
OUT_PATH   = os.path.join(DATA_DIR, 'tranco.csv')   # matches tranco_checker._LIST_PATH and load_phishtank
# Latest aggregated Tranco list (changes weekly; use the stable URL)
TRANCO_URL = 'https://tranco-list.eu/top-1m.csv.zip'
TOP_N      = 100_000


def download():
    os.makedirs(DATA_DIR, exist_ok=True)

    print(f'Downloading Tranco list from {TRANCO_URL}...')
    try:
        with urllib.request.urlopen(TRANCO_URL, timeout=60) as resp:
            raw = resp.read()
    except Exception as exc:
        print(f'ERROR: Download failed — {exc}')
        print('The app will use its fallback whitelist instead.')
        sys.exit(1)

    print(f'Downloaded {len(raw):,} bytes. Extracting top {TOP_N:,} domains...')
    zf   = zipfile.ZipFile(io.BytesIO(raw))
    name = zf.namelist()[0]          # usually 'top-1m.csv'

    written = 0
    with zf.open(name) as csv_fh, open(OUT_PATH, 'w', encoding='utf-8') as out_fh:
        # Write raw rank,domain lines — no comment header so pandas can read without extra kwargs.
        # Source file is already "rank,domain" CSV; write it directly up to TOP_N rows.
        for line in csv_fh:
            if written >= TOP_N:
                break
            decoded = line.decode('utf-8').rstrip('\n\r')
            if decoded and ',' in decoded:
                out_fh.write(decoded + '\n')
                written += 1

    print(f'Saved {written:,} domains to {OUT_PATH}')
    print('TrancoChecker will use this file automatically on next server start.')


if __name__ == '__main__':
    download()
