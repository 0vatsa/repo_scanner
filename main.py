#!/usr/bin/env python3
# main.py  —  convenience shim at the repo root
# Usage: python main.py /path/to/scan [--severity HIGH] [--output report.json]

from repo_scanner.__main__ import main

if __name__ == "__main__":
    main()
