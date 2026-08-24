#!/usr/bin/env python3
"""
VulnScan Lite — Safe Local Scanner Runner Script

Usage:
    python run_scanner_test.py https://example.com
"""
import os
import sys

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.cli import main

if __name__ == "__main__":
    main()
