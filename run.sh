#!/usr/bin/env bash
# SecureAccess Pro - one-command launcher for macOS / Linux.
cd "$(dirname "$0")" || exit 1
echo "Installing dependencies (first run may take a minute)..."
python3 -m pip install -r backend/requirements.txt
echo "Starting SecureAccess Pro..."
python3 run.py
