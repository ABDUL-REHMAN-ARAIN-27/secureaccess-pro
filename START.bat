@echo off
REM SecureAccess Pro - one-click launcher for Windows.
REM Double-click this file, or run it from a terminal.
cd /d "%~dp0"

echo Installing dependencies (first run may take a minute)...
python -m pip install -r backend\requirements.txt

echo Starting SecureAccess Pro...
python run.py

pause
