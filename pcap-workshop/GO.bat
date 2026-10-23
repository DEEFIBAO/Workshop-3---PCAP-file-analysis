@echo off
rem Double-click me: installs what's missing, checks everyone's work, then starts the website.
cd /d "%~dp0"

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (
    where python >nul 2>nul && set "PY=python"
)
if not defined PY (
    echo Python 3 was not found.
    echo Install it from https://www.python.org/downloads/ and tick "Add Python to PATH".
    pause
    exit /b 1
)

%PY% go.py %*
echo.
pause
