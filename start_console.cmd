@echo off
setlocal
chcp 65001 >nul
set "PYTHONUTF8=1"
pushd "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    py -3 -m venv .venv
    if errorlevel 1 goto failed
)
".venv\Scripts\python.exe" -c "import Crypto, requests, socks" >nul 2>&1
if errorlevel 1 (
    ".venv\Scripts\python.exe" -m pip install ".[console]"
    if errorlevel 1 goto failed
)
".venv\Scripts\python.exe" vpn_console.py %*
if errorlevel 1 goto failed
popd
exit /b 0
:failed
echo.
echo Console could not start. See the message above.
pause
popd
exit /b 1
