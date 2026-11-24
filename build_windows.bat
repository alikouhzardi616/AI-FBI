@echo off
setlocal
cd /d "%~dp0"

py -3 -m pip install -r requirements.txt
if errorlevel 1 exit /b %errorlevel%

py -3 -m pip install "pyinstaller>=6.0"
if errorlevel 1 exit /b %errorlevel%

py -3 scripts\generate_icon.py
if errorlevel 1 exit /b %errorlevel%

py -3 scripts\generate_donate_qr.py
if errorlevel 1 exit /b %errorlevel%

py -3 -m PyInstaller --clean --noconfirm ai_fbi.spec
if errorlevel 1 exit /b %errorlevel%

echo Build complete: dist\AI FBI.exe
endlocal
