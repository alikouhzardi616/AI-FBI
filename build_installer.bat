@echo off
setlocal
cd /d "%~dp0"

if not exist "dist\AI FBI.exe" (
  echo Missing dist\AI FBI.exe. Run build_windows.bat first.
  exit /b 1
)

set "ISCC="
where ISCC.exe >nul 2>nul
if not errorlevel 1 set "ISCC=ISCC.exe"
if not defined ISCC if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"

if not defined ISCC (
  echo Inno Setup 6 was not found. Install it, then rerun build_installer.bat.
  exit /b 2
)

"%ISCC%" "installer\AI_FBI_Setup.iss"
if errorlevel 1 exit /b %errorlevel%
echo Installer created: dist\AI_FBI_Installer.exe
endlocal
