@echo off
setlocal EnableExtensions
set "APP_DIR=%~dp0"
set "APP_ROOT=%APP_DIR:~0,-1%"
set "ELECTRON_EXE=%APP_DIR%node_modules\electron\dist\electron.exe"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%APP_DIR%scripts\newcyber_toggle.ps1" -AppDir "%APP_ROOT%" -Action Toggle
set "TOGGLE_RESULT=%ERRORLEVEL%"
if "%TOGGLE_RESULT%"=="0" exit /b 0
if not "%TOGGLE_RESULT%"=="10" goto :failed

cd /d "%APP_DIR%"
where npm >nul 2>nul
if errorlevel 1 (
  echo Node.js and npm are required to start NewCyber.
  goto :failed
)

if not exist "%ELECTRON_EXE%" (
  echo Installing NewCyber dependencies...
  call npm install
  if errorlevel 1 goto :failed
)

if not exist "%ELECTRON_EXE%" (
  echo Preparing the Electron runtime...
  call "%APP_DIR%node_modules\.bin\electron.cmd" --version
  if errorlevel 1 goto :failed
)

if not exist "%ELECTRON_EXE%" goto :failed
start "NewCyber" "%ELECTRON_EXE%" "%APP_DIR%"
exit /b 0

:failed
echo NewCyber could not start or close. Check the message above.
pause
exit /b 1
