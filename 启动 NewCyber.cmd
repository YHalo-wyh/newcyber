@echo off
setlocal EnableExtensions
set "APP_DIR=%~dp0"
set "ELECTRON_EXE=%APP_DIR%node_modules\electron\dist\electron.exe"

cd /d "%APP_DIR%"

where npm >nul 2>nul
if errorlevel 1 (
  echo Node.js and npm are required to start NewCyber.
  echo Install Node.js LTS, then run this script again.
  pause
  exit /b 1
)

if not exist "%ELECTRON_EXE%" (
  echo Installing NewCyber dependencies...
  call npm install
  if errorlevel 1 goto :install_failed
)

if not exist "%ELECTRON_EXE%" (
  echo Preparing the Electron runtime...
  call "%APP_DIR%node_modules\.bin\electron.cmd" --version
  if errorlevel 1 goto :install_failed
)

if not exist "%ELECTRON_EXE%" goto :install_failed

rem trailing backslash would escape the closing quote for electron arg parsing
start "NewCyber" "%ELECTRON_EXE%" "%APP_DIR%."
endlocal
exit /b 0

:install_failed
echo.
echo NewCyber could not prepare its Electron runtime.
echo Check your network connection, then run this script again.
pause
endlocal
exit /b 1
