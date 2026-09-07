@echo off
setlocal
set "APP_DIR=%~dp0"
set "ELECTRON_EXE=%APP_DIR%node_modules\electron\dist\electron.exe"

if not exist "%ELECTRON_EXE%" (
  echo NewCyber dependencies are not installed.
  echo Run npm install in: %APP_DIR%
  pause
  exit /b 1
)

start "NewCyber" "%ELECTRON_EXE%" "%APP_DIR%"
endlocal
