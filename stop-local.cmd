@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "LOCAL_ROOT=%~dp0"
set "LOCAL_LOG_DIR=%LOCAL_ROOT%deploy-data\local-logs"

call :stop_process "%LOCAL_LOG_DIR%\web.pid" "web server"
call :stop_process "%LOCAL_LOG_DIR%\runtime.pid" "analysis Runtime"

echo Local services stopped.
exit /b 0

:stop_process
if not exist "%~1" exit /b 0

set "LOCAL_PID_VALUE="
set /p LOCAL_PID_VALUE=<"%~1"
echo(%LOCAL_PID_VALUE%| findstr /r "^[0-9][0-9]*$" >nul
if errorlevel 1 (
  del /q "%~1" >nul 2>nul
  exit /b 0
)

powershell.exe -NoProfile -Command "Stop-Process -Id $env:LOCAL_PID_VALUE -Force -ErrorAction SilentlyContinue"
del /q "%~1" >nul 2>nul
echo Stopped %~2.
exit /b 0
