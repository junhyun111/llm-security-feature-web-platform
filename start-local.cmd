@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "LOCAL_ROOT=%~dp0"
set "LOCAL_WEB_PORT=8080"
set "LOCAL_FORCE_SETUP=0"
set "LOCAL_NO_OPEN=0"

:parse_args
if "%~1"=="" goto :start
if /I "%~1"=="--setup" (
  set "LOCAL_FORCE_SETUP=1"
  shift
  goto :parse_args
)
if /I "%~1"=="--no-open" (
  set "LOCAL_NO_OPEN=1"
  shift
  goto :parse_args
)
if /I "%~1"=="--help" goto :help

echo Unknown option: %~1
goto :help_error

:start
pushd "%LOCAL_ROOT%" >nul || (
  echo Cannot open the project directory.
  exit /b 1
)

set "LOCAL_VENV=%LOCAL_ROOT%.local-runtime-venv"
set "LOCAL_RUNTIME_PYTHON=%LOCAL_VENV%\Scripts\python.exe"
set "LOCAL_LOG_DIR=%LOCAL_ROOT%deploy-data\local-logs"
set "LOCAL_RUNTIME_PID=%LOCAL_LOG_DIR%\runtime.pid"
set "LOCAL_WEB_PID=%LOCAL_LOG_DIR%\web.pid"
set "LOCAL_RUNTIME_STDOUT=%LOCAL_LOG_DIR%\runtime.out.log"
set "LOCAL_RUNTIME_STDERR=%LOCAL_LOG_DIR%\runtime.err.log"
set "LOCAL_WEB_STDOUT=%LOCAL_LOG_DIR%\web.out.log"
set "LOCAL_WEB_STDERR=%LOCAL_LOG_DIR%\web.err.log"
set "LOCAL_WEB_DIR=%LOCAL_ROOT%backend\LlmSecurity.Api"

echo.
echo LLM Security Web Platform - local Windows mode
echo.

python --version >nul 2>&1
if errorlevel 1 (
  echo Python 3.11 or later is required. Install it, then run this file again.
  goto :failure
)

dotnet --version >nul 2>&1
if errorlevel 1 (
  echo .NET SDK 10 is required. Install it, then run this file again.
  goto :failure
)

call npm.cmd --version >nul 2>&1
if errorlevel 1 (
  echo Node.js 22 and npm are required. Install them, then run this file again.
  goto :failure
)

if not exist "%LOCAL_ROOT%model_runtime\artifacts\router.pkl" (
  echo Runtime router artifact is missing: model_runtime\artifacts\router.pkl
  goto :failure
)
if not exist "%LOCAL_ROOT%model_runtime\artifacts\candidate_ranker.pkl" (
  echo Runtime candidate-ranker artifact is missing: model_runtime\artifacts\candidate_ranker.pkl
  goto :failure
)

if not exist "%LOCAL_LOG_DIR%" mkdir "%LOCAL_LOG_DIR%"
if not exist "%LOCAL_ROOT%deploy-data\sqlite" mkdir "%LOCAL_ROOT%deploy-data\sqlite"
if not exist "%LOCAL_ROOT%deploy-data\keys" mkdir "%LOCAL_ROOT%deploy-data\keys"
if not exist "%LOCAL_ROOT%deploy-data\runtime" mkdir "%LOCAL_ROOT%deploy-data\runtime"

set "LOCAL_NEEDS_PYTHON_SETUP=0"
if not exist "%LOCAL_RUNTIME_PYTHON%" (
  echo Creating Python virtual environment...
  python -m venv "%LOCAL_VENV%"
  if errorlevel 1 goto :setup_failure
  set "LOCAL_NEEDS_PYTHON_SETUP=1"
)
if not exist "%LOCAL_VENV%\Scripts\llm-security-runtime.exe" set "LOCAL_NEEDS_PYTHON_SETUP=1"
if "%LOCAL_FORCE_SETUP%"=="1" set "LOCAL_NEEDS_PYTHON_SETUP=1"

if "%LOCAL_NEEDS_PYTHON_SETUP%"=="1" (
  echo Installing Python runtime dependencies. This can take several minutes on the first run...
  "%LOCAL_RUNTIME_PYTHON%" -c "import torch; assert torch.__version__.startswith('2.8.0')" >nul 2>nul
  if errorlevel 1 (
    "%LOCAL_RUNTIME_PYTHON%" -m pip install --ignore-installed --index-url https://download.pytorch.org/whl/cpu "torch==2.8.0"
    if errorlevel 1 goto :setup_failure
  )
  "%LOCAL_RUNTIME_PYTHON%" -m pip install "httpx>=0.27,<1" "numpy>=1.26" "scikit-learn==1.9.0" "tree-sitter>=0.25,<0.26" "tree-sitter-c>=0.24,<0.25" "tree-sitter-cpp>=0.23,<0.24" "fastapi>=0.115,<1" "python-multipart>=0.0.9,<1" "uvicorn>=0.30,<1"
  if errorlevel 1 goto :setup_failure
  "%LOCAL_RUNTIME_PYTHON%" -m pip install --no-deps -e "%LOCAL_ROOT%model_runtime"
  if errorlevel 1 goto :setup_failure
)

set "LOCAL_NEEDS_NODE_SETUP=0"
if not exist "%LOCAL_ROOT%frontend\node_modules" set "LOCAL_NEEDS_NODE_SETUP=1"
if "%LOCAL_FORCE_SETUP%"=="1" set "LOCAL_NEEDS_NODE_SETUP=1"
if "%LOCAL_NEEDS_NODE_SETUP%"=="1" (
  echo Installing frontend dependencies...
  call npm.cmd --prefix "%LOCAL_ROOT%frontend" ci
  if errorlevel 1 goto :setup_failure
)

echo Building the web interface...
call npm.cmd --prefix "%LOCAL_ROOT%frontend" run build
if errorlevel 1 goto :setup_failure

if not exist "%LOCAL_WEB_DIR%\wwwroot" mkdir "%LOCAL_WEB_DIR%\wwwroot"
robocopy "%LOCAL_ROOT%frontend\dist" "%LOCAL_WEB_DIR%\wwwroot" /MIR /NFL /NDL /NJH /NJS
set "LOCAL_COPY_RESULT=%ERRORLEVEL%"
if %LOCAL_COPY_RESULT% GEQ 8 (
  echo Copying the web build failed. Robocopy exit code: %LOCAL_COPY_RESULT%
  goto :failure
)

set "ASPNETCORE_ENVIRONMENT=Development"
set "ASPNETCORE_URLS=http://127.0.0.1:%LOCAL_WEB_PORT%"
set "Analyzer__BaseUrl=http://127.0.0.1:8000"
set "ConnectionStrings__DefaultConnection=Data Source=%LOCAL_ROOT%deploy-data\sqlite\llm-security.db;Cache=Shared;Foreign Keys=True;Default Timeout=30"
set "DataProtection__KeysPath=%LOCAL_ROOT%deploy-data\keys"
set "LLM_SECURITY_RUNTIME_ROOT=%LOCAL_ROOT%model_runtime"

call :health_check 8000 /api/health
if errorlevel 1 (
  echo Starting analysis Runtime in the background...
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$process = Start-Process -FilePath $env:LOCAL_RUNTIME_PYTHON -ArgumentList @('-m','llm_security_runtime','serve','--host','127.0.0.1','--port','8000') -WorkingDirectory $env:LOCAL_ROOT -WindowStyle Hidden -RedirectStandardOutput $env:LOCAL_RUNTIME_STDOUT -RedirectStandardError $env:LOCAL_RUNTIME_STDERR -PassThru; Set-Content -LiteralPath $env:LOCAL_RUNTIME_PID -Value $process.Id -NoNewline"
  if errorlevel 1 goto :failure
  call :wait_for_health 8000 /api/health
  if errorlevel 1 (
    echo Runtime did not become ready. Check %LOCAL_RUNTIME_STDERR%
    goto :failure
  )
) else (
  echo Analysis Runtime is already running on port 8000.
)

call :health_check %LOCAL_WEB_PORT% /api/health
if errorlevel 1 (
  echo Starting the web server in the background...
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$process = Start-Process -FilePath 'dotnet' -ArgumentList @('run','--no-launch-profile') -WorkingDirectory $env:LOCAL_WEB_DIR -WindowStyle Hidden -RedirectStandardOutput $env:LOCAL_WEB_STDOUT -RedirectStandardError $env:LOCAL_WEB_STDERR -PassThru; Set-Content -LiteralPath $env:LOCAL_WEB_PID -Value $process.Id -NoNewline"
  if errorlevel 1 goto :failure
  call :wait_for_health %LOCAL_WEB_PORT% /api/health
  if errorlevel 1 (
    echo Web server did not become ready. Check %LOCAL_WEB_STDERR%
    goto :failure
  )
) else (
  echo Web server is already running on port %LOCAL_WEB_PORT%.
)

echo.
echo Ready: http://localhost:%LOCAL_WEB_PORT%
echo Stop it later with: .\stop-local.cmd
echo Logs: deploy-data\local-logs\
if "%LOCAL_NO_OPEN%"=="1" goto :success
start "" "http://localhost:%LOCAL_WEB_PORT%"

:success
popd
exit /b 0

:health_check
set "LOCAL_HEALTH_URL=http://127.0.0.1:%~1%~2"
powershell.exe -NoProfile -Command "try { $response = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 -Uri $env:LOCAL_HEALTH_URL; if ($response.StatusCode -eq 200) { exit 0 } } catch {}; exit 1" >nul 2>nul
exit /b %ERRORLEVEL%

:wait_for_health
set "LOCAL_HEALTH_URL=http://127.0.0.1:%~1%~2"
powershell.exe -NoProfile -Command "$deadline = (Get-Date).AddSeconds(90); do { try { $response = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 -Uri $env:LOCAL_HEALTH_URL; if ($response.StatusCode -eq 200) { exit 0 } } catch {}; Start-Sleep -Seconds 1 } while ((Get-Date) -lt $deadline); exit 1"
exit /b %ERRORLEVEL%

:setup_failure
echo Setup failed. Fix the reported error and run .\start-local.cmd --setup again.
goto :failure

:failure
popd
exit /b 1

:help
echo Usage: .\start-local.cmd [--setup] [--no-open]
echo.
echo   --setup    Reinstall Python and frontend dependencies.
echo   --no-open  Do not open the browser after the server is ready.
exit /b 0

:help_error
exit /b 1
