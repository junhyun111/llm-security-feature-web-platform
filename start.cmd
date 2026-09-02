@echo off
setlocal

where docker >nul 2>nul
if errorlevel 1 (
  echo Docker Desktop 또는 Docker Engine을 먼저 설치해주세요.
  exit /b 1
)

docker compose up --build -d
if errorlevel 1 exit /b %ERRORLEVEL%

if "%WEB_PORT%"=="" set "WEB_PORT=8080"
echo.
echo LLM Security Web Platform: http://localhost:%WEB_PORT%
echo 상태 확인: docker compose ps
