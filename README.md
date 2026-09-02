# LLM Security Web Platform

C/C++ 프로젝트를 업로드하면 정적 분석, Utility Router, OpenRouter LLM 검증을 거쳐 취약점과 통합 패치를 제공하는 웹 애플리케이션입니다.

## 빠른 실행: Docker 없이 Windows에서 실행

다음 프로그램만 설치되어 있으면 Docker 없이 실행할 수 있습니다.

- Python 3.11 이상
- .NET SDK 10
- Node.js 22

저장소 루트에서 다음 명령 하나를 실행합니다.

```powershell
.\start-local.cmd
```

첫 실행에서는 Python 가상환경, CPU용 PyTorch, 프런트엔드 의존성을 설치하므로 시간이 걸립니다. 이후 실행은 Runtime과 웹 서버를 백그라운드로 시작하고 브라우저를 엽니다.

```text
http://localhost:8080
```

종료와 로그 확인:

```powershell
.\stop-local.cmd
Get-Content .\deploy-data\local-logs\web.err.log -Wait
```

의존성을 다시 설치해야 하면 다음을 사용합니다.

```powershell
.\start-local.cmd --setup
```

로컬 모드와 Docker 모드를 동시에 실행하면 같은 SQLite/분석 데이터에 접근할 수 있으므로, 한 번에 하나만 실행하십시오.

## Docker로 실행

Docker Desktop 또는 Docker Engine + Compose가 있다면 기존 Docker 배포 방식도 그대로 사용할 수 있습니다.

Windows에서는 다음 명령 하나를 실행합니다.

```powershell
.\start.cmd
```

운영체제와 관계없이 직접 실행할 수도 있습니다.

```bash
docker compose up --build -d
```

첫 빌드에서는 CPU용 PyTorch와 .NET/Node 의존성을 설치하므로 시간이 걸립니다. 완료 후 다음 주소로 접속합니다.

```text
http://localhost:8080
```

상태 확인과 종료:

```bash
docker compose ps
docker compose logs -f
docker compose down
```

`docker compose down`은 SQLite와 분석 기록을 삭제하지 않습니다.

## 구성

```text
Browser
  -> ASP.NET Core :8080
       - React 정적 파일
       - Identity 인증/API
       - SQLite
  -> Python model_runtime :8000 (Docker 내부 전용)
       - 정적 분석
       - Candidate Ranker
       - Utility Router
       - OpenRouter LLM
```

외부에는 ASP.NET 포트 하나만 공개됩니다. React 개발 서버와 Python Runtime 포트는 공개하지 않습니다.

## OpenRouter 설정

OpenRouter API Key와 모델명은 `.env`에 저장하지 않습니다.

1. 회원가입 또는 로그인합니다.
2. `새 분석` 화면에 본인의 OpenRouter API Key를 입력합니다.
3. `OpenRouter 모델 목록 불러오기`를 누르거나 모델 ID를 직접 입력합니다.
4. 프로젝트 폴더와 민감도를 선택하고 분석을 시작합니다.

API Key는 브라우저에서 ASP.NET을 거쳐 내부 Runtime으로 전달되며 다음 위치에 저장되지 않습니다.

- SQLite
- 분석 결과 JSON
- 업로드 프로젝트
- 서버 `.env`

분석 종료 후 Runtime 메모리에서도 제거됩니다. 통합 패치를 생성할 때는 API Key를 다시 입력해야 합니다.

현재 Router가 학습된 권장 모델은 Runtime artifact 메타데이터에서 자동으로 표시합니다. 다른 OpenRouter 텍스트 모델도 실행할 수 있지만 UI에 `Router 성능 미검증`으로 표시됩니다.

## 분석 결과 워크벤치

완료된 분석의 `Code` 탭은 배포본에 포함된 Monaco Editor를 사용하며 외부 CDN에 의존하지 않습니다.

- 프로젝트 파일 트리와 C/C++ 구문 강조
- 취약점 라인·거터 마커, hover 요약, Problems 목록
- CWE, 검증 결과, 신뢰도, Expert 근거를 보여주는 Finding Inspector
- 승인 전 임시 복사본에만 패치를 적용하는 원본/수정본 Diff Editor
- 실제 저장된 Router 점수, Expert 선택, Validator 결과, 모델 사용량을 보여주는 Analysis Trace
- 탐지 신뢰도와 검증 결과/검증 신뢰도를 분리하고 deterministic 검증은 `규칙 기반`으로 표시
- Aggregation 전 구조 검증과 Validator hard check 결과를 Analysis Trace에 표시

폴더 업로드 시 `.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hh`, `.hpp`만 전송됩니다. `.git`, `node_modules`, `build`, `dist`, `out`, `vendor`, `.venv`, `__pycache__` 안의 파일과 5MB를 넘는 개별 소스 파일은 브라우저에서 제외됩니다.

## SQLite와 영구 데이터

SQLite 스키마는 시작 시 EF Core Migration으로 자동 갱신됩니다.

```text
deploy-data/sqlite/llm-security.db  # 사용자와 분석 이력
deploy-data/keys/                   # 로그인 쿠키 보호 키
deploy-data/runtime/                # 업로드, 분석 결과, 승인된 패치
```

백업할 때는 쓰기를 잠시 멈춘 후 `deploy-data` 전체를 복사하는 것이 가장 안전합니다.

```bash
docker compose stop web analyzer
# deploy-data 디렉터리 백업
docker compose start analyzer web
```

## 서버 설정

포트나 허용 도메인을 바꾸려면 `.env.example`을 `.env`로 복사합니다.

```powershell
Copy-Item .env.example .env
```

```dotenv
WEB_PORT=8080
ALLOWED_HOSTS=security.example.com
```

이 `.env`에도 OpenRouter API Key를 넣지 않습니다.

인터넷에 공개할 때는 Caddy, Nginx 또는 클라우드 로드 밸런서에서 HTTPS를 적용한 뒤 8080 포트로 프록시해야 합니다. 사용자 API Key가 전송되므로 평문 HTTP 공개 배포는 사용하지 마십시오.

## 주요 폴더

```text
backend/LlmSecurity.Api/  # ASP.NET Core, Identity, EF Core, SQLite
frontend/                 # React + TypeScript + Vite
model_runtime/            # 배포용 Python 분석 모델과 artifact
deploy-data/              # 실행 중 생성되는 영구 데이터
```

## 유지보수 명령

이미지 다시 빌드:

```bash
docker compose up --build -d
```

Runtime artifact 확인:

```bash
docker compose run --rm analyzer llm-security-runtime inspect
```

Docker 없이 Runtime artifact 확인:

```powershell
.\.local-runtime-venv\Scripts\python.exe .\model_runtime\run.py inspect
```

NuGet 취약 패키지 확인:

```powershell
dotnet list backend\LlmSecurity.Api\LlmSecurity.Api.csproj package --vulnerable --include-transitive
```

프런트엔드 빌드 확인:

```powershell
cd frontend
npm ci
npm run build
```

Aggregator와 검증 순서 회귀 테스트:

```powershell
$env:PYTHONPATH='model_runtime\src'
.\.local-runtime-venv\Scripts\python.exe -m unittest discover -s model_runtime\tests -v
```
