# model_runtime

웹 플랫폼에서 사용하는 배포용 C/C++ 취약점 분석 Runtime입니다. 외부에 직접 공개하지 않고 ASP.NET 백엔드만 호출합니다. Docker Compose와 Windows 네이티브 실행을 모두 지원합니다.

필수 artifact:

```text
artifacts/router.pkl
artifacts/candidate_ranker.pkl
artifacts/decision_layer.pt
```

Runtime은 요청마다 다음 값을 받습니다.

- OpenRouter API Key
- OpenRouter 모델 ID
- 분석 민감도

API Key는 작업 JSON이나 분석 결과에 기록하지 않으며 분석이 끝나면 메모리에서도 제거합니다. 패치 생성 요청은 API Key를 다시 받아 한 번의 요청에만 사용합니다.

Artifact 확인:

```bash
docker compose run --rm analyzer llm-security-runtime inspect
```

Windows에서 Docker 없이 웹 플랫폼을 실행하려면 저장소 루트의 `start-local.cmd`를 사용합니다. 이 스크립트가 가상환경을 만들고 Runtime을 `127.0.0.1:8000`에 내부용으로 실행합니다.

```powershell
.\start-local.cmd
```

Docker 배포는 기존과 동일합니다.

```bash
docker compose up --build -d
```
