
# PR Risk Radar (FastAPI)

Microsoft Copilot Studio에서 사용할 **PR(풀 리퀘스트) 리스크 레이더** 최소 구현입니다.
자연어로 `owner/repo`와 PR 번호를 알려주면, FastAPI가 GitHub API를 호출해 다음 신호를 수집하고 점수를 계산합니다.

## 수집 신호 (요약)
- 크기/변경량 (additions+deletions) → 과도하면 감점
- 변경 파일 수 → 많을수록 감점
- 민감 경로 수정(Dockerfile, .github/workflows, IaC, lockfiles 등) → 감점
- Diff 내 시크릿 패턴 감지(AWS 키, Private Key, Slack, Google API Key 등) → 크게 감점
- GitHub Actions에서 unpinned `uses:` 탐지 → 감점
- CI 체크런 실패 개수 → 감점
- 리뷰 `CHANGES_REQUESTED` 존재 → 감점
- 작성자 연관(Author Association) → 첫 기여자면 감점
- PR 오래됨(14일+) → 소폭 감점

총점으로 등급(A~F)을 부여합니다.

## 실행

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# .env 파일에 GITHUB_TOKEN=... (필수 스코프: repo/metadata/contents/actions/security_events 등 읽기 권한) 
echo "GITHUB_TOKEN=ghp_xxx" > .env

uvicorn app.main:app --reload --port 8080
```

호출 예:
```
GET http://localhost:8080/api/scan-pr?owner=octocat&repo=Hello-World&pr=1
```

## Copilot Studio 연결

1. 서버를 공인 HTTPS로 배포 (Railway/Render/Azure 등)
2. `openapi-pr.yaml`을 Copilot Studio → Actions → Add an action → OpenAPI 업로드
3. Playground에서 문장으로 테스트: "octocat/Hello-World의 PR #1 위험도 평가해"

## 주의
- PoC 수준으로, 대규모 리포·초대형 PR에서 페이지네이션/성능 고려는 최소화되어 있습니다.
- Secret 탐지는 간단한 정규식만 포함합니다. 조직 정책에 맞춰 패턴을 확장하세요.
- GitHub App 전환과 캐싱/레이트리밋 백오프, 보안 헤더, 로깅 강화가 운영에 필요합니다.

(생성 시각: 2025-09-16T01:29:10.942863Z)
