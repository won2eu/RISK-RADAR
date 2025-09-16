
from fastapi import FastAPI
from typing import Optional
import httpx
from .github import get_json
from .secret_patterns import find_secrets_in_diff_patch
from .scoring_pr import compute_score, calc_age_days, clamp

SENSITIVE_PATH_HINTS = [
    ".github/workflows/",
    "Dockerfile",
    "docker-compose.yml",
    "k8s/", "helm/",
    ".tf", "terraform", "cloudformation",
    "ansible/",
    "package.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "requirements.txt",
    "build.gradle", "pom.xml", "Gemfile.lock"
]

def touched_sensitive_path(filename: str) -> bool:
    fname = filename.lower()
    for hint in SENSITIVE_PATH_HINTS:
        if hint.lower() in fname:
            return True
    return False

def action_unpinned(line: str) -> bool:
    # 'uses: owner/repo@v3' => not pinned (version tag). SHA (40-hex) is preferable.
    if 'uses:' not in line:
        return False
    if '@' not in line:
        return True
    after = line.split('@',1)[1].strip()
    # if not 40-hex, treat as unpinned
    return not (len(after)>=40 and all(c in '0123456789abcdef' for c in after[:40].lower()))

app = FastAPI(title="PR Risk Radar API")

@app.get("/healthz")
async def healthz():
    return {"ok": True}

@app.get("/api/scan-pr")
async def scan_pr(owner: str, repo: str, pr: int):
    async with httpx.AsyncClient() as client:
        prj, _ = await get_json(client, f"/repos/{owner}/{repo}/pulls/{pr}")
        head_sha = prj.get("head",{}).get("sha")
        created_at = prj.get("created_at")
        author_assoc = prj.get("author_association","NONE")
        is_draft = prj.get("draft", False)
        changed_files = prj.get("changed_files", 0)
        additions = prj.get("additions", 0)
        deletions = prj.get("deletions", 0)
        base_ref = prj.get("base",{}).get("ref","")
        title = prj.get("title","")
        state = prj.get("state","open")

        files, _ = await get_json(client, f"/repos/{owner}/{repo}/pulls/{pr}/files?per_page=100")
        sensitive_touches = 0
        secret_hits = 0
        gha_unpinned = 0
        for f in files:
            filename = f.get("filename","")
            patch = f.get("patch","")
            if touched_sensitive_path(filename):
                sensitive_touches += 1
            secret_hits += find_secrets_in_diff_patch(patch or "")
            if filename.startswith(".github/workflows/"):
                for line in (patch or "").splitlines():
                    if line.startswith('+') and not line.startswith('+++') and 'uses:' in line:
                        if action_unpinned(line):
                            gha_unpinned += 1

        reviews, _ = await get_json(client, f"/repos/{owner}/{repo}/pulls/{pr}/reviews")
        changes_requested = any(r.get("state") == "CHANGES_REQUESTED" for r in reviews)

        ci_failures = 0
        if head_sha:
            check_runs, _ = await get_json(client, f"/repos/{owner}/{repo}/commits/{head_sha}/check-runs")
            runs = check_runs.get("check_runs", [])
            for r in runs:
                concl = r.get("conclusion")
                if concl in ("failure","timed_out","action_required","cancelled"):
                    ci_failures += 1

        age_days = calc_age_days(created_at or "")

        assoc_risk = {
            "FIRST_TIME_CONTRIBUTOR": 1.0,
            "CONTRIBUTOR": 0.7,
            "NONE": 1.0,
            "COLLABORATOR": 0.5,
            "MEMBER": 0.3,
            "OWNER": 0.2
        }.get(author_assoc, 0.8)

        # 점수 산정 상세 내역
        score_details = []

        # S1: Size & churn (max 20)
        s1 = 20 - clamp(int((additions + deletions)/200), 0, 20)
        score_details.append(f"Size & Churn: +{s1}점 (추가 {additions}, 삭제 {deletions})")

        # S2: Files changed (max 10)
        s2 = 10 - clamp(int(changed_files/5), 0, 10)
        score_details.append(f"변경 파일 수: +{s2}점 ({changed_files}개 파일 변경)")

        # S3: 민감 파일 터치 (max 20)
        s3 = 20 - clamp(sensitive_touches*4, 0, 20)
        score_details.append(f"민감 파일 터치: +{s3}점 ({sensitive_touches}개 민감 파일)")

        # S4: 시크릿 노출 (max 20)
        s4 = 20 - clamp(secret_hits*5, 0, 20)
        score_details.append(f"시크릿 노출: +{s4}점 ({secret_hits}건 감지)")

        # S5: GitHub Actions unpinned uses (max 10)
        s5 = 10 - clamp(gha_unpinned*3, 0, 10)
        score_details.append(f"GitHub Actions unpinned: +{s5}점 ({gha_unpinned}건)")

        # S6: CI 실패 (max 10)
        s6 = 10 - clamp(ci_failures*5, 0, 10)
        score_details.append(f"CI 실패: +{s6}점 ({ci_failures}건)")

        # S7: 리뷰 요청 (max 5)
        s7 = 5 - (5 if changes_requested else 0)
        score_details.append(f"리뷰 변경 요청: +{s7}점 ({'요청됨' if changes_requested else '없음'})")

        # S8: 작성자 신뢰도 (max 3)
        s8 = int(3 - clamp(assoc_risk*2, 0, 3))
        score_details.append(f"작성자 신뢰도: +{s8}점 (Association: {author_assoc})")

        # S9: PR 오래됨 (max 2)
        s9 = 2 - (1 if age_days >= 14 else 0)
        score_details.append(f"PR 오래됨: +{s9}점 ({age_days}일 경과)")

        signals = {
            "size_churn": {"additions": additions, "deletions": deletions, "points": s1},
            "files_changed": {"count": changed_files, "points": s2},
            "sensitive_paths": {"count": sensitive_touches, "points": s3},
            "secrets_in_diff": {"hits": secret_hits, "points": s4},
            "gha_unpinned_actions": {"count": gha_unpinned, "points": s5},
            "ci_failures": {"count": ci_failures, "points": s6},
            "reviews_changes_requested": {"flag": changes_requested, "points": s7},
            "author_association": {"value": author_assoc, "points": s8},
            "age_days": {"value": age_days, "points": s9},
        }

        total, letter = compute_score(signals)
        return {
            "owner": owner,
            "repo": repo,
            "pr": pr,
            "title": title,
            "state": state,
            "base": base_ref,
            "draft": is_draft,
            "score": total,
            "grade": letter,
            "signals": signals,
            "score_details": score_details
        }
