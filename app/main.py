from fastapi import FastAPI, Body, HTTPException
from typing import Optional
import httpx
from .github import get_json
from .secret_patterns import find_secrets_in_diff_patch
from .scoring_pr import compute_score, calc_age_days, clamp
import os
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="PR Risk Radar API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 필요시 특정 도메인으로 제한
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    after = line.split('@', 1)[1].strip()
    # if not 40-hex, treat as unpinned
    return not (len(after) >= 40 and all(c in '0123456789abcdef' for c in after[:40].lower()))

@app.get("/healthz")
async def healthz():
    return {"ok": True}

@app.get("/api/scan-pr")
async def scan_pr(owner: str, repo: str, pr: int):
    async with httpx.AsyncClient() as client:
        # PR detail
        prj, _ = await get_json(client, f"/repos/{owner}/{repo}/pulls/{pr}")
        head_sha = prj.get("head", {}).get("sha")
        created_at = prj.get("created_at")
        author_assoc = prj.get("author_association", "NONE")
        is_draft = prj.get("draft", False)
        changed_files = prj.get("changed_files", 0)
        additions = prj.get("additions", 0)
        deletions = prj.get("deletions", 0)
        base_ref = prj.get("base", {}).get("ref", "")
        title = prj.get("title", "")
        state = prj.get("state", "open")

        # PR files (first 100)
        files, _ = await get_json(client, f"/repos/{owner}/{repo}/pulls/{pr}/files?per_page=100")
        sensitive_touches = 0
        secret_hits = 0
        gha_unpinned = 0
        for f in files:
            filename = f.get("filename", "")
            patch = f.get("patch", "")
            if touched_sensitive_path(filename):
                sensitive_touches += 1
            secret_hits += find_secrets_in_diff_patch(patch or "")
            if filename.startswith(".github/workflows/"):
                # scan added lines for unpinned actions
                for line in (patch or "").splitlines():
                    if line.startswith('+') and not line.startswith('+++') and 'uses:' in line:
                        if action_unpinned(line):
                            gha_unpinned += 1

        # reviews
        reviews, _ = await get_json(client, f"/repos/{owner}/{repo}/pulls/{pr}/reviews")
        changes_requested = any(r.get("state") == "CHANGES_REQUESTED" for r in reviews)

        # checks on head sha
        ci_failures = 0
        if head_sha:
            check_runs, _ = await get_json(client, f"/repos/{owner}/{repo}/commits/{head_sha}/check-runs")
            runs = check_runs.get("check_runs", [])
            for r in runs:
                concl = r.get("conclusion")
                if concl in ("failure", "timed_out", "action_required", "cancelled"):
                    ci_failures += 1

        # age
        age_days = calc_age_days(created_at or "")

        # Author risk factor
        assoc_risk = {
            "FIRST_TIME_CONTRIBUTOR": 1.0,
            "CONTRIBUTOR": 0.7,
            "NONE": 1.0,
            "COLLABORATOR": 0.5,
            "MEMBER": 0.3,
            "OWNER": 0.2
        }.get(author_assoc, 0.8)

        # Scoring (100 pts)
        s1 = 20 - clamp(int((additions + deletions) / 200), 0, 20)           # Size & churn
        s2 = 10 - clamp(int(changed_files / 5), 0, 10)                       # Files changed
        s3 = 20 - clamp(sensitive_touches * 4, 0, 20)                        # Sensitive paths
        s4 = 20 - clamp(secret_hits * 5, 0, 20)                              # Secrets in diff
        s5 = 10 - clamp(gha_unpinned * 3, 0, 10)                             # Unpinned actions
        s6 = 10 - clamp(ci_failures * 5, 0, 10)                              # CI failures
        s7 = 5 - (5 if changes_requested else 0)                             # Reviews
        s8 = int(3 - clamp(assoc_risk * 2, 0, 3))                            # Author association
        s9 = 2 - (1 if age_days >= 14 else 0)                                # Age

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
            "signals": signals
        }


def estimate_performance_impact(pr_data):
    """PR 데이터로부터 성능 영향 추정"""
    additions = pr_data.get("additions", 0)
    deletions = pr_data.get("deletions", 0)
    changed_files = pr_data.get("changed_files", 0)
    
    # 코드 복잡도 점수 계산
    complexity_score = (additions + deletions) / 1000
    file_impact = changed_files / 10
    
    # 성능 영향 레벨 결정
    if complexity_score > 2 or file_impact > 5:
        impact_level = "high"
    elif complexity_score > 1 or file_impact > 2:
        impact_level = "medium"
    else:
        impact_level = "low"
    
    return {
        "impact_level": impact_level,
        "complexity_score": round(complexity_score, 2),
        "file_impact_score": round(file_impact, 2),
        "total_changes": additions + deletions,
        "changed_files": changed_files
    }

def analyze_dependency_changes(files):
    """의존성 파일 변경 분석"""
    dependency_files = [
        "package.json", "yarn.lock", "pnpm-lock.yaml",
        "requirements.txt", "poetry.lock", "Pipfile",
        "pom.xml", "build.gradle", "Gemfile", "Gemfile.lock",
        "composer.json", "Cargo.toml", "go.mod"
    ]
    
    changes = []
    for file in files:
        filename = file.get("filename", "")
        if any(dep_file in filename for dep_file in dependency_files):
            changes.append({
                "file": filename,
                "additions": file.get("additions", 0),
                "deletions": file.get("deletions", 0),
                "status": file.get("status", "unknown")
            })
    
    return changes

def analyze_file_types(files):
    """파일 타입별 변경 분석"""
    file_types = {
        "source_code": [".py", ".js", ".ts", ".java", ".cpp", ".c", ".go", ".rs"],
        "config": [".json", ".yaml", ".yml", ".toml", ".ini", ".conf"],
        "documentation": [".md", ".rst", ".txt"],
        "tests": ["test_", "_test", ".test.", "spec."],
        "assets": [".png", ".jpg", ".svg", ".css", ".scss"]
    }
    
    analysis = {category: 0 for category in file_types.keys()}
    analysis["total_files"] = len(files)
    
    for file in files:
        filename = file.get("filename", "").lower()
        for category, extensions in file_types.items():
            if any(filename.endswith(ext) or any(pattern in filename for pattern in extensions) for ext in extensions):
                analysis[category] += 1
                break
    
    return analysis

async def get_ci_metrics(owner: str, repo: str, head_sha: str, token: str):
    """CI 메타데이터에서 성능 관련 지표 추출"""
    async with httpx.AsyncClient() as client:
        try:
            check_runs, _ = await get_json(client, f"/repos/{owner}/{repo}/commits/{head_sha}/check-runs")
            runs = check_runs.get("check_runs", [])
            
            total_duration = 0
            success_count = 0
            failure_count = 0
            
            for run in runs:
                if run.get("status") == "completed":
                    total_duration += run.get("duration", 0)
                    conclusion = run.get("conclusion")
                    if conclusion == "success":
                        success_count += 1
                    elif conclusion in ["failure", "timed_out", "cancelled"]:
                        failure_count += 1
            
            return {
                "total_duration_ms": total_duration,
                "success_count": success_count,
                "failure_count": failure_count,
                "total_checks": len(runs),
                "avg_duration_ms": total_duration / max(len(runs), 1)
            }
        except:
            return {
                "total_duration_ms": 0,
                "success_count": 0,
                "failure_count": 0,
                "total_checks": 0,
                "avg_duration_ms": 0
            }

def calculate_performance_risk(complexity, dependency_changes, ci_metrics, file_types):
    """종합적인 성능 위험도 계산"""
    risk_score = 0
    
    # 코드 복잡도 기여
    risk_score += complexity["complexity_score"] * 30
    
    # 의존성 변경 기여
    risk_score += len(dependency_changes) * 20
    
    # CI 실패 기여
    if ci_metrics["failure_count"] > 0:
        risk_score += ci_metrics["failure_count"] * 15
    
    # 파일 타입 기여
    if file_types["source_code"] > 10:
        risk_score += 10
    if file_types["config"] > 3:
        risk_score += 15
    
    # 위험도 레벨 결정
    if risk_score > 100:
        risk_level = "high"
    elif risk_score > 50:
        risk_level = "medium"
    else:
        risk_level = "low"
    
    return {
        "risk_level": risk_level,
        "risk_score": round(risk_score, 1),
        "factors": {
            "code_complexity": complexity["complexity_score"] * 30,
            "dependency_changes": len(dependency_changes) * 20,
            "ci_failures": ci_metrics["failure_count"] * 15,
            "file_volume": file_types["source_code"] * 2
        }
    }

@app.post("/api/analyze-pr-performance")
async def analyze_pr_performance(payload: dict = Body(...)):
    """
    벤치마크 없이 PR 성능 영향 분석 (메타데이터 기반)
    Body 예: { "owner":"Hwang9170", "repo":"Copilot_ai", "pr":3 }
    """
    owner = payload["owner"]
    repo = payload["repo"]
    pr = int(payload["pr"])
    
    async with httpx.AsyncClient() as client:
        # PR 기본 정보 가져오기
        pr_data, _ = await get_json(client, f"/repos/{owner}/{repo}/pulls/{pr}")
        files, _ = await get_json(client, f"/repos/{owner}/{repo}/pulls/{pr}/files?per_page=100")
        
        # 1. 코드 복잡도 분석
        complexity = estimate_performance_impact(pr_data)
        
        # 2. 의존성 변경 분석
        dependency_changes = analyze_dependency_changes(files)
        
        # 3. 파일 타입 분석
        file_types = analyze_file_types(files)
        
        # 4. CI 메타데이터 분석
        head_sha = pr_data.get("head", {}).get("sha")
        ci_metrics = await get_ci_metrics(owner, repo, head_sha, os.getenv("GITHUB_TOKEN", ""))
        
        # 5. 종합 성능 위험도 계산
        performance_risk = calculate_performance_risk(complexity, dependency_changes, ci_metrics, file_types)
        
        # 6. 마크다운 댓글 생성
        comment_md = f"""### 🔍 Performance Impact Analysis (PR #{pr})

**Overall Risk Level:** {performance_risk['risk_level'].upper()}
**Risk Score:** {performance_risk['risk_score']}/100

#### 📊 Code Complexity
- **Impact Level:** {complexity['impact_level']}
- **Total Changes:** {complexity['total_changes']} lines
- **Files Changed:** {complexity['changed_files']}

#### 📦 Dependency Changes
{dependency_changes and f"- {len(dependency_changes)} dependency files modified" or "- No dependency changes"}

#### 🏗️ CI Metrics
- **Total Duration:** {ci_metrics['total_duration_ms']}ms
- **Success Rate:** {ci_metrics['success_count']}/{ci_metrics['total_checks']} checks passed

#### 📁 File Type Analysis
- **Source Code:** {file_types['source_code']} files
- **Configuration:** {file_types['config']} files
- **Tests:** {file_types['tests']} files
"""
        
        return {
            "ok": True,
            "pr": pr,
            "title": pr_data.get("title", ""),
            "complexity_analysis": complexity,
            "dependency_changes": dependency_changes,
            "file_type_analysis": file_types,
            "ci_metrics": ci_metrics,
            "performance_risk": performance_risk,
            "comment_markdown": comment_md,
            "summary": {
                "risk_level": performance_risk["risk_level"],
                "risk_score": performance_risk["risk_score"],
                "recommendation": "Review carefully" if performance_risk["risk_level"] == "high" else "Standard review" if performance_risk["risk_level"] == "medium" else "Low risk"
            }
        }
