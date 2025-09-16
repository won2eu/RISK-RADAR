
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
        # PR detail
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

        # PR files (first 100)
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
                if concl in ("failure","timed_out","action_required","cancelled"):
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
        # S1: Size & churn (max 20)
        s1 = 20 - clamp(int((additions + deletions)/200), 0, 20)

        # S2: Files changed (max 10)
        s2 = 10 - clamp(int(changed_files/5), 0, 10)

        # S3: Sensitive files touched (max 20) -> more sensitive touches reduce points
        s3 = 20 - clamp(sensitive_touches*4, 0, 20)

        # S4: Secrets in diff (max 20) -> each hit is severe
        s4 = 20 - clamp(secret_hits*5, 0, 20)

        # S5: GitHub Actions unpinned uses (max 10) -> each unpinned reduces
        s5 = 10 - clamp(gha_unpinned*3, 0, 10)

        # S6: CI status (max 10) -> failures reduce
        s6 = 10 - clamp(ci_failures*5, 0, 10)

        # S7: Reviews (max 5) -> changes requested reduces
        s7 = 5 - (5 if changes_requested else 0)

        # S8: Author association (max 3) -> lower trust reduces
        s8 = int(3 - clamp(assoc_risk*2, 0, 3))

        # S9: Age (staleness) (max 2) -> very old PR reduce
        s9 = 2 - (1 if age_days >= 14 else 0)

        # S10: Target default branch boost (max 0 bonus) - omitted in PoC

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
