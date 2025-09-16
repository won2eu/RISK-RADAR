
import os
import httpx
from fastapi import HTTPException
from dotenv import load_dotenv

load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    raise RuntimeError("GITHUB_TOKEN not set. Put it in .env or environment.")

BASE = "https://api.github.com"
HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json"
}

async def get_json(client: httpx.AsyncClient, path: str, ok=(200,)):
    url = f"{BASE}{path}"
    r = await client.get(url, headers=HEADERS, timeout=30)
    if r.status_code not in ok:
        raise HTTPException(status_code=502, detail=f"GitHub API {r.status_code}: {r.text[:200]}")
    return r.json(), r.headers
