
from datetime import datetime, timezone

def grade(score:int)->str:
    if score>=90: return "A"
    if score>=80: return "B"
    if score>=70: return "C"
    if score>=60: return "D"
    return "F"

def clamp(x, lo, hi):
    return max(lo, min(hi, x))

def calc_age_days(created_at_iso: str) -> int:
    try:
        dt = datetime.fromisoformat(created_at_iso.replace('Z','+00:00'))
        return int((datetime.now(timezone.utc) - dt).total_seconds() // 86400)
    except Exception:
        return 0

def compute_score(signals: dict) -> tuple[int,str]:
    total = sum(v.get("points",0) for v in signals.values())
    return int(total), grade(int(total))
