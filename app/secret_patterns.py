
import re

# Very small PoC set. Expand as needed.
PATTERNS = [
    # AWS Access Key ID (AKIA...)
    re.compile(r'AKIA[0-9A-Z]{16}'),
    # Generic private key header
    re.compile(r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'),
    # Slack token (legacy formats)
    re.compile(r'xox[baprs]-[0-9A-Za-z-]{10,48}'),
    # Google API key
    re.compile(r'AIza[0-9A-Za-z\\-_]{35}'),
]

def find_secrets_in_diff_patch(patch: str) -> int:
    if not patch:
        return 0
    hits = 0
    for line in patch.splitlines():
        if not line.startswith('+') or line.startswith('+++'):
            continue
        for pat in PATTERNS:
            if pat.search(line):
                hits += 1
                break
    return hits
