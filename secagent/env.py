"""
Minimal .env loader (stdlib only — no python-dotenv dependency).

Secrets (the Anthropic API key) live in a .env file at the repo root, never in
code or git (see .gitignore). load_dotenv() reads KEY=VALUE lines into os.environ
so the Anthropic SDK — which reads ANTHROPIC_API_KEY from the environment — picks
them up. By default it does NOT override a variable that's already set, so an
explicitly-exported env var still wins over the file.

Supported lines:
    KEY=value
    KEY="quoted value"     # surrounding single/double quotes stripped
    export KEY=value       # leading `export ` ignored
    # comment               (and blank lines)
"""

from __future__ import annotations

import os


def parse_env(text: str) -> dict[str, str]:
    """Parse .env text into a dict. Tolerant: bad lines are skipped, not fatal."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        out[key] = value
    return out


def load_dotenv(path: str = ".env", *, override: bool = False) -> dict[str, str]:
    """
    Load `path` into os.environ. Missing file is a silent no-op. Returns the keys
    that were actually applied. Existing env vars are kept unless override=True.
    """
    try:
        with open(path, encoding="utf-8") as f:
            parsed = parse_env(f.read())
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return {}
    applied: dict[str, str] = {}
    for key, value in parsed.items():
        if override or key not in os.environ:
            os.environ[key] = value
            applied[key] = value
    return applied
