#!/usr/bin/env python3
"""Generate BaseAI Clash ruleset from upstream providers."""

from __future__ import annotations

from datetime import UTC, datetime
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable, List, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_PATH = REPO_ROOT / "ruleset" / "BaseAI.list"

SOURCES: Sequence[tuple[str, str]] = (
    (
        "Anthropic",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Anthropic/Anthropic.list",
    ),
    (
        "OpenAI",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.yaml",
    ),
    (
        "Gemini",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Gemini/Gemini.list",
    ),
    (
        "Copilot",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Copilot/Copilot.list",
    ),
)

EXTRA_RULES: Sequence[str] = (
    "DOMAIN-SUFFIX,zed.dev",
    "DOMAIN,copilot-proxy.githubusercontent.com",
    "DOMAIN,origin-tracker.githubusercontent.com",
    "DOMAIN-SUFFIX,githubcopilot.com",
    "DOMAIN-SUFFIX,individual.githubcopilot.com",
    "DOMAIN-SUFFIX,business.githubcopilot.com",
    "DOMAIN-SUFFIX,enterprise.githubcopilot.com",
    "DOMAIN,copilot-telemetry.githubusercontent.com",
)

VALID_PREFIXES: Sequence[str] = (
    "DOMAIN,",
    "DOMAIN-SUFFIX,",
    "DOMAIN-KEYWORD,",
    "IP-CIDR,",
    "IP-CIDR6,",
    "IP-ASN,",
)


def fetch_text(url: str) -> str:
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:  # pragma: no cover - network failure
        raise SystemExit(f"Failed to download {url}: {exc}") from exc


def normalize_rule(rule: str) -> str | None:
    line = rule.strip()
    if not line:
        return None
    if line.startswith("#"):
        return None
    if line.startswith("-"):
        line = line[1:].strip()
    if line.startswith('"') and line.endswith('"'):
        line = line[1:-1].strip()
    if line.startswith("'") and line.endswith("'"):
        line = line[1:-1].strip()
    if not any(line.startswith(prefix) for prefix in VALID_PREFIXES):
        return None
    return line


def parse_upstream(content: str) -> List[str]:
    parsed: List[str] = []
    for raw_line in content.splitlines():
        normalized = normalize_rule(raw_line)
        if normalized:
            parsed.append(normalized)
    return parsed


def ordered_unique(items: Iterable[str]) -> List[str]:
    result: List[str] = []
    seen: set[str] = set()
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def sort_key(rule: str) -> tuple[int, str]:
    rule_type = rule.split(",", 1)[0]
    order = {
        "DOMAIN": 0,
        "DOMAIN-SUFFIX": 1,
        "DOMAIN-KEYWORD": 2,
        "IP-CIDR": 3,
        "IP-CIDR6": 4,
        "IP-ASN": 5,
    }.get(rule_type, 99)
    return (order, rule)


def main() -> None:
    collected: List[str] = []
    for _, url in SOURCES:
        collected.extend(parse_upstream(fetch_text(url)))
    collected.extend(EXTRA_RULES)
    rules = sorted(ordered_unique(collected), key=sort_key)

    timestamp = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    header = [
        "# DO NOT EDIT MANUALLY",
        f"# Generated on {timestamp}",
        "# Sources:",
        *[f"# - {name}: {url}" for name, url in SOURCES],
        "# - Custom additions: Copilot + Zed domains",
        "",
    ]

    TARGET_PATH.parent.mkdir(parents=True, exist_ok=True)
    TARGET_PATH.write_text("\n".join(header + rules) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
