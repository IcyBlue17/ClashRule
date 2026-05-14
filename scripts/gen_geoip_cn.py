#!/usr/bin/env python3
"""Generate GeoIP-CN Clash rulesets from upstream ipset lists."""

from __future__ import annotations

import ipaddress
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable, List, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
RULESET_DIR = REPO_ROOT / "ruleset"

SOURCES: Sequence[tuple[str, str, str, str]] = (
    (
        "v4",
        "https://cira.moedove.com/china_domestic_backbone_v4.txt",
        "geoip-cn-v4.list",
        "IP-CIDR",
    ),
    (
        "v6",
        "https://cira.moedove.com/china_domestic_backbone_v6.txt",
        "geoip-cn-v6.list",
        "IP-CIDR6",
    ),
)


USER_AGENT = "Mozilla/5.0 (ClashRule geoip-cn updater; +https://github.com/IcyMichiko/ClashRule)"


def fetch_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:  # pragma: no cover - network failure
        raise SystemExit(f"Failed to download {url}: {exc}") from exc


def parse_cidrs(content: str, family: str) -> List[str]:
    want_v6 = family == "v6"
    parsed: List[str] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if network.version == 6 and not want_v6:
            continue
        if network.version == 4 and want_v6:
            continue
        parsed.append(network.with_prefixlen)
    return parsed


def ordered_unique(items: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def write_ruleset(target: Path, rule_type: str, source_url: str, cidrs: Sequence[str]) -> None:
    timestamp = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    header = [
        "# DO NOT EDIT MANUALLY",
        f"# Generated on {timestamp}",
        f"# Source: {source_url}",
        f"# Total: {len(cidrs)}",
        "",
    ]
    body = [f"{rule_type},{cidr},no-resolve" for cidr in cidrs]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(header + body) + "\n", encoding="utf-8")


def main() -> None:
    for family, url, filename, rule_type in SOURCES:
        cidrs = ordered_unique(parse_cidrs(fetch_text(url), family))
        write_ruleset(RULESET_DIR / filename, rule_type, url, cidrs)


if __name__ == "__main__":
    main()
