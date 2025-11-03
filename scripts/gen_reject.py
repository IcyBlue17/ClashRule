#!/usr/bin/env python3
"""Fetch upstream rule lists, convert them into Clash format, and simplify the result."""

from __future__ import annotations

import datetime
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Sequence, Set, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_PATH = REPO_ROOT / "ruleset" / "reject.list"


@dataclass(frozen=True)
class Source:
    kind: str
    url: str
    description: str


@dataclass(frozen=True)
class Rule:
    rtype: str
    value: str
    options: Tuple[str, ...] = ()

    def to_line(self) -> str:
        return ",".join((self.rtype, self.value, *self.options))


SOURCES: Sequence[Source] = (
    Source(
        kind="quanx",
        url="https://raw.githubusercontent.com/enriquephl/QuantumultX_config/main/filters/NoMalwares.conf",
        description="NoMalwares (Quantumult X)",
    ),
    Source(
        kind="quanx",
        url="https://raw.githubusercontent.com/Elysian-Realme/FuGfConfig/main/ConfigFile/QuantumultX/FuckRogueSoftwareRules.conf",
        description="FuckRogueSoftwareRules (Quantumult X)",
    ),
    Source(
        kind="surge",
        url="https://raw.githubusercontent.com/SukkaLab/ruleset.skk.moe/master/List/non_ip/reject-no-drop.conf",
        description="Reject No Drop (Surge)",
    ),
)

TYPE_MAP_QUANX = {
    "HOST": "DOMAIN",
    "HOST-SUFFIX": "DOMAIN-SUFFIX",
    "HOST-KEYWORD": "DOMAIN-KEYWORD",
    "HOST-WILDCARD": "DOMAIN-WILDCARD",
    "HOST-REGEX": "DOMAIN-REGEX",
    "IP-CIDR": "IP-CIDR",
    "IP6-CIDR": "IP-CIDR6",
}

TYPE_ORDER = {
    "DOMAIN": 0,
    "DOMAIN-SUFFIX": 1,
    "DOMAIN-KEYWORD": 2,
    "DOMAIN-WILDCARD": 3,
    "DOMAIN-REGEX": 4,
    "IP-CIDR": 5,
    "IP-CIDR6": 6,
}

DOMAIN_LIKE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
}

INLINE_COMMENT_RE = re.compile(r"\s+(#|//|;).*$")
REGEX_HAS_BOUNDARY = re.compile(r"^\^.*\$$")
LABEL_WITH_DIGITS = re.compile(r"[0-9]")


def strip_inline_comment(line: str) -> str:
    return INLINE_COMMENT_RE.sub("", line).strip()


def fetch_text(url: str) -> str:
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:  # pragma: no cover - network failure
        raise SystemExit(f"Failed to download {url}: {exc}") from exc


def normalize_regex(value: str) -> str:
    value = value.strip()
    if not REGEX_HAS_BOUNDARY.match(value):
        if not value.startswith("^"):
            value = "^" + value
        if not value.endswith("$"):
            value = value + "$"
    return value


def parse_quanx(content: str) -> Iterator[Rule]:
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//") or line.startswith(";"):
            continue
        line = strip_inline_comment(line)
        if not line:
            continue
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 2:
            continue
        kind_raw = parts[0].upper()
        kind = TYPE_MAP_QUANX.get(kind_raw)
        if not kind:
            print(f"[warn] Unsupported Quantumult X rule type: {kind_raw}", file=sys.stderr)
            continue
        value = parts[1].strip()
        if not value:
            continue
        remainder = [item for item in parts[2:] if item]
        options: List[str] = []
        if remainder:
            remainder = remainder[1:]
            options = [item.strip() for item in remainder if item.strip()]
        if kind in DOMAIN_LIKE_TYPES:
            value = value.lower()
        if kind == "DOMAIN-REGEX":
            value = normalize_regex(value)
        yield Rule(kind, value, tuple(options))


def parse_surge(content: str) -> Iterator[Rule]:
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//") or line.startswith(";"):
            continue
        line = strip_inline_comment(line)
        if not line:
            continue
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 2:
            continue
        kind = parts[0].upper()
        value = parts[1].strip()
        if not value:
            continue
        if kind in DOMAIN_LIKE_TYPES:
            value = value.lower()
        options: List[str] = []
        if len(parts) > 2:
            options = [opt.strip() for opt in parts[2:] if opt.strip()]
        if kind == "DOMAIN-REGEX":
            value = normalize_regex(value)
        yield Rule(kind, value, tuple(options))


def promote_dynamic_labels(rule: Rule) -> Rule | None:
    if rule.rtype != "DOMAIN":
        return None
    labels = rule.value.split(".")
    if len(labels) < 3:
        return None
    dynamic_positions = [
        idx for idx, label in enumerate(labels[:-2]) if LABEL_WITH_DIGITS.search(label) and len(label) >= 4
    ]
    if not dynamic_positions:
        return None
    new_labels = labels[:]
    for idx in dynamic_positions:
        new_labels[idx] = "*"
    wildcard_value = ".".join(new_labels)
    return Rule("DOMAIN-WILDCARD", wildcard_value, rule.options)


def simplify_rules(rules: Sequence[Rule]) -> List[Rule]:
    # Promote single entries with obviously dynamic labels
    promoted: List[Rule] = []
    consumed_indexes: Set[int] = set()
    for idx, rule in enumerate(rules):
        promoted_rule = promote_dynamic_labels(rule)
        if promoted_rule:
            promoted.append(promoted_rule)
            consumed_indexes.add(idx)

    remaining = [rule for idx, rule in enumerate(rules) if idx not in consumed_indexes]

    domain_indexes = [idx for idx, rule in enumerate(remaining) if rule.rtype == "DOMAIN"]
    suffix_map: Dict[Tuple[Tuple[str, ...], int], Set[int]] = defaultdict(set)
    for idx in domain_indexes:
        rule = remaining[idx]
        labels = rule.value.split(".")
        if len(labels) < 3:
            continue
        max_suffix_len = min(len(labels) - 1, 5)
        for suffix_len in range(2, max_suffix_len + 1):
            suffix = tuple(labels[-suffix_len:])
            prefix_count = len(labels) - suffix_len
            if prefix_count < 1:
                continue
            suffix_map[(suffix, prefix_count)].add(idx)

    removed: Set[int] = set()
    generalized: Set[Rule] = set()
    existing_rules: Set[Rule] = set(remaining)

    def candidate_key(item):
        (suffix, prefix_count), indexes = item
        return (-len(suffix), prefix_count, -len(indexes))

    for (suffix, prefix_count), indexes in sorted(suffix_map.items(), key=candidate_key):
        active_indexes = {idx for idx in indexes if idx not in removed}
        if len(active_indexes) < 2:
            continue
        options_set = {remaining[idx].options for idx in active_indexes}
        if len(options_set) != 1:
            continue
        options = options_set.pop()
        suffix_str = ".".join(suffix)
        if len(suffix) < 2 or suffix_str in {"com", "net", "org", "cn"}:
            continue
        if prefix_count == 1:
            new_rule = Rule("DOMAIN-WILDCARD", f"*.{suffix_str}", options)
        else:
            prefix_pattern = r"\.".join(["[^.]+"] * prefix_count)
            escaped_suffix = re.escape(suffix_str)
            regex = f"^{prefix_pattern}\\.{escaped_suffix}$"
            new_rule = Rule("DOMAIN-REGEX", regex, options)
        if new_rule in existing_rules:
            continue
        existing_rules.add(new_rule)
        generalized.add(new_rule)
        removed.update(active_indexes)

    simplified = [rule for idx, rule in enumerate(remaining) if idx not in removed]
    simplified.extend(sorted(generalized, key=lambda rule: (TYPE_ORDER.get(rule.rtype, 99), rule.value)))
    simplified.extend(promoted)

    unique_rules: List[Rule] = []
    seen: Set[Rule] = set()
    for rule in simplified:
        if rule not in seen:
            seen.add(rule)
            unique_rules.append(rule)
    return unique_rules


def sort_rules(lines: Iterable[str]) -> List[str]:
    def sort_key(item: str):
        rule_type, _, remainder = item.partition(",")
        order = TYPE_ORDER.get(rule_type, 99)
        return (order, rule_type, remainder)

    return sorted(lines, key=sort_key)


def main() -> None:
    collected: List[Rule] = []
    seen: Set[Rule] = set()
    for source in SOURCES:
        text = fetch_text(source.url)
        parser = parse_quanx if source.kind == "quanx" else parse_surge
        for rule in parser(text):
            if rule not in seen:
                seen.add(rule)
                collected.append(rule)

    simplified = simplify_rules(collected)
    lines = sort_rules(rule.to_line() for rule in simplified)
    header_lines = [
        "# DO NOT EDIT MANUALLY",
        f"# Generated on {datetime.datetime.utcnow().isoformat(timespec='seconds')}Z",
        "# Sources:",
        *[f"# - {source.description}: {source.url}" for source in SOURCES],
        "",
    ]
    TARGET_PATH.parent.mkdir(parents=True, exist_ok=True)
    TARGET_PATH.write_text("\n".join(header_lines + lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
