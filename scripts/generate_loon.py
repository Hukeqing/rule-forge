#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except ModuleNotFoundError:
    yaml = None


ENTITY_FIELD_TO_RULE_TYPE = (
    ("domains", "DOMAIN", False),
    ("suffix-domains", "DOMAIN-SUFFIX", False),
    ("keyword", "DOMAIN-KEYWORD", False),
    ("ipv4s", "IP-CIDR", True),
    ("ipv6s", "IP-CIDR6", True),
    ("geo-ips", "GEOIP", False),
)
EXCLUDED_ENTITY_REL_PATHS = {"demo.yaml"}


def load_yaml(path: Path) -> Any:
    raw_text = path.read_text(encoding="utf-8")
    normalized = re.sub(r"^(\s*-\s*)\*(\s*(?:#.*)?)$", r'\1"*"\2', raw_text, flags=re.MULTILINE)

    if yaml is not None:
        return yaml.safe_load(normalized) or {}

    result = subprocess.run(
        [
            "ruby",
            "-e",
            "require 'yaml'; require 'json'; "
            "obj = YAML.load(STDIN.read); "
            "puts JSON.dump(obj)",
        ],
        input=normalized,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout) if result.stdout.strip() else {}


def sorted_entity_files(entities_dir: Path) -> list[Path]:
    files: list[Path] = []
    for p in entities_dir.rglob("*.yaml"):
        if not p.is_file():
            continue
        rel = p.relative_to(entities_dir).as_posix()
        if rel in EXCLUDED_ENTITY_REL_PATHS:
            continue
        files.append(p)
    return sorted(files)


def resolve_entity_selector(entities_dir: Path, selector: str) -> list[Path]:
    selector = selector.strip()
    if not selector:
        return []

    if selector == "*":
        return sorted_entity_files(entities_dir)

    if "*" in selector or "?" in selector or "[" in selector:
        return sorted(p for p in entities_dir.glob(selector) if p.is_file() and p.suffix == ".yaml")

    if selector.endswith("/*"):
        target_dir = entities_dir / selector[:-2]
        if target_dir.is_dir():
            return sorted(p for p in target_dir.rglob("*.yaml") if p.is_file())
        return []

    target = entities_dir / selector
    if target.is_dir():
        return sorted(p for p in target.rglob("*.yaml") if p.is_file())

    if target.suffix:
        if target.is_file() and target.suffix == ".yaml":
            return [target]
        return []

    candidate = target.with_suffix(".yaml")
    if candidate.is_file():
        return [candidate]
    return []


def entity_loon_rules(entity_data: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for field, rule_type, with_no_resolve in ENTITY_FIELD_TO_RULE_TYPE:
        values = entity_data.get(field, [])
        if not isinstance(values, list):
            continue
        for value in values:
            text = str(value).strip()
            if not text:
                continue
            line = f"{rule_type},{text}"
            if with_no_resolve:
                line = f"{line},no-resolve"
            lines.append(line)
    return lines


def group_to_filename(group: str) -> str:
    normalized = re.sub(r"[^\w\u4e00-\u9fff]+", "-", group, flags=re.UNICODE).strip("-_")
    normalized = re.sub(r"-{2,}", "-", normalized)
    normalized = normalized.lower()
    return normalized


def build_loon_rules_by_group(base_dir: Path) -> dict[str, list[str]]:
    policies_dir = base_dir / "policies"
    entities_dir = base_dir / "entities"

    policy_rules = load_yaml(policies_dir / "rule.yaml")
    all_entities = sorted_entity_files(entities_dir)

    entity_cache: dict[Path, dict[str, Any]] = {}

    def get_entity(path: Path) -> dict[str, Any]:
        if path not in entity_cache:
            data = load_yaml(path)
            entity_cache[path] = data if isinstance(data, dict) else {}
        return entity_cache[path]

    group_rules: dict[str, list[str]] = {}
    group_emitted_rules: dict[str, set[str]] = {}
    assigned_entities: set[Path] = set()

    for item in policy_rules:
        if not isinstance(item, dict):
            continue

        if item.get("name") == "default":
            continue
        group = str(item.get("group", "")).strip()
        if not group:
            continue

        selected: list[Path] = []
        seen_in_item: set[Path] = set()

        for selector in item.get("entities", []) or []:
            for matched in resolve_entity_selector(entities_dir, str(selector)):
                if matched not in seen_in_item:
                    selected.append(matched)
                    seen_in_item.add(matched)

        tag_filters = {str(t) for t in (item.get("tags", []) or [])}
        if tag_filters:
            for entity_file in all_entities:
                data = get_entity(entity_file)
                tags = {str(t) for t in (data.get("tags", []) or [])}
                if tags & tag_filters and entity_file not in seen_in_item:
                    selected.append(entity_file)
                    seen_in_item.add(entity_file)

        for entity_file in selected:
            if entity_file in assigned_entities:
                continue
            assigned_entities.add(entity_file)

            data = get_entity(entity_file)
            for line in entity_loon_rules(data):
                if group not in group_emitted_rules:
                    group_emitted_rules[group] = set()
                    group_rules[group] = []
                if line in group_emitted_rules[group]:
                    continue
                group_rules[group].append(line)
                group_emitted_rules[group].add(line)

    return {group: lines for group, lines in group_rules.items() if lines}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate Loon rules from policies and entities.")
    parser.add_argument(
        "-o",
        "--output",
        default="loon",
        help="Output directory path (default: loon)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base_dir = Path(__file__).resolve().parents[1]
    output_dir = (base_dir / args.output).resolve()
    if output_dir.exists() and not output_dir.is_dir():
        raise RuntimeError(f"Output path exists and is not a directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    rules_by_group = build_loon_rules_by_group(base_dir)

    filename_count: dict[str, int] = {}
    generated_files: list[Path] = []
    for group, rules in rules_by_group.items():
        base_name = group_to_filename(group)
        if not base_name:
            base_name = "group"
        used = filename_count.get(base_name, 0)
        filename_count[base_name] = used + 1
        final_name = f"loon-{base_name}.txt" if used == 0 else f"loon-{base_name}-{used + 1}.txt"
        output_path = output_dir / final_name
        output_path.write_text("\n".join(rules) + "\n", encoding="utf-8")
        generated_files.append(output_path)

    print(f"Generated directory: {output_dir}")
    print(f"Generated files: {len(generated_files)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
