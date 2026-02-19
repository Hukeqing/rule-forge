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
BUILTIN_CONFIG: dict[str, Any] = {
    "port": 7890,
    "socks-port": 7891,
    "allow-lan": True,
    "mode": "Rule",
    "log-level": "info",
    "external-controller": ":9090",
}
BUILTIN_PROXY_PROVIDERS: dict[str, dict[str, Any]] = {
    "providers": {
        "type": "file",
        "path": "./sub.yaml",
        "health-check": {
            "enable": True,
            "interval": 600,
            "lazy": True,
            "url": "https://www.gstatic.com/generate_204",
        },
    }
}


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


def entity_rules(entity_data: dict[str, Any], group: str) -> list[str]:
    lines: list[str] = []
    for field, rule_type, with_no_resolve in ENTITY_FIELD_TO_RULE_TYPE:
        values = entity_data.get(field, [])
        if not isinstance(values, list):
            continue
        for value in values:
            text = str(value).strip()
            if not text:
                continue
            line = f"{rule_type},{text},{group}"
            if with_no_resolve:
                line = f"{line},no-resolve"
            lines.append(line)
    return lines


def build_config(base_dir: Path) -> dict[str, Any]:
    policies_dir = base_dir / "policies"
    entities_dir = base_dir / "entities"

    config = dict(BUILTIN_CONFIG)
    groups = load_yaml(policies_dir / "groups.yaml")
    policy_rules = load_yaml(policies_dir / "rule.yaml")

    all_entities = sorted_entity_files(entities_dir)
    entity_cache: dict[Path, dict[str, Any]] = {}

    def get_entity(path: Path) -> dict[str, Any]:
        if path not in entity_cache:
            data = load_yaml(path)
            entity_cache[path] = data if isinstance(data, dict) else {}
        return entity_cache[path]

    rules: list[str] = []
    emitted_rules: set[str] = set()
    assigned_entities: set[Path] = set()
    default_group: str | None = None

    for item in policy_rules:
        if not isinstance(item, dict):
            continue

        group = item.get("group")
        if not group:
            continue

        if item.get("name") == "default":
            default_group = str(group)
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
            for line in entity_rules(data, str(group)):
                if line in emitted_rules:
                    continue
                rules.append(line)
                emitted_rules.add(line)

    if default_group:
        rules.append(f"MATCH,{default_group}")

    config["proxy-providers"] = BUILTIN_PROXY_PROVIDERS

    if isinstance(groups, list):
        config["proxy-groups"] = groups

    config["rules"] = rules
    return config


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate Clash config from policies and entities.")
    parser.add_argument(
        "-o",
        "--output",
        default="clash.generated.yaml",
        help="Output file path (default: clash.generated.yaml)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base_dir = Path(__file__).resolve().parents[1]
    output_path = (base_dir / args.output).resolve()

    config = build_config(base_dir)
    if yaml is not None:
        with output_path.open("w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, sort_keys=False, allow_unicode=True)
    else:
        json_text = json.dumps(config, ensure_ascii=False)
        result = subprocess.run(
            [
                "ruby",
                "-e",
                "require 'yaml'; require 'json'; "
                "obj = JSON.parse(STDIN.read); "
                "puts YAML.dump(obj)",
            ],
            input=json_text,
            capture_output=True,
            text=True,
            check=True,
        )
        output_path.write_text(result.stdout, encoding="utf-8")

    print(f"Generated: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
