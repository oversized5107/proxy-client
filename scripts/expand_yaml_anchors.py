#!/usr/bin/env python3
"""Expand YAML anchors from the OpenClash source config.

The source file is intended for humans and may use anchors, aliases, merge keys,
comments, and helper-only top-level keys. The generated file is intended for
OpenClash and contains resolved values only.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - exercised only without PyYAML
    raise SystemExit(
        "PyYAML is required. Install it with: python3 -m pip install PyYAML"
    ) from exc


REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Target:
    source: Path
    output: Path


TARGETS = {
    "openclash": Target(
        source=REPO_ROOT / "clash" / "overwrite" / "openclash.src.yaml",
        output=REPO_ROOT / "clash" / "overwrite" / "openclash.yaml",
    ),
}

DEFAULT_TARGET = "openclash"

HELPER_KEYS = {
    "bootstrap_dns_servers",
    "global_dns_servers",
    "cn_dns_servers",
    "proxy_groups",
    "direct_groups",
    "auto_select",
    "hk_filter",
    "sg_filter",
    "jp_filter",
    "kr_filter",
    "us_filter",
    "tw_filter",
    "uk_filter",
    "tr_filter",
    "rule-anchor",
}


class ExpandedYamlDumper(yaml.SafeDumper):
    """YAML dumper that never reintroduces anchors for shared objects."""

    def ignore_aliases(self, data: Any) -> bool:
        return True

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        return super().increase_indent(flow, False)


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _represent_list(dumper: yaml.SafeDumper, data: list[Any]) -> yaml.SequenceNode:
    # Keep short scalar lists compact, for example DNS servers and proxy names.
    flow_style = bool(data) and len(data) <= 16 and all(_is_scalar(item) for item in data)
    return dumper.represent_sequence("tag:yaml.org,2002:seq", data, flow_style=flow_style)


ExpandedYamlDumper.add_representer(list, _represent_list)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Expand anchors in configured YAML targets."
    )
    parser.add_argument(
        "target_or_source",
        nargs="?",
        help=(
            "configured target name, or a source YAML path. "
            "Omit to expand all configured targets."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="expanded output YAML path for a single target or custom source path",
    )
    parser.add_argument(
        "--keep-helper-keys",
        action="store_true",
        help="keep top-level keys that only exist to define anchors",
    )
    return parser.parse_args()


def format_path(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def resolve_jobs(args: argparse.Namespace) -> list[tuple[str, Path, Path]]:
    if args.target_or_source is None:
        if args.output is not None:
            raise ValueError("--output can only be used with one target or source path")
        return [(name, target.source, target.output) for name, target in TARGETS.items()]

    if args.target_or_source in TARGETS:
        target = TARGETS[args.target_or_source]
        return [
            (
                args.target_or_source,
                target.source,
                args.output or target.output,
            )
        ]

    if args.output is None:
        raise ValueError("--output is required when using a custom source path")

    source = Path(args.target_or_source)
    output = args.output
    return [("custom", source, output)]


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def remove_helper_keys(config: Any) -> Any:
    if not isinstance(config, dict):
        raise TypeError("OpenClash config must be a YAML mapping at the top level")

    return {key: value for key, value in config.items() if key not in HELPER_KEYS}


def dump_yaml(config: Any) -> str:
    return yaml.dump(
        config,
        Dumper=ExpandedYamlDumper,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        width=10_000,
    )


def main() -> int:
    args = parse_args()
    try:
        jobs = resolve_jobs(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    for name, source, output in jobs:
        source = source.resolve()
        output = output.resolve()

        if not source.exists():
            print(f"source file does not exist: {source}", file=sys.stderr)
            return 1

        config = load_yaml(source)
        if not args.keep_helper_keys:
            config = remove_helper_keys(config)

        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(dump_yaml(config), encoding="utf-8")
        print(f"expanded {name}: {format_path(source)} -> {format_path(output)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
