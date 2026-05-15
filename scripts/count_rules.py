#!/usr/bin/env python3
"""Count rules listed in rules.yaml and print a console table.

The file format is intentionally simple:
- optional ``geox-url:`` blocks configure dat sources;
- comment lines start a group;
- ``name: https://...`` lines are downloaded and counted as rule files;
- other non-empty lines are treated as geosite tags by default;
- ``GEOSITE:tag`` and ``GEOIP:code`` prefixes are also supported.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from rich import box
    from rich.console import Console
    from rich.table import Table
except ImportError:  # pragma: no cover - exercised only without uv dependencies
    box = None
    Console = None
    Table = None


DEFAULT_GEOIP_URL = (
    "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"
)
DEFAULT_GEOSITE_URL = (
    "https://testingcf.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"
)
URL_RE = re.compile(r"https?://[^\s'\"]+")
LOCAL_REPO_MARKER = "/gh/oversized5107/proxy-client@"


@dataclass
class RuleItem:
    line: int
    label: str
    kind: str
    url: Optional[str] = None


@dataclass
class RuleGroup:
    line: int
    name: str
    items: list[RuleItem] = field(default_factory=list)


@dataclass
class RuleIndex:
    groups: list[RuleGroup]
    geoip_url: str
    geosite_url: str


class ProtoReader:
    def __init__(self, data: bytes):
        self.data = data
        self.index = 0

    def eof(self) -> bool:
        return self.index >= len(self.data)

    def read_varint(self) -> int:
        shift = 0
        value = 0
        while True:
            if self.index >= len(self.data):
                raise ValueError("unexpected end of protobuf varint")
            byte = self.data[self.index]
            self.index += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
            shift += 7

    def read_field(self) -> tuple[int, int]:
        key = self.read_varint()
        return key >> 3, key & 7

    def read_bytes(self) -> bytes:
        length = self.read_varint()
        end = self.index + length
        if end > len(self.data):
            raise ValueError("unexpected end of protobuf bytes field")
        chunk = self.data[self.index:end]
        self.index = end
        return chunk

    def skip(self, wire_type: int) -> None:
        if wire_type == 0:
            self.read_varint()
        elif wire_type == 1:
            self.index += 8
        elif wire_type == 2:
            self.read_bytes()
        elif wire_type == 5:
            self.index += 4
        else:
            raise ValueError(f"unsupported protobuf wire type: {wire_type}")
        if self.index > len(self.data):
            raise ValueError("unexpected end of protobuf field")


def line_indent(raw_line: str) -> int:
    return len(raw_line) - len(raw_line.lstrip(" "))


def parse_key_url(line: str) -> Optional[tuple[str, str]]:
    if ":" not in line:
        return None
    key, value = line.split(":", 1)
    match = URL_RE.search(value)
    if match:
        url = match.group(0)
        return key.strip(), url
    return None


def parse_rules(path: Path) -> RuleIndex:
    groups: list[RuleGroup] = []
    current: Optional[RuleGroup] = None
    geoip_url = DEFAULT_GEOIP_URL
    geosite_url = DEFAULT_GEOSITE_URL
    in_geox_url = False
    geox_indent = 0

    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        indent = line_indent(raw_line)
        line = raw_line.strip()
        if not line:
            continue

        if in_geox_url and indent <= geox_indent:
            in_geox_url = False

        if line == "geox-url:":
            in_geox_url = True
            geox_indent = indent
            continue

        if in_geox_url:
            key_url = parse_key_url(line)
            if key_url:
                key, url = key_url
                key_lower = key.lower()
                if key_lower == "geoip":
                    geoip_url = url
                elif key_lower == "geosite":
                    geosite_url = url
            continue

        if line.startswith("#"):
            current = RuleGroup(line=line_no, name=line.lstrip("#").strip())
            groups.append(current)
            continue

        key_url = parse_key_url(line)
        if key_url:
            key, url = key_url
            key_lower = key.lower()
            if key_lower == "geoip":
                geoip_url = url
                continue
            if key_lower == "geosite":
                geosite_url = url
                continue
            item = RuleItem(line=line_no, label=key, kind="url", url=url)
        else:
            item = RuleItem(line=line_no, label=line, kind="tag")

        if current is None:
            current = RuleGroup(line=0, name="未分组")
            groups.append(current)
        current.items.append(item)

    return RuleIndex(groups=groups, geoip_url=geoip_url, geosite_url=geosite_url)


def cache_path(cache_dir: Path, url: str) -> Path:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]
    suffix = Path(urllib.request.urlparse(url).path).suffix or ".dat"
    return cache_dir / f"{digest}{suffix}"


def fetch(url: str, cache_dir: Path, timeout: int, offline: bool) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    target = cache_path(cache_dir, url)
    if offline:
        if target.exists():
            return target
        raise FileNotFoundError(f"cache miss for {url}")

    request = urllib.request.Request(url, headers={"User-Agent": "proxy-client-rule-counter"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            target.write_bytes(response.read())
    except urllib.error.HTTPError as exc:
        if target.exists():
            print(f"warning: using cached copy after download failed: {url}: {exc}", file=sys.stderr)
            return target
        raise
    except (urllib.error.URLError, TimeoutError) as exc:
        if target.exists():
            print(f"warning: using cached copy after download failed: {url}: {exc}", file=sys.stderr)
            return target
        raise RuntimeError(f"download failed: {url}: {exc}") from exc
    return target


def local_repo_path(url: str, repo_root: Path) -> Optional[Path]:
    parsed = urllib.request.urlparse(url)
    if LOCAL_REPO_MARKER not in parsed.path:
        return None

    repo_ref_path = parsed.path.split(LOCAL_REPO_MARKER, 1)[1]
    _, _, relative_path = repo_ref_path.partition("/")
    if not relative_path:
        return None

    path = (repo_root / relative_path).resolve()
    try:
        path.relative_to(repo_root)
    except ValueError:
        return None
    if path.exists():
        return path
    return None


def count_rule_file(path: Path) -> int:
    count = 0
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if line in {"payload:", "payload: []"}:
            continue
        count += 1
    return count


def parse_geosite_attr(data: bytes) -> tuple[Optional[str], Optional[bool]]:
    reader = ProtoReader(data)
    key: Optional[str] = None
    value: Optional[bool] = None
    while not reader.eof():
        field_no, wire_type = reader.read_field()
        if field_no == 1 and wire_type == 2:
            key = reader.read_bytes().decode("utf-8", "replace")
        elif field_no == 2 and wire_type == 0:
            value = bool(reader.read_varint())
        else:
            reader.skip(wire_type)
    return key, value


def parse_geosite_domain(data: bytes) -> list[tuple[Optional[str], Optional[bool]]]:
    reader = ProtoReader(data)
    attrs: list[tuple[Optional[str], Optional[bool]]] = []
    while not reader.eof():
        field_no, wire_type = reader.read_field()
        if field_no == 3 and wire_type == 2:
            attrs.append(parse_geosite_attr(reader.read_bytes()))
        else:
            reader.skip(wire_type)
    return attrs


def parse_geosite_entry(data: bytes) -> tuple[Optional[str], list[list[tuple[Optional[str], Optional[bool]]]]]:
    reader = ProtoReader(data)
    code: Optional[str] = None
    domains: list[list[tuple[Optional[str], Optional[bool]]]] = []
    while not reader.eof():
        field_no, wire_type = reader.read_field()
        if field_no == 1 and wire_type == 2:
            code = reader.read_bytes().decode("utf-8", "replace")
        elif field_no == 2 and wire_type == 2:
            domains.append(parse_geosite_domain(reader.read_bytes()))
        else:
            reader.skip(wire_type)
    return code, domains


def parse_geosite_dat(path: Path) -> dict[str, list[list[tuple[Optional[str], Optional[bool]]]]]:
    sites: dict[str, list[list[tuple[Optional[str], Optional[bool]]]]] = {}
    reader = ProtoReader(path.read_bytes())
    while not reader.eof():
        field_no, wire_type = reader.read_field()
        if field_no == 1 and wire_type == 2:
            code, domains = parse_geosite_entry(reader.read_bytes())
            if code:
                sites[code.lower()] = domains
        else:
            reader.skip(wire_type)
    return sites


def parse_geoip_entry(data: bytes) -> tuple[Optional[str], int]:
    reader = ProtoReader(data)
    code: Optional[str] = None
    cidr_count = 0
    while not reader.eof():
        field_no, wire_type = reader.read_field()
        if field_no == 1 and wire_type == 2:
            code = reader.read_bytes().decode("utf-8", "replace")
        elif field_no == 2 and wire_type == 2:
            reader.read_bytes()
            cidr_count += 1
        else:
            reader.skip(wire_type)
    return code, cidr_count


def parse_geoip_dat(path: Path) -> dict[str, int]:
    geoips: dict[str, int] = {}
    reader = ProtoReader(path.read_bytes())
    while not reader.eof():
        field_no, wire_type = reader.read_field()
        if field_no == 1 and wire_type == 2:
            code, cidr_count = parse_geoip_entry(reader.read_bytes())
            if code:
                geoips[code.lower()] = cidr_count
        else:
            reader.skip(wire_type)
    return geoips


def count_geosite(tag: str, sites: dict[str, list[list[tuple[Optional[str], Optional[bool]]]]]) -> tuple[Optional[int], str]:
    raw = tag.strip()
    if raw.upper().startswith("GEOSITE:"):
        raw = raw.split(":", 1)[1].strip()
    normalized = raw.lower()

    # Prefer exact tags. Some tags, such as category-ai-!cn, exist directly.
    if normalized in sites:
        return len(sites[normalized]), "geosite"

    if "@" not in normalized:
        return None, "geosite missing"

    base, attr = normalized.split("@", 1)
    domains = sites.get(base)
    if domains is None:
        return None, "geosite missing"

    negated = attr.startswith("!")
    key = attr[1:] if negated else attr
    count = 0
    for domain_attrs in domains:
        has_attr = any(attr_key == key and attr_value is True for attr_key, attr_value in domain_attrs)
        if (not has_attr) if negated else has_attr:
            count += 1
    return count, f"geosite@{attr}"


def count_geoip(tag: str, geoips: dict[str, int]) -> tuple[Optional[int], str]:
    code = tag.split(":", 1)[1].strip().lower()
    if code in geoips:
        return geoips[code], "geoip"
    return None, "geoip missing"


def escape_cell(value: object) -> str:
    text = str(value).replace("\n", " ").replace("|", "\\|")
    if len(text) > 120:
        text = text[:117] + "..."
    return text


def format_error(exc: Exception) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}"
    if isinstance(exc, FileNotFoundError):
        return "CACHE MISS"
    if isinstance(exc, TimeoutError):
        return "TIMEOUT"
    if isinstance(exc, urllib.error.URLError):
        return "DOWNLOAD ERR"
    return exc.__class__.__name__


def print_table(rows: list[list[object]], width: int) -> None:
    if Console is not None and Table is not None and box is not None:
        console = Console(width=None if width <= 0 else width)
        table = Table(title="规则统计", box=box.ROUNDED, show_lines=False)
        table.add_column("分组", style="cyan", max_width=28)
        table.add_column("行", justify="right", style="dim")
        table.add_column("规则", overflow="fold", ratio=3)
        table.add_column("来源", style="magenta", no_wrap=True)
        table.add_column("数量", justify="right", style="green")
        table.add_column("状态", justify="center", no_wrap=True)

        for row in rows:
            status = str(row[5])
            status_style = "green"
            if status != "OK":
                status_style = "yellow" if status in {"EMPTY", "MISSING", "ZERO", "CHECK"} else "red"
            table.add_row(
                str(row[0]),
                str(row[1]),
                str(row[2]),
                str(row[3]),
                str(row[4]),
                f"[{status_style}]{status}[/{status_style}]",
            )

        console.print(table)
        return

    headers = ["分组", "行", "规则", "来源", "数量", "状态"]
    print("| " + " | ".join(headers) + " |")
    print("|---|---:|---|---|---:|---|")
    for row in rows:
        print("| " + " | ".join(escape_cell(cell) for cell in row) + " |")


def build_rows(args: argparse.Namespace) -> tuple[list[list[object]], bool]:
    index = parse_rules(args.rules)
    geosite_sites = None
    geoip_sites = None
    rows: list[list[object]] = []
    total = 0
    item_count = 0
    ok = True

    def get_geosite() -> dict[str, list[list[tuple[Optional[str], Optional[bool]]]]]:
        nonlocal geosite_sites
        if geosite_sites is None:
            path = fetch(index.geosite_url, args.cache_dir, args.timeout, args.offline)
            geosite_sites = parse_geosite_dat(path)
        return geosite_sites

    def get_geoip() -> dict[str, int]:
        nonlocal geoip_sites
        if geoip_sites is None:
            path = fetch(index.geoip_url, args.cache_dir, args.timeout, args.offline)
            geoip_sites = parse_geoip_dat(path)
        return geoip_sites

    for group in index.groups:
        if not group.items:
            rows.append([group.name, group.line, "(空分组)", "-", 0, "EMPTY"])
            ok = False
            continue

        for item in group.items:
            item_count += 1
            count: Optional[int]
            source: str
            status = "OK"
            try:
                if item.kind == "url":
                    assert item.url is not None
                    path = local_repo_path(item.url, args.repo_root)
                    source = "local" if path is not None else "url"
                    if path is None:
                        path = fetch(item.url, args.cache_dir, args.timeout, args.offline)
                    count = count_rule_file(path)
                elif item.label.upper().startswith("GEOIP:"):
                    count, source = count_geoip(item.label, get_geoip())
                else:
                    count, source = count_geosite(item.label, get_geosite())
                if count is None:
                    status = "MISSING"
                    ok = False
                elif count == 0:
                    status = "ZERO"
                    ok = False
                else:
                    total += count
            except Exception as exc:  # Keep the table useful when one source fails.
                count = "-"
                source = item.kind
                status = format_error(exc)
                ok = False
            rows.append([group.name, item.line, item.label, source, count, status])

    rows.append(["合计", "-", item_count, "-", total, "OK" if ok else "CHECK"])
    return rows, ok


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Count rules in rules.yaml and print a table.")
    parser.add_argument(
        "rules",
        nargs="?",
        type=Path,
        default=repo_root / "clash" / "rulesets" / "rules.yaml",
        help="rules.yaml path, defaults to clash/rulesets/rules.yaml",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(tempfile.gettempdir()) / "proxy-client-all-rules-cache",
        help="download cache directory",
    )
    parser.add_argument("--timeout", type=int, default=30, help="download timeout in seconds")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="use cached downloads only; fail rows whose cache files are missing",
    )
    parser.add_argument(
        "--width",
        type=int,
        default=140,
        help="Rich table width; use 0 to let Rich detect the terminal width",
    )
    args = parser.parse_args()
    args.repo_root = repo_root
    return args


def main() -> int:
    args = parse_args()
    rows, ok = build_rows(args)
    print_table(rows, args.width)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
