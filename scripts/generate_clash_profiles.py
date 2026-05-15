#!/usr/bin/env python3
"""Generate static Clash/Mihomo profiles from source YAML profiles.

The generator expands YAML anchors, GEOSITE, GEOIP, and non-MRS RULE-SET rules
into plain static rules. RULE-SET entries backed by format: mrs providers are
kept as RULE-SET rules. Downloads and Mihomo validation artifacts are kept in a
single /tmp temporary directory for the duration of one run only.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
PROFILES_DIR = REPO_ROOT / "clash" / "profiles"
GENERATED_DIR = REPO_ROOT / "clash" / "generated"
FORBIDDEN_FINAL_RULE_TYPES = {"GEOSITE", "GEOIP"}
USER_AGENT = "proxy-client-profile-generator/1.0"
LOCAL_REPO_URL_MARKER = "/gh/oversized5107/proxy-client@"

# These keys only exist in this repository to define YAML anchors. Keeping them
# in generated profiles makes the output less likely to pass Mihomo validation.
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

ANCHOR_TOKEN_RE = re.compile(r"(^|[\s\[{])([&*])[-A-Za-z0-9_]+(?=$|[\s\]}])")


class ProfileGenerationError(RuntimeError):
    """Raised for profile generation and validation failures."""


class ExpandedYamlDumper(yaml.SafeDumper):
    """YAML dumper that never reintroduces anchors for shared objects."""

    def ignore_aliases(self, data: Any) -> bool:
        return True

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        return super().increase_indent(flow, False)


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, str | int | float | bool)


def _represent_list(dumper: yaml.SafeDumper, data: list[Any]) -> yaml.SequenceNode:
    flow_style = bool(data) and len(data) <= 16 and all(_is_scalar(item) for item in data)
    return dumper.represent_sequence("tag:yaml.org,2002:seq", data, flow_style=flow_style)


ExpandedYamlDumper.add_representer(list, _represent_list)


@dataclass(frozen=True)
class DownloadedContent:
    url: str
    path: Path
    data: bytes


@dataclass(frozen=True)
class GeoSiteDomain:
    domain_type: int
    value: str
    attrs: frozenset[str]


@dataclass(frozen=True)
class GeneratedProfile:
    source: Path
    output: Path
    rule_count: int
    duplicates_removed: int
    providers_removed: int


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
            if shift > 63:
                raise ValueError("protobuf varint is too long")

    def read_field(self) -> tuple[int, int]:
        key = self.read_varint()
        if key == 0:
            raise ValueError("invalid protobuf field key 0")
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


class Downloader:
    def __init__(self, temp_dir: Path, timeout: int, verbose: bool):
        self.temp_dir = temp_dir
        self.timeout = timeout
        self.verbose = verbose
        self.download_dir = temp_dir / "downloads"
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, DownloadedContent] = {}

    def fetch(self, profile_name: str, url: str, purpose: str) -> DownloadedContent:
        if not isinstance(url, str) or not url.strip():
            raise ProfileGenerationError(f"{profile_name}: {purpose} URL is empty or not a string")

        url = url.strip()
        if url in self._cache:
            if self.verbose:
                print(f"reuse {purpose}: {url}")
            return self._cache[url]

        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ProfileGenerationError(
                f"{profile_name}: unsupported URL scheme for {purpose}: {url}"
            )

        local_path = local_repo_url_path(url)
        if local_path is not None:
            if self.verbose:
                print(f"use local workspace copy for {purpose}: {url}")
            data = local_path.read_bytes()
            downloaded = self._store_download(url, parsed.path, data)
            self._cache[url] = downloaded
            return downloaded

        if self.verbose:
            print(f"download {purpose}: {url}")

        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = response.read()
        except urllib.error.HTTPError as exc:
            raise ProfileGenerationError(
                f"{profile_name}: failed to download {purpose}: {url}: HTTP {exc.code} {exc.reason}"
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ProfileGenerationError(
                f"{profile_name}: failed to download {purpose}: {url}: {exc}"
            ) from exc

        downloaded = self._store_download(url, parsed.path, data)
        self._cache[url] = downloaded
        return downloaded

    def _store_download(self, url: str, url_path: str, data: bytes) -> DownloadedContent:
        suffix = Path(url_path).suffix or ".download"
        if url_path.endswith(".tar.gz"):
            suffix = ".tar.gz"
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]
        target = self.download_dir / f"{digest}{suffix}"
        target.write_bytes(data)
        return DownloadedContent(url=url, path=target, data=data)


class RuleExpander:
    def __init__(self, downloader: Downloader, verbose: bool):
        self.downloader = downloader
        self.verbose = verbose
        self._provider_cache: dict[str, dict[str, Any]] = {}
        self._geosite_cache: dict[str, dict[str, list[GeoSiteDomain]]] = {}
        self._geoip_cache: dict[str, dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]] = {}

    def expand_profile_rules(self, profile_path: Path, config: dict[str, Any]) -> tuple[list[str], int, set[str]]:
        profile_name = profile_path.name
        rules = config.get("rules")
        if not isinstance(rules, list):
            raise ProfileGenerationError(f"{profile_name}: rules must exist and be a YAML list")

        expanded: list[str] = []
        processed_providers: set[str] = set()
        for raw_rule in rules:
            if not isinstance(raw_rule, str):
                raise ProfileGenerationError(
                    f"{profile_name}: rule must be a string: {raw_rule!r}"
                )
            rule_type = get_rule_type(raw_rule)
            if rule_type == "RULE-SET":
                ruleset_rules, provider_name, was_processed = self._expand_ruleset(profile_path, config, raw_rule)
                expanded.extend(ruleset_rules)
                if was_processed:
                    processed_providers.add(provider_name)
            elif rule_type == "GEOSITE":
                expanded.extend(self._expand_geosite(profile_path, config, raw_rule))
            elif rule_type == "GEOIP":
                expanded.extend(self._expand_geoip(profile_path, config, raw_rule))
            else:
                expanded.append(raw_rule.strip())

        deduped, duplicate_count = dedupe_rules(expanded)
        if duplicate_count and self.verbose:
            print(f"{profile_name}: removed {duplicate_count} duplicate rules")

        assert_no_forbidden_rules(profile_name, deduped, config)
        return deduped, duplicate_count, processed_providers

    def _expand_ruleset(self, profile_path: Path, config: dict[str, Any], raw_rule: str) -> tuple[list[str], str, bool]:
        profile_name = profile_path.name
        parts = split_rule(raw_rule, profile_name)
        if len(parts) < 3:
            raise rule_error(profile_name, raw_rule, "RULE-SET rule must be RULE-SET,<provider>,<policy>[,<extra>...]")

        provider_name = parts[1]
        action_parts = parts[2:]
        providers = config.get("rule-providers")
        if not isinstance(providers, dict):
            raise rule_error(profile_name, raw_rule, "rule-providers must exist and be a YAML mapping")
        provider = providers.get(provider_name)
        if provider is None:
            raise rule_error(profile_name, raw_rule, f"RULE-SET references missing provider {provider_name!r}")
        if not isinstance(provider, dict):
            raise rule_error(profile_name, raw_rule, f"provider {provider_name!r} must be a YAML mapping")

        provider_format = str(provider.get("format", "")).lower()
        if provider_format == "mrs":
            if self.verbose:
                print(f"{profile_name}: keep RULE-SET {provider_name} because provider is format: mrs")
            return [raw_rule.strip()], provider_name, False

        url = provider.get("url")
        if not isinstance(url, str) or not url.strip():
            raise rule_error(profile_name, raw_rule, f"provider {provider_name!r} has no valid url")

        behavior = str(provider.get("behavior", "classical")).lower()
        if behavior not in {"classical", "domain", "ipcidr"}:
            raise rule_error(
                profile_name,
                raw_rule,
                f"provider {provider_name!r} has unsupported behavior {behavior!r}",
            )

        provider_yaml = self._load_provider_yaml(profile_name, provider_name, url)
        payload = provider_yaml.get("payload")
        if not isinstance(payload, list):
            raise rule_error(
                profile_name,
                raw_rule,
                f"provider {provider_name!r} YAML must contain payload as a list",
            )

        if self.verbose:
            print(f"{profile_name}: expand RULE-SET {provider_name} ({behavior}) with {len(payload)} entries")

        if behavior == "classical":
            return (
                [
                    append_action_to_classical_rule(profile_name, raw_rule, item, action_parts)
                    for item in payload
                ],
                provider_name,
                True,
            )
        if behavior == "domain":
            return (
                [
                    join_rule_parts(domain_set_item_to_rule_parts(profile_name, raw_rule, item) + action_parts)
                    for item in payload
                ],
                provider_name,
                True,
            )
        return (
            [
                join_rule_parts(ipcidr_item_to_rule_parts(profile_name, raw_rule, item) + action_parts)
                for item in payload
            ],
            provider_name,
            True,
        )

    def _load_provider_yaml(self, profile_name: str, provider_name: str, url: str) -> dict[str, Any]:
        if url in self._provider_cache:
            return self._provider_cache[url]

        downloaded = self.downloader.fetch(profile_name, url, f"provider {provider_name}")
        try:
            text = downloaded.data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProfileGenerationError(
                f"{profile_name}: provider {provider_name!r} is not UTF-8 YAML: {url}: {exc}"
            ) from exc
        try:
            parsed = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ProfileGenerationError(
                f"{profile_name}: provider {provider_name!r} YAML parse failed: {url}: {exc}"
            ) from exc
        if not isinstance(parsed, dict):
            raise ProfileGenerationError(
                f"{profile_name}: provider {provider_name!r} is not a YAML mapping with payload: {url}"
            )
        self._provider_cache[url] = parsed
        return parsed

    def _expand_geosite(self, profile_path: Path, config: dict[str, Any], raw_rule: str) -> list[str]:
        profile_name = profile_path.name
        parts = split_rule(raw_rule, profile_name)
        if len(parts) < 3:
            raise rule_error(profile_name, raw_rule, "GEOSITE rule must be GEOSITE,<category>,<policy>[,<extra>...]")

        category_expr = parts[1]
        if category_expr.startswith("!"):
            raise rule_error(
                profile_name,
                raw_rule,
                "GEOSITE whole-category negation is not supported for static expansion",
            )

        geox_url = config.get("geox-url")
        if not isinstance(geox_url, dict) or not isinstance(geox_url.get("geosite"), str):
            raise rule_error(profile_name, raw_rule, "GEOSITE is used but geox-url.geosite is missing")
        geosite = self._load_geosite(profile_name, geox_url["geosite"])
        domains = filter_geosite_domains(profile_name, raw_rule, geosite, category_expr)
        action_parts = parts[2:]

        if self.verbose:
            print(f"{profile_name}: expand GEOSITE {category_expr} with {len(domains)} entries")

        expanded: list[str] = []
        for domain in domains:
            rule_prefix = geosite_domain_to_rule_parts(profile_name, raw_rule, domain)
            expanded.append(join_rule_parts(rule_prefix + action_parts))
        return expanded

    def _load_geosite(self, profile_name: str, url: str) -> dict[str, list[GeoSiteDomain]]:
        if url in self._geosite_cache:
            return self._geosite_cache[url]
        downloaded = self.downloader.fetch(profile_name, url, "geosite.dat")
        try:
            parsed = parse_geosite_dat(downloaded.data)
        except ValueError as exc:
            raise ProfileGenerationError(
                f"{profile_name}: geosite data format cannot be parsed: {url}: {exc}"
            ) from exc
        self._geosite_cache[url] = parsed
        return parsed

    def _expand_geoip(self, profile_path: Path, config: dict[str, Any], raw_rule: str) -> list[str]:
        profile_name = profile_path.name
        parts = split_rule(raw_rule, profile_name)
        if len(parts) < 3:
            raise rule_error(profile_name, raw_rule, "GEOIP rule must be GEOIP,<country>,<policy>[,<extra>...]")

        code = parts[1]
        if code.startswith("!"):
            raise rule_error(
                profile_name,
                raw_rule,
                "GEOIP country-code negation is not supported for static expansion",
            )

        geox_url = config.get("geox-url")
        if not isinstance(geox_url, dict) or not isinstance(geox_url.get("geoip"), str):
            raise rule_error(profile_name, raw_rule, "GEOIP is used but geox-url.geoip is missing")
        geoip = self._load_geoip(profile_name, geox_url["geoip"])
        networks = geoip.get(code.lower())
        if networks is None:
            raise rule_error(profile_name, raw_rule, f"geoip country code {code!r} does not exist")

        action_parts = parts[2:]
        if self.verbose:
            print(f"{profile_name}: expand GEOIP {code} with {len(networks)} entries")

        expanded: list[str] = []
        for network in networks:
            rule_type = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
            expanded.append(join_rule_parts([rule_type, str(network)] + action_parts))
        return expanded

    def _load_geoip(self, profile_name: str, url: str) -> dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
        if url in self._geoip_cache:
            return self._geoip_cache[url]
        downloaded = self.downloader.fetch(profile_name, url, "geoip.dat")
        try:
            parsed = parse_geoip_dat(downloaded.data)
        except ValueError as exc:
            raise ProfileGenerationError(
                f"{profile_name}: geoip data format cannot be parsed: {url}: {exc}"
            ) from exc
        self._geoip_cache[url] = parsed
        return parsed


def parse_geosite_attr(data: bytes) -> tuple[str | None, bool | None]:
    reader = ProtoReader(data)
    key: str | None = None
    bool_value: bool | None = None
    while not reader.eof():
        field_no, wire_type = reader.read_field()
        if field_no == 1 and wire_type == 2:
            key = reader.read_bytes().decode("utf-8")
        elif field_no == 2 and wire_type == 0:
            bool_value = bool(reader.read_varint())
        else:
            reader.skip(wire_type)
    return key, bool_value


def parse_geosite_domain(data: bytes) -> GeoSiteDomain:
    reader = ProtoReader(data)
    domain_type = 0
    value: str | None = None
    attrs: set[str] = set()
    while not reader.eof():
        field_no, wire_type = reader.read_field()
        if field_no == 1 and wire_type == 0:
            domain_type = reader.read_varint()
        elif field_no == 2 and wire_type == 2:
            value = reader.read_bytes().decode("utf-8")
        elif field_no == 3 and wire_type == 2:
            key, bool_value = parse_geosite_attr(reader.read_bytes())
            if key and bool_value is True:
                attrs.add(key.lower())
        else:
            reader.skip(wire_type)
    if value is None:
        raise ValueError("geosite domain entry is missing value")
    return GeoSiteDomain(domain_type=domain_type, value=value, attrs=frozenset(attrs))


def parse_geosite_entry(data: bytes) -> tuple[str | None, list[GeoSiteDomain]]:
    reader = ProtoReader(data)
    code: str | None = None
    domains: list[GeoSiteDomain] = []
    while not reader.eof():
        field_no, wire_type = reader.read_field()
        if field_no == 1 and wire_type == 2:
            code = reader.read_bytes().decode("utf-8")
        elif field_no == 2 and wire_type == 2:
            domains.append(parse_geosite_domain(reader.read_bytes()))
        else:
            reader.skip(wire_type)
    return code, domains


def parse_geosite_dat(data: bytes) -> dict[str, list[GeoSiteDomain]]:
    sites: dict[str, list[GeoSiteDomain]] = {}
    reader = ProtoReader(data)
    while not reader.eof():
        field_no, wire_type = reader.read_field()
        if field_no == 1 and wire_type == 2:
            code, domains = parse_geosite_entry(reader.read_bytes())
            if code:
                sites.setdefault(code.lower(), []).extend(domains)
        else:
            reader.skip(wire_type)

    if not sites or not any(domains for domains in sites.values()):
        raise ValueError("no geosite entries found")
    return sites


def parse_geoip_cidr(data: bytes) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    reader = ProtoReader(data)
    ip_bytes: bytes | None = None
    prefix: int | None = None
    while not reader.eof():
        field_no, wire_type = reader.read_field()
        if field_no == 1 and wire_type == 2:
            ip_bytes = reader.read_bytes()
        elif field_no == 2 and wire_type == 0:
            prefix = reader.read_varint()
        else:
            reader.skip(wire_type)

    if ip_bytes is None:
        raise ValueError("geoip CIDR entry is missing IP bytes")
    if len(ip_bytes) not in {4, 16}:
        raise ValueError(f"geoip CIDR has unsupported IP byte length {len(ip_bytes)}")
    if prefix is None:
        prefix = 0

    ip_addr = ipaddress.ip_address(ip_bytes)
    return ipaddress.ip_network(f"{ip_addr}/{prefix}", strict=False)


def parse_geoip_entry(data: bytes) -> tuple[str | None, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    reader = ProtoReader(data)
    code: str | None = None
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    while not reader.eof():
        field_no, wire_type = reader.read_field()
        if field_no == 1 and wire_type == 2:
            code = reader.read_bytes().decode("utf-8")
        elif field_no == 2 and wire_type == 2:
            networks.append(parse_geoip_cidr(reader.read_bytes()))
        else:
            reader.skip(wire_type)
    return code, networks


def parse_geoip_dat(data: bytes) -> dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    geoips: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {}
    reader = ProtoReader(data)
    while not reader.eof():
        field_no, wire_type = reader.read_field()
        if field_no == 1 and wire_type == 2:
            code, networks = parse_geoip_entry(reader.read_bytes())
            if code:
                geoips.setdefault(code.lower(), []).extend(networks)
        else:
            reader.skip(wire_type)

    if not geoips or not any(networks for networks in geoips.values()):
        raise ValueError("no geoip entries found")
    return geoips


def rule_error(profile_name: str, raw_rule: str, reason: str) -> ProfileGenerationError:
    return ProfileGenerationError(f"{profile_name}: rule {raw_rule!r}: {reason}")


def get_rule_type(rule: str) -> str:
    return rule.split(",", 1)[0].strip().upper()


def local_repo_url_path(url: str) -> Path | None:
    parsed = urllib.parse.urlparse(url)
    if LOCAL_REPO_URL_MARKER not in parsed.path:
        return None

    repo_ref_path = parsed.path.split(LOCAL_REPO_URL_MARKER, 1)[1]
    _, _, relative_path = repo_ref_path.partition("/")
    if not relative_path:
        return None

    path = (REPO_ROOT / relative_path).resolve()
    try:
        path.relative_to(REPO_ROOT)
    except ValueError:
        return None
    if path.exists() and path.is_file():
        return path
    return None


def split_rule(rule: str, profile_name: str) -> list[str]:
    parts = [part.strip() for part in rule.split(",")]
    if not parts or not parts[0]:
        raise ProfileGenerationError(f"{profile_name}: empty rule: {rule!r}")
    return parts


def join_rule_parts(parts: list[str]) -> str:
    return ",".join(str(part).strip() for part in parts)


def append_action_to_classical_rule(
    profile_name: str,
    raw_rule: str,
    payload_item: Any,
    action_parts: list[str],
) -> str:
    if not isinstance(payload_item, str) or not payload_item.strip():
        raise rule_error(profile_name, raw_rule, f"classical provider payload item is not a rule string: {payload_item!r}")

    item_parts = split_rule(payload_item.strip(), profile_name)
    item_type = item_parts[0].upper()
    if item_type == "MATCH":
        return join_rule_parts(item_parts[:1] + action_parts + item_parts[1:])
    if len(item_parts) < 2:
        raise rule_error(profile_name, raw_rule, f"classical provider rule is incomplete: {payload_item!r}")
    return join_rule_parts(item_parts[:2] + action_parts + item_parts[2:])


def domain_set_item_to_rule_parts(profile_name: str, raw_rule: str, payload_item: Any) -> list[str]:
    if not isinstance(payload_item, str) or not payload_item.strip():
        raise rule_error(profile_name, raw_rule, f"domain provider payload item is not a string: {payload_item!r}")

    item = payload_item.strip()
    lower = item.lower()
    if item.startswith("+.") and len(item) > 2:
        return ["DOMAIN-SUFFIX", item[2:]]
    if item.startswith(".") and len(item) > 1:
        return ["DOMAIN-SUFFIX", item[1:]]
    if item.startswith("*.") and len(item) > 2:
        return ["DOMAIN-WILDCARD", item]
    if lower.startswith("keyword:") and len(item) > len("keyword:"):
        return ["DOMAIN-KEYWORD", item.split(":", 1)[1]]
    if lower.startswith("regexp:") and len(item) > len("regexp:"):
        return ["DOMAIN-REGEX", item.split(":", 1)[1]]
    if lower.startswith("full:") and len(item) > len("full:"):
        return ["DOMAIN", item.split(":", 1)[1]]
    if lower.startswith("domain:") and len(item) > len("domain:"):
        return ["DOMAIN-SUFFIX", item.split(":", 1)[1]]
    if any(token in item for token in ["/", ",", " ", "\t"]):
        raise rule_error(profile_name, raw_rule, f"cannot reliably convert domain-set item {item!r}")
    if item.startswith(("+", "*", ":")) or item.endswith("."):
        raise rule_error(profile_name, raw_rule, f"cannot reliably convert domain-set item {item!r}")
    return ["DOMAIN", item]


def ipcidr_item_to_rule_parts(profile_name: str, raw_rule: str, payload_item: Any) -> list[str]:
    if not isinstance(payload_item, str) or not payload_item.strip():
        raise rule_error(profile_name, raw_rule, f"ipcidr provider payload item is not a string: {payload_item!r}")
    item = payload_item.strip()
    if "," in item:
        raise rule_error(profile_name, raw_rule, f"ipcidr provider payload item must be a bare CIDR: {item!r}")
    try:
        network = ipaddress.ip_network(item, strict=False)
    except ValueError as exc:
        raise rule_error(profile_name, raw_rule, f"invalid ipcidr provider payload item {item!r}: {exc}") from exc
    rule_type = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
    return [rule_type, str(network)]


def filter_geosite_domains(
    profile_name: str,
    raw_rule: str,
    geosite: dict[str, list[GeoSiteDomain]],
    category_expr: str,
) -> list[GeoSiteDomain]:
    normalized = category_expr.lower()
    if normalized in geosite:
        return geosite[normalized]

    if "@" not in normalized:
        raise rule_error(profile_name, raw_rule, f"geosite category {category_expr!r} does not exist")

    category, attr_expr = normalized.split("@", 1)
    if category.startswith("!"):
        raise rule_error(
            profile_name,
            raw_rule,
            "GEOSITE whole-category negation is not supported for static expansion",
        )
    if not category or not attr_expr:
        raise rule_error(profile_name, raw_rule, f"invalid GEOSITE attribute expression {category_expr!r}")

    domains = geosite.get(category)
    if domains is None:
        raise rule_error(profile_name, raw_rule, f"geosite category {category!r} does not exist")

    negated = attr_expr.startswith("!")
    attr = attr_expr[1:] if negated else attr_expr
    if not attr or attr.startswith("!"):
        raise rule_error(profile_name, raw_rule, f"invalid GEOSITE attribute expression {category_expr!r}")

    filtered = [domain for domain in domains if ((attr not in domain.attrs) if negated else (attr in domain.attrs))]
    if not filtered:
        if negated:
            raise rule_error(
                profile_name,
                raw_rule,
                f"geosite category {category!r} has no entries left after @!{attr} filtering",
            )
        raise rule_error(
            profile_name,
            raw_rule,
            f"geosite category {category!r} has no entries with attribute {attr!r}",
        )
    return filtered


def geosite_domain_to_rule_parts(profile_name: str, raw_rule: str, domain: GeoSiteDomain) -> list[str]:
    if domain.domain_type == 0:
        return ["DOMAIN-KEYWORD", domain.value]
    if domain.domain_type == 1:
        return ["DOMAIN-REGEX", domain.value]
    if domain.domain_type == 2:
        return ["DOMAIN-SUFFIX", domain.value]
    if domain.domain_type == 3:
        return ["DOMAIN", domain.value]
    raise rule_error(profile_name, raw_rule, f"unsupported geosite domain type {domain.domain_type} for {domain.value!r}")


def dedupe_rules(rules: list[str]) -> tuple[list[str], int]:
    seen: set[str] = set()
    deduped: list[str] = []
    duplicate_count = 0
    for rule in rules:
        if rule in seen:
            duplicate_count += 1
            continue
        seen.add(rule)
        deduped.append(rule)
    return deduped, duplicate_count


def assert_no_forbidden_rules(profile_name: str, rules: list[str], config: dict[str, Any]) -> None:
    for rule in rules:
        rule_type = get_rule_type(rule)
        if rule_type in FORBIDDEN_FINAL_RULE_TYPES:
            raise rule_error(profile_name, rule, f"expanded rules still contain {rule_type}")
        if rule_type == "RULE-SET" and not is_mrs_ruleset_rule(profile_name, rule, config):
            raise rule_error(
                profile_name,
                rule,
                "expanded rules contain RULE-SET that is not backed by a retained format: mrs provider",
            )


def is_mrs_ruleset_rule(profile_name: str, rule: str, config: dict[str, Any]) -> bool:
    parts = split_rule(rule, profile_name)
    if len(parts) < 2:
        return False
    providers = config.get("rule-providers")
    if not isinstance(providers, dict):
        return False
    provider = providers.get(parts[1])
    return isinstance(provider, dict) and str(provider.get("format", "")).lower() == "mrs"


def remove_processed_rule_providers(config: dict[str, Any], processed_providers: set[str]) -> int:
    providers = config.get("rule-providers")
    if not processed_providers or not isinstance(providers, dict):
        return 0
    removed = 0
    for provider_name in processed_providers:
        if provider_name in providers:
            del providers[provider_name]
            removed += 1
    return removed


def load_profile(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as file:
            parsed = yaml.safe_load(file)
    except yaml.YAMLError as exc:
        raise ProfileGenerationError(f"{path.name}: YAML profile parse failed: {exc}") from exc
    except OSError as exc:
        raise ProfileGenerationError(f"{path.name}: failed to read profile: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ProfileGenerationError(f"{path.name}: YAML profile must be a mapping at the top level")
    return parsed


def strip_helper_keys(config: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in config.items() if key not in HELPER_KEYS}


def dump_yaml(config: dict[str, Any]) -> str:
    return yaml.dump(
        config,
        Dumper=ExpandedYamlDumper,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        width=10_000,
    )


def has_merge_key(value: Any) -> bool:
    if isinstance(value, dict):
        return any(key == "<<" or has_merge_key(child) for key, child in value.items())
    if isinstance(value, list):
        return any(has_merge_key(child) for child in value)
    return False


def validate_generated_yaml(source: Path, output: Path, original_config: dict[str, Any]) -> None:
    text = output.read_text(encoding="utf-8")
    if ANCHOR_TOKEN_RE.search(text):
        raise ProfileGenerationError(f"{output.name}: generated YAML still contains an anchor or alias token")
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ProfileGenerationError(f"{output.name}: generated YAML cannot be parsed: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ProfileGenerationError(f"{output.name}: generated YAML must be a top-level mapping")
    if has_merge_key(parsed):
        raise ProfileGenerationError(f"{output.name}: generated YAML still contains a merge key")
    rules = parsed.get("rules")
    if not isinstance(rules, list):
        raise ProfileGenerationError(f"{output.name}: generated YAML rules must be a list")
    assert_no_forbidden_rules(output.name, [rule for rule in rules if isinstance(rule, str)], parsed)

    if "rule-providers" in original_config and "rule-providers" not in parsed:
        raise ProfileGenerationError(f"{output.name}: generated YAML did not preserve rule-providers")
    if "geox-url" in original_config and "geox-url" not in parsed:
        raise ProfileGenerationError(f"{output.name}: generated YAML did not preserve geox-url")

    seen: set[str] = set()
    for rule in rules:
        if not isinstance(rule, str):
            raise ProfileGenerationError(f"{output.name}: generated rule is not a string: {rule!r}")
        if rule in seen:
            raise ProfileGenerationError(f"{output.name}: generated rules still contain duplicate rule {rule!r}")
        seen.add(rule)


def generate_one_profile(profile_path: Path, expander: RuleExpander) -> GeneratedProfile:
    original_config = load_profile(profile_path)
    config = strip_helper_keys(original_config)
    expanded_rules, duplicates_removed, processed_providers = expander.expand_profile_rules(profile_path, config)
    config["rules"] = expanded_rules
    providers_removed = remove_processed_rule_providers(config, processed_providers)

    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    output_path = GENERATED_DIR / profile_path.name
    output_path.write_text(dump_yaml(config), encoding="utf-8")
    validate_generated_yaml(profile_path, output_path, original_config)
    return GeneratedProfile(
        source=profile_path,
        output=output_path,
        rule_count=len(expanded_rules),
        duplicates_removed=duplicates_removed,
        providers_removed=providers_removed,
    )


def resolve_profiles(args: argparse.Namespace) -> list[Path]:
    if args.profile:
        profiles = [Path(args.profile)]
    else:
        profiles = sorted({*PROFILES_DIR.glob("*.yaml"), *PROFILES_DIR.glob("*.yml")})

    resolved: list[Path] = []
    for profile in profiles:
        if not profile.is_absolute():
            profile = (REPO_ROOT / profile).resolve()
        if not profile.exists():
            raise ProfileGenerationError(f"profile does not exist: {profile}")
        try:
            profile.relative_to(PROFILES_DIR.resolve())
        except ValueError as exc:
            raise ProfileGenerationError(f"profile must be under {PROFILES_DIR}: {profile}") from exc
        if profile.suffix.lower() not in {".yaml", ".yml"}:
            raise ProfileGenerationError(f"profile must be a .yaml or .yml file: {profile}")
        resolved.append(profile)

    if not resolved:
        raise ProfileGenerationError(f"no profiles found under {PROFILES_DIR}")
    return resolved


def normalize_machine() -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return "amd64"
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    raise ProfileGenerationError(f"unsupported CPU architecture for Mihomo download: {platform.machine()}")


def normalize_system() -> str:
    system = platform.system()
    if system == "Linux":
        return "linux"
    if system == "Darwin":
        return "darwin"
    if system == "Windows":
        return "windows"
    raise ProfileGenerationError(f"unsupported platform for Mihomo download: {system}")


def mihomo_asset_score(asset_name: str, system_name: str, arch: str) -> int | None:
    lower = asset_name.lower()
    if system_name not in lower or arch not in lower:
        return None
    if any(token in lower for token in [".sha", "checksums", "digest", ".deb", ".rpm", ".apk"]):
        return None
    if not lower.endswith((".gz", ".zip", ".tar.gz", ".exe")):
        return None

    score = 100
    if system_name == "linux" and "android" in lower:
        return None
    if arch == "amd64":
        if "amd64-v3" in lower:
            score -= 30
        elif "amd64-v2" in lower:
            score -= 20
        elif "amd64-v1" in lower or "compatible" in lower:
            score += 15
        else:
            score += 20
    if lower.endswith(".tar.gz"):
        score += 3
    elif lower.endswith(".gz"):
        score += 2
    elif lower.endswith(".zip"):
        score += 1
    return score


def select_mihomo_asset(release: dict[str, Any]) -> tuple[str, str]:
    system_name = normalize_system()
    arch = normalize_machine()
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ProfileGenerationError("GitHub latest release response does not contain an assets list")

    candidates: list[tuple[int, str, str]] = []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = asset.get("name")
        url = asset.get("browser_download_url")
        if not isinstance(name, str) or not isinstance(url, str):
            continue
        score = mihomo_asset_score(name, system_name, arch)
        if score is not None:
            candidates.append((score, name, url))

    if not candidates:
        raise ProfileGenerationError(
            f"no suitable Mihomo release asset found for {platform.system()} {platform.machine()}"
        )
    candidates.sort(reverse=True)
    _, name, url = candidates[0]
    return name, url


def safe_extract_tar(archive: Path, target_dir: Path) -> None:
    target_resolved = target_dir.resolve()
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            member_path = (target_dir / member.name).resolve()
            try:
                member_path.relative_to(target_resolved)
            except ValueError as exc:
                raise ProfileGenerationError(f"Mihomo archive contains unsafe path: {member.name}") from exc
        tar.extractall(target_dir)


def safe_extract_zip(archive: Path, target_dir: Path) -> None:
    target_resolved = target_dir.resolve()
    with zipfile.ZipFile(archive) as zip_file:
        for name in zip_file.namelist():
            member_path = (target_dir / name).resolve()
            try:
                member_path.relative_to(target_resolved)
            except ValueError as exc:
                raise ProfileGenerationError(f"Mihomo archive contains unsafe path: {name}") from exc
        zip_file.extractall(target_dir)


def extract_mihomo_binary(archive: Path, target_dir: Path, binary_name: str) -> Path:
    target_dir.mkdir(parents=True, exist_ok=True)
    lower = archive.name.lower()
    try:
        if lower.endswith(".tar.gz"):
            safe_extract_tar(archive, target_dir)
        elif lower.endswith(".zip"):
            safe_extract_zip(archive, target_dir)
        elif lower.endswith(".gz"):
            output = target_dir / binary_name
            with gzip.open(archive, "rb") as source, output.open("wb") as dest:
                shutil.copyfileobj(source, dest)
        else:
            shutil.copy2(archive, target_dir / binary_name)
    except (OSError, tarfile.TarError, zipfile.BadZipFile, EOFError) as exc:
        raise ProfileGenerationError(f"failed to extract Mihomo archive {archive}: {exc}") from exc

    binary = find_mihomo_binary(target_dir)
    make_executable(binary)
    return binary


def find_mihomo_binary(root: Path) -> Path:
    candidates: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        lower = path.name.lower()
        if lower in {"mihomo", "mihomo.exe"} or lower.startswith("mihomo-"):
            if not lower.endswith((".yaml", ".yml", ".txt", ".md", ".json")):
                candidates.append(path)
    if not candidates:
        raise ProfileGenerationError(f"could not find Mihomo executable in extracted archive {root}")
    candidates.sort(key=lambda path: (len(path.parts), len(path.name)))
    return candidates[0]


def make_executable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    if not os.access(path, os.X_OK):
        raise ProfileGenerationError(f"Mihomo binary is not executable: {path}")


def download_mihomo(downloader: Downloader) -> Path:
    release_url = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
    downloaded_release = downloader.fetch("mihomo", release_url, "Mihomo latest release metadata")
    try:
        release = json.loads(downloaded_release.data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileGenerationError(f"failed to parse Mihomo release metadata: {exc}") from exc
    asset_name, asset_url = select_mihomo_asset(release)
    if downloader.verbose:
        print(f"download Mihomo asset: {asset_name}")
    archive = downloader.fetch("mihomo", asset_url, f"Mihomo asset {asset_name}")
    binary_name = "mihomo.exe" if asset_name.lower().endswith(".exe") or ".exe." in asset_name.lower() else "mihomo"
    return extract_mihomo_binary(archive.path, downloader.temp_dir / "mihomo", binary_name)


def resolve_mihomo_binary(args: argparse.Namespace, downloader: Downloader) -> Path:
    if args.mihomo_path:
        path = Path(args.mihomo_path)
        if not path.exists():
            raise ProfileGenerationError(f"Mihomo binary does not exist: {path}")
        if not path.is_file():
            raise ProfileGenerationError(f"Mihomo path is not a file: {path}")
        if not os.access(path, os.X_OK):
            raise ProfileGenerationError(f"Mihomo binary is not executable: {path}")
        return path
    return download_mihomo(downloader)


def validate_with_mihomo(generated: list[GeneratedProfile], mihomo_path: Path) -> None:
    for profile in generated:
        command = [str(mihomo_path), "-t", "-f", str(profile.output)]
        completed = subprocess.run(command, text=True, capture_output=True, check=False)
        if completed.returncode != 0:
            raise ProfileGenerationError(
                "Mihomo validation failed\n"
                f"profile: {profile.output}\n"
                f"mihomo: {mihomo_path}\n"
                f"command: {' '.join(command)}\n"
                f"exit code: {completed.returncode}\n"
                f"stdout:\n{completed.stdout}\n"
                f"stderr:\n{completed.stderr}"
            )


def format_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate static Clash/Mihomo profiles from clash/profiles."
    )
    parser.add_argument(
        "--profile",
        type=Path,
        help="only process one profile under clash/profiles",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print download, expansion, and deduplication details",
    )
    parser.add_argument(
        "--validate-with-mihomo",
        action="store_true",
        help="download Mihomo into /tmp and validate generated profiles",
    )
    parser.add_argument(
        "--mihomo-path",
        type=Path,
        help="use this Mihomo binary for validation instead of downloading one",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="download timeout in seconds",
    )
    return parser.parse_args()


def run(args: argparse.Namespace) -> list[GeneratedProfile]:
    profiles = resolve_profiles(args)
    with tempfile.TemporaryDirectory(dir="/tmp") as temp_name:
        temp_dir = Path(temp_name)
        if args.verbose:
            print(f"temporary directory: {temp_dir}")
        downloader = Downloader(temp_dir=temp_dir, timeout=args.timeout, verbose=args.verbose)
        expander = RuleExpander(downloader=downloader, verbose=args.verbose)
        generated: list[GeneratedProfile] = []
        for profile in profiles:
            result = generate_one_profile(profile, expander)
            generated.append(result)
            print(
                f"generated {format_path(result.source)} -> {format_path(result.output)} "
                f"({result.rule_count} rules, {result.duplicates_removed} duplicates removed, "
                f"{result.providers_removed} providers removed)"
            )

        if args.validate_with_mihomo or args.mihomo_path:
            if not generated:
                raise ProfileGenerationError("no profiles were generated, so Mihomo validation cannot run")
            mihomo_path = resolve_mihomo_binary(args, downloader)
            validate_with_mihomo(generated, mihomo_path)
            print(f"mihomo validation passed for {len(generated)} generated profile(s)")
        return generated


def main() -> int:
    args = parse_args()
    try:
        run(args)
    except ProfileGenerationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
