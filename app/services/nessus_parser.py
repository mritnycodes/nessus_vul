"""Parse Nessus .nessus / XML exports; match on local tag names (namespace-safe)."""
from __future__ import annotations

import io
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import BinaryIO, Iterator, List, Optional


def _local(tag: str) -> str:
    if tag.startswith("{"):
        return tag.split("}", 1)[-1]
    return tag


def _child_text_by_local(parent: ET.Element, local: str) -> Optional[str]:
    for ch in parent:
        if _local(ch.tag) == local and ch.text and ch.text.strip():
            return ch.text.strip()
    return None


def _float_or_none(s: Optional[str]) -> Optional[float]:
    if s is None:
        return None
    try:
        return float(s.strip())
    except (TypeError, ValueError):
        return None


def _nessus_severity_to_label(raw: str) -> str:
    s = (raw or "").strip().lower()
    mapping = {
        "0": "info",
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "critical",
        "info": "info",
        "informational": "info",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }
    return mapping.get(s, "info")


def _parse_port(raw: Optional[str]) -> int:
    if not raw:
        return 0
    raw = raw.strip()
    if raw.isdigit():
        return int(raw)
    return 0


def _hostname_from_host_properties(host_props: Optional[ET.Element]) -> Optional[str]:
    if host_props is None:
        return None
    candidates = ("host-fqdn", "hostname", "host-ip", "netbios-name")
    tags: dict[str, str] = {}
    for ch in host_props:
        if _local(ch.tag) != "tag":
            continue
        name = ch.attrib.get("name")
        if name and ch.text and ch.text.strip():
            tags[name.lower()] = ch.text.strip()
    for key in candidates:
        v = tags.get(key)
        if v:
            return v
    return None


@dataclass
class ParsedFinding:
    ip_address: str
    hostname: Optional[str]
    plugin_id: str
    name: str
    port: int
    protocol: str
    severity: str
    cvss_score: Optional[float]


def _iter_report_hosts(root: ET.Element) -> Iterator[ET.Element]:
    for el in root.iter():
        if _local(el.tag) == "ReportHost":
            yield el


def _report_items(report_host: ET.Element) -> Iterator[ET.Element]:
    for ch in report_host:
        if _local(ch.tag) == "ReportItem":
            yield ch


def parse_nessus_stream(stream: BinaryIO) -> List[ParsedFinding]:
    data = stream.read()
    if not data:
        return []
    return parse_nessus_bytes(data)


def parse_nessus_bytes(data: bytes) -> List[ParsedFinding]:
    bio = io.BytesIO(data)
    try:
        tree = ET.parse(bio)
    except ET.ParseError as e:
        raise ValueError(f"Invalid XML: {e}") from e
    root = tree.getroot()
    out: List[ParsedFinding] = []
    for host in _iter_report_hosts(root):
        ip = (host.attrib.get("name") or "").strip()
        if not ip:
            continue
        host_props = None
        for ch in host:
            if _local(ch.tag) == "HostProperties":
                host_props = ch
                break
        hostname = _hostname_from_host_properties(host_props)
        for item in _report_items(host):
            plugin_id = (item.attrib.get("pluginID") or item.attrib.get("pluginId") or "").strip()
            if not plugin_id:
                continue
            name = (item.attrib.get("pluginName") or item.attrib.get("pluginname") or "").strip() or f"plugin-{plugin_id}"
            sev_raw = item.attrib.get("severity") or "0"
            port = _parse_port(item.attrib.get("port"))
            protocol = (item.attrib.get("protocol") or "tcp").strip().lower() or "tcp"
            cvss = _float_or_none(_child_text_by_local(item, "cvss3_base_score"))
            if cvss is None:
                cvss = _float_or_none(_child_text_by_local(item, "cvss_base_score"))
            out.append(
                ParsedFinding(
                    ip_address=ip,
                    hostname=hostname,
                    plugin_id=plugin_id,
                    name=name,
                    port=port,
                    protocol=protocol,
                    severity=_nessus_severity_to_label(sev_raw),
                    cvss_score=cvss,
                )
            )
    return out
