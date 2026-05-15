from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import threading
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple

import requests
from scapy.all import IP, TCP, UDP, rdpcap  # type: ignore


APP_SIGNATURES: Dict[str, Tuple[str, ...]] = {
    "YOUTUBE": ("youtube.com", "googlevideo.com"),
    "FACEBOOK": ("facebook.com", "fbcdn.net"),
    "INSTAGRAM": ("instagram.com",),
    "TWITTER": ("twitter.com", "x.com"),
    "GITHUB": ("github.com",),
    "GOOGLE": ("google.com", "googleapis.com"),
    "NETFLIX": ("netflix.com",),
    "TIKTOK": ("tiktok.com",),
}


@dataclass
class FlowState:
    packets: int = 0
    bytes: int = 0
    app_type: str = "UNKNOWN"
    sni: str = ""
    blocked: bool = False


@dataclass
class RuleManager:
    blocked_ips: Set[str] = field(default_factory=set)
    blocked_domains: Set[str] = field(default_factory=set)
    blocked_apps: Set[str] = field(default_factory=set)

    def add_rule(self, rule_type: str, value: str) -> None:
        value = value.strip()
        if not value:
            raise ValueError("Rule value cannot be empty")
        if rule_type == "ip":
            self.blocked_ips.add(value)
        elif rule_type == "domain":
            self.blocked_domains.add(value.lower())
        elif rule_type == "app":
            self.blocked_apps.add(value.upper())
        else:
            raise ValueError("Invalid rule type. Must be ip, domain, or app.")

    def remove_rule(self, rule_type: str, value: str) -> None:
        value = value.strip()
        if rule_type == "ip":
            self.blocked_ips.discard(value)
        elif rule_type == "domain":
            self.blocked_domains.discard(value.lower())
        elif rule_type == "app":
            self.blocked_apps.discard(value.upper())
        else:
            raise ValueError("Invalid rule type. Must be ip, domain, or app.")

    def is_blocked(self, src_ip: str, app_type: str, domain: str) -> bool:
        if src_ip in self.blocked_ips:
            return True
        if app_type.upper() in self.blocked_apps:
            return True
        domain_l = (domain or "").lower()
        return any(needle in domain_l for needle in self.blocked_domains)

    def as_dict(self) -> Dict[str, List[str]]:
        return {
            "ip": sorted(self.blocked_ips),
            "domain": sorted(self.blocked_domains),
            "app": sorted(self.blocked_apps),
        }


class DPIEngine:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.rules = RuleManager()
        self.reset_state()

    def reset_state(self) -> None:
        with self._lock:
            self.packets: List[Dict[str, Any]] = []
            self.flows: Dict[Tuple[str, str, int, int, str], FlowState] = {}
            self.app_counts: Counter[str] = Counter()
            self.total_packets = 0
            self.forwarded_packets = 0
            self.dropped_packets = 0
            self.alerts: List[Dict[str, str]] = []
            self.detected_domains: Dict[str, str] = {}
            self.geo_cache: Dict[str, Dict[str, Any]] = {}
            self.processing = False
            self.progress = 0.0
            self._ddos_counter: Dict[Tuple[str, int], int] = defaultdict(int)
            self._ddos_alerted: Set[Tuple[str, int]] = set()
            self._new_ip_first_seen: Dict[str, int] = {}
            self._new_ip_window: deque[int] = deque()
            self._last_port_scan_alert_second = -1

    async def process_pcap_async(
        self,
        file_path: str,
        packet_callback: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None,
        sleep_seconds: float = 0.01,
    ) -> None:
        packets = await asyncio.to_thread(rdpcap, file_path)
        total = len(packets)

        with self._lock:
            self.reset_state()
            self.processing = True

        try:
            for idx, packet in enumerate(packets, start=1):
                processed = await asyncio.to_thread(self._process_single_packet, packet, idx, total)
                if processed and packet_callback:
                    await packet_callback(processed)
                if sleep_seconds > 0:
                    await asyncio.sleep(sleep_seconds)
        finally:
            with self._lock:
                self.processing = False
                self.progress = 100.0

    def _process_single_packet(self, packet: Any, idx: int, total: int) -> Optional[Dict[str, Any]]:
        parsed = self._extract_packet_fields(packet)
        if not parsed:
            with self._lock:
                self.total_packets += 1
                self.forwarded_packets += 1
                self.progress = (idx / total) * 100 if total else 100.0
            return None

        src_ip, dst_ip, src_port, dst_port, protocol, payload, packet_time, byte_size = parsed
        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)

        sni = self._extract_sni_from_tls(payload) if protocol == "TCP" else None
        host = self._extract_http_host(payload) if protocol == "TCP" and not sni else None
        domain = (sni or host or "").strip().lower()
        app_type = self._classify_app(domain, dst_port)

        with self._lock:
            flow = self.flows.setdefault(flow_key, FlowState())
            flow.packets += 1
            flow.bytes += byte_size

            if domain and not flow.sni:
                flow.sni = domain
            if flow.app_type == "UNKNOWN" and app_type != "UNKNOWN":
                flow.app_type = app_type

            blocked_now = flow.blocked or self.rules.is_blocked(src_ip, flow.app_type, flow.sni)
            if blocked_now:
                flow.blocked = True
                status = "BLOCKED"
                self.dropped_packets += 1
            else:
                status = "ALLOWED"
                self.forwarded_packets += 1

            self.total_packets += 1
            resolved_app = flow.app_type if flow.app_type != "UNKNOWN" else app_type
            self.app_counts[resolved_app] += 1

            if flow.sni:
                self.detected_domains[flow.sni] = resolved_app

            self._update_anomaly_state(src_ip, packet_time)

            self.progress = (idx / total) * 100 if total else 100.0

            packet_record = {
                "id": idx,
                "time": datetime.fromtimestamp(packet_time, tz=timezone.utc).isoformat(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "app": resolved_app,
                "sni": flow.sni,
                "status": status,
                "bytes": byte_size,
                "country_code": self.geo_cache.get(src_ip, {}).get("countryCode", ""),
            }
            self.packets.append(packet_record)

        if src_ip not in self.geo_cache and self._is_public_ipv4(src_ip):
            try:
                geo = self._lookup_geo_sync(src_ip)
                with self._lock:
                    self.geo_cache[src_ip] = geo
                    packet_record["country_code"] = geo.get("countryCode", "")
            except Exception:
                pass
        return packet_record

    def _extract_packet_fields(
        self, packet: Any
    ) -> Optional[Tuple[str, str, int, int, str, bytes, float, int]]:
        if IP not in packet:
            return None

        ip_layer = packet[IP]
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        packet_time = float(getattr(packet, "time", datetime.now(tz=timezone.utc).timestamp()))
        byte_size = int(len(packet))

        if TCP in packet:
            tcp = packet[TCP]
            payload = bytes(tcp.payload) if tcp.payload else b""
            return (
                src_ip,
                dst_ip,
                int(tcp.sport),
                int(tcp.dport),
                "TCP",
                payload,
                packet_time,
                byte_size,
            )

        if UDP in packet:
            udp = packet[UDP]
            payload = bytes(udp.payload) if udp.payload else b""
            return (
                src_ip,
                dst_ip,
                int(udp.sport),
                int(udp.dport),
                "UDP",
                payload,
                packet_time,
                byte_size,
            )
        return None

    def _classify_app(self, domain: str, dst_port: int) -> str:
        domain_l = domain.lower()
        for app, signatures in APP_SIGNATURES.items():
            if any(sig in domain_l for sig in signatures):
                return app
        if dst_port == 443:
            return "HTTPS"
        if dst_port == 80:
            return "HTTP"
        if dst_port == 53:
            return "DNS"
        return "UNKNOWN"

    def _extract_http_host(self, payload: bytes) -> Optional[str]:
        if not payload:
            return None
        try:
            text = payload.decode("utf-8", errors="ignore")
        except Exception:
            return None
        if not text.startswith(("GET ", "POST ", "HEAD ", "PUT ", "PATCH ", "DELETE ", "OPTIONS ")):
            return None
        lines = text.split("\r\n")
        for line in lines:
            if line.lower().startswith("host:"):
                return line.split(":", 1)[1].strip()
        return None

    def _extract_sni_from_tls(self, payload: bytes) -> Optional[str]:
        if len(payload) < 6:
            return None
        if payload[0] != 0x16:
            return None
        if payload[5] != 0x01:
            return None

        try:
            offset = 43
            if offset >= len(payload):
                return None

            session_len = payload[offset]
            offset += 1 + session_len
            if offset + 2 > len(payload):
                return None

            cipher_len = int.from_bytes(payload[offset : offset + 2], "big")
            offset += 2 + cipher_len
            if offset >= len(payload):
                return None

            comp_len = payload[offset]
            offset += 1 + comp_len
            if offset + 2 > len(payload):
                return None

            ext_len = int.from_bytes(payload[offset : offset + 2], "big")
            offset += 2
            ext_end = min(len(payload), offset + ext_len)

            while offset + 4 <= ext_end:
                ext_type = int.from_bytes(payload[offset : offset + 2], "big")
                ext_data_len = int.from_bytes(payload[offset + 2 : offset + 4], "big")
                offset += 4
                if offset + ext_data_len > ext_end:
                    return None
                if ext_type == 0x0000:
                    if ext_data_len < 5:
                        return None
                    server_name_list_len = int.from_bytes(payload[offset : offset + 2], "big")
                    if server_name_list_len + 2 > ext_data_len:
                        return None
                    name_type = payload[offset + 2]
                    if name_type != 0x00:
                        return None
                    name_len = int.from_bytes(payload[offset + 3 : offset + 5], "big")
                    name_start = offset + 5
                    name_end = name_start + name_len
                    if name_end > offset + ext_data_len:
                        return None
                    return payload[name_start:name_end].decode("utf-8", errors="ignore").strip()
                offset += ext_data_len
            return None
        except Exception:
            return None

    def _update_anomaly_state(self, src_ip: str, packet_time: float) -> None:
        ts_sec = int(packet_time)
        key = (src_ip, ts_sec)
        self._ddos_counter[key] += 1
        if self._ddos_counter[key] >= 100 and key not in self._ddos_alerted:
            self._ddos_alerted.add(key)
            self._add_alert(
                f"POSSIBLE DDOS — {src_ip} sent {self._ddos_counter[key]} packets in 1 second"
            )

        if src_ip not in self._new_ip_first_seen:
            self._new_ip_first_seen[src_ip] = ts_sec
            self._new_ip_window.append(ts_sec)

        while self._new_ip_window and self._new_ip_window[0] < ts_sec - 10:
            self._new_ip_window.popleft()

        if len(self._new_ip_window) > 50 and self._last_port_scan_alert_second != ts_sec:
            self._last_port_scan_alert_second = ts_sec
            self._add_alert(f"PORT SCAN — More than 50 new IPs detected in the last 10 seconds")

    def _add_alert(self, message: str) -> None:
        self.alerts.append({"timestamp": datetime.now(tz=timezone.utc).isoformat(), "description": message})

    def _lookup_geo_sync(self, ip: str) -> Dict[str, Any]:
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        response.raise_for_status()
        data = response.json()
        if data.get("status") != "success":
            raise ValueError(data.get("message", "Geo lookup failed"))
        return {
            "country": data.get("country", ""),
            "countryCode": data.get("countryCode", ""),
            "city": data.get("city", ""),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
        }

    async def get_geoip(self, ip: str) -> Dict[str, Any]:
        with self._lock:
            if ip in self.geo_cache:
                return self.geo_cache[ip]
        if not self._is_public_ipv4(ip):
            result = {"country": "Private/Reserved", "countryCode": "", "city": "", "lat": None, "lon": None}
            with self._lock:
                self.geo_cache[ip] = result
            return result
        geo = await asyncio.to_thread(self._lookup_geo_sync, ip)
        with self._lock:
            self.geo_cache[ip] = geo
        return geo

    def get_packets(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.packets)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self.total_packets
            app_percent = {
                app: {"count": count, "percent": round((count / total) * 100, 2) if total else 0.0}
                for app, count in sorted(self.app_counts.items(), key=lambda x: x[1], reverse=True)
            }
            return {
                "processing": self.processing,
                "progress": round(self.progress, 2),
                "total": self.total_packets,
                "forwarded": self.forwarded_packets,
                "dropped": self.dropped_packets,
                "active_flows": len(self.flows),
                "per_app_counts": dict(self.app_counts),
                "per_app_percent": app_percent,
                "alerts": list(self.alerts),
                "detected_domains": [
                    {"domain": domain, "app": app, "country_code": self._country_code_for_domain(domain)}
                    for domain, app in sorted(self.detected_domains.items())
                ],
            }

    def _country_code_for_domain(self, domain: str) -> str:
        for packet in reversed(self.packets):
            if packet.get("sni") == domain:
                return packet.get("country_code", "")
        return ""

    def generate_csv_report(self) -> bytes:
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "id",
                "time",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "protocol",
                "app",
                "sni",
                "status",
                "bytes",
                "country_code",
            ],
        )
        writer.writeheader()
        for packet in self.get_packets():
            writer.writerow(packet)
        return output.getvalue().encode("utf-8")

    @staticmethod
    def _is_public_ipv4(ip: str) -> bool:
        try:
            parsed = ipaddress.ip_address(ip)
            return isinstance(parsed, ipaddress.IPv4Address) and parsed.is_global
        except ValueError:
            return False


def country_code_to_flag(code: str) -> str:
    if not code or len(code) != 2:
        return ""
    return "".join(chr(127397 + ord(c.upper())) for c in code)
