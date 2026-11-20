"""Shodan InternetDB: what Shodan's own scans have indexed for one IP address (issue 10.3).

``https://internetdb.shodan.io/<ip>`` is free and needs no key. It returns the open ports, the
software (CPE) and the CVEs Shodan infers from those versions, plus host names and tags (``cdn``,
``cloud`` ...). We read what Shodan already indexed; nothing is sent to the IP itself. InternetDB
gives no scan date, so ``source_scan_date`` stays unknown (it is refreshed roughly weekly).

Indexed data is not verification: a port Shodan saw may be closed now, a CVE is a guess from a
version string, and an IP behind a CDN or shared host says nothing about the company itself.
"""

from __future__ import annotations

import ipaddress
import json
import os
import time
from dataclasses import dataclass

import httpx

BASE_URL = "https://internetdb.shodan.io/"
DEFAULT_USER_AGENT = "cyber-risk-intelligence-research/0.1 (indexed exposure lookup)"
SOURCE = "shodan_internetdb"

# Well-known ports: a hint of the service, not what Shodan confirmed is running there.
SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 587: "submission", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs", 2375: "docker", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 5985: "winrm", 5986: "winrm", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}
# Remote administration, file sharing and databases: services that should rarely face the internet.
SENSITIVE_PORTS = frozenset({21, 23, 111, 135, 139, 161, 389, 445, 873, 1433, 1521, 1723, 2049, 2375, 3306,
                             3389, 5432, 5900, 5985, 5986, 6379, 9200, 11211, 27017})

# Networks of mail and collaboration services that host thousands of companies on the same IPs, so
# an IP inside them is never the company's own even when Shodan knows no host name for it.
# Microsoft 365 / Exchange Online and Exchange Online Protection, from Microsoft's published
# "Microsoft 365 URLs and IP address ranges" (Exchange Online endpoint sets).
SHARED_SERVICE_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "13.107.6.152/31", "13.107.18.10/31", "13.107.128.0/22", "23.103.160.0/20", "40.92.0.0/15",
    "40.96.0.0/13", "40.104.0.0/15", "40.107.0.0/16", "52.96.0.0/14", "52.100.0.0/14", "52.238.78.88/32",
    "104.47.0.0/17", "131.253.33.215/32", "132.245.0.0/16", "150.171.32.0/22", "204.79.197.215/32",
    "2603:1006::/40", "2603:1016::/36", "2603:1026::/36", "2603:1036::/36", "2603:1046::/36",
    "2603:1056::/36", "2620:1ec:4::152/128", "2620:1ec:4::153/128", "2620:1ec:c::10/128",
    "2620:1ec:c::11/128", "2620:1ec:d::10/128", "2620:1ec:d::11/128", "2620:1ec:8f0::/46",
    "2620:1ec:900::/46", "2620:1ec:a92::152/128", "2620:1ec:a92::153/128", "2a01:111:f400::/48",
    "2a01:111:f403::/48",
))


def in_shared_service(ip: str | None) -> bool:
    try:
        addr = ipaddress.ip_address(ip) if ip else None
    except ValueError:
        return False
    return bool(addr) and any(addr.version == n.version and addr in n for n in SHARED_SERVICE_NETWORKS)


@dataclass
class HostRecord:
    outcome: str  # found / not_indexed / lookup_failed
    ip: str
    url: str
    data: dict | None = None
    http_status: int | None = None
    message: str | None = None

    def document(self) -> bytes:
        """The stored evidence: InternetDB's answer with keys and lists sorted, so an unchanged answer
        is the same bytes on every run."""
        d = {k: sorted(v) if isinstance(v, list) else v for k, v in (self.data or {}).items()}
        return json.dumps(d, indent=1, sort_keys=True).encode()


class InternetDbClient:
    def __init__(self, client: httpx.Client | None = None, timeout: float = 20.0, pause: float = 0.5,
                 retries: int = 3):
        agent = os.environ.get("COLLECTOR_USER_AGENT") or DEFAULT_USER_AGENT
        self.client = client or httpx.Client(timeout=timeout, headers={"User-Agent": agent})
        self.pause, self.retries = pause, retries

    def host(self, ip: str) -> HostRecord:
        url = BASE_URL + ip
        for attempt in range(self.retries + 1):
            time.sleep(self.pause if attempt == 0 else self.pause * 4 * 2 ** attempt)
            try:
                r = self.client.get(url)
            except httpx.HTTPError as exc:
                if attempt < self.retries:
                    continue
                return HostRecord("lookup_failed", ip, url, message=f"{type(exc).__name__}: {exc}"[:300])
            if r.status_code == 404:
                return HostRecord("not_indexed", ip, url, http_status=404)
            if r.status_code == 200:
                try:
                    return HostRecord("found", ip, url, r.json(), 200)
                except ValueError:
                    return HostRecord("lookup_failed", ip, url, http_status=200, message="answer is not JSON")
            if r.status_code in (429, 500, 502, 503, 504) and attempt < self.retries:
                continue
            return HostRecord("lookup_failed", ip, url, http_status=r.status_code, message=f"HTTP {r.status_code}")
        return HostRecord("lookup_failed", ip, url, message="no answer")  # pragma: no cover


def _registered(name: str) -> str:
    from ..email_security.dmarc import organizational_domain

    return organizational_domain(name.lower().rstrip("."))


def attribution(data: dict, company_domains: set[str], ip: str | None = None) -> str:
    """How far the IP can be tied to the company, from InternetDB's own tags and host names:

    * ``cdn``: Shodan tags it as a CDN; the ports are the CDN's, not the company's.
    * ``shared``: it also serves other organizations' names (shared hosting or a cloud load balancer),
      or it is in a mail/collaboration service's network (``SHARED_SERVICE_NETWORKS``, e.g.
      Microsoft 365). The job also marks an IP shared when two companies' hosts point to it.
    * ``company_only``: every host name Shodan knows for it is under one of the company's domains.
    * ``unknown``: Shodan knows no host name for it.

    Even ``company_only`` doesn't prove ownership; it only means nothing points elsewhere.
    """
    if "cdn" in (data.get("tags") or []):
        return "cdn"
    if in_shared_service(ip):
        return "shared"
    names = [h for h in data.get("hostnames") or [] if h]
    if not names:
        return "unknown"
    mine = {_registered(d) for d in company_domains}
    return "company_only" if all(_registered(h) in mine for h in names) else "shared"
