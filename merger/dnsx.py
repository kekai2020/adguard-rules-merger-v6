"""Portable DNS resolution via dnspython (V5.3).

Replaces the getaddrinfo + glibc-string-matching approach in
whitelist_audit._dns_check with dnspython's explicit rcode handling,
which works identically on glibc / musl / Windows. When dnspython is
not installed, falls back to getaddrinfo with best-effort NXDOMAIN
detection (platform-dependent strings).
"""
from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DNS_AVAILABLE = False
try:
    import dns.exception
    import dns.resolver
    _DNS_AVAILABLE = True
except ImportError:  # pragma: no cover
    logger.warning(
        "dnspython not installed; DnsChecker falls back to getaddrinfo "
        "(NXDOMAIN detection will be best-effort)")


class _Nxdomain(Exception):
    pass


class _Servfail(Exception):
    pass


class _Timeout(Exception):
    pass


class DnsChecker:
    """Portable async DNS resolver with explicit NXDOMAIN detection.

    Uses dnspython when available (explicit rcode, no string matching).
    Falls back to getaddrinfo when dnspython is missing.
    """

    def __init__(
        self,
        resolvers: Optional[List[str]] = None,
        timeout: float = 5.0,
        force_tcp: bool = False,
    ) -> None:
        self.timeout = timeout
        self.force_tcp = force_tcp
        self._resolver = None
        if _DNS_AVAILABLE:
            self._resolver = dns.resolver.Resolver()
            if resolvers:
                self._resolver.nameservers = list(resolvers)
            self._resolver.lifetime = timeout
            self._resolver.timeout = timeout

    async def check(self, domain: str) -> Dict[str, Any]:
        """Resolve *domain*.

        Returns ``{"rcode", "nxdomain", "ips", "error_type"}`` where
        error_type is None on success or one of
        ``nxdomain``/``servfail``/``timeout``/``resolver_error``.
        """
        if self._resolver is not None:
            return await self._check_dnspython(domain)
        return await self._check_getaddrinfo(domain)

    async def _check_dnspython(self, domain: str) -> Dict[str, Any]:
        loop = asyncio.get_running_loop()
        ips: List[str] = []
        try:
            a_ips = await loop.run_in_executor(
                None, self._resolve, domain, "A")
            ips.extend(a_ips)
            aaaa_ips = await loop.run_in_executor(
                None, self._resolve, domain, "AAAA")
            ips.extend(aaaa_ips)
            return {"rcode": 0, "nxdomain": False, "ips": ips,
                    "error_type": None}
        except _Nxdomain:
            return {"rcode": 3, "nxdomain": True, "ips": [],
                    "error_type": "nxdomain"}
        except _Servfail:
            return {"rcode": 2, "nxdomain": False, "ips": [],
                    "error_type": "servfail"}
        except _Timeout:
            return {"rcode": None, "nxdomain": False, "ips": [],
                    "error_type": "timeout"}
        except Exception:  # noqa: BLE001
            return {"rcode": None, "nxdomain": False, "ips": [],
                    "error_type": "resolver_error"}

    def _resolve(self, domain: str, rdtype: str) -> List[str]:
        try:
            answer = self._resolver.resolve(domain, rdtype, tcp=self.force_tcp)
            return [r.to_text() for r in answer]
        except dns.resolver.NXDOMAIN:
            raise _Nxdomain
        except dns.resolver.NoNameservers:
            raise _Servfail
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            raise _Timeout
        except dns.resolver.NoAnswer:
            return []

    async def _check_getaddrinfo(self, domain: str) -> Dict[str, Any]:
        try:
            loop = asyncio.get_running_loop()
            infos = await asyncio.wait_for(
                loop.getaddrinfo(domain, None, family=socket.AF_UNSPEC),
                timeout=self.timeout,
            )
            ips = list({info[4][0] for info in infos})
            return {"rcode": 0, "nxdomain": False, "ips": ips,
                    "error_type": None}
        except asyncio.TimeoutError:
            return {"rcode": None, "nxdomain": False, "ips": [],
                    "error_type": "timeout"}
        except Exception as e:
            msg = str(e).lower()
            if ("name or service not known" in msg
                    or "nodename nor servname" in msg
                    or "getaddrinfo failed" in msg
                    or "name resolution" in msg):
                return {"rcode": 3, "nxdomain": True, "ips": [],
                        "error_type": "nxdomain"}
            return {"rcode": None, "nxdomain": False, "ips": [],
                    "error_type": "resolver_error"}