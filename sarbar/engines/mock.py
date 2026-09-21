"""Mock engine: deterministic offline demo data for tests/defense without network.

Used when no real scanner binary is installed or --offline is passed.
Data is clearly labeled engine=mock and must never be mistaken for
a real CVE feed — it exists so `sarbar scan` is demonstrable anywhere.
"""
from __future__ import annotations

from sarbar.engines import Engine
from sarbar.model import Finding


class MockEngine(Engine):
    name = "mock"

    def is_available(self) -> bool:
        return True

    def run(self, target: str, kind: str) -> list[Finding]:
        demo = [
            Finding("CVE-2023-44487", "HTTP/2 rapid reset in nghttp2", "HIGH",
                    target=target, package="nghttp2", installed_version="1.55.0",
                    fixed_version="1.57.0", cvss=7.5, engine="mock", category="vuln",
                    description="Demo finding (offline mock, not a live CVE feed)."),
            Finding("CVE-2024-21626", "Container escape via runC", "CRITICAL",
                    target=target, package="runc", installed_version="1.1.9",
                    fixed_version="1.1.12", cvss=8.6, engine="mock", category="vuln",
                    description="Demo finding (offline mock)."),
        ]
        if kind in ("dockerfile", "image"):
            demo.append(Finding("DKL-DI-001", "Avoid 'latest' tag", "MEDIUM",
                                target=target, engine="mock", category="misconfig",
                                description="Demo misconfig (offline mock)."))
        return demo
