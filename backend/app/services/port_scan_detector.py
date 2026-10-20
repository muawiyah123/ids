"""Correlate short TCP SYN flows into a port-scan signal.

The ML model classifies individual flows, while a port scan is a pattern across
many destination ports. This small in-process correlator detects that pattern
across events submitted to the single API worker used by the local Compose app.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock
from typing import Deque


WINDOW_SECONDS = 60.0
MIN_UNIQUE_PORTS = 20


class PortScanDetector:
    def __init__(self) -> None:
        self._lock = Lock()
        self._events: dict[tuple[str, str], Deque[tuple[float, int]]] = defaultdict(deque)
        self._triggered: dict[tuple[str, str], float] = {}
        self._last_prune = time.monotonic()

    def observe(self, source_ip: str | None, destination_ip: str | None,
                destination_port: int | None, protocol: str | None,
                features: dict) -> bool:
        """Return True once per scan window when enough unique TCP SYN ports appear."""
        if (not source_ip or not destination_ip or destination_port is None
                or (protocol or "").upper() != "TCP"):
            return False
        try:
            syn_count = float(features.get("SYN Flag Count", 0) or 0)
        except (TypeError, ValueError):
            return False
        if syn_count <= 0:
            return False

        now = time.monotonic()
        key = (source_ip, destination_ip)
        with self._lock:
            if now - self._last_prune >= WINDOW_SECONDS:
                cutoff = now - WINDOW_SECONDS
                for stale_key, stale_events in list(self._events.items()):
                    while stale_events and stale_events[0][0] < cutoff:
                        stale_events.popleft()
                    if not stale_events:
                        self._events.pop(stale_key, None)
                self._triggered = {
                    stale_key: triggered_at
                    for stale_key, triggered_at in self._triggered.items()
                    if triggered_at >= cutoff
                }
                self._last_prune = now

            events = self._events[key]
            cutoff = now - WINDOW_SECONDS
            while events and events[0][0] < cutoff:
                events.popleft()
            events.append((now, int(destination_port)))

            triggered_at = self._triggered.get(key)
            if triggered_at is not None and triggered_at >= cutoff:
                return False
            if len({port for _, port in events}) < MIN_UNIQUE_PORTS:
                return False

            self._triggered[key] = now
            return True


port_scan_detector = PortScanDetector()
