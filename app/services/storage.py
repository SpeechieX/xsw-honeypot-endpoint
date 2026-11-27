# storage.py — Capture storage service.

# Persists SAMLCapture records to Redis (primary) and optionally to disk as
# newline-delimited JSON (fallback / archive). Provides query methods for the
# dashboard.

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
import redis.asyncio as aioredis

from ..models import SAMLCapture, DashboardStats, Severity
from ..config import settings


# Redis key conventions
CAPTURE_KEY    = "xsw:capture:{id}"          # Hash: full serialized capture
CAPTURE_INDEX  = "xsw:captures"              # Sorted set: (timestamp, id)
IP_SET_KEY     = "xsw:ips"                   # Set of all seen source IPs
ISSUER_SET_KEY = "xsw:issuers"               # Set of all seen issuers
SEVERITY_KEY   = "xsw:severity:{level}"      # Set of capture IDs per severity


class StorageService:
    def __init__(self):
        self._redis: Optional[aioredis.Redis] = None
        self._disk_path: Optional[Path] = None

    async def connect(self):
        # Initialize connections. Called at app startup.
        try:
            self._redis = aioredis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
            await self._redis.ping()
        except Exception as e:
            print(f"[storage] Redis unavailable ({e}), falling back to disk-only mode.")
            self._redis = None

        if settings.persist_to_disk:
            self._disk_path = Path(settings.captures_dir)
            self._disk_path.mkdir(parents=True, exist_ok=True)

    async def disconnect(self):
        if self._redis:
            await self._redis.aclose()

    # ── Write ─────────────────────────────────────────────────────────────────

    async def save_capture(self, capture: SAMLCapture) -> None:
        # Persist a capture to Redis and/or disk.
        serialized = capture.model_dump_json()
        timestamp = capture.captured_at.timestamp()

        if self._redis:
            pipe = self._redis.pipeline()
            # Store full JSON under a per-ID key with TTL
            pipe.set(
                CAPTURE_KEY.format(id=capture.id),
                serialized,
                ex=settings.capture_ttl_seconds,
            )
            # Add to sorted set for time-ordered retrieval
            pipe.zadd(CAPTURE_INDEX, {capture.id: timestamp})
            # Update aggregate sets for stats
            pipe.sadd(IP_SET_KEY, capture.request.source_ip)
            if capture.issuer:
                pipe.sadd(ISSUER_SET_KEY, capture.issuer)
            pipe.sadd(
                SEVERITY_KEY.format(level=capture.xsw_analysis.severity.value),
                capture.id,
            )
            await pipe.execute()

        if self._disk_path:
            date_str = capture.captured_at.strftime("%Y-%m-%d")
            log_file = self._disk_path / f"captures-{date_str}.jsonl"
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(serialized + "\n")

    # ── Read ──────────────────────────────────────────────────────────────────

    async def get_capture(self, capture_id: str) -> Optional[SAMLCapture]:
        # Retrieve a single capture by ID.
        if self._redis:
            raw = await self._redis.get(CAPTURE_KEY.format(id=capture_id))
            if raw:
                return SAMLCapture.model_validate_json(raw)

        # Fallback: scan disk
        if self._disk_path:
            return await self._scan_disk_for_id(capture_id)

        return None

    async def get_recent_captures(self, limit: int = 50) -> list[SAMLCapture]:
        # Return the most recent N captures, newest first.
        if self._redis:
            # ZREVRANGE returns IDs sorted by descending timestamp score
            ids = await self._redis.zrevrange(CAPTURE_INDEX, 0, limit - 1)
            captures = []
            for cid in ids:
                raw = await self._redis.get(CAPTURE_KEY.format(id=cid))
                if raw:
                    try:
                        captures.append(SAMLCapture.model_validate_json(raw))
                    except Exception:
                        pass
            return captures

        return await self._read_disk_captures(limit)

    async def get_stats(self) -> DashboardStats:
        # Aggregate statistics for the dashboard.
        stats = DashboardStats()

        if self._redis:
            pipe = self._redis.pipeline()
            pipe.zcard(CAPTURE_INDEX)
            pipe.scard(IP_SET_KEY)
            pipe.scard(ISSUER_SET_KEY)
            for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                pipe.scard(SEVERITY_KEY.format(level=level))
            results = await pipe.execute()

            stats.total_captures = results[0]
            stats.unique_ips = results[1]
            stats.unique_issuers = results[2]
            stats.critical_count = results[3]
            stats.high_count = results[4]
            stats.medium_count = results[5]
            stats.low_count = results[6]
        else:
            # Count from disk files
            captures = await self._read_disk_captures(limit=10_000)
            stats.total_captures = len(captures)
            stats.unique_ips = len({c.request.source_ip for c in captures})
            stats.unique_issuers = len({c.issuer for c in captures if c.issuer})
            stats.critical_count = sum(1 for c in captures if c.xsw_analysis.severity == Severity.CRITICAL)
            stats.high_count = sum(1 for c in captures if c.xsw_analysis.severity == Severity.HIGH)
            stats.medium_count = sum(1 for c in captures if c.xsw_analysis.severity == Severity.MEDIUM)
            stats.low_count = sum(1 for c in captures if c.xsw_analysis.severity == Severity.LOW)

        stats.xsw_suspected = stats.critical_count + stats.high_count + stats.medium_count
        stats.recent_captures = await self.get_recent_captures(limit=20)
        return stats

    # ── Disk Fallback ─────────────────────────────────────────────────────────

    async def _read_disk_captures(self, limit: int) -> list[SAMLCapture]:
        if not self._disk_path:
            return []
        captures = []
        files = sorted(self._disk_path.glob("captures-*.jsonl"), reverse=True)
        for fpath in files:
            if len(captures) >= limit:
                break
            try:
                with open(fpath, encoding="utf-8") as f:
                    lines = f.readlines()
                for line in reversed(lines):
                    if len(captures) >= limit:
                        break
                    try:
                        captures.append(SAMLCapture.model_validate_json(line.strip()))
                    except Exception:
                        pass
            except OSError:
                pass
        return captures

    async def _scan_disk_for_id(self, capture_id: str) -> Optional[SAMLCapture]:
        if not self._disk_path:
            return None
        for fpath in sorted(self._disk_path.glob("captures-*.jsonl"), reverse=True):
            try:
                with open(fpath, encoding="utf-8") as f:
                    for line in f:
                        if capture_id in line:
                            try:
                                c = SAMLCapture.model_validate_json(line.strip())
                                if c.id == capture_id:
                                    return c
                            except Exception:
                                pass
            except OSError:
                pass
        return None


# Singleton instance
storage = StorageService()
