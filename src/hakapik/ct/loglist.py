"""Fetch and parse Certificate Transparency log lists (Google v3, Apple)."""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

import httpx

ACTIVE_STATES = frozenset({"usable", "qualified", "readonly"})


@dataclass(frozen=True)
class LogInfo:
    log_id: str
    description: str
    kind: Literal["rfc6962", "tiled"]
    url: str
    monitoring_url: str | None
    state: str
    operator: str


def parse_log_list(data: dict) -> list[LogInfo]:
    """Parse one log list into LogInfo entries, keeping only active states."""
    result: list[LogInfo] = []
    for operator in data.get("operators", []):
        entries = [*operator.get("logs", []), *operator.get("tiled_logs", [])]
        for log in entries:
            state = next(iter(log.get("state", {})), None)
            if state not in ACTIVE_STATES:
                continue
            monitoring_url = log.get("monitoring_url")
            tiled = monitoring_url is not None
            result.append(
                LogInfo(
                    log_id=log["log_id"],
                    description=log["description"],
                    kind="tiled" if tiled else "rfc6962",
                    url=log["submission_url"] if tiled else log["url"],
                    monitoring_url=monitoring_url,
                    state=state,
                    operator=operator["name"],
                )
            )
    return result


async def fetch_log_lists(
    urls: Sequence[str], client: httpx.AsyncClient
) -> list[LogInfo]:
    """Fetch all lists, merge, and dedup by log_id (first occurrence wins)."""
    seen: dict[str, LogInfo] = {}
    for url in urls:
        response = await client.get(url)
        response.raise_for_status()
        for info in parse_log_list(response.json()):
            seen.setdefault(info.log_id, info)
    return list(seen.values())
