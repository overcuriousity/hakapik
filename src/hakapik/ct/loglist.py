"""Fetch and parse Certificate Transparency log lists (Google v3, Apple)."""

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

import httpx

ACTIVE_STATES = frozenset({"usable", "qualified", "readonly"})

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class LogInfo:
    log_id: str
    description: str
    kind: Literal["rfc6962", "tiled"]
    url: str
    monitoring_url: str | None
    state: str
    operator: str


def _entries(data: dict):
    for operator in data.get("operators", []):
        for log in [*operator.get("logs", []), *operator.get("tiled_logs", [])]:
            yield operator, log


def _state(log: dict) -> str | None:
    return next(iter(log.get("state", {})), None)


def retired_ids(data: dict) -> set[str]:
    """Ids of the logs this list marks retired."""
    return {
        log["log_id"]
        for _, log in _entries(data)
        if _state(log) == "retired" and "log_id" in log
    }


def parse_log_list(data: dict) -> list[LogInfo]:
    """Parse one log list into LogInfo entries, keeping only active states.

    An entry missing a required field is skipped with a warning, so one
    malformed entry does not discard the rest of the list.
    """
    result: list[LogInfo] = []
    for operator, log in _entries(data):
        state = _state(log)
        if state not in ACTIVE_STATES:
            continue
        monitoring_url = log.get("monitoring_url")
        tiled = monitoring_url is not None
        try:
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
        except KeyError as exc:
            _log.warning("skipping log list entry %r: missing %s", log.get("log_id"), exc)
    return result


async def fetch_log_lists(
    urls: Sequence[str], client: httpx.AsyncClient
) -> list[LogInfo]:
    """Fetch all lists, merge, and dedup by log_id (first occurrence wins).

    A log that any list marks retired is dropped, even if another list still
    calls it usable or readonly: a retired log may be shut down, and tailing
    it would retry forever. A list that cannot be fetched is skipped with a
    warning, so the others still work; only if none can be fetched is the
    last error raised.
    """
    seen: dict[str, LogInfo] = {}
    retired: set[str] = set()
    last_error: Exception | None = None
    fetched = 0
    for url in urls:
        try:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError(f"top level is {type(data).__name__}, not an object")
        except (httpx.HTTPError, ValueError) as exc:
            _log.warning("log list %s failed: %r", url, exc)
            last_error = exc
            continue
        fetched += 1
        retired |= retired_ids(data)
        for info in parse_log_list(data):
            seen.setdefault(info.log_id, info)
    if not fetched and last_error is not None:
        raise last_error
    return [info for log_id, info in seen.items() if log_id not in retired]
