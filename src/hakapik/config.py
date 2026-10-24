from __future__ import annotations

import tomllib
from dataclasses import dataclass, fields
from pathlib import Path

DEFAULT_LOG_LISTS = (
    "https://www.gstatic.com/ct/log_list/v3/log_list.json",
    "https://valid.apple.com/ct/log_list/current_log_list.json",
)


@dataclass(frozen=True)
class Config:
    data_dir: Path
    database_url: str
    raw_retention_days: int = 7
    tranco_top_n: int = 100_000
    public_apexes: tuple[str, ...] = ()
    log_lists: tuple[str, ...] = DEFAULT_LOG_LISTS
    per_log_concurrency: int = 2  # reserved, not used yet
    batch_size: int = 256
    max_db_connections: int = 64
    fetch_workers: int = 2
    fetch_per_ip_interval_s: float | None = None  # unset = unlimited
    fetch_daily_cap: int | None = None  # unset = unlimited
    fetch_proxy: str | None = None
    egress_address: str | None = None
    resolver_nameservers: tuple[str, ...] = ()  # empty = system resolver
    retry_ladder_s: tuple[int, ...] = (0, 120, 600, 3600, 21600, 86400)
    recheck_days: int = 30
    queue_cap: int | None = None
    ageout_hours: float = 24.0
    nav_timeout_s: float = 30.0
    lease_s: int = 600
    asn_mmdb: Path | None = None  # GeoLite2-ASN .mmdb supplied by the operator


# Minimum for each numeric key (None = no lower bound beyond the type).
_INT_MIN = {
    "raw_retention_days": 0, "tranco_top_n": 0, "per_log_concurrency": 1,
    "batch_size": 1, "max_db_connections": 1, "fetch_workers": 1,
    "fetch_daily_cap": 0, "recheck_days": 0, "queue_cap": 0, "lease_s": 1,
}
_FLOAT_MIN = {
    "fetch_per_ip_interval_s": 0.0, "ageout_hours": 0.0, "nav_timeout_s": 0.0,
}
_STR_KEYS = ("database_url", "fetch_proxy", "egress_address")
_STR_TUPLE_KEYS = ("public_apexes", "log_lists", "resolver_nameservers")


def _validate_types(raw: dict) -> None:
    """Reject wrong types and out-of-range numbers with a ValueError naming the key."""
    for key in ("data_dir", "database_url"):
        if key not in raw:
            raise ValueError(f"missing required config key: {key}")
    for key, value in raw.items():
        if key in _INT_MIN:
            ok = isinstance(value, int) and not isinstance(value, bool)
            kind, low = "an integer", _INT_MIN[key]
        elif key in _FLOAT_MIN:
            ok = isinstance(value, (int, float)) and not isinstance(value, bool)
            kind, low = "a number", _FLOAT_MIN[key]
        elif key in _STR_KEYS or key in ("data_dir", "asn_mmdb"):
            ok, kind, low = isinstance(value, str), "a string", None
        elif key in _STR_TUPLE_KEYS:
            ok = isinstance(value, tuple) and all(isinstance(v, str) for v in value)
            kind, low = "a list of strings", None
        elif key == "retry_ladder_s":
            ok = isinstance(value, tuple) and all(
                isinstance(v, int) and not isinstance(v, bool) for v in value
            )
            kind, low = "a list of integers", None
        else:
            continue
        if not ok:
            raise ValueError(f"{key} must be {kind}")
        if low is not None and value < low:
            raise ValueError(f"{key} must be at least {low}")


def load_config(path: Path) -> Config:
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    known = {f.name for f in fields(Config)}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ValueError(f"unknown config keys: {', '.join(unknown)}")
    for key, value in raw.items():
        if isinstance(value, list):
            raw[key] = tuple(value)
    _validate_types(raw)
    for key in ("data_dir", "asn_mmdb"):
        if key in raw:
            raw[key] = Path(raw[key])
    ladder = raw.get("retry_ladder_s")
    if ladder is not None and (
        not ladder or ladder[0] != 0 or any(a >= b for a, b in zip(ladder, ladder[1:]))
    ):
        raise ValueError("retry_ladder_s must be non-empty, start at 0 and strictly increase")
    cfg = Config(**raw)
    # Worst-case capture: landing plus up to 3 click hops, plus resolve. A
    # shorter lease lets a running job be claimed again mid-run.
    if cfg.lease_s < 4 * cfg.nav_timeout_s + 60:
        raise ValueError("lease_s must be at least 4 * nav_timeout_s + 60")
    return cfg
