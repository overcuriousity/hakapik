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


def load_config(path: Path) -> Config:
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    known = {f.name for f in fields(Config)}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ValueError(f"unknown config keys: {', '.join(unknown)}")
    for key in ("public_apexes", "log_lists"):
        if key in raw:
            raw[key] = tuple(raw[key])
    if "data_dir" in raw:
        raw["data_dir"] = Path(raw["data_dir"])
    return Config(**raw)
