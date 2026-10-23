# hakapik

Proof of concept for finding phishing sites within minutes to hours of their
first machine-visible signal: the certificate appearing in a Certificate
Transparency (CT) log.

This repository currently holds the first stage of the pipeline, ingest and
first-seen:

- tails every active CT log, both RFC 6962 and static-CT (tiled) logs,
- deduplicates certificates across logs, normalises every SAN (IDNA, Public
  Suffix List), and keeps an embedded first-seen index per FQDN,
- drops renewals, wildcards, top-list apexes and shared-hosting apexes,
- mirrors raw entries into a content-addressed blob store with a Postgres
  index, and emits the remaining first-seen names as fetch candidates,
- reports per-log, per-day volumes so the later stages can be sized from
  measurements rather than estimates.

The design and the literature it rests on are in
`docs/superpowers/specs/2026-10-23-hakapik-design.md`; the implementation
plan for this stage is in `docs/superpowers/plans/`.

## Requirements

Python 3.13, [uv](https://docs.astral.sh/uv/), Docker or Podman with compose
for Postgres.

## Quick start

```sh
uv sync
docker compose up -d                       # Postgres 17
cp hakapik.example.toml hakapik.toml       # set data_dir and database_url
curl -sSL https://tranco-list.eu/top-1m.csv.zip | funzip > "$DATA_DIR/tranco.csv"
uv run hakapik --config hakapik.toml bootstrap   # index the last N days
uv run hakapik --config hakapik.toml tail        # follow all logs live
uv run hakapik --config hakapik.toml stats       # per-log, per-day volumes
uv run hakapik --config hakapik.toml sample --n 200 --out candidates.csv
uv run hakapik --config hakapik.toml prune       # apply raw-entry retention
```

`bootstrap` must finish for a log before `tail` emits candidates for it;
`tail` skips logs that were never bootstrapped and says so.

## Tests

```sh
uv run pytest -W error
```

Database tests need a Postgres database whose name ends in `_test`; see
`docs/testing.md`.

## Status

Ingest and first-seen are implemented and reviewed. The measurement run that
sizes the next stages (fetch, embed, cluster, score, feed) is in progress.
