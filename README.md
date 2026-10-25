# hakapik

Proof of concept for finding phishing sites within minutes to hours of their
first machine-visible signal: the certificate appearing in a Certificate
Transparency (CT) log.

This repository holds the first two stages of the pipeline.

Ingest and first-seen:

- tails every active CT log, both RFC 6962 and static-CT (tiled) logs,
- deduplicates certificates across logs, normalises every SAN (IDNA, Public
  Suffix List), and keeps an embedded first-seen index per FQDN,
- drops renewals, wildcards, top-list apexes and shared-hosting apexes,
- mirrors raw entries into a content-addressed blob store with a Postgres
  index, and emits the remaining first-seen names as fetch candidates,
- reports per-log, per-day volumes (`hakapik stats`).

Resolve and fetch:

- queues each candidate as a fetch job and retries it along a ladder of
  delays, with lease-based claims, age-out and an optional queue cap,
- resolves the name, renders it in Chromium (Playwright) on a mobile and,
  if live, a desktop profile with login click-through, and keeps WARC,
  screenshot, DOM and certificate chain in the blob store,
- seals each attempt as an Ed25519-signed result that the head verifies
  before storing it, with versioned manifests and optional ASN enrichment.

The design and the literature it rests on are in
`docs/superpowers/specs/2026-10-23-hakapik-design.md`; the implementation
plans for both stages are in `docs/superpowers/plans/`.

## Requirements

Python 3.13, [uv](https://docs.astral.sh/uv/), Docker or Podman with compose
for Postgres.

`data_dir` must be on a local filesystem with hard links (ext4, xfs and btrfs
all qualify): the node key is published atomically with a hard link, and
hakapik stops with a clear error where that is not supported.

## Quick start

```sh
uv sync
docker compose up -d                       # Postgres 17
cp hakapik.example.toml hakapik.toml       # set data_dir and database_url
curl -sSL https://tranco-list.eu/top-1m.csv.zip | funzip > "$DATA_DIR/tranco.csv"
uv run hakapik --config hakapik.toml tail     # follow all logs live
uv run hakapik --config hakapik.toml stats    # per-log, per-day volumes
uv run hakapik --config hakapik.toml sample --n 200 --out candidates.csv
uv run hakapik --config hakapik.toml prune    # raw-entry retention, then unreferenced blobs

uv run playwright install chromium --no-shell # once, for fetch
uv run hakapik --config hakapik.toml enqueue example.com   # or --file names.txt
uv run hakapik --config hakapik.toml fetch    # --once for a single pass
uv run hakapik --config hakapik.toml show example.com
```

A database created before the bootstrap was removed has `log_cursor.bootstrap_done`
(NOT NULL) and `ingest_stat.mode`, which the current code does not write; migration
does not drop them. Recreate such a database (`docker compose down -v`, or drop
`log_cursor` and `ingest_stat`) before running `tail`.

There is no history backfill. `tail` starts each log it has not seen before
at the log's current tree size and emits candidates from its first batch on;
the first-seen index fills from the live stream, so early candidates include
names that are not actually new, and that share falls as the index grows.

`enqueue` queues names by hand (one name per line with `--file`, `#` starts a
comment) and prints `name`, a tab and the outcome: `queued`, `already_open`,
`invalid` or `wildcard`. `fetch` resolves and fetches the queued names with a
browser; `show` prints a name's candidates, jobs, attempts and latest manifest.
No running `tail` is needed.

Ctrl-C stops claiming/tailing and lets running work finish (tail: a running
batch gets 5 s; fetch: up to job_timeout_s); a second Ctrl-C aborts.

`fetch` contacts sites from this machine's own address, or through
`fetch_proxy` if that is set. Rate limits (`fetch_per_ip_interval_s`,
`fetch_daily_cap`) are off unless configured.

To run the fetcher safely, set `egress_address` (recorded in every signed
result) together with `fetch_proxy`. The fetcher visits attacker-controlled
pages, so when this machine shares a network with anything sensitive (the
Postgres container, for example), run `hakapik fetch` in a separate network
namespace or behind `fetch_proxy`. On a headless server Playwright also needs
its system libraries: `uv run playwright install-deps chromium` on
Debian/Ubuntu, or the distribution's packages elsewhere.

For ASN enrichment, set `asn_mmdb` to a GeoLite2-ASN file (this needs a
MaxMind account); refresh it by replacing the file. Without it, ASNs are null.

## Tests

```sh
uv run pytest -W error
```

Database tests need a Postgres database whose name ends in `_test`; see
`docs/testing.md`.

## Status

Ingest and first-seen, and resolve and fetch, are implemented.
No measuring run gates the later stages; their sizes are configuration.
