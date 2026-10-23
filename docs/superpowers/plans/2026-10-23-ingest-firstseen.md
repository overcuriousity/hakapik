# Ingest and First-Seen (Plan 1 of the hakapik PoC) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tail every active CT log over both log APIs, dedup certificates, normalise names, keep a first-seen FQDN index, emit candidates after suppression, and report the per-stage volumes the design's later sizing depends on.

**Architecture:** One Python package `hakapik` with a `ct` subpackage for the two log protocols and leaf parsing, pure functions for names, dedup and suppression, an embedded key-value store for the first-seen index, Postgres for cursors, candidates and daily stats, and a content-addressed blob store for packed raw entries. An asyncio orchestrator runs one tailer per log; a CLI exposes bootstrap, tail, stats and sample.

**Tech Stack:** Python 3.13, uv, httpx (async), asn1crypto, idna, tldextract, rocksdict, psycopg 3, zstandard, pytest, pytest-asyncio, respx, Docker or Podman compose for Postgres.

**Spec:** `docs/superpowers/specs/2026-10-23-hakapik-design.md` (sections 5.1, 5.2, 7, 11a, 14).

## Global Constraints

- Python `>=3.13` as pinned in `pyproject.toml`; all code under `src/hakapik/`, tests under `tests/`.
- Dependencies are added with `uv add`; dev dependencies with `uv add --dev`.
- Nothing is updated in place in Postgres; corrections are new rows.
- Bootstrap writes only the first-seen index, never raw entries, never candidates.
- The live tail mirrors raw entries but emits no candidates for a log until that log's bootstrap has completed.
- Dedup key across logs: SHA-256 of the issuer DN DER concatenated with the serial number bytes (same for precertificate and final certificate).
- Wildcards: stored with `*.` stripped and `wildcard=true`; never candidates.
- Suppression: Tranco top N apex and `www` only; public-apex list from PSL private domains plus a config list. N and lists are config.
- Retention of raw entries that never became candidates: 7 days default, config.
- Commit messages end with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.

## Review Focus

1. A log answers HTTP 429 or 5xx mid-batch: the tailer must back off and resume from the same cursor, never skip entries. Pinned in Task 4 (`test_get_entries_retries_on_429`).
2. A leaf whose certificate fails to parse (garbage DER, unknown entry type): the entry is counted as `parse_failed`, stored raw, and the batch continues. Pinned in Task 3 (`test_parse_leaf_garbage_returns_error_record`).
3. A SAN containing an IDN label, an uppercase label, or a trailing dot: normalisation yields the same FQDN key for all spellings. Pinned in Task 6 (`test_normalize_idn_case_and_trailing_dot`).
4. A name under a PSL private suffix such as `pages.dev` or `github.io`: the registrable domain is the user's subdomain, not the hosting apex, and the hosting apex is suppressed while the subdomain is not. Pinned in Task 6 and Task 8.
5. Process restart during a batch: cursor was advanced only after the batch's index writes and blob write finished, so re-run reprocesses the same entries idempotently. Pinned in Task 10 (`test_cursor_advances_only_after_batch_commit`).

---

## File structure

```
src/hakapik/
  __init__.py
  config.py          # TOML config -> frozen dataclasses
  ct/__init__.py
  ct/loglist.py      # fetch and parse Google + Apple log lists -> list[LogInfo]
  ct/leaf.py         # bytes -> ParsedLeaf (both RFC 6962 leaf_input and static-CT TileLeaf)
  ct/rfc6962.py      # get-sth, get-entries, bisect index by timestamp
  ct/static_ct.py    # checkpoint, data tiles, bisect index by timestamp
  ct/source.py       # LogSource protocol + factory
  names.py           # normalise SAN -> NameRecord (fqdn, registrable, wildcard, idn)
  dedup.py           # cert key
  firstseen.py       # FirstSeenIndex over rocksdict
  suppress.py        # Tranco + public-apex suppression
  blobstore.py       # content-addressed store
  db.py              # Postgres schema, cursors, candidates, stats
  ingest.py          # per-log tailer + bootstrap orchestration
  cli.py             # hakapik bootstrap | tail | stats | sample
tests/
  conftest.py
  fixtures/          # real leaf bytes captured from logs, small log lists
  test_*.py          # one per module
compose.yaml         # postgres only, for now
hakapik.example.toml
```

---

### Task 1: Project scaffold, config, compose

**Files:**
- Modify: `pyproject.toml`
- Create: `src/hakapik/__init__.py`, `src/hakapik/config.py`, `hakapik.example.toml`, `compose.yaml`, `tests/conftest.py`, `tests/test_config.py`
- Delete: `main.py`

**Interfaces:**
- Produces: `load_config(path: Path) -> Config`; `Config` frozen dataclass with fields `data_dir: Path`, `database_url: str`, `bootstrap_days: int = 90`, `raw_retention_days: int = 7`, `tranco_top_n: int = 100_000`, `public_apexes: tuple[str, ...]`, `log_lists: tuple[str, ...]`, `per_log_concurrency: int = 2`, `batch_size: int = 256`.

- [ ] **Step 1: Convert the project to a src layout and add dependencies**

Run:
```bash
uv add httpx asn1crypto idna tldextract rocksdict "psycopg[binary]" zstandard
uv add --dev pytest pytest-asyncio respx
```
Set `[build-system]` to hatchling, `[tool.pytest.ini_options] asyncio_mode = "auto"`, and `[project.scripts] hakapik = "hakapik.cli:main"`. Remove `main.py`.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_config.py
def test_load_config_defaults(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('data_dir = "/var/lib/hakapik"\ndatabase_url = "postgresql://x"\n')
    cfg = load_config(p)
    assert cfg.bootstrap_days == 90
    assert cfg.raw_retention_days == 7
    assert cfg.tranco_top_n == 100_000
    assert cfg.log_lists == (
        "https://www.gstatic.com/ct/log_list/v3/log_list.json",
        "https://valid.apple.com/ct/log_list/current_log_list.json",
    )
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/test_config.py -v`
Expected: FAIL with ImportError.

- [ ] **Step 4: Implement `load_config` in `src/hakapik/config.py`**

Use `tomllib`; unknown keys raise `ValueError`.

- [ ] **Step 5: Write `hakapik.example.toml` and `compose.yaml`**

Compose runs `postgres:17` with a named volume and `POSTGRES_PASSWORD`; expose 5432 on localhost only.

- [ ] **Step 6: Run tests, verify pass, commit**

Run: `uv run pytest -v`
Expected: PASS.
```bash
git add -A && git commit -m "feat: scaffold package, config loader, compose"
```

---

### Task 2: Log list

**Files:**
- Create: `src/hakapik/ct/__init__.py`, `src/hakapik/ct/loglist.py`, `tests/test_loglist.py`, `tests/fixtures/log_list_v3_small.json`, `tests/fixtures/apple_log_list_small.json`

**Interfaces:**
- Produces: `@dataclass(frozen=True) LogInfo(log_id: str, description: str, kind: Literal["rfc6962", "tiled"], url: str, monitoring_url: str | None, state: str, operator: str)`; `parse_log_list(data: dict) -> list[LogInfo]`; `async fetch_log_lists(urls: Sequence[str], client: httpx.AsyncClient) -> list[LogInfo]` (merged, deduplicated by `log_id`, only states `usable`, `qualified`, `readonly`).

- [ ] **Step 1: Capture fixtures**

Download both live lists, cut each to two operators and four logs, including at least one entry with `monitoring_url` (tiled) and one without.

- [ ] **Step 2: Write the failing tests**

```python
def test_parse_marks_tiled_logs(v3_fixture):
    logs = parse_log_list(v3_fixture)
    tiled = [l for l in logs if l.kind == "tiled"]
    assert tiled and all(l.monitoring_url for l in tiled)

def test_parse_drops_retired_and_pending(v3_fixture):
    assert all(l.state in {"usable", "qualified", "readonly"} for l in parse_log_list(v3_fixture))

async def test_fetch_merges_and_dedups(respx_mock, v3_fixture, apple_fixture):
    ...  # two URLs mocked, one shared log_id -> appears once
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_loglist.py -v`
Expected: FAIL.

- [ ] **Step 4: Implement `loglist.py`**

`log_id` is the base64 value from the list as given. State is the single key present in each log's `state` object. A log is `tiled` when `monitoring_url` is present; `url` is then `submission_url`.

- [ ] **Step 5: Run tests, verify pass, commit**

```bash
git add -A && git commit -m "feat: fetch and parse CT log lists"
```

---

### Task 3: Leaf parsing

**Files:**
- Create: `src/hakapik/ct/leaf.py`, `tests/test_leaf.py`, `tests/fixtures/leaf_x509.bin`, `tests/fixtures/leaf_precert.bin`, `tests/fixtures/tileleaf_x509.bin`, `tests/fixtures/tileleaf_precert.bin`

**Interfaces:**
- Produces: `@dataclass(frozen=True) ParsedLeaf(timestamp_ms: int, entry_type: Literal["x509", "precert"], issuer_dn_der: bytes, serial: bytes, san_dns: tuple[str, ...], not_before: datetime, not_after: datetime, raw_len: int)`; `@dataclass(frozen=True) LeafError(timestamp_ms: int | None, reason: str)`; `parse_rfc6962_leaf(leaf_input: bytes) -> ParsedLeaf | LeafError`; `parse_tile_leaf(buf: memoryview, offset: int) -> tuple[ParsedLeaf | LeafError, int]` returning the next offset.

- [ ] **Step 1: Capture fixtures**

Fetch one x509 and one precert entry from a live RFC 6962 log via `get-entries` and store the decoded `leaf_input`. Fetch one data tile from a live tiled log and store the first two leaves' bytes. Record the expected SANs and serials in the test.

- [ ] **Step 2: Write the failing tests**

```python
def test_parse_x509_leaf_sans(leaf_x509):
    p = parse_rfc6962_leaf(leaf_x509)
    assert p.entry_type == "x509" and p.san_dns == EXPECTED_SANS_X509

def test_parse_precert_leaf_uses_tbs(leaf_precert):
    p = parse_rfc6962_leaf(leaf_precert)
    assert p.entry_type == "precert" and p.serial == EXPECTED_SERIAL_PRECERT

def test_parse_tile_leaf_advances_offset(tile_bytes):
    p1, off = parse_tile_leaf(memoryview(tile_bytes), 0)
    p2, off2 = parse_tile_leaf(memoryview(tile_bytes), off)
    assert off2 > off and isinstance(p2, ParsedLeaf)

def test_parse_leaf_garbage_returns_error_record():
    r = parse_rfc6962_leaf(b"\x00" * 40)
    assert isinstance(r, LeafError)
```

- [ ] **Step 3: Run tests to verify they fail**

- [ ] **Step 4: Implement `leaf.py` with asn1crypto**

RFC 6962 `MerkleTreeLeaf`: version(1) leaf_type(1) timestamp(8) entry_type(2); x509: 3-byte length + DER; precert: 32-byte issuer key hash + 3-byte length + TBS. Static-CT `TileLeaf` per c2sp.org/static-ct-api: timestamp(8) entry_type(2) + same payload, then extensions (2-byte length), then for x509 a fingerprint list (2-byte length, 32 bytes each), for precert the 3-byte-length precertificate plus fingerprint list. Parse TBS with `asn1crypto.x509.TbsCertificate` for precerts and `asn1crypto.x509.Certificate` for x509; read SAN `dNSName` values only; issuer DN DER is `tbs['issuer'].dump()`.

- [ ] **Step 5: Run tests, verify pass, commit**

```bash
git add -A && git commit -m "feat: parse RFC 6962 and static-CT leaves"
```

---

### Task 4: RFC 6962 client

**Files:**
- Create: `src/hakapik/ct/rfc6962.py`, `tests/test_rfc6962.py`

**Interfaces:**
- Produces: `class Rfc6962Log: __init__(self, info: LogInfo, client: httpx.AsyncClient)`; `async tree_size() -> int`; `async entries(start: int, end: int) -> list[tuple[int, bytes, bytes]]` (index, leaf_input, extra_data; may return fewer than requested); `async index_at(ts_ms: int) -> int` (first index whose timestamp is >= ts_ms, by bisection).

- [ ] **Step 1: Write the failing tests**

```python
async def test_entries_decodes_base64(respx_mock, log):
    ...  # mock get-entries returning 2 entries -> list of (idx, bytes, bytes)

async def test_get_entries_retries_on_429(respx_mock, log):
    route = respx_mock.get(url__regex=r".*get-entries.*").mock(side_effect=[httpx.Response(429), httpx.Response(200, json=TWO_ENTRIES)])
    out = await log.entries(0, 1)
    assert len(out) == 2 and route.call_count == 2

async def test_index_at_bisects(respx_mock, log):
    ...  # tree_size 1000, timestamps = 1000*i; index_at(500_000) == 500
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement `rfc6962.py`**

Backoff: exponential from 1 s, cap 60 s, retry on 429, 5xx and transport errors, honour `Retry-After`. Bisection reads one entry per probe.

- [ ] **Step 4: Run tests, verify pass, commit**

```bash
git add -A && git commit -m "feat: RFC 6962 log client with backoff and bisection"
```

---

### Task 5: Static-CT client

**Files:**
- Create: `src/hakapik/ct/static_ct.py`, `src/hakapik/ct/source.py`, `tests/test_static_ct.py`

**Interfaces:**
- Produces: `class StaticCtLog` with the same three methods as `Rfc6962Log`, where `entries(start, end)` reads whole data tiles and slices; `parse_checkpoint(text: str) -> tuple[int, bytes]` (tree size, root hash); `tile_path(index: int, partial: int | None) -> str`.
- `source.py`: `class LogSource(Protocol)` with `info`, `tree_size`, `entries`, `index_at`; `make_source(info: LogInfo, client: httpx.AsyncClient) -> LogSource`.

- [ ] **Step 1: Write the failing tests**

```python
def test_parse_checkpoint():
    size, root = parse_checkpoint("example.org/log\n12345\nAAAA...\n\n— example.org/log sigb64\n")
    assert size == 12345

def test_tile_path_encodes_three_digit_groups():
    assert tile_path(1234567, None) == "tile/data/x001/x234/567"
    assert tile_path(5, 200) == "tile/data/005.p/200"

async def test_entries_spanning_two_tiles(respx_mock, tlog):
    out = await tlog.entries(254, 258)
    assert [i for i, *_ in out] == [254, 255, 256, 257, 258]
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement `static_ct.py` and `source.py`**

Tiles are 256 entries wide; a partial tile is fetched only for the last incomplete tile. `entries` returns `(index, tile_leaf_bytes, b"")` so Task 3's `parse_tile_leaf` consumes the second element. Same backoff policy as Task 4, shared in a small `_retry` helper in `source.py`.

- [ ] **Step 4: Run tests, verify pass, commit**

```bash
git add -A && git commit -m "feat: static-CT tiled log client and source factory"
```

---

### Task 6: Name normalisation

**Files:**
- Create: `src/hakapik/names.py`, `tests/test_names.py`

**Interfaces:**
- Produces: `@dataclass(frozen=True) NameRecord(fqdn: str, registrable: str, wildcard: bool, idn: bool, valid: bool)`; `normalize(name: str) -> NameRecord`.

- [ ] **Step 1: Write the failing tests**

```python
def test_normalize_idn_case_and_trailing_dot():
    a = normalize("Sparkasse-Prüfung.DE.")
    b = normalize("xn--sparkasse-prfung-3vb.de")
    assert a.fqdn == b.fqdn and a.idn and a.valid

def test_private_suffix_registrable():
    r = normalize("login.microsoft-secure.pages.dev")
    assert r.registrable == "microsoft-secure.pages.dev"

def test_wildcard_stripped_and_flagged():
    r = normalize("*.example.com")
    assert r.fqdn == "example.com" and r.wildcard

def test_invalid_name_flagged():
    assert not normalize("bad_label!.com").valid
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement `names.py`**

`idna.encode(..., uts46=True)` for normalisation; `tldextract.TLDExtract(include_psl_private_domains=True, suffix_list_urls=())` using the bundled snapshot so tests are offline. `valid=False` when idna raises or the suffix is empty.

- [ ] **Step 4: Run tests, verify pass, commit**

```bash
git add -A && git commit -m "feat: IDNA and PSL name normalisation"
```

---

### Task 7: Dedup key and first-seen index

**Files:**
- Create: `src/hakapik/dedup.py`, `src/hakapik/firstseen.py`, `tests/test_dedup.py`, `tests/test_firstseen.py`

**Interfaces:**
- Produces: `cert_key(issuer_dn_der: bytes, serial: bytes) -> bytes` (32 bytes).
- `class FirstSeenIndex: __init__(self, path: Path)`; `seen_cert(key: bytes) -> bool` (returns prior state, then marks); `first_seen(fqdn: str, ts_ms: int, log_id: str, index: int) -> bool` (True if newly inserted; stores `(ts_ms, log_id, index)` packed); `get(fqdn: str) -> tuple[int, str, int] | None`; `close()`; context manager.

- [ ] **Step 1: Write the failing tests**

```python
def test_cert_key_is_sha256_of_issuer_and_serial():
    assert cert_key(b"i", b"s") == hashlib.sha256(b"i" + b"s").digest()

def test_first_seen_inserts_once(tmp_path):
    with FirstSeenIndex(tmp_path / "idx") as ix:
        assert ix.first_seen("a.example", 1, "L", 7) is True
        assert ix.first_seen("a.example", 2, "M", 9) is False
        assert ix.get("a.example") == (1, "L", 7)

def test_seen_cert_marks(tmp_path):
    with FirstSeenIndex(tmp_path / "idx") as ix:
        k = b"\x01" * 32
        assert ix.seen_cert(k) is False and ix.seen_cert(k) is True
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement with rocksdict**

Two column families, `fqdn` and `cert`, with RocksDB bloom filters enabled (10 bits per key). `first_seen` uses a read-then-write; single writer per process is a documented assumption.

- [ ] **Step 4: Run tests, verify pass, commit**

```bash
git add -A && git commit -m "feat: cert dedup key and first-seen index"
```

---

### Task 8: Suppression lists

**Files:**
- Create: `src/hakapik/suppress.py`, `tests/test_suppress.py`, `tests/fixtures/tranco_small.csv`

**Interfaces:**
- Produces: `class Suppressor: __init__(self, tranco_apexes: frozenset[str], public_apexes: frozenset[str])`; `classmethod from_files(tranco_csv: Path, top_n: int, public_apexes: Iterable[str]) -> Suppressor`; `reason(rec: NameRecord) -> str | None` returning `"tranco"`, `"public_apex"`, `"wildcard"`, `"invalid"` or `None` (None means candidate-eligible).

- [ ] **Step 1: Write the failing tests**

```python
def test_tranco_suppresses_apex_and_www_only(sup):
    assert sup.reason(normalize("google.com")) == "tranco"
    assert sup.reason(normalize("www.google.com")) == "tranco"
    assert sup.reason(normalize("login-check.google.com")) is None

def test_public_apex_suppressed_but_subdomain_not(sup):
    assert sup.reason(normalize("pages.dev")) == "public_apex"
    assert sup.reason(normalize("x.pages.dev")) is None

def test_wildcard_and_invalid(sup):
    assert sup.reason(normalize("*.a.com")) == "wildcard"
    assert sup.reason(normalize("bad_!.com")) == "invalid"
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement `suppress.py`**

Public apexes = PSL private-domain suffixes from tldextract's snapshot, union the config list.

- [ ] **Step 4: Run tests, verify pass, commit**

```bash
git add -A && git commit -m "feat: suppression lists"
```

---

### Task 9: Blob store and Postgres schema

**Files:**
- Create: `src/hakapik/blobstore.py`, `src/hakapik/db.py`, `tests/test_blobstore.py`, `tests/test_db.py`

**Interfaces:**
- `class BlobStore: __init__(self, root: Path)`; `put(data: bytes, media_type: str) -> str` (hex SHA-256; path `root/ab/cd/<hex>`; file mode 0o444; existing file is not rewritten); `open(hexdigest: str) -> BinaryIO`; `path(hexdigest: str) -> Path`.
- `db.py`: `async def connect(url: str) -> psycopg.AsyncConnection`; `async def migrate(conn) -> None` creating tables `log_cursor(log_id text pk, next_index bigint, bootstrap_done bool, updated_at timestamptz)`, `raw_batch(id bigserial pk, log_id text, start_index bigint, end_index bigint, blob_sha256 text, entries int, bytes int, created_at timestamptz)`, `candidate(id bigserial pk, fqdn text, registrable text, log_id text, log_index bigint, cert_key bytea, first_seen_ms bigint, created_at timestamptz)`, `ingest_stat(log_id text, day date, entries bigint, bytes bigint, parse_failed bigint, certs_unique bigint, fqdns_new bigint, suppressed bigint, candidates bigint, pk(log_id, day))`; `async get_cursor(conn, log_id) -> tuple[int, bool]`; `async set_cursor(conn, log_id, next_index, bootstrap_done)`; `@dataclass(frozen=True) CandidateRow(fqdn: str, registrable: str, log_id: str, log_index: int, cert_key: bytes, first_seen_ms: int)`; `async add_candidates(conn, rows: list[CandidateRow])`; `async add_raw_batch(conn, log_id: str, start_index: int, end_index: int, blob_sha256: str, entries: int, nbytes: int)`; `async bump_stat(conn, log_id, day, **increments)` (upsert, additive); `async read_stat(conn, log_id, day) -> dict`.

Deferred to later plans, on purpose: inclusion proofs (evidence plan) and the re-check window (needs last-fetch, fetch plan).

- [ ] **Step 1: Write the failing tests**

```python
def test_blobstore_put_is_idempotent_and_readonly(tmp_path):
    bs = BlobStore(tmp_path)
    h = bs.put(b"abc", "application/octet-stream")
    assert h == hashlib.sha256(b"abc").hexdigest()
    assert bs.put(b"abc", "x") == h
    assert (bs.path(h).stat().st_mode & 0o777) == 0o444

@pytest.mark.skipif(not os.getenv("HAKAPIK_TEST_DB"), reason="needs postgres")
async def test_cursor_and_stat_roundtrip(conn):
    await set_cursor(conn, "L", 10, False)
    assert await get_cursor(conn, "L") == (10, False)
    await bump_stat(conn, "L", date(2026, 10, 23), entries=5)
    await bump_stat(conn, "L", date(2026, 10, 23), entries=2)
    assert (await read_stat(conn, "L", date(2026, 10, 23)))["entries"] == 7
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement both modules**

`conftest.py` provides `conn` from `HAKAPIK_TEST_DB`, runs `migrate`, and truncates tables per test. Migrations are plain `CREATE TABLE IF NOT EXISTS` statements.

- [ ] **Step 4: Run tests with Postgres up, verify pass, commit**

Run: `docker compose up -d && HAKAPIK_TEST_DB=postgresql://... uv run pytest -v`
```bash
git add -A && git commit -m "feat: blob store and postgres schema"
```

---

### Task 10: Tailer and bootstrap orchestration

**Files:**
- Create: `src/hakapik/ingest.py`, `tests/test_ingest.py`

**Interfaces:**
- Consumes: everything above.
- Produces: `async def process_batch(src: LogSource, start: int, end: int, *, mode: Literal["bootstrap", "live"], ix: FirstSeenIndex, sup: Suppressor, bs: BlobStore, conn, stats: StatCounter) -> int` (entries processed); `async def bootstrap_log(src, cfg, ...) -> None` (finds `index_at(now - bootstrap_days)`, walks to current tree size, sets `bootstrap_done`); `async def tail_log_once(src, cfg, ...) -> int` (one batch from the cursor; returns entries processed); `async def tail_log(src, cfg, ..., stop: asyncio.Event) -> None` (loops `tail_log_once`, sleeps 10 s when caught up); `async def run(cfg: Config, mode: Literal["bootstrap", "tail"]) -> None` (one task per log, `per_log_concurrency` in-flight batches per log).

- [ ] **Step 1: Write the failing tests**

Use a `FakeSource` in-memory `LogSource` with fixture leaves.

```python
async def test_bootstrap_writes_index_only(fake, ix, sup, bs, conn):
    await process_batch(fake, 0, 1, mode="bootstrap", ix=ix, sup=sup, bs=bs, conn=conn, stats=StatCounter())
    assert ix.get(EXPECTED_FQDN) is not None
    assert await count(conn, "candidate") == 0 and await count(conn, "raw_batch") == 0

async def test_live_emits_candidate_once_and_stores_raw(fake, ...):
    await process_batch(fake, 0, 1, mode="live", ...)
    await process_batch(fake, 2, 3, mode="live", ...)  # same cert, other log index
    assert await count(conn, "candidate") == len(EXPECTED_NEW_FQDNS)
    assert await count(conn, "raw_batch") == 2

async def test_cursor_advances_only_after_batch_commit(fake_failing_blobstore, ...):
    with pytest.raises(OSError):
        await tail_log_once(...)
    assert await get_cursor(conn, fake.info.log_id) == (0, True)

async def test_live_skips_candidates_until_bootstrap_done(...):
    ...  # cursor bootstrap_done=False -> raw stored, no candidates, stat counts entries
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement `ingest.py`**

Per batch: fetch entries, parse each, compute `cert_key`, `seen_cert`; for unseen certs normalise every SAN, `first_seen` per FQDN; in live mode pack `(index, leaf, extra)` records with zstandard into one blob and insert `raw_batch`; eligible new FQDNs become candidates only when `mode == "live"` and the cursor's `bootstrap_done` is true; stats bumped per batch; cursor set in the same transaction as candidates and raw_batch, after the blob and index writes. `StatCounter` is a small dataclass of ints flushed with `bump_stat`.

- [ ] **Step 4: Run tests, verify pass, commit**

```bash
git add -A && git commit -m "feat: tailer and bootstrap orchestration"
```

---

### Task 11: CLI, retention, and measurement output

**Files:**
- Create: `src/hakapik/cli.py`, `tests/test_cli.py`
- Modify: `src/hakapik/db.py` (add `read_stats(conn, since: date) -> list[dict]`, `sample_candidates(conn, n: int) -> list[dict]`, `prune_raw(conn, bs, older_than: date) -> int`)

**Interfaces:**
- Produces: `hakapik --config PATH bootstrap`, `hakapik --config PATH tail`, `hakapik --config PATH stats [--since DATE]` (table: per log and day, all `ingest_stat` columns, plus a totals row), `hakapik --config PATH sample --n 200 --out candidates.csv`, `hakapik --config PATH prune`.

- [ ] **Step 1: Write the failing tests**

```python
def test_stats_prints_totals_row(capsys, seeded_db):
    main(["--config", cfg_path, "stats"])
    assert "TOTAL" in capsys.readouterr().out

def test_sample_writes_csv(tmp_path, seeded_db):
    out = tmp_path / "c.csv"
    main(["--config", cfg_path, "sample", "--n", "2", "--out", str(out)])
    assert len(out.read_text().splitlines()) == 3

async def test_prune_removes_raw_batches_without_candidates(...):
    ...  # batch older than retention, no candidate referencing its log range -> deleted and blob unlinked
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement `cli.py` with argparse**

Logging to stderr with per-log lag (tree size minus cursor) printed every 60 s during `tail`.

- [ ] **Step 4: Run tests, verify pass, commit**

```bash
git add -A && git commit -m "feat: CLI with bootstrap, tail, stats, sample, prune"
```

---

### Task 12: Measurement run and report

> Dropped 2026-10-24 by the owner: no measuring run gates later stages
> (spec section 14). Kept below as history.

**Files:**
- Create: `docs/measurements/2026-XX-XX-ingest-spike.md`

- [ ] **Step 1: Run bootstrap against all logs on the target machine**

Run: `hakapik --config hakapik.toml bootstrap` and record wall time and bytes.

- [ ] **Step 2: Run tail for at least three full days**

Run: `hakapik --config hakapik.toml tail` under systemd or `nohup`.

- [ ] **Step 3: Collect**

Run: `hakapik --config hakapik.toml stats --since <start>` and `hakapik --config hakapik.toml sample --n 200 --out candidates.csv`. Hand-classify the 200 rows into: likely phishing, parked or default, legitimate new site, unclear.

- [ ] **Step 4: Write the report**

Sections: entries per day per log, bytes per day, parse throughput per core (from log timing), first-seen FQDNs per day, suppression share per reason, candidates per day, the 200-row classification, and which design estimates in sections 4, 5.1 and 11a change. Commit.

```bash
git add docs/measurements && git commit -m "docs: ingest spike measurements"
```
