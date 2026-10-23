# Resolve and Fetch (Plan 2 of the hakapik PoC) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn every candidate into a ranked, capped fetch job. Resolve and render it on the retry ladder with a real mobile-first browser, store every DNS answer, WARC, screenshot, DOM and served certificate chain in the blob store, and keep a hash-chained manifest per candidate. The work runs behind the worker-role boundary of spec section 6, with the head running the role itself.

**Architecture:** Postgres holds the job queue (`fetch_job`, claimed with `FOR UPDATE SKIP LOCKED` and a lease) and the append-only results (`attempt`, `dns_answer`, `artifact`, `blob`, `manifest`). The worker role (`hakapik.worker`) takes a `Job`, resolves the name with dnspython, renders it with Playwright Chromium, writes blobs, and returns an Ed25519-signed result envelope. The head (`hakapik.store`) verifies the signature and every blob hash before writing anything. `hakapik fetch` runs the head's scheduler and its own worker role in one process; `hakapik enqueue` adds names by hand, so no tail is needed.

**Tech Stack:** Python 3.13, uv, psycopg 3, playwright (Chromium, `channel="chromium"`), dnspython, warcio, cryptography (Ed25519), maxminddb, pytest, pytest-asyncio, mmdb-writer (tests only).

**Spec:** `docs/superpowers/specs/2026-10-23-hakapik-design.md` (sections 5.2 re-check rule, 5.4, 5.5, 6, 7, 8, and 11 items 6 and 7). Literature numbers: `docs/literature/README.md`.

## Global Constraints

- Python `>=3.13`; code under `src/hakapik/`, tests under `tests/`; dependencies via `uv add`.
- Database functions do not commit; the caller owns the transaction (existing `db.py` convention). Results are append-only. Only operational state changes in place: `fetch_job.step/due_at/state/claimed_until`.
- Retry ladder, offsets from the job's creation: `0, 120, 600, 3600, 21600, 86400` seconds (spec 5.5: immediately, 2 min, 10 min, 1 h, 6 h, 24 h). Every job runs the whole ladder. After the ladder, the next fetch of that FQDN comes only from the re-check rule.
- Re-check rule (spec 5.2): a renewal of an already-seen FQDN becomes a candidate if that FQDN's last attempt finished more than `recheck_days` ago and its registrable domain is not in the Tranco top set.
- Egress (spec 11.6): the PoC fetches from the head's own address. All browser traffic goes through the single optional `fetch_proxy` setting; DNS goes to `resolver_nameservers` (empty = system resolver).
- Rate limits (spec 11.7): `fetch_per_ip_interval_s` and `fetch_daily_cap` have no defaults; unset (key omitted) means unlimited.
- Mobile profile first (spec 5.5); the desktop pass and the login click-through run only when the mobile pass reached `live`.
- No favicon or robots.txt requests are made by our code. Downloads are refused (`accept_downloads=False`).
- Never point tests at the live `hakapik` database. The `conn` fixture drops every table it knows; extend its table list.
- Commit messages end with `Co-Authored-By:` naming the model that actually wrote the commit (owner ruling 2026-10-24).

## Review Focus

1. **The fetcher dies mid-attempt** (kill -9, OOM, Chromium crash). The job's lease expires and the job is claimed again; a second result for the same `(job_id, step)` is a no-op, never a duplicate attempt. Pinned in Task 3 (`test_expired_lease_is_reclaimed`) and Task 9 (`test_duplicate_envelope_is_noop`).
2. **A page that never settles** (endless meta-refresh or JS redirect loop, a download, a hanging response). The capture ends within `nav_timeout_s` plus the settle time and records an outcome; it never blocks a worker slot. Pinned in Task 6 (`test_meta_refresh_loop_terminates`, `test_download_is_refused`).
3. **A forged or inconsistent worker result** (unknown node, bad signature, a blob missing or with the wrong hash). The head rejects it and writes nothing. Pinned in Task 9 (`test_rejects_bad_signature`, `test_rejects_blob_hash_mismatch`).
4. **The same FQDN arrives twice** (duplicate candidate after an ingest crash, a CT name that is also enqueued by hand). At most one open job per FQDN exists. Pinned in Task 3 (`test_one_open_job_per_fqdn`).
5. **Backlog beyond capacity** (day one: most renewals look new). Untried jobs older than `ageout_hours`, or ranked beyond `queue_cap`, are marked `aged_out`; the newest due job is claimed first, so fresh candidates keep the "first attempt immediately" promise. Pinned in Task 3 (`test_sweep_ages_out_old_and_excess`, `test_claim_newest_first`).

---

## File structure

```
src/hakapik/
  config.py          # + fetch, resolver, queue keys (Task 1)
  db.py              # + schema for the new tables, CandidateRow.reason, add_candidates enqueues (Task 1, 3)
  protocol.py        # Job, DnsAnswer, PageResult, BlobRef, AttemptResult, NodeKey, seal/open (Task 2)
  jobs.py            # queue: claim, advance, sweep, daily count, last_fetched, enqueue_manual (Task 3)
  ingest.py          # + re-check rule (Task 4)
  suppress.py        # + top_listed(registrable) (Task 4)
  resolve.py         # Resolver over dnspython (Task 5)
  warc.py            # Exchange -> gzipped WARC bytes (Task 6)
  browser.py         # Browser, Capture, profiles, classify(), click-through (Task 6, 7)
  worker.py          # run_job: the worker role (Task 8)
  store.py           # register_node, store_result, write_manifest (Task 9)
  asn.py             # AsnDb over a GeoLite2-ASN .mmdb (Task 10)
  fetchloop.py       # run_fetch: head scheduler + own worker role (Task 11)
  cli.py             # + enqueue, fetch, show (Task 12)
tests/
  conftest.py        # + new tables in the DROP list
  dnsserver.py       # tiny UDP DNS responder for resolver tests (Task 5)
  sites.py           # local HTTP test site for browser tests (Task 6)
  test_protocol.py test_jobs.py test_recheck.py test_resolve.py test_warc.py
  test_browser.py test_worker.py test_store.py test_asn.py test_fetchloop.py test_cli_fetch.py
```

---

### Task 1: Config keys and schema

**Files:**
- Modify: `src/hakapik/config.py`, `src/hakapik/db.py`, `tests/conftest.py`, `hakapik.example.toml`
- Test: `tests/test_config.py`, `tests/test_db.py`

**Interfaces:**
- Produces: `Config` fields (all optional in TOML):
  `fetch_workers: int = 2`, `fetch_per_ip_interval_s: float | None = None`, `fetch_daily_cap: int | None = None`, `fetch_proxy: str | None = None`, `egress_address: str | None = None`, `resolver_nameservers: tuple[str, ...] = ()`, `retry_ladder_s: tuple[int, ...] = (0, 120, 600, 3600, 21600, 86400)`, `recheck_days: int = 30`, `queue_cap: int | None = None`, `ageout_hours: float = 24.0`, `nav_timeout_s: float = 30.0`, `lease_s: int = 600`, `asn_mmdb: Path | None = None` (path to a GeoLite2-ASN `.mmdb` the operator supplies).
- Produces: the tables below, created by `migrate()`; `CandidateRow` gains `reason: str = "first_seen"`, and its `log_id`, `log_index`, `cert_key`, `first_seen_ms` become `| None`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_config.py
def test_fetch_defaults(tmp_path):
    cfg = _load(tmp_path, "")           # existing helper writing data_dir + database_url
    assert cfg.retry_ladder_s == (0, 120, 600, 3600, 21600, 86400)
    assert cfg.fetch_per_ip_interval_s is None and cfg.fetch_daily_cap is None
    assert cfg.fetch_proxy is None and cfg.resolver_nameservers == ()
    assert cfg.fetch_workers == 2 and cfg.recheck_days == 30 and cfg.ageout_hours == 24.0

def test_ladder_must_start_at_zero_and_increase(tmp_path):
    with pytest.raises(ValueError, match="retry_ladder_s"):
        _load(tmp_path, "retry_ladder_s = [0, 600, 120]")
    with pytest.raises(ValueError, match="retry_ladder_s"):
        _load(tmp_path, "retry_ladder_s = [60, 120]")

def test_list_values_become_tuples(tmp_path):
    cfg = _load(tmp_path, 'resolver_nameservers = ["9.9.9.9"]')
    assert cfg.resolver_nameservers == ("9.9.9.9",)

# tests/test_db.py
async def test_new_tables_exist(conn):
    for t in ("fetch_job", "attempt", "dns_answer", "artifact", "blob", "manifest", "node"):
        cur = await conn.execute("SELECT to_regclass(%s)", (t,))
        assert (await cur.fetchone())[0] is not None

async def test_migrate_upgrades_old_candidate_table(conn):
    # a stage-one candidate table (NOT NULL log columns, no reason) is upgraded in place
    await conn.execute("DROP TABLE candidate CASCADE")
    await conn.execute(STAGE_ONE_CANDIDATE_DDL)   # copy of the pre-change CREATE TABLE
    await migrate(conn)
    await conn.execute("INSERT INTO candidate (fqdn, registrable, reason) VALUES ('a.example.com','example.com','manual')")
```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_config.py tests/test_db.py -v -W error` (with `HAKAPIK_TEST_DB` set)
Expected: FAIL (unknown attributes, missing tables).

- [ ] **Step 3: Implement the config**

`load_config` turns every list value into a tuple (generalising the two hard-coded keys) and raises `ValueError` naming `retry_ladder_s` unless it is non-empty, starts with 0 and strictly increases. TOML has no null, so "unset" means the key is omitted.

- [ ] **Step 4: Implement the schema in `db.py` `_SCHEMA`** (appended; `IF NOT EXISTS` / idempotent `ALTER`s so existing databases upgrade)

```sql
ALTER TABLE candidate ADD COLUMN IF NOT EXISTS reason text NOT NULL DEFAULT 'first_seen';
ALTER TABLE candidate ALTER COLUMN log_id DROP NOT NULL;      -- also log_index, cert_key, first_seen_ms
CREATE INDEX IF NOT EXISTS candidate_fqdn ON candidate (fqdn);
CREATE TABLE IF NOT EXISTS fetch_job (
  id bigserial PRIMARY KEY,
  candidate_id bigint NOT NULL REFERENCES candidate(id),
  fqdn text NOT NULL, registrable text NOT NULL,
  priority real NOT NULL DEFAULT 0,          -- T0 score later; 0 for now
  step int NOT NULL DEFAULT 0,               -- index into retry_ladder_s of the next attempt
  due_at timestamptz NOT NULL,
  state text NOT NULL DEFAULT 'open',        -- open | done | aged_out
  claimed_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX IF NOT EXISTS fetch_job_open_fqdn ON fetch_job (fqdn) WHERE state = 'open';
CREATE INDEX IF NOT EXISTS fetch_job_due ON fetch_job (priority DESC, due_at DESC) WHERE state = 'open';
CREATE INDEX IF NOT EXISTS fetch_job_fqdn ON fetch_job (fqdn);
CREATE TABLE IF NOT EXISTS node (node_id text PRIMARY KEY, public_key bytea NOT NULL, added_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS blob (sha256 text PRIMARY KEY, size bigint NOT NULL, media_type text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS attempt (
  id bigserial PRIMARY KEY,
  job_id bigint NOT NULL REFERENCES fetch_job(id), step int NOT NULL,
  node_id text NOT NULL REFERENCES node(node_id), egress_address text,
  started_at timestamptz NOT NULL, finished_at timestamptz NOT NULL,
  outcome text NOT NULL, http_status int, final_url text, error text,
  envelope_sha256 text NOT NULL REFERENCES blob(sha256),
  asn bigint, asn_org text, asn_db_sha256 text REFERENCES blob(sha256),   -- head-side enrichment (Task 10)
  UNIQUE (job_id, step));
CREATE TABLE IF NOT EXISTS dns_answer (
  id bigserial PRIMARY KEY, attempt_id bigint NOT NULL REFERENCES attempt(id),
  node_id text NOT NULL, qname text NOT NULL, rrtype text NOT NULL, rcode text NOT NULL,
  ttl int, answers text[] NOT NULL, resolver text NOT NULL, queried_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS artifact (
  id bigserial PRIMARY KEY, attempt_id bigint NOT NULL REFERENCES attempt(id),
  profile text NOT NULL, kind text NOT NULL, sha256 text NOT NULL REFERENCES blob(sha256));
CREATE TABLE IF NOT EXISTS manifest (
  id bigserial PRIMARY KEY, candidate_id bigint NOT NULL REFERENCES candidate(id),
  version int NOT NULL, sha256 text NOT NULL REFERENCES blob(sha256), prev_sha256 text,
  created_at timestamptz NOT NULL DEFAULT now(), UNIQUE (candidate_id, version));
```

Extend the `conftest.py` DROP to `... CASCADE` over all eleven tables. Document every new key in `hakapik.example.toml`: comment out the unset-by-default rate limits and state "omitted = unlimited".

- [ ] **Step 5: Run the full suite and commit**

Run: `uv run pytest -W error` → all pass.
`git commit -m "feat: config and schema for resolve and fetch"`

---

### Task 2: Worker protocol (spec 6)

**Files:**
- Create: `src/hakapik/protocol.py`
- Test: `tests/test_protocol.py`
- `uv add cryptography`

**Interfaces (Produces):**
```python
OUTCOMES = ("dns_fail", "connect_fail", "tls_error", "timeout", "http_error", "download", "live", "error")

@dataclass(frozen=True) class Job:
    job_id: int; candidate_id: int; fqdn: str; registrable: str; step: int
    url: str                                  # "https://{fqdn}/"
@dataclass(frozen=True) class DnsAnswer:
    qname: str; rrtype: str; rcode: str        # NOERROR | NXDOMAIN | SERVFAIL | REFUSED | TIMEOUT | ...
    ttl: int | None; answers: tuple[str, ...]; resolver: str; queried_at: str   # RFC 3339 UTC
@dataclass(frozen=True) class PageResult:
    profile: str                               # mobile | desktop | desktop-click1..3
    outcome: str; http_status: int | None; final_url: str | None; server_ip: str | None
    redirects: tuple[str, ...]; error: str | None; started_at: str; finished_at: str
@dataclass(frozen=True) class BlobRef:
    profile: str; kind: str                    # warc | screenshot | dom | certchain
    sha256: str; size: int; media_type: str
@dataclass(frozen=True) class AttemptResult:
    job_id: int; step: int; node_id: str; egress_address: str | None
    started_at: str; finished_at: str; outcome: str; error: str | None
    dns: tuple[DnsAnswer, ...]; pages: tuple[PageResult, ...]; blobs: tuple[BlobRef, ...]

def canonical_json(obj) -> bytes            # sort_keys, separators=(",", ":"), ensure_ascii=True
def result_to_json(r: AttemptResult) -> bytes
def result_from_json(b: bytes) -> AttemptResult
class NodeKey:
    @classmethod load_or_create(cls, path: Path) -> NodeKey   # raw 32-byte Ed25519 seed, file mode 0o600
    node_id: str                              # sha256(public_key).hexdigest()[:32]
    public_key: bytes                         # raw 32 bytes
def seal(r: AttemptResult, key: NodeKey) -> bytes
    # canonical_json({"node_id", "payload": b64(result_to_json(r)), "signature": b64(sig over payload bytes)})
class BadEnvelope(Exception)
def open_envelope(env: bytes, public_key_for: Callable[[str], bytes | None]) -> AttemptResult
    # raises BadEnvelope: malformed, unknown node, bad signature, or payload node_id != envelope node_id
```

- [ ] **Step 1: Write the failing tests**

```python
def test_seal_open_roundtrip(tmp_path):
    k = NodeKey.load_or_create(tmp_path / "node.key")
    r = _result(node_id=k.node_id)            # helper building a full AttemptResult
    assert open_envelope(seal(r, k), {k.node_id: k.public_key}.get) == r

def test_key_is_persistent_and_private(tmp_path):
    p = tmp_path / "node.key"
    assert NodeKey.load_or_create(p).node_id == NodeKey.load_or_create(p).node_id
    assert p.stat().st_mode & 0o777 == 0o600

def test_tampered_payload_rejected(tmp_path): ...   # flip one byte inside payload -> BadEnvelope
def test_unknown_node_rejected(tmp_path): ...       # public_key_for returns None -> BadEnvelope
def test_node_id_mismatch_rejected(tmp_path): ...   # result.node_id != signer -> BadEnvelope
def test_canonical_json_is_stable():
    assert canonical_json({"b": 1, "a": "ü"}) == b'{"a":"\\u00fc","b":1}'
```

- [ ] **Step 2: Run, verify FAIL. Step 3: Implement. Step 4: Run, verify PASS.**

Run: `uv run pytest tests/test_protocol.py -v -W error`

- [ ] **Step 5: Commit** — `git commit -m "feat: signed worker result protocol"`

---

### Task 3: Fetch queue

**Files:**
- Create: `src/hakapik/jobs.py`
- Modify: `src/hakapik/db.py` (`add_candidates`)
- Test: `tests/test_jobs.py`

**Interfaces:**
- Consumes: `Job` (Task 2), `normalize` from `names.py`, `Suppressor` is NOT consulted for manual names.
- Produces:
```python
# db.py
async def add_candidates(conn, rows: list[CandidateRow]) -> None
    # each row: insert candidate (with reason) and, in the same statement, its job:
    # WITH c AS (INSERT INTO candidate (...) VALUES (...) RETURNING id, fqdn, registrable, created_at)
    # INSERT INTO fetch_job (candidate_id, fqdn, registrable, due_at)
    #   SELECT id, fqdn, registrable, created_at FROM c
    #   ON CONFLICT (fqdn) WHERE state = 'open' DO NOTHING
# jobs.py
async def claim_jobs(conn, n: int, lease_s: int) -> list[Job]
    # open, due_at <= now(), claimed_until null or past; ORDER BY priority DESC, due_at DESC;
    # FOR UPDATE SKIP LOCKED; sets claimed_until = now() + lease
async def advance_job(conn, job_id: int, step: int, ladder: tuple[int, ...]) -> None
    # only if the row's step == step: next step -> due_at = created_at + ladder[step+1] s, claimed_until NULL;
    # after the last step -> state 'done'
async def sweep(conn, ageout_hours: float, queue_cap: int | None) -> int
    # open & step = 0 & created_at older than ageout -> aged_out;
    # then if untried open jobs > queue_cap, the lowest (priority ASC, created_at ASC) excess -> aged_out
async def attempts_today(conn) -> int          # attempts with started_at >= today 00:00 UTC
async def last_fetched(conn, fqdns: list[str]) -> dict[str, datetime]   # max attempt.finished_at per fqdn
async def enqueue_manual(conn, names: list[str]) -> list[tuple[str, str]]
    # (input, status): queued | already_open | invalid | wildcard; candidate reason 'manual'
```

- [ ] **Step 1: Write the failing tests** (all against `conn`)

```python
async def test_one_open_job_per_fqdn(conn):
    await add_candidates(conn, [_row("a.example.com"), _row("a.example.com")])
    assert await enqueue_manual(conn, ["A.Example.com."]) == [("A.Example.com.", "already_open")]
    assert await _count(conn, "fetch_job") == 1
    assert await _count(conn, "candidate") == 2     # the already_open manual name adds no candidate

async def test_claim_newest_first(conn):         # three due jobs created at t, t+1, t+2 -> claim(1) returns t+2
async def test_claim_respects_due_and_lease(conn):
    # job with due_at in the future is not claimed; a claimed job is not claimed again before its lease ends
async def test_expired_lease_is_reclaimed(conn):
    # claim with lease_s=1, set claimed_until into the past, claim again -> same job returned
async def test_advance_walks_the_ladder(conn):
    ladder = (0, 120, 600)
    # after advance(step 0): step 1, due_at == created_at + 120 s, claimed_until NULL
    # advance(step 0) again is a no-op (stale step); after advance(step 2): state 'done'
async def test_sweep_ages_out_old_and_excess(conn):
    # 1 untried job older than ageout -> aged_out; with queue_cap=2 and 4 fresh untried jobs,
    # the 2 oldest -> aged_out; a job at step 1 is never aged out; returns 3
async def test_enqueue_manual_rejects(conn):
    assert [s for _, s in await enqueue_manual(conn, ["*.x.com", "bad..name", "ok.example.org"])] == \
        ["wildcard", "invalid", "queued"]
async def test_last_fetched(conn): ...           # fqdn without attempts is absent from the dict
```

- [ ] **Step 2: Run, verify FAIL. Step 3: Implement. Step 4: Run `uv run pytest tests/test_jobs.py tests/test_ingest.py -v -W error`, verify PASS** (ingest tests still pass with jobs now created).

- [ ] **Step 5: Commit** — `git commit -m "feat: ranked fetch queue with lease, ladder and age-out"`

---

### Task 4: Re-check rule in ingest (spec 5.2)

**Files:**
- Modify: `src/hakapik/ingest.py` (`_process_batch`, `StatCounter`), `src/hakapik/suppress.py`, `src/hakapik/db.py` (`STAT_COLUMNS`, `ingest_stat` gets `candidates_recheck bigint NOT NULL DEFAULT 0` via `ADD COLUMN IF NOT EXISTS`)
- Test: `tests/test_recheck.py`

**Interfaces:**
- Consumes: `last_fetched` (Task 3).
- Produces: `Suppressor.top_listed(registrable: str) -> bool`; `_process_batch(..., recheck_days: int)` (keyword; `tail_log` passes `cfg.recheck_days`, `process_batch` defaults it to 30).

Rule, inside `_process_batch`: a SAN whose name is valid, not a wildcard, already in the index (`ix.get(key) is not None`), and not suppressed is collected once per batch. After the loop, one `last_fetched` query decides. Names whose last attempt finished before `now - recheck_days`, and whose registrable is not `top_listed`, are added as `CandidateRow(reason="recheck")` (log fields from the current entry) and counted in `candidates_recheck`. A name never attempted is not re-checked.

- [ ] **Step 1: Write the failing tests**

```python
async def test_old_fetch_renewal_becomes_recheck_candidate(conn, ...):
    # index already holds a.example.com; an attempt for it finished 40 days ago; a new cert for it
    # arrives -> one candidate with reason 'recheck', stat candidates_recheck == 1
async def test_recent_fetch_is_not_rechecked(conn, ...):   # attempt 5 days ago -> no candidate
async def test_never_fetched_is_not_rechecked(conn, ...):  # seen but no attempt -> no candidate
async def test_top_listed_registrable_is_not_rechecked(conn, ...)
```

Build the batches the way `tests/test_ingest.py` does (fake `LogSource` serving fixture leaves). Insert the old attempt rows directly, with a registered dummy node and blob.

- [ ] **Step 2: Run, verify FAIL. Step 3: Implement. Step 4: Run `uv run pytest tests/test_recheck.py tests/test_ingest.py -v -W error`, verify PASS.**

- [ ] **Step 5: Commit** — `git commit -m "feat: re-check window for renewals of fetched names"`

---

### Task 5: Resolver (spec 5.4)

**Files:**
- Create: `src/hakapik/resolve.py`, `tests/dnsserver.py`
- Test: `tests/test_resolve.py`
- `uv add dnspython`

**Interfaces (Produces):**
```python
class Resolver:
    def __init__(self, nameservers: tuple[str, ...] = (), *, port: int = 53, timeout_s: float = 5.0)
        # empty nameservers -> system configuration (resolv.conf)
    async def resolve(self, fqdn: str, registrable: str) -> tuple[DnsAnswer, ...]
        # A, AAAA, CNAME, NS, MX, TXT on fqdn; NS on registrable if it differs from fqdn;
        # then PTR for every address in the A and AAAA answers. Queries run concurrently.
def addresses(answers: tuple[DnsAnswer, ...], fqdn: str) -> list[str]
    # A then AAAA addresses for fqdn, in answer order
```
Each query yields exactly one `DnsAnswer`, whatever happens. If the name exists but the type has no data, the answer has `rcode="NOERROR"` and `answers=()` (use `raise_on_no_answer=False`). A timeout gives `rcode="TIMEOUT"`. `resolver` is the nameserver that answered, or for a timeout the first configured one. `ttl` is the answer RRset's TTL. Answers are rdata `to_text()`, sorted for stable output.

`tests/dnsserver.py`: an asyncio UDP responder on 127.0.0.1, port 0, built on `dns.message.from_wire` / `dns.message.make_response`. It serves a dict `{(qname, rdtype): (rcode, [rdata text], ttl)}` and stays silent for names marked `"drop"`.

- [ ] **Step 1: Write the failing tests**

```python
async def test_records_every_type_and_ptr(dns_server):
    r = Resolver(("127.0.0.1",), port=dns_server.port)
    ans = await r.resolve("login.example.com", "example.com")
    kinds = {(a.qname, a.rrtype) for a in ans}
    assert {("login.example.com", t) for t in ("A", "AAAA", "CNAME", "NS", "MX", "TXT")} <= kinds
    assert ("example.com", "NS") in kinds
    assert ("4.3.2.1.in-addr.arpa", "PTR") in kinds          # for A 1.2.3.4
    a = next(x for x in ans if x.rrtype == "A")
    assert a.answers == ("1.2.3.4",) and a.ttl == 300 and a.resolver == "127.0.0.1"
async def test_nxdomain_recorded(dns_server): ...           # rcode NXDOMAIN, answers (), addresses() == []
async def test_timeout_recorded_not_raised(dns_server): ... # dropped name, timeout_s=0.5 -> rcode TIMEOUT
async def test_empty_type_is_noerror(dns_server): ...       # AAAA absent -> NOERROR, ()
```

- [ ] **Step 2: Run, verify FAIL. Step 3: Implement. Step 4: Run `uv run pytest tests/test_resolve.py -v -W error`, verify PASS.**

- [ ] **Step 5: Commit** — `git commit -m "feat: resolver recording every DNS answer"`

---

### Task 6: WARC writer and browser capture (spec 5.5)

**Files:**
- Create: `src/hakapik/warc.py`, `src/hakapik/browser.py`, `tests/sites.py`
- Test: `tests/test_warc.py`, `tests/test_browser.py`
- `uv add playwright warcio`; install the browser once with `uv run playwright install chromium --no-shell`

**Interfaces (Produces):**
```python
# warc.py
MAX_BODY = 20 * 1024 * 1024
@dataclass(frozen=True) class Exchange:
    url: str; method: str; request_headers: tuple[tuple[str, str], ...]; request_body: bytes | None
    status: int; status_text: str; response_headers: tuple[tuple[str, str], ...]; body: bytes
    server_ip: str | None; at: datetime
def build_warc(exchanges: list[Exchange], info: dict[str, str]) -> bytes
    # gzipped WARC 1.1: one warcinfo record (info + "http-headers: reconstructed from the browser,
    # not wire bytes"), then per exchange a request and a response record linked by
    # WARC-Concurrent-To; response has WARC-IP-Address when known; HTTP/2 pseudo-headers dropped;
    # status line "HTTP/1.1 {status} {status_text}"; body over MAX_BODY truncated with WARC-Truncated: length
# browser.py
PROFILES: dict[str, dict]   # "mobile": playwright devices["Pixel 7"]; "desktop": 1366x768, no touch,
                            # Windows Chrome UA; both UAs carry the running browser's exact version
@dataclass(frozen=True) class ClickCapture:
    label: str; page: PageResult; screenshot: bytes | None; dom: bytes | None
@dataclass(frozen=True) class Capture:
    page: PageResult; screenshot: bytes | None; dom: bytes | None; warc: bytes
    cert_chain: tuple[bytes, ...]; clicks: tuple[ClickCapture, ...]
def classify(error: str | None, status: int | None) -> str
    # Chromium net errors: ERR_NAME_NOT_RESOLVED -> dns_fail; ERR_CONNECTION_*, ERR_ADDRESS_*,
    # ERR_TIMED_OUT -> connect_fail; ERR_CERT_*, ERR_SSL_* -> tls_error; playwright TimeoutError -> timeout;
    # "Download is starting" -> download; other error -> error; status >= 400 -> http_error; else live
class Browser:
    def __init__(self, *, proxy: str | None, nav_timeout_s: float, settle_s: float = 3.0)
    async def __aenter__ / __aexit__     # one Chromium, launch(channel="chromium",
                                         # args=["--disable-blink-features=AutomationControlled"], proxy=...)
    async def capture(self, url: str, profile: str, *, click_through: bool = False) -> Capture
```

`capture` uses a fresh browser context per call (no shared cookies) with `accept_downloads=False`. A CDP session runs `Network.enable` before navigation. Exchanges are collected from `context.on("requestfinished")` and `on("requestfailed")`. The main-frame URL list comes from `page.on("framenavigated")`, capped at 50 entries. Navigation is `goto(url, wait_until="load", timeout=nav_timeout_s)`, then `settle_s` for JS and meta redirects. Recorded: final URL, `response.server_addr()`, viewport screenshot (PNG), `page.content()` (UTF-8), and `Network.getCertificate` for the final URL's origin (base64 DER list → bytes; empty for http). A failed navigation still returns a `Capture` with the outcome from `classify`, `screenshot=None` and the WARC of whatever was exchanged. `capture` raises nothing a page can trigger; it closes the context in all cases.

`tests/sites.py` provides the `site` fixture and a session-scoped `browser` fixture (`Browser(proxy=None, nav_timeout_s=10, settle_s=1)`). The `site` fixture serves a small site on 127.0.0.1 from a thread (`http.server`). Pages: `/` (plain page with a "Sign in" link to `/login` holding a password form), `/redirect` (302 → `/`), `/js` (JS `location` redirect → `/`), `/loop` (meta refresh to itself every 0 s), `/apk` (`Content-Disposition: attachment`), `/404`. Browser tests skip if `playwright` cannot launch Chromium.

- [ ] **Step 1: Write the failing tests**

```python
def test_warc_roundtrip():
    data = build_warc([_ex("https://a.test/", 200, b"<html>hi</html>", "1.2.3.4")], {"software": "hakapik"})
    recs = list(ArchiveIterator(io.BytesIO(data)))
    assert [r.rec_type for r in recs] == ["warcinfo", "request", "response"]
    resp = recs[2]
    assert resp.rec_headers.get_header("WARC-IP-Address") == "1.2.3.4"
    assert resp.rec_headers.get_header("WARC-Concurrent-To") == recs[1].rec_headers.get_header("WARC-Record-ID")
    assert resp.content_stream().read() == b"<html>hi</html>"
def test_warc_drops_pseudo_headers_and_truncates(): ...
def test_classify_table():
    assert classify("net::ERR_NAME_NOT_RESOLVED at https://x/", None) == "dns_fail"
    assert classify("net::ERR_CONNECTION_REFUSED", None) == "connect_fail"
    assert classify("net::ERR_CERT_DATE_INVALID", None) == "tls_error"
    assert classify(None, 404) == "http_error" and classify(None, 200) == "live"

async def test_capture_live_page(site, browser):
    c = await browser.capture(site.url("/redirect"), "mobile")
    assert c.page.outcome == "live" and c.page.http_status == 200
    assert c.page.final_url == site.url("/") and site.url("/redirect") in c.page.redirects
    assert c.screenshot.startswith(b"\x89PNG") and b"Sign in" in c.dom
    assert c.page.server_ip == "127.0.0.1"
    assert "/favicon.ico" not in site.paths_requested and "/robots.txt" not in site.paths_requested
async def test_mobile_profile_claims_matching_browser(site, browser):
    # the user agent the site received contains "Android" and the browser's exact version (from browser.version)
async def test_js_redirect_followed(site, browser): ...     # final_url == "/"
async def test_meta_refresh_loop_terminates(site, browser): # returns within nav_timeout_s + settle_s + 5 s
async def test_download_is_refused(site, browser): ...      # outcome "download", no exception
async def test_http_error_and_dns_fail(site, browser): ...  # /404 -> http_error; "http://nonexistent.invalid/" -> dns_fail
```

- [ ] **Step 2: Run, verify FAIL. Step 3: Implement. Step 4: Run `uv run pytest tests/test_warc.py tests/test_browser.py -v -W error`, verify PASS.**

- [ ] **Step 5: Commit** — `git commit -m "feat: WARC writer and Playwright capture with mobile profile"`

---

### Task 7: Login click-through (spec 5.5)

**Files:**
- Modify: `src/hakapik/browser.py`
- Test: `tests/test_browser.py`

**Interfaces:**
- Produces: `LOGIN_PATTERN` (case-insensitive regex: `log ?in|sign ?in|anmelden|einloggen|connexion|se connecter|iniciar sesi[oó]n|accedi|inloggen`), and `capture(..., click_through=True)` filling `Capture.clicks`.

After the landing capture, find at most three visible `a, button, input[type=submit], [role=button]` whose inner text or `value` matches `LOGIN_PATTERN`, in document order. For each: open a new page in the same context, go to the landing URL, click the n-th match, wait for load plus `settle_s`, then record `ClickCapture(label, page, screenshot, dom)` with profile `desktop-click{n}`. That is one hop deep only: nothing on the clicked page is clicked. These exchanges go into the same WARC. A click that fails becomes a `ClickCapture` with outcome `error`.

- [ ] **Step 1: Write the failing tests**

```python
async def test_click_through_reaches_login_form(site, browser):
    c = await browser.capture(site.url("/"), "desktop", click_through=True)
    assert len(c.clicks) == 1 and c.clicks[0].label.lower() == "sign in"
    assert c.clicks[0].page.final_url == site.url("/login") and b'type="password"' in c.clicks[0].dom
async def test_click_through_capped_at_three(site, browser): ...   # page /many with five "Log in" links -> 3
async def test_no_click_through_by_default(site, browser): ...     # clicks == ()
```

- [ ] **Step 2: Run, verify FAIL. Step 3: Implement. Step 4: Run `uv run pytest tests/test_browser.py -v -W error`, verify PASS.**

- [ ] **Step 5: Commit** — `git commit -m "feat: login click-through one hop deep"`

---

### Task 8: Worker role

**Files:**
- Create: `src/hakapik/worker.py`
- Test: `tests/test_worker.py`

**Interfaces:**
- Consumes: `Job`, `AttemptResult`, `NodeKey`, `seal` (Task 2); `Resolver`, `addresses` (Task 5); `Browser`, `Capture` (Task 6); `BlobStore.put`.
- Produces:
```python
class IpSpacer:
    def __init__(self, interval_s: float | None)
    async def wait(self, ip: str) -> None    # >= interval_s between starts per IP; None -> returns at once
async def run_job(job: Job, *, resolver, browser, bs: BlobStore, key: NodeKey,
                  egress_address: str | None, spacer: IpSpacer) -> bytes   # sealed envelope
```

Order: resolve. If `addresses()` is empty, the outcome is `dns_fail` and no browser runs. Otherwise `spacer.wait(first address)`, then the mobile capture. Only if the mobile outcome is `live` comes the desktop capture with `click_through=True`. Every capture's blobs go to `bs` and are listed as `BlobRef`s:

| kind | media type |
| --- | --- |
| `warc` | `application/warc+gzip` |
| `screenshot` | `image/png` |
| `dom` | `text/html; charset=utf-8` |
| `certchain` | `application/json` (canonical JSON list of base64 DER) |

Click captures add `screenshot` and `dom` under profile `desktop-click{n}`. The attempt outcome is `dns_fail`, or the mobile page's outcome. Any exception inside the role becomes a sealed result with outcome `error` and `error=repr(exc)` (blobs already written are kept and listed). A page that crashes Chromium every time therefore still advances the ladder instead of looping on lease expiry.

- [ ] **Step 1: Write the failing tests** (fake resolver and fake browser objects; real `BlobStore` in `tmp_path`)

```python
async def test_dns_fail_skips_browser(tmp_path): ...       # resolver returns NXDOMAIN; fake browser never called
async def test_live_runs_desktop_with_clicks(tmp_path):
    r = open_envelope(env, {key.node_id: key.public_key}.get)
    assert r.outcome == "live" and [p.profile for p in r.pages] == ["mobile", "desktop", "desktop-click1"]
    assert {(b.profile, b.kind) for b in r.blobs} >= {("mobile", "warc"), ("mobile", "screenshot"),
        ("desktop", "dom"), ("desktop-click1", "screenshot")}
    assert all(bs.path(b.sha256).stat().st_size == b.size for b in r.blobs)
async def test_non_live_mobile_skips_desktop(tmp_path): ...  # mobile http_error -> one page only
async def test_browser_exception_becomes_error_result(tmp_path): ...
async def test_ip_spacer_waits(): ...                         # interval 0.2: second wait on same IP >= 0.2 s; other IP immediate
```

- [ ] **Step 2: Run, verify FAIL. Step 3: Implement. Step 4: Run `uv run pytest tests/test_worker.py -v -W error`, verify PASS.**

- [ ] **Step 5: Commit** — `git commit -m "feat: worker role producing signed attempt results"`

---

### Task 9: Head-side store and manifests (spec 6, 8)

**Files:**
- Create: `src/hakapik/store.py`
- Test: `tests/test_store.py`

**Interfaces:**
- Consumes: `open_envelope`, `BadEnvelope` (Task 2); `advance_job` (Task 3).
- Produces:
```python
async def register_node(conn, node_id: str, public_key: bytes) -> None   # insert; same key again is a no-op;
                                                                          # a different key for a known id raises ValueError
class ResultRejected(Exception)
async def store_result(conn, bs: BlobStore, envelope: bytes, ladder: tuple[int, ...]) -> int | None
async def write_manifest(conn, bs: BlobStore, candidate_id: int) -> str  # returns the new manifest's sha256
```

`store_result` runs in the caller's transaction:
1. Open the envelope against the `node` table; a `BadEnvelope` becomes `ResultRejected`.
2. Check that the job exists and that its current step is the result's step. Otherwise the result is stale: return `None`.
3. Re-hash every `BlobRef` from `bs`. A missing file, a wrong hash or a wrong size raises `ResultRejected`.
4. Put the envelope itself into `bs` (`application/json`). Insert `blob` rows (`ON CONFLICT DO NOTHING`) for the envelope and all refs.
5. Insert the `attempt` row with `ON CONFLICT (job_id, step) DO NOTHING RETURNING id`. If no row comes back, return `None` (duplicate).
6. Insert the `dns_answer` and `artifact` rows, call `advance_job`, call `write_manifest`, and return the attempt id.

`final_url` and `http_status` come from the mobile page.

`write_manifest` builds a canonical JSON document:
- `version`, and `prev` (the previous manifest's sha256 or null);
- `candidate`: every column, `cert_key` as hex;
- `ct_raw_batch`: the sha256 of the `raw_batch` row whose range holds `(log_id, log_index)`, or null;
- `attempts`, in step order, each with `attempt_id`, `step`, `node_id`, `outcome`, `started_at`, `envelope_sha256`, and `blobs` (`profile`, `kind`, `sha256`, `size`, `media_type`).

It stores the document in `bs` and inserts `manifest(version = previous + 1, prev_sha256)`. The version and `prev` make the per-candidate history a hash chain; the daily RFC 3161 anchoring of manifest hashes is a later stage.

- [ ] **Step 1: Write the failing tests** (real DB; envelopes from `seal` with a test `NodeKey` and blobs put into `bs`)

```python
async def test_store_writes_attempt_dns_artifacts_manifest(conn, tmp_path):
    aid = await store_result(conn, bs, env, LADDER)
    # attempt row with outcome/http_status/final_url; dns_answer count == len(result.dns);
    # artifact rows == blobs; job step == 1; manifest version 1 whose JSON lists the envelope sha256
async def test_duplicate_envelope_is_noop(conn, tmp_path):   # second store_result -> None; one attempt row
async def test_rejects_bad_signature(conn, tmp_path): ...    # no attempt, no blob rows
async def test_rejects_unregistered_node(conn, tmp_path): ...
async def test_rejects_blob_hash_mismatch(conn, tmp_path):
    # BlobRef with a sha256 that is not in bs -> ResultRejected, nothing written
async def test_manifest_chain(conn, tmp_path):
    # two steps stored -> versions 1 and 2; v2.prev == v1.sha256; v2 lists both attempts;
    # sha256 of the stored manifest bytes equals manifest.sha256
async def test_register_node_conflicting_key_raises(conn): ...
```

- [ ] **Step 2: Run, verify FAIL. Step 3: Implement. Step 4: Run `uv run pytest tests/test_store.py -v -W error`, verify PASS.**

- [ ] **Step 5: Commit** — `git commit -m "feat: verified result store and per-candidate manifest chain"`

---

### Task 10: ASN enrichment (spec 5.5)

**Files:**
- Create: `src/hakapik/asn.py`
- Modify: `src/hakapik/store.py`
- Test: `tests/test_asn.py`, `tests/test_store.py`
- `uv add maxminddb`; `uv add --dev mmdb-writer netaddr`

**Interfaces:**
- Produces:
```python
@dataclass(frozen=True) class AsnHit:
    asn: int; org: str | None
class AsnDb:
    @classmethod
    def load(cls, path: Path, bs: BlobStore) -> AsnDb
        # copies the .mmdb file into bs (media type application/vnd.maxmind.mmdb) and keeps its sha256,
        # so every recorded ASN points at the exact snapshot that produced it
    sha256: str
    build_epoch: int                         # from the file's metadata, logged at load
    def lookup(self, ip: str) -> AsnHit | None   # None for unknown, private or malformed addresses
```
- `store_result` gains a keyword `asn_db: AsnDb | None = None`: the looked-up address is the mobile page's `server_ip`, or failing that the first address from `addresses(result.dns, fqdn)`. The attempt row gets `asn`, `asn_org`, and `asn_db_sha256` (`asn_db.sha256`; `blob` row inserted). With no `asn_db` or no address, the three columns are null.

The ASN is head-side enrichment, not part of the signed worker result: it derives from the IP, not from the vantage, and keeping the database on the head means workers need no data file.

The operator supplies the file (GeoLite2-ASN from MaxMind, under its own licence and account) and refreshes it by replacing the file; `run_fetch` loads it at start. If `asn_mmdb` is unset or the file is missing, `run_fetch` logs one warning and stores null ASNs.

- [ ] **Step 1: Write the failing tests** (build a tiny `.mmdb` in `tmp_path` with `mmdb_writer.MMDBWriter(ip_version=6, database_type="GeoLite2-ASN", ipv4_compatible=True)`, mapping `1.2.3.0/24` to `{"autonomous_system_number": 64500, "autonomous_system_organization": "Example AS"}`)

```python
def test_lookup_hit_and_miss(tmp_path):
    db = AsnDb.load(_mmdb(tmp_path), BlobStore(tmp_path / "blobs"))
    assert db.lookup("1.2.3.4") == AsnHit(64500, "Example AS")
    assert db.lookup("8.8.8.8") is None and db.lookup("not-an-ip") is None
def test_snapshot_stored_in_blobstore(tmp_path):
    bs = BlobStore(tmp_path / "blobs"); db = AsnDb.load(_mmdb(tmp_path), bs)
    assert hashlib.sha256(bs.path(db.sha256).read_bytes()).hexdigest() == db.sha256
async def test_store_records_asn(conn, tmp_path):
    # result whose mobile page has server_ip 1.2.3.4 -> attempt.asn == 64500, asn_db_sha256 == db.sha256
async def test_store_without_asn_db_leaves_nulls(conn, tmp_path): ...
```

- [ ] **Step 2: Run, verify FAIL. Step 3: Implement. Step 4: Run `uv run pytest tests/test_asn.py tests/test_store.py -v -W error`, verify PASS.**

- [ ] **Step 5: Commit** — `git commit -m "feat: ASN enrichment from a versioned GeoLite2-ASN snapshot"`

---

### Task 11: Fetch loop

**Files:**
- Create: `src/hakapik/fetchloop.py`
- Test: `tests/test_fetchloop.py`

**Interfaces:**
- Consumes: everything above, including `AsnDb` (Task 10); `ConnPool` from `ingest.py`.
- Produces:
```python
async def run_fetch(cfg: Config, *, stop: asyncio.Event, resolver=None, browser=None,
                    once: bool = False) -> None
```

On start: `migrate`, `NodeKey.load_or_create(cfg.data_dir / "node.key")`, and `register_node` for the head's own key, so the head is its own trusted worker. Loads `AsnDb` from `cfg.asn_mmdb` if set and present (else one warning) and passes it to every `store_result`. Defaults when not injected: `Resolver(cfg.resolver_nameservers)` and `Browser(proxy=cfg.fetch_proxy, nav_timeout_s=cfg.nav_timeout_s)`.

Each iteration:
1. `sweep(ageout_hours, queue_cap)`.
2. If `fetch_daily_cap` is set and `attempts_today >= cap`, sleep 60 s.
3. Otherwise `claim_jobs(free slots, lease_s)`, where free slots is `fetch_workers` minus the running tasks, and commit.
4. Start one task per job: `run_job` → `store_result` in a borrowed connection → commit. A `ResultRejected` is logged and rolled back.
5. Sleep 2 s when nothing was claimed.

`once=True` runs a single iteration and waits for its tasks; that is for tests and `hakapik fetch --once`. Every claim, finish and outcome is logged at INFO with the job id and FQDN. On `stop`, no new claims; running tasks finish.

- [ ] **Step 1: Write the failing test**

```python
async def test_enqueue_then_fetch_once_end_to_end(conn, tmp_path):
    cfg = _cfg(tmp_path, fetch_workers=2)          # data_dir=tmp_path, database_url=test DB
    await enqueue_manual(conn, ["a.example.com", "b.example.com"]); await conn.commit()
    await run_fetch(cfg, stop=asyncio.Event(), resolver=FakeResolver(live=True),
                    browser=FakeBrowser(), once=True)
    # two attempt rows, both jobs at step 1, two manifests, node table holds the head key
async def test_daily_cap_blocks_claims(conn, tmp_path): ...   # fetch_daily_cap=0 -> no attempt
```

- [ ] **Step 2: Run, verify FAIL. Step 3: Implement. Step 4: Run `uv run pytest tests/test_fetchloop.py -v -W error`, verify PASS.**

- [ ] **Step 5: Commit** — `git commit -m "feat: fetch loop running the head's own worker role"`

---

### Task 12: CLI and docs

**Files:**
- Modify: `src/hakapik/cli.py`, `README.md`, `docs/testing.md`, `hakapik.example.toml`
- Test: `tests/test_cli_fetch.py`

**Interfaces (Produces):**
- `hakapik enqueue NAME... [--file PATH]`: one name per line in the file, `#` comments allowed. Prints `name<TAB>status` per input. Exits 0 even when some names are rejected.
- `hakapik fetch [--once]`: runs `run_fetch` with SIGINT/SIGTERM handling as in `ingest.run`.
- `hakapik show FQDN`: prints each candidate (id, reason, created_at), job (state, step, due_at), and each attempt (step, started_at, outcome, http_status, final_url), plus the latest manifest's version and sha256. Exits 1 if the name has no candidate.

- [ ] **Step 1: Write the failing tests**

```python
def test_enqueue_cli(cfg_file, capsys):              # cfg_file points at the test DB
    assert main(["--config", str(cfg_file), "enqueue", "Sparkasse-Prüfung.de", "*.x.com"]) == 0
    out = capsys.readouterr().out
    assert "Sparkasse-Prüfung.de\tqueued" in out and "*.x.com\twildcard" in out
def test_show_unknown_name_exits_1(cfg_file): ...
def test_show_after_enqueue(cfg_file, capsys): ...   # lists reason manual, state open, step 0
```

- [ ] **Step 2: Run, verify FAIL. Step 3: Implement.**

- [ ] **Step 4: Docs**

README:
- Quick start gains `uv run playwright install chromium --no-shell`, `hakapik enqueue example.com`, `hakapik fetch`, `hakapik show example.com`.
- One paragraph: `fetch` contacts the sites from this machine's address (or `fetch_proxy`), and rate limits are off unless configured.
- ASN: set `asn_mmdb` to a GeoLite2-ASN file (MaxMind account; refresh by replacing the file); without it ASNs are null.
- Status: resolve and fetch implemented.

`docs/testing.md`: browser tests need the Chromium install and skip without it.

- [ ] **Step 5: Run the full suite and commit**

Run: `uv run pytest -W error` → all pass, browser tests not skipped on this machine.
`git commit -m "feat: enqueue, fetch and show commands; docs"`

---

## Deviations from the spec (rulings, reported to the owner)

- **Mobile profile is Chrome on Android (Playwright "Pixel 7"), not mobile Safari.** Spec 5.5 asks for both a mobile Safari user agent and a TLS fingerprint that matches the claimed client. On Linux no engine produces Safari's TLS fingerprint, because Playwright's WebKit uses a different TLS stack. So the mobile pass claims the browser it really is. Mobile-only cloaking (PhishFarm filter B) keys on "mobile", not on Safari. Checked on this machine: `channel="chromium"` runs, the UA carries the engine's exact version, and `navigator.webdriver` is false.
- **`fetch_workers` defaults to 2.** It sizes this node (browser pages in parallel), and it is not a courtesy limit towards targets. The owner's "no defaults, unset = unlimited" ruling applies to the per-IP spacing and the daily cap.
- **https only.** Every candidate comes from a certificate, so the job URL is `https://{fqdn}/`; there is no http fallback.
- **Whole ladder for every job, newest due job first.** Placeholders far outnumber live phish at detection time (Drichel), and sites flip during a testing phase (Pletinckx), so a `live` first attempt does not end the ladder. Under backlog, newest-first keeps fresh candidates near their CT time, and the old ones age out.
- **WARC headers are reconstructed from the browser's view**, not wire bytes: a recording proxy would change the TLS fingerprint and hide the served certificate chain. This is stated inside every WARC's warcinfo record.

## Not in this plan (and where it goes)


- T0 ranking: `fetch_job.priority` is the hook; it stays 0 until the T0 plan.
- Parked and hosting-default classification: an attempt reaching such a page is `live` here. The fingerprint stage appends the classification as new rows.
- Quorum across vantages (spec 5.4): with one vantage the head's answer stands. The quorum function comes with the remote worker transport (HTTP/2, mTLS) in the worker-protocol plan; `dns_answer.node_id` already keys answers per vantage.
- Inclusion proofs, STH at read time, and RFC 3161 anchoring of manifest hashes go to the evidence plan.
- NATS JetStream: this plan has one producer (ingest or enqueue) and one in-process consumer, both meeting in Postgres, which spec 11 already makes the queue. NATS enters with the first downstream stage (embed), which consumes "attempt stored" events.
