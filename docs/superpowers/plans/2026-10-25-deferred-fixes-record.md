# Deferred fixes: record (2026-10-24 to 2026-10-25)

Branch `fix-tail-deadlock-tile404`, from master ddb0850. Commit 3f1eac0 holds
the live-run fixes (tail deadlock, tile 404, prompt stop). This document
records how each item under "Deferred after review" in
`2026-10-24-resolve-fetch.md` (and the ingest plan's review findings) was
closed. The items were worked in five groups (A to E), each with its own
review and fix rounds, then a final review and fix wave.

Status: FIXED (commit) or OBSOLETE (evidence). "Trade-off" means the fix
states a limit instead of removing it. "Superseded" means a later round or
ruling replaced the fix.

## Group A: CT log clients

Commits 3ca67b9 (loglist), 9bfb74c (leaf), 704c42c (clients, retry, _url),
361c9e0 (tiled batch, lag); review rounds ed41346, e8372d5, 64479de.

- P1T2 misleading test name: FIXED 3ca67b9 (`test_parse_drops_retired`).
- P1T2 one failing list aborts the fetch: FIXED 3ca67b9 (skip with warning; raise only if all fail).
- P1T2 hard key access in the list parser: FIXED 3ca67b9 (malformed entry warned and skipped).
- P1T2 first-list-wins dedup not pinned: FIXED 3ca67b9 (`test_fetch_dedup_first_list_wins`).
- P1T3 timestamp lost on truncated extensions: FIXED 9bfb74c.
- P1T3 positional-arg signalling, `or ts` drops ts 0: FIXED 9bfb74c (`_Malformed(reason, ts)`).
- P1T3 no version/leaf_type/trailing-bytes validation: FIXED 9bfb74c.
- P1T3 issuer DN asserted by first byte only: FIXED 9bfb74c (full DER compared).
- P1T3 negative tile offset: FIXED 9bfb74c (range check).
- P1T3 extended_datetime leak (year 0): FIXED 9bfb74c.
- P1T4 Retry-After isdigit accepts non-ASCII: FIXED 704c42c (isascii()).
- P1T4 over-long entries response not trimmed: FIXED 704c42c.
- P1T4 bare RuntimeError on empty probe: OBSOLETE (no probe exists; `git log -S probe -- src` empty).
- P1T4 tests for empty log and exhausted 5xx: FIXED 704c42c.
- P1T5 truncation test cannot tell which error: FIXED 704c42c (`match=` plus a distinguishing test).
- P1T5 fixture pool period weakens the slice check: FIXED 704c42c (unique timestamp per index).
- P1T5 base_url helper and lazy imports: FIXED 704c42c (`ct/_url.py`, top-level imports).
- P1T5 monitoring_url None gives AttributeError: FIXED 704c42c (ValueError).
- P1T5 unknown log kind falls back to RFC 6962: FIXED 704c42c (ValueError).
- P1T5 and final: checkpoint fetched per entries() call: FIXED 704c42c (size cached from tree_size()).
- P1T5 parse_checkpoint unchecked input: FIXED 704c42c.
- Final: tiled batches ignore batch_size: FIXED 361c9e0.
- New: a log retired in any list is still tailed: FIXED 3ca67b9 (retired-anywhere rule; spec 5.1 in ed41346).
- New: negative lag in the log line: FIXED 361c9e0 (clamped, with a note).
- Review: non-object list JSON aborts the merge: FIXED ed41346.
- Review: readonly logs: FIXED ed41346, e8372d5, 64479de (see Rulings; one INFO line; stop-aware startup probe; failure path tested).

## Group B: config, names, first-seen, suppression, blob store, migrations

Commit 1442286 (its ingest.py hunk landed in ed41346); fix round eb7937c.

- P1T1 missing keys raise TypeError; no type or range checks: FIXED 1442286 (`_validate_types`).
- P1T1 test helper order: FIXED 1442286.
- P1T1 pyproject description placeholder: FIXED 1442286.
- P1T6 redundant underscore check: FIXED 1442286 (idna rejects it).
- P1T6 invalid records carry the raw lowercased fqdn: FIXED 1442286 (documented, tested).
- P1T6 unpinned edge-case tests: FIXED 1442286 (16 cases, full-width folding).
- P1T6 hasattr fallback for tldextract: FIXED 1442286 (removed; >=5.4 pinned).
- P1T7 first-seen contract, utf-8, typed `__exit__`, u64 bounds: FIXED 1442286.
- P1T7 non-ASCII test checks other keys: FIXED 1442286.
- P1T7 a raising CF close skips the second close: FIXED 1442286.
- P1T7 no closed-guard: FIXED 1442286 (`_check_open`).
- P1T8 blank CSV lines and header count toward top_n: FIXED 1442286.
- P1T8 public_apexes not sanitised: FIXED 1442286.
- P1T9 blob path() lacks hex validation: OBSOLETE (`_HEX64` check and test already present).
- P1T9 no directory fsync after replace: FIXED 1442286.
- P1T9 existing blob trusted without mode check: FIXED 1442286 (0o444 restored); eb7937c (stat/chmod races tolerated).
- P1T9 bump_stat empty-increment no-op undocumented: FIXED 1442286.
- P1T9 test gaps (multi-column bump, no-commit proof, empty add_candidates): FIXED 1442286.
- P1T9 conftest import order: OBSOLETE (already ordered).
- P2T1 upgrade test only asserts no-raise: FIXED 1442286.
- P2T1 ladder TypeError on bad types; no custom-ladder test: FIXED 1442286.
- P2T1 ALTERs take ACCESS EXCLUSIVE on every migrate: OBSOLETE (guarded by information_schema since 2d83e97).
- P2T1 example-config test checks one key: FIXED 1442286 (whole Config compared).
- Remove-bootstrap: README note on recreating old DBs: FIXED 1442286.
- Remove-bootstrap: first cursor insert must not overwrite: FIXED 1442286 (`init_cursor`).
- Remove-bootstrap: stale tail_log_once docstring: OBSOLETE (docstring matches the code).
- P2 final: CREATE INDEX takes SHARE lock on each start: FIXED 1442286, eb7937c (pg_indexes guard, IF NOT EXISTS).
- Review: non-finite floats accepted: FIXED eb7937c.

## Group C: ingest orchestration, CLI, prune

Commits daa5fcf, 5f95799, 7ae1a86, 1721819, 7f7c12a; fix rounds 55db3ea, 36d6334.

- P1T10 per_log_concurrency unused: FIXED daa5fcf (removed).
- P1T10 run() untested without network: OBSOLETE (fixture-based run tests exist).
- P1T10 never-bootstrapped log only warns: OBSOLETE (bootstrap removed in 9544df7).
- P1T10 bootstrap does not retry: OBSOLETE (bootstrap removed).
- P1T10 short-read, mid-commit failure and 429 tests: FIXED 7ae1a86 (429 already covered in test_retry).
- P1T10 duplicate raw_batch rows on rewind: FIXED 7ae1a86 (compare-and-set cursor).
- P1T10 traceback per failed attempt: OBSOLETE (rate-limited `_Failures` since 1c27dca).
- P1T10 signal handlers never removed: OBSOLETE (removed in finally since 2aa79c8).
- P1T10 timing-based stop test: FIXED 7ae1a86.
- P1T10 no contiguity guard on log responses: FIXED 7ae1a86.
- P1T10 signal handlers installed before try: FIXED 5f95799 (`signals.py`).
- P1T10 log bootstrapped mid-tail not picked up: OBSOLETE (no bootstrap mode).
- P1T11 lag task logs next_index: OBSOLETE (lag task gone; `_Progress` logs lag).
- P1T11 orphan blobs not reclaimed by prune: FIXED 55db3ea (orphan sweep; see Rulings).
- P1T11 date vs timestamptz cutoff: FIXED 1721819.
- P1T11 prune/ingest unlink race on a shared blob: FIXED 1721819 (`lock_blob`).
- P1T11 unlink OSError not caught: FIXED 1721819.
- P1T11 lag-task failure swallowed: OBSOLETE (no lag task).
- P1T11 stats/sample run migrate: FIXED 1721819 (stated; migrate takes no conflicting lock).
- P1T11 test gaps (shared blob, missing file, start bound): FIXED 1721819.
- P1 final: bootstrap backoff never resets: OBSOLETE (bootstrap removed).
- P1 final: 429 loop ignores stop: OBSOLETE (fixed in 3f1eac0, `_finish_or_stop`).
- P1 final: unknown suppression reasons dropped: FIXED 7ae1a86 (batch fails loudly).
- P1 final: ConnPool cancel-during-rollback and close errors: FIXED 7ae1a86.
- P1 final: second-signal traceback on fetch: OBSOLETE (fixed in 3f1eac0; test added 5f95799).
- P2T4 stats.candidates for a recheck batch not pinned: FIXED 7ae1a86.
- P2T4 recheck cases missing: FIXED 7ae1a86.
- P2T4 sup.reason for every indexed SAN: FIXED 7ae1a86 (cost stated).
- P2T4 redundant `not rec.wildcard`: FIXED 7ae1a86.
- P2T4 positional tuple for recheck entries: FIXED 7ae1a86 (`_Recheck`).
- P2T4 recheck row although the open-job index drops the job: FIXED 7ae1a86 (`open_job_fqdns`).
- P2T12 cli docstring lists old commands: OBSOLETE (updated in 2d83e97).
- P2T12 fetch signal wiring duplicated: FIXED 5f95799.
- P2T12 show_fqdn N+1 queries: FIXED 7f7c12a (four queries).
- P2T12 fetch only --help-tested: FIXED 5f95799.
- P2T12 show output with attempts and manifest untested: FIXED 7f7c12a.
- P2 final: second SIGINT traceback on fetch and tail: OBSOLETE (fixed in 3f1eac0; tests exist).
- Review: orphan-sweep wording and store lock comment Minors: FIXED 36d6334.

## Group D: protocol, queue, resolver, worker, store, ASN, fetch loop

Commits ff29699, d6176c6, bb66841, 36a9a07, 657f597, fc22eb8; fix rounds
39e489e, 9e0c4cb, 913f0d0, a233c04, 4603933.

- P2T2 key not fsynced before link: FIXED ff29699.
- P2T2 os.link unsupported on some filesystems: FIXED 4603933 (clear error; README states the hard-link requirement; the fallback of ff29699..a233c04 was removed, see Rulings).
- P2T2 loose mode or wrong key length unclear: FIXED ff29699.
- P2T2 test signs through a private attribute: FIXED ff29699.
- P2T2 canonical_json allows NaN: FIXED ff29699.
- P2T2 node_id mismatch test lacks match=: FIXED ff29699.
- P2T3 priority order and re-sort untested: FIXED d6176c6.
- P2T3 RED not captured: FIXED d6176c6 (RED runs recorded).
- P2T3 lost-race test simulated: FIXED d6176c6 (real second connection).
- P2T5 list where a tuple is annotated: FIXED bb66841.
- P2T5 qname case not normalised: FIXED bb66841; `addresses()` too in 39e489e.
- P2T5 DNS fixture not reusable: FIXED bb66841 (pytest plugin, UDP and TCP).
- P2T5 coverage gaps (A sort, IPv6 PTR, TCP fallback): FIXED bb66841.
- P2T5 empty nameserver list IndexError: OBSOLETE (ValueError at construction since 2d83e97).
- P2T5 worst case N x timeout across servers: FIXED 39e489e (per-query deadline; see Rulings).
- P2T8 no resolver-raises test: FIXED 36a9a07.
- P2T8 spacer key not pinned to the first address: FIXED 36a9a07.
- P2T8 wall-clock spacer tests: FIXED 36a9a07 (fake clock).
- P2T8 IpSpacer map never pruned: FIXED 36a9a07.
- P2T8 cancelled spacer waiter: FIXED 36a9a07 (give-back); superseded 9edfbb2 (waiter keeps its slot; see Rulings).
- P2T8 resolver/browser params untyped: FIXED 36a9a07 (Protocols).
- P2T9 stale result writes before ON CONFLICT: OBSOLETE (row lock first since 2d83e97).
- P2T9 determinism test compares parsed dicts: FIXED 657f597 (bytes, two time zones).
- P2T9 bad or naive timestamps untested: FIXED 657f597.
- P2T9 envelope parsed twice: FIXED 657f597 (stated).
- P2T9 blob read before size check: FIXED 657f597.
- P2T10 AsnDb never closed: FIXED fc22eb8.
- P2T10 MMDB test helper duplicated: FIXED 657f597, fc22eb8.
- P2T10 local imports in test_store: FIXED 657f597.
- P2T10 AsnDb.load raises raw errors: OBSOLETE (`_load_asn` warns once; tests exist).
- P2T10 closed in-memory reader still answers: FIXED fc22eb8 (lookup after close raises).
- P2T11 sweep failure blocks claims: FIXED fc22eb8.
- P2T11 outcome re-read after the store can mislabel: FIXED fc22eb8.
- P2T11 `one` untyped: FIXED fc22eb8.
- P2T11 default Browser/Resolver construction untested: FIXED fc22eb8.
- P2 final: mobile blob write fails after the page is recorded: FIXED 36a9a07 (page recorded only with all its blobs).
- P2 final: node public key in the evidence bundle: FIXED 657f597 (manifest; spec 8).
- Review: lease too short for a slow job: FIXED 9e0c4cb (heartbeat), 913f0d0 (job_timeout_s, claim token); simplified 2f9c2ed (see Rulings).
- Review: spurious "lease lost" and heartbeat waiting on the store's row lock: FIXED 913f0d0, a233c04; superseded 2f9c2ed (heartbeat ends before the store).
- Review: timeout log conflates an inner TimeoutError: FIXED a233c04 (`expired()`).
- Review: overrun past job_timeout_s: FIXED a233c04 (documented); corrected to 2 x nav_timeout_s in c0d0cde.
- Review: key load blocks the event loop: FIXED 9e0c4cb (`to_thread`).
- Review: real-browser job timeout untested: FIXED a233c04.

## Group E: browser capture and WARC

Commits b8688d9, 6983a2e, d8826ce, a90091f, 589459a, d5727f7; fix rounds 3ebbbff, 75e0449.

- T6 browser fixture module-scoped: FIXED 6983a2e (session scope).
- T6 cert_chain on HTTPS untested: FIXED 6983a2e (local TLS site).
- T6 robots.txt only checked on the local site: FIXED 6983a2e (WARC request records).
- T6 pre-navigation steps and context.close unbounded: FIXED a90091f.
- T6 favicon aborts not tested: FIXED 6983a2e.
- T6 bodies read fully before the MAX_BODY cut: FIXED a90091f (Chromium's DevTools buffer is below MAX_BODY; pinned).
- T6 popup's first request before the CDP override: Trade-off 589459a (three fixes tried and failed; limit stated and pinned).
- T6 load timeout without a final document counted live: FIXED d8826ce.
- T6 refused download has no status: FIXED d8826ce.
- T6 browser.py too long: FIXED b8688d9 (recorder split out).
- T6 brands probe costs a blank page: Trade-off 589459a (no cheaper source).
- T7 post-click load may resolve on the old document: FIXED 589459a.
- T7 browser.py too long (split candidate): FIXED b8688d9.
- T7 popup exchanges and hop budget untested: FIXED d8826ce, 589459a.
- T7 login matching runs in the page's JS world: FIXED d5727f7 (isolated world, content-script selector engine).
- T7 click pages open until the drain: FIXED 589459a.
- T7 popup event after clear() still counts: FIXED 589459a (new-target filter).
- T7 hold route handler may leave a route unresolved: FIXED 589459a.
- T7 aborted URL may trail final_url in the chain: Trade-off 589459a (stated).
- Found: popup's first navigation before its page exists lost chain and status: FIXED d8826ce.
- Review: chain growth taken as a hung click: FIXED 3ebbbff.
- Review: context created after the setup timeout left open: FIXED 3ebbbff, 75e0449 (also on cancellation; `__aexit__` cancels late closes).
- Review: Playwright unpinned; click margin past the hop deadline: FIXED 75e0449.

## Final review and fix wave

- I1 enqueue_manual breaks the global fqdn insert order: FIXED 41b8f80.
- I2 open jobs past step 0 retried for ever: FIXED a3abd47 (age-out past the last ladder step plus ageout_hours).
- M3 overrun bound understated: FIXED c0d0cde (2 x nav_timeout_s).
- M4 silent first Ctrl-C on fetch; stop semantics undocumented: FIXED 68c6a63.
- M5 stale README intro: FIXED 29c5b8e.
- M6/M7 deferred list pointed at a gitignored ledger: FIXED by this record and the note in the resolve-fetch plan.
- Simplifications (rulings below): heartbeat 2f9c2ed, IpSpacer 9edfbb2.

## Rulings

- Readonly logs: skip a readonly log with no cursor; follow one with a cursor until caught up; spec 5.1 says so. Cost if wrong: entries appended just before a log froze are missed, but only for a log never read before.
- Commit history of ed41346 (which carried Group B's ingest hunk) is left as is, no force-push; HEAD is consistent. Cost if wrong: ed41346 alone does not import cleanly, which only matters when bisecting.
- Orphan blobs: prune sweeps unreferenced blobs older than orphan_margin_hours (24, longer than the lease), under lock_blob with a re-check; put() refreshes mtime on reuse; the ASN snapshot gets its blob row at load; store_result takes sorted blob locks before verifying. Cost if wrong: one extra lock per blob in store_result.
- DNS: one total deadline per query across all servers (resolver_query_deadline_s, default 10), folded into the lease floor. Cost if wrong: a slow last-resort server is not asked after the deadline.
- Lease heartbeat: extend claimed_until every lease_s / 3 while the job runs; the lease check stays as a sanity floor. Cost if wrong: one UPDATE per running job per lease_s / 3.
- job_timeout_s bounds a run; the claim token is the claimed_until value (the protocol Job is unchanged). Cost if wrong: a job hitting job_timeout_s is retried rather than finished.
- Key lock via flock (later removed with the fallback). Cost if wrong: none on Linux; advisory only on NFS.
- No hard-link fallback for the node key: a filesystem without hard links is a clear error, and the README states the requirement. Cost if wrong: hakapik cannot run with data_dir on such a filesystem (some FUSE or SMB mounts).
- Simplifications: the heartbeat ends when run_job returns, before store_result (no stored event, no lock_timeout, no skip branch); a cancelled IpSpacer waiter keeps its slot; extend_lease keeps the step guard as a belt. The late-context cleanup and isolated-world login matching stay. Cost if wrong: none material (a cancelled waiter may leave one unused spacing gap).
- This record is committed because `.superpowers/` is gitignored. Cost if wrong: none.
