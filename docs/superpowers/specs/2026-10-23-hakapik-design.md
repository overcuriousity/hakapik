# hakapik: phishing detection on Certificate Transparency, PoC design

Date: 2026-10-23. Status: draft for builder review.

## 1. Intent

Prove, end to end and on live data, that phishing sites can be found within
minutes to hours of their first machine-visible signal, which is the
certificate appearing in a Certificate Transparency (CT) log. The proof is a
running system on one machine that tails all active CT logs, selects
candidates, fetches and renders them, groups kit copies into campaigns,
scores them, and shows the result in a filterable feed with per-site
metadata. Every verdict must be reconstructible from stored evidence by an
internal auditor every day and by a court in the extreme case.

The PoC stands alone. It will be integrated into another application later;
that application is out of scope and unknown to this document. The UI is a
demo and labelling surface, not a product.

## 2. Success criteria

In the owner's words: correctly classify phishing sites, display a
filterable feed with metadata, few false positives, work on any published
domain near real time going forward only, store all data forensically
auditable.

Operationalised:

- **Correctness** is measured as true positives at a fixed false-positive
  rate on a time-ordered held-out week of live CT, with labels obtained
  retrospectively from community feeds and VirusTotal at least two months
  later, plus human labels from the feed. Never balanced-set accuracy or
  k-fold. (Drichel et al. 2021 saw held-out ROC above 10 percent TPR collapse
  to under 1 percent on the live stream; Pendlebury et al. 2019 showed k-fold
  overstates F1 by 30 to 60 points under drift.)
- **Near real time** means: candidate selected within one minute of the CT
  entry being read; first fetch attempt immediately; the retry ladder covers
  the window in which sites go live (Sakurai et al. 2021: spam observed on
  average 3 h after issuance, minimum 4 min; at issuance only 8 to 17 percent
  of hosts showed a login page).
- **Few false positives** means the top risk band shown as "phishing" targets
  a false-positive rate in the low single digits on human review, in line
  with PhishIntention's 6.7 percent in a three-month live run and the
  Fake-Shop Detector's 0 to 1 percent top band.
- **Forensic auditability** means every artefact is written once, hashed,
  linked to its CT origin, and externally timestamped daily.

## 3. Goals, non-goals, anti-goals

Goals:

- Every active CT log tailed, raw entries mirrored locally with inclusion
  proofs.
- Any FQDN that is new to us, or re-check-due, becomes a candidate.
- Rendered evidence, embeddings, campaign clustering, calibrated risk bands.
- Site-first feed with campaign column, filters, evidence drawer, labels.
- Head node runs every role itself; a worker node can be added without
  redesign.
- Configurable retention and the evidence chain described in section 8.

Non-goals for the PoC:

- Building our own brand recognition. PhishIntention's shipped reference list
  and models are reused as a black box.
- Passive DNS enrichment from CIRCL (not available for the PoC; interface is
  designed so it plugs in for production).
- Residential or mobile egress. The PoC fetches from the head node's
  datacenter address with a mobile browser profile.
- Running distributed workers. The protocol and interface exist; only the
  head runs them.
- CZDS zone files, fake-shop detection, compromised-domain focus, a
  production UI.

Anti-goals (would make the PoC a failure even if it runs):

- A feed dominated by hosting default pages, SSO pages, builder templates or
  cPanel webmail. These were the dominant false-positive classes in
  Phishpedia and VisualPhishNet.
- Verdicts that cannot be replayed from stored evidence.
- Precision numbers reported on balanced data.
- A design where removing the worker protocol or the vector store would be
  a rewrite.

## 4. Constraints

- Python 3.13 under uv, already initialised in this repo. The brand model
  (PhishIntention, Detectron2) likely cannot run on 3.13; it runs as its own
  isolated service with its own pinned Python.
- One beefy machine, no GPU assumed. All inference must be acceptable on
  CPU. Budget: two to three cores for inference yields a few thousand
  rendered pages a day, matching the post-filter candidate volume AlSabah et
  al. observed (about 25 K domains per 10-minute batch before their
  classifier, a few hundred positives per batch).
- Anterograde only: no mining of historic data for phishing, and no
  history bootstrap of the first-seen index (decided 2026-10-24; see 5.1).
  Each log is picked up at its current tree size.
- Qdrant with telemetry disabled is the vector store. No MinIO. NATS
  JetStream is the queue. Postgres holds metadata, features, labels, jobs
  state, and the evidence index.
- Retention periods are configuration. Defaults in section 8.
- The owner's location is in Europe; European brands are underrepresented in
  the reused brand list. Extending the list is post-PoC data entry.

## 5. Pipeline

Each stage is a NATS JetStream subject with a durable consumer. A stage
reads a message, does its work, writes its artefacts and metadata, and
publishes to the next subject. Stages that depend on vantage point
(resolution, fetch, render) are "worker roles" and may run on remote nodes;
in the PoC they run on the head.

### 5.1 Ingest

- Read the Google and Apple CT log lists; tail every log in state usable,
  qualified or readonly-with-recent-entries. Support both RFC 6962
  get-entries logs and static-CT (Sunlight tile) logs. Per-log cursor in
  Postgres. Raw leaf, extra data, and the log's signed tree head at read time
  are stored in the blob store; an inclusion proof is fetched and stored
  lazily for any entry that becomes a candidate.
- No bootstrap (decided 2026-10-24, superseding the 90-day bootstrap in
  earlier drafts and in section 11). A log is picked up at its current tree
  size the first time it is seen and tailed forward from there. The
  first-seen index starts empty and fills from the live stream, so on day
  one most renewals of existing names look new; detections exist from day
  one and precision improves naturally as the index warms over the
  certificate lifetime. The owner's rule: carry no complexity that cannot be
  explained later. The measured reason: single-core parsing runs at about
  3.4 thousand entries per second, so reading 90 days of history would take
  weeks and gain nothing a week of live tailing does not.
- Dedup across logs by issuer plus serial (Drichel et al.). Precertificates
  and their final certificates count once.
- Extract every SAN DNS name. Wildcards are recorded with the `*.` stripped
  and marked wildcard; they are not fetched (Pletinckx et al. and AlSabah et
  al. both treat wildcards as unfetchable without passive DNS).
- Live-mirror volume estimate: about 10 M certs a day, 20 to 40 GB a day
  raw. Raw entries that never became candidates are pruned per the
  retention config; their first-seen index rows are kept forever.

### 5.2 Normalise and first-seen

- IDNA to ASCII, Public Suffix List to split registrable domain and FQDN.
- First-seen index keyed on FQDN, not registrable domain. A new FQDN under an
  aged registrable domain is a candidate: a large share of phishing sits on
  compromised hosts and free subdomain hosting (Moore and Clayton 2007; Oest
  et al. 2020; Sakurai et al.: 88.7 percent of hit CNs had labels below
  eTLD+1).
- Bloom filter in front of the index for the hot path; an embedded
  key-value store (RocksDB or equivalent) is the truth (see 11a).
- Candidate rule: an entry is a candidate if any SAN FQDN is first-seen, or
  if its last fetch is older than the configurable re-check window and the
  registrable domain is not on the stable top-list. Exact-FQDN renewals that
  fail both tests are recorded and not fetched. Renewals are about 96 percent
  of the stream (Pletinckx et al.: 986 first-time vs 24,333 renewals in one
  day's slice), so this is the main cost lever.
- Suppression lists: Tranco top N entries that have been stable in the list
  for a year (AlSabah et al. removed 2 percent this way), apex and `www` only,
  never whole subtrees; a public-apex list built from the PSL plus CDN and
  hosting apexes (AlSabah: 8 percent). Both lists are versioned config.

### 5.3 T0 rule-based prefilter and rank

T0 is not a trained model. It is a transparent score that ranks the fetch
queue and decides retry priority. It never produces a verdict.

Feature families and their evidence-backed weight:

1. **Domain history** (strongest): number of certificates for the
   registrable domain in our mirror, inter-arrival time of certificates,
   number of distinct issuance months, lifetime first-to-last, SAN count and
   SAN 2LD-match ratio. (AlSabah et al.: 30 percent of phishing domains had
   near-zero cert inter-arrival vs 0.3 percent benign; 60 percent of phishing
   certs issued within two distinct months.)
2. **Registration** via RDAP: domain age, registration period, registrar,
   privacy proxy. (Beyond Phish and Scamdog Millionaire: domain age and
   registration period among the top features and costly to evade.)
3. **Brand keyword and TLD rules**: the Phishing Catcher keyword and TLD
   lists, inner-TLD pattern (`.com-`), deep nesting, hyphen count, entropy.
   (Drichel et al.: on live CT at a fixed FPR, hand-made rules beat RF and
   RNN.) Keyword hits alone never trigger a fetch, because 63 percent of CT
   bots do exactly that and kits cloak on it (Kondracki et al.).
4. **Generic lexical** features get little weight (AlSabah ablation: 24
   percent FPR alone).
5. **Issuer** is not a feature of any weight (AlSabah).

Passive DNS features are declared in the feature schema with a null provider
in the PoC so CIRCL can be added without schema change.

### 5.4 Resolve

Worker role. For each candidate, A/AAAA/CNAME/NS/MX/TXT from the node's own
recursive resolver, with the answers, TTLs, resolver address and wall-clock
stored. Reverse DNS for each address. When several vantages exist, the
peephole quorum rule applies: an answer stands when more than half of the
responding vantages agree, and disagreement is recorded as a feature. Every
resolution at every retry is kept; this is the PoC's private passive DNS.

### 5.5 Fetch and render

Worker role. Playwright with Chromium.

- Default profile: current mobile Safari user agent on a phone viewport,
  because PhishFarm's mobile-only cloaking filter defeated every blacklist
  crawler in 2018, and 63 percent of victim traffic in Oest et al. 2020 was
  mobile. Second pass: desktop Chrome profile. Both passes use a real browser
  so the TLS fingerprint matches the claimed client (Kondracki et al.: most
  CT bots claim a browser but have an HTTP-library JA3).
- No favicon or robots.txt requests. Follow HTTP, meta-refresh and
  JavaScript redirects; keep the full chain. Click through at most three
  "login" or "sign in" candidates one hop deep (PhishIntention: 7 percent of
  true positives appeared only after a click).
- Retry ladder: immediately, then 2 min, 10 min, 1 h, 6 h, 24 h, then the
  re-check window. Outcomes recorded per attempt: DNS fail, connect fail,
  TLS error, HTTP status, parked or hosting default page, live. (Drichel:
  placeholders far outnumber live phish at detection time; Pletinckx:
  first-time sites flip offline in a testing-out phase.)
- Artefacts per successful attempt: WARC of all requests and responses,
  screenshot per profile, DOM snapshot after load, redirect chain, resolved
  IP and ASN, served certificate chain, timing.
- Egress identity: the PoC uses the head's datacenter address. The design
  reserves a separate identifying crawler identity with contact and opt-out
  for a future verification crawl (Pletinckx et al. precedent); the PoC does
  not run it.

### 5.6 Embed and fingerprint

CPU-only models, all behind a common interface.

- Text: a small multilingual sentence-transformer over visible text.
- Visual: OpenCLIP ViT-B/32 over the mobile screenshot, plus perceptual hash.
- Kit fingerprint: a structural hash over the DOM tag tree and the set of
  loaded resource URLs and inline script digests, plus the typed layout
  boxes from PhishIntention's layout detector. Structural fingerprints are
  what the Fake-Shop Detector production system and Scamdog's template reuse
  features rest on; the layout boxes are obfuscation-resistant.
- Content signals from the isolated PhishIntention service: brand match and
  score, credential-requiring page (CRP) yes or no, and whether the domain
  belongs to the matched brand. The three are stored separately.
- Vectors go to Qdrant in three collections (text, visual, structure) with
  the site attempt id as payload.

### 5.7 T1 campaign clustering

- HDBSCAN over the concatenated, normalised embeddings, run periodically
  over a sliding window. Kit fingerprint equality is the strongest key: exact
  structural matches are merged before clustering.
- Campaign membership window: 90 days (Sakurai et al.: 90 percent of
  certificates in one operator's cluster issued within 60 days, maximum 89).
- A campaign record carries: size, share of first-seen domains, TLD and
  registrar concentration, ASN and IP overlap, shared external resource URLs
  (phishing pages routinely embed resources from the impersonated brand,
  Oest et al.), representative screenshot, brand, purity.
- Size alone never raises the risk band. Builder and identity-provider
  templates are allow-listed by fingerprint, with the allow-list versioned.
- Cluster purity against human labels is a tracked metric.

### 5.8 T2 scoring

- Starts as a rule-based scorer combining: the three content signals, T0
  features, campaign features, and fetch outcome history. Outputs a
  calibrated risk band: high, medium, low, pending. Only high is shown as a
  verdict; medium and low are shown as suspicious with the band visible.
- Replaced by one trained model, CatBoost, once labels justify it: target a
  few thousand verified positives plus a benign pool sampled from the CT
  stream itself, never from top-lists (AlSabah). CatBoost is chosen because
  the domain evidence favours gradient-boosted trees on tabular features
  (Beyond Phish: XGBoost matched or beat the neural net; Scamdog: RF in
  production), and because its ordered target statistics handle
  high-cardinality categoricals such as registrar, TLD and ASN without the
  text-feature overfitting that made XGBoost fail in Scamdog's production run
  (Prokhorenkova et al. 2018). Text features are capped in count.
- Validation is time-ordered: train on an earlier window, validate on a
  later one. Metric: true positives at fixed FPR, plus top-band precision
  on human review.
- Retraining is monthly. Labels come from the feed with uncertainty sampling
  of one to five percent of monthly volume, which recovers most of the gain
  of full monthly retraining (Pendlebury et al. 2019, Table 3). Decay without
  retraining is negligible to six months, noticeable by a year, catastrophic
  by two (Scamdog, Beyond Phish, ScamNet).
- Model version and feature vector are stored with every score.

### 5.9 Feed and labelling UI

Site-first. Rows are site attempts, newest first. Columns: band, FQDN,
brand, CRP, campaign id and size, first seen, last fetch outcome, infra
(ASN, TLD, issuer), label status. Filters: band, time window, brand, TLD,
hosting geo, language, labelled or not, group by campaign. Selecting a row
opens an evidence drawer: screenshots per profile, the three content
signals, campaign summary, CT provenance (log, index, issuer, SANs), DNS per
vantage, scores with model version, retry history, and an evidence-bundle
export. Labels: phishing, benign, unsure, with an offer to apply to campaign
siblings. Every label is a signed, append-only record and feeds training.

Server-rendered FastAPI with HTMX. No JavaScript framework.

## 6. Topology and worker protocol

- **Head node** runs every role: ingest, normalise, T0, resolve, fetch,
  embed, cluster, score, UI, and the brand-model service.
- **Worker roles** (resolve, fetch and render) are the roles that benefit
  from vantage. Remote workers connect to the head over HTTP/2 with mutual
  TLS and pinned Ed25519 node keys, pull jobs for their roles, and return
  results signed by their node key with their egress address and wall-clock.
  The head verifies the signature before storing anything. This adopts
  peephole's transport and signing model and omits its credit market,
  audits and membership rules, which exist for mutually distrusting
  operators; hakapik's workers are one operator's fleet.
- Nothing in the pipeline blocks on a remote worker existing. The head's own
  worker role is always a valid vantage.
- Wire format compatibility with peephole is in spirit, not byte for byte;
  peephole is Rust, hakapik is Python.

## 7. Storage

- **Embedded key-value store**: the first-seen FQDN index (billions of keys).
- **Postgres**: CT cursors, candidates, attempts, features,
  campaign records, scores, labels, evidence index, config versions. Nothing
  is updated in place; corrections are new rows pointing at old ones.
- **Qdrant**: embeddings only, telemetry disabled, three collections.
- **Blob store**: a content-addressed directory on NVMe; path derived from
  the SHA-256 of the content; files written once then made read-only; hash,
  size and media type recorded in Postgres. Holds raw CT entries, inclusion
  proofs, WARCs, screenshots, DOM snapshots, model artefacts.
- **NATS JetStream**: one stream per stage, durable consumers, at-least-once
  delivery; every message carries the ids needed to make redelivery
  idempotent.

## 8. Evidence chain and retention

- Every blob is hashed at write time. Every candidate has a manifest listing
  its blobs and their hashes, re-issued as a new version whenever a blob is
  added. A daily batch of manifest hashes is timestamped through an RFC 3161
  timestamp authority and the token stored.
- CT provenance: the raw entry plus its inclusion proof against the log's
  signed tree head, so "this certificate existed at this time" is verifiable
  against the public log.
- Fetched content is WARC (ISO 28500) with request, response, timestamps
  and resolved address per record.
- Signed worker results carry node identity, egress address and time.
- Evidence bundle export: manifest, blobs, timestamp tokens, and a
  human-readable summary of the verdict chain.
- Known limit, stated for the PoC: immutability of the blob store rests on
  filesystem permissions and the external timestamp, not on object lock.
- Retention defaults, all configurable: flagged-site evidence 2 years; benign
  and pending fetch evidence 30 days; raw CT entries that never became
  candidates 7 days; first-seen index, Postgres metadata, labels, scores and
  manifests indefinitely.

## 9. Metrics

Time from CT entry to first fetch; time from CT entry to live page; true
positives at fixed FPR on the held-out week; top-band precision on human
review; cluster purity; per-log ingestion lag; fetch outcome distribution
per retry step; share of candidates suppressed by each filter.

## 10. Failure modes and their mitigations

- False-positive flood at T0: T0 ranks, it never verdicts; suppression lists
  and the three content signals gate the band.
- Builder, SSO and hosting-default pages: fingerprint allow-list, CRP
  requirement, domain-ownership check.
- Cloaking: mobile profile default, real browser, no bot tells, IP-keyed
  paths handled by per-session fetches; residential egress deferred.
- Concept drift: monthly retraining, time-ordered validation.
- CT merge delay: entries usually appear well before the 24 h bound
  (Pletinckx et al.); the tailer measures lag per log.
- Wildcards and no-cert registrations: invisible; documented.
- IDN and homoglyphs: IDNA normalisation plus a confusables feature in T0.
- Our crawler being enumerated: real browser fingerprint, varied egress
  later; consider running a small CT honeypot to measure our own footprint.

## 11. Decisions from the builder check

Settled by the author (not owner decisions):

- **Fetch budget vs volume.** Roughly 400 K new FQDNs a day enter against a
  few thousand renders a day. The fetch queue is a ranked, capped table in
  Postgres ordered by T0 score and age; NATS only dispatches. Candidates not
  fetched within a configurable window are aged out and recorded as
  unfetched. All metrics are reported over the fetched population with the
  unfetched share stated beside them.
- **No bootstrap** (superseded 2026-10-24). The live tail starts at once,
  mirrors raw entries and emits candidates from the first batch; the
  first-seen index fills from the stream.
- **Brand model input** is the desktop screenshot. The desktop pass runs for
  every attempt that reached a live page, not for parked, default or failed
  outcomes. Both profiles share one retry ladder.
- **UI access and labels**: localhost only, one reviewer, one local Ed25519
  signing key for labels, no authentication in the PoC.
- **Deployment**: compose services for Postgres, NATS, Qdrant and the brand
  model service; the Python pipeline runs as one uv-managed process group.
  (Pending owner confirmation that a container runtime exists.)

Answered by the owner (2026-10-23):

1. **Definition of done**: the PoC ships with the rule-based scorer, the
   evaluation harness and the training code. The first measured number and
   the first trained CatBoost are produced later on the running system.
2. **Label sources**: no VirusTotal, PhishTank or OpenPhish keys for the PoC.
   A VirusTotal tier may exist at the owner's workplace and may be added
   later. The PoC's labels are human labels from the feed plus whatever the
   free feeds expose without a key. The evaluation harness takes label
   providers as plug-ins.
3. **Timestamp authority**: any public RFC 3161 TSA. No special handling of
   personal data in WARCs or screenshots beyond the configurable retention.
4. **Deployment**: Docker or Podman is available; compose services as
   planned.

Answered by the owner (2026-10-24):

5. **Measuring gate** removed; see section 14.
6. **Fetcher egress**: the PoC fetches and resolves from the head's own
   address. All outbound fetch and resolve traffic goes through one egress
   setting so that a proxy or VPN is a configuration change later, not a
   code change.
7. **Fetcher rate limits** (concurrency, per-address spacing, daily cap)
   are configuration with no shipped defaults; unset means unlimited.

## 11a. Additions from the sibling fake-shop design (2026-10-13)

- **Volume**: that design estimates 150 M CT entries and 150 to 300 GB
  download per day, counting entries per log and precertificates; our 10 M
  certs per day is the deduplicated figure. The tailer is sized for the entry
  rate. Python parsing throughput was a risk; ingest measured about 3.4
  thousand entries per second on one core against a live rate of about 1.7
  thousand (see 5.1). No separate measuring run gates later stages (see
  section 14).
- **First-seen index** moves from Postgres to an embedded key-value store
  (RocksDB or equivalent) keyed on FQDN, with the bloom filter in front.
  Postgres keeps only what humans query.
- **Shared-key graph clustering** is added beside HDBSCAN. Nodes are site
  attempts; an edge is a shared key: form action target, exfiltration
  endpoint found in page source (Telegram bot token, drop e-mail, webhook
  URL), favicon hash, kit fingerprint, name-server set, IP, co-SAN,
  external resource URL. Leiden community detection yields campaigns; the
  two clusterings are merged by shared members. A new site with weak
  signals that lands in a labelled phishing cluster inherits the band, with
  the inheritance shown in the evidence drawer. (Oest et al. 2020: kit
  signature or drop-e-mail grouping would beat domain grouping.)
- **Bulk registration** as a T0 feature from RDAP: count of domains at the
  same registrar within the same minute.
- **Training rows are the feature vector at detection time**, never a later
  re-fetch.

## 14. No measuring gate (amended 2026-10-24)

Earlier drafts required a multi-day measuring run of the tailer before the
fetch budget and storage were sized. The owner removed that gate: no stage
waits on a measurement report. Every quantity the run would have measured
is configuration instead (fetch budget per day, queue cap, age-out window,
retention), and the running system reports the actual volumes through the
metrics in section 9 (`hakapik stats` already reports entries, first-seen
names, suppression per reason and candidates per log and day). Later
stages can be exercised without a running tail by enqueueing FQDNs by hand.

## 12. Left to the builder

- Exact Postgres schema, NATS subject names, Qdrant collection parameters.
- Choice of the specific small multilingual sentence model and CLIP weights.
- HDBSCAN parameters and the normalisation of concatenated embeddings.
- The rule weights in T0 and the initial T2 rule scorer, to be tuned on the
  first weeks of live data.
- Packaging of the PhishIntention service and its Python version.
- The evidence bundle's human-readable summary format.

## 13. Literature, as read for this design

Reading notes with the numbers used in this design are in
`docs/literature/README.md`.

Core:

1. Drichel, Drury, von Brandt, Meyer. Finding Phish in a Haystack. ARES
   2021. arXiv:2106.12343. Code GPL-3.0 at gitlab.com/rwth-itsec/ctl-pipeline.
   Live-stream evaluation collapse; rules beat ML at fixed FPR; placeholders
   dominate at detection time.
2. AlSabah, Nabeel, Choo, Boshmaf. Content-Agnostic Detection of Phishing
   Domains using CT and Passive DNS. RAID 2022. Feature-family ablation; live
   prototype volumes and filters; benign sampling from the stream.
3. Fasllija, Enişer, Prünster. Phish-Hook. SecureComm 2019. Catalogue of
   cheap lexical heuristics only; its 91 percent is on the UCI dataset, not
   CT.
4. Kondracki, So, Nikiforakis. Uninvited Guests. USENIX Security 2022. CT
   bot timing and identity; crawler enumeration risk.
5. Pletinckx, Nguyen, Fiebig, Kruegel, Vigna. Certifiably Vulnerable. IEEE
   EuroS&P 2023. First contact 23 s DNS, 84 s HTTPS; 96 percent renewals;
   CT entries far faster than MMD.
6. Abdelnabi, Krombholz, Fritz. VisualPhishNet. CCS 2020. Metric-learned
   screenshot embedding; false positives on generic login forms; 88 percent
   of live PhishTank pages were visual duplicates.
7. Lin et al. Phishpedia. USENIX Security 2021. Logo plus domain; 33 percent
   live FPR; template false positives.
8. Liu et al. PhishIntention. USENIX Security 2022. Brand plus CRP plus
   domain; 6.7 percent live FPR; CC0 code, weights and 277-brand list.
9. Sakurai et al. Identifying the Phishing Websites Using the Patterns of
   TLS Certificates. J. Cyber Security and Mobility 2021 (extends EuroS&PW
   2020). CN clustering; time-to-live after issuance; 90-day campaign window.
10. Oest et al. Sunrise to Sunset. USENIX Security 2020. Nine-hour window to
    detection; universal cloaking in top campaigns; mobile share; campaign
    structure.
11. Oest et al. PhishFarm. IEEE S&P 2019. Cloaking filters vs crawlers;
    mobile-only filter defeated all.

Context:

12. Bitaab et al. Beyond Phish. IEEE S&P 2023. Infrastructure features;
    XGBoost vs NN; 83 percent at ten months.
13. Kotzias et al. Scamdog Millionaire. ACSAC 2023. Production deployment;
    XGBoost text overfitting; precision-first thresholds; weekly top-N review.
14. Bitaab et al. ScamNet. AAAI 2025. 90 to 22 percent TPR over two and a
    half years, two-point measurement.
15. Beltzung et al. Real-Time Detection of Fake-Shops. IEEE BigData 2020.
    Closed access; reconstructed from abstract, re-implementation and model
    card. Structural fingerprints; risk bands.
16. Pendlebury et al. TESSERACT. USENIX Security 2019. Time-aware
    evaluation; active-learning label budget.
17. Ejaz, Mian, Manzoor. Life-long phishing attack detection using continual
    learning. Scientific Reports 2023. Half-year decay on HTML models.
18. Prokhorenkova et al. CatBoost. NeurIPS 2018. Ordered target statistics
    for categoricals.
19. Moore, Clayton. Examining the impact of website take-down on phishing.
    eCrime 2007. Compromised-host share.
