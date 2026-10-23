# Literature notes

Full-text reads done 2026-10-23 for the design in
`docs/superpowers/specs/2026-10-23-hakapik-design.md`. Numbers are from the
papers themselves (section or table noted where it matters). Verdicts are
what each paper tells this build to do or avoid. PDFs are not stored here;
sources are given per entry.

## CT-pipeline papers

### Drichel, Drury, von Brandt, Meyer. Finding Phish in a Haystack. ARES 2021. arXiv:2106.12343. Code GPL-3.0, gitlab.com/rwth-itsec/ctl-pipeline
- Data: 56,479 malicious certs from PhishTank/PhishStats/OpenPhish URLs (2019 to May 2020), balanced with Xenon-log benign certs; test = one week of May 2020 from four Xenon logs, about 22.5 M unique certs.
- Features: 126 (22 certificate, 55 domain lexical, 49 brand keyword). Keywords mattered: RF with keywords beat RF without everywhere.
- Result on the live week at FPR 1e-4 (about 2,251 FPs): Sakurai regex 117 TPs, Phishing Catcher rules 110, RF 55, RNN 36. Held-out ROC had shown over 10 percent TPR; on the live stream under 1 percent. Authors blame label noise: most phishing is on compromised hosts whose certs look benign.
- Also: placeholder and empty pages far outnumber live phish at detection time; re-query needed. Screenshotting via Selenium, no retries.
- Verdict: evaluate only on the live stream at fixed FPR; keep a rule layer; expect placeholders; certificate-only features are a prefilter at best.

### AlSabah, Nabeel, Choo, Boshmaf. Content-Agnostic Detection of Phishing Domains using CT and Passive DNS. RAID 2022. No code; Farsight pDNS
- Data: 10.8 K phishing domains (PhishTank, VT-confirmed), benign sampled from 35 M CT domains with VT 0 over a year; balanced experiments; fresh April 2021 set of 12 K/12 K.
- 20 features: CT temporal (lifetime, cert inter-arrival, cert count), CT cert (SAN size, issuers, DV/OV/EV, validity), pDNS (duration, IPs, queries, NS, SOA), lexical.
- Findings: 30 percent of phishing domains had near-zero cert inter-arrival vs 0.3 percent benign; 60 percent of phishing certs issued within two distinct months; issuer alone not discriminative; 30 percent of phishing certs 1-year validity vs over 90 percent benign at 90 days.
- Ablation FPR (Table 1): lexical alone 24 percent, CT alone 9.8, pDNS alone 5.9, all 0.3. RF: precision 98, recall 90.
- Live prototype: CertStream, 4.4 M domains/day; filters removed 2 percent (Alexa 1M stable a year) and 8 percent (PSL apex plus CDN/hosting list); one batch gave 492 predictions, 21 manual FPs; 151 of 471 never flagged by VT/GSB in a week, mostly parked or under construction.
- Verdict: domain-history and DNS features first, lexical last; sample benign from the stream, not top lists; treat parked positives as early, re-crawl.

### Fasllija, Enişer, Prünster. Phish-Hook. SecureComm 2019
- Eight cert-name heuristics (keyword distance, nesting, free CA, suspicious TLD, inner TLD, keyword list, entropy, hyphens). Reported 91 percent is on the UCI phishing dataset, not CT; CT labels were the authors' own heuristic (0.075 percent "suspicious").
- Verdict: use as a heuristic catalogue only; never cite its numbers for CT.

### Kondracki, So, Nikiforakis. Uninvited Guests: CT Bots. USENIX Security 2022. Dataset at uninvited-guests.github.io
- CT honeypot, 4,657 certs over 10 weeks, 1.5 M requests from 31,898 IPs.
- First request on average 5.9 min after issuance, as early as 12 s. 63 percent of IPs targeted only brand-keyword domains. About 80 percent of visitors to those were single-shot. 76 to 85 percent claimed a browser UA but only 2 to 11 percent had a real browser JA3; 41 percent were python/Go HTTP stacks.
- Verdict: our fetcher is one of thousands and will be enumerated; use a real browser whose TLS fingerprint matches the UA, vary egress, never trigger on keywords alone, schedule retries over days.

### Pletinckx, Nguyen, Fiebig, Kruegel, Vigna. Certifiably Vulnerable. IEEE EuroS&P 2023
- Honeypot 200 days: first DNS query 23 s after issuance, first HTTPS 84 s (2018 baseline was minutes to days). Surges at every renewal.
- One day of CertStream: 662,562 URLs, 501,791 after domain dedup; among version-exposing servers 986 first-time deployments vs 24,333 renewals (about 96 percent renewals).
- CT entries appear far sooner than the 24 h MMD. Wildcards skipped as unfetchable.
- Verdict: first-seen is the main volume lever; expect contact within a minute; retry over days (sites flip offline in a testing phase).

## Visual and content papers

### Abdelnabi, Krombholz, Fritz. VisualPhishNet. CCS 2020. Code github.com/S-Abdelnabi/VisualPhishNet (no licence file)
- 10,250 live PhishTank pages collapsed to 1,195 unique designs (about 88 percent visual duplicates). Triplet VGG16 embedding, nearest neighbour to a trusted list of 155 brands; AUC 0.988, about 93 percent TPR at 4 percent FPR; pretrained CNN features 30 AUC points worse.
- Main FP mode: benign pages with login forms and similar layout. Browser changes move embeddings far less than mild perturbations.
- Verdict: metric-learned screenshot embedding is a strong same-kit signal (distance 0 to 2 near copies, 2 to 4 same layout); never a verdict on its own.

### Lin et al. Phishpedia. USENIX Security 2021. CC0, github.com/lindsey98/Phishpedia
- 29,496 phishing pages with verified brand; top 100 brands cover 95.8 percent; 98.6 percent of phishing pages carry a logo. Logo detection plus Siamese match plus domain check; precision 98.2, recall 87.1 on the dataset.
- Live CertStream 30 days: 1,820 reported, 1,704 real; 74.6 percent still unknown to VT after a week. Digest matching: 48 percent of second-half pages reused an earlier visual template.
- FPs: hosting default pages with vendor logos (cPanel webmail), SSO and ad logos. Live FPR 33 percent in the later PhishIntention comparison.

### Liu et al. PhishIntention. USENIX Security 2022. CC0, github.com/lindsey98/PhishIntention, 277-brand list and weights
- Decomposes a page into brand identity (logo plus OCR Siamese), credential-requiring page (layout masks plus pixels, 95 percent vs 60.8 percent for HTML form heuristics), and domain alignment; clicks through up to three login buttons one hop deep (7 percent of true positives appear only after a click).
- Live 3 months on CertStream with VPN rotation: 2,081 reported, 1,942 TP, FPR 6.7 percent vs Phishpedia 33 percent; on 3,049 benign sites with SSO/ads: 5.1 percent FPR vs 45 to 60 percent for screenshot-only methods. Top 20 brands 80 percent of hits. CPU 0.6 s/page.
- Verdict: use as a black box for the three signals; whitelist builder and SSO templates by fingerprint; the typed layout boxes are an obfuscation-resistant structural fingerprint.

### Sakurai, Watanabe, Okuda, Akiyama, Mori. Identifying Phishing Websites Using the Patterns of TLS Certificates. J. Cyber Security and Mobility 2021 (extends EuroS&PW 2020)
- DBSCAN over certificate CNs (Ratcliff/Obershelp distance), templates gated by entropy reduction; 106 clusters from 1,634 certs; applied to 38.7 M Let's Encrypt and cPanel certs found 1,650 unknown to OpenPhish, 90.8 percent VT-flagged; 88.7 percent of hits had labels below eTLD+1.
- Timing: at issuance only 8.5 percent of sampled hosts showed a login page, 34 percent unreachable; spam observed on average 3 h after issuance, minimum 4 min 21 s; 90 percent of one operator's certs issued within 60 days, max 89.
- Verdict: CN clustering is the earliest campaign signal; re-crawl repeatedly; 60 to 90 day campaign window; gate templates on entropy or benign words leak in.

### Oest et al. Sunrise to Sunset. USENIX Security 2020
- PayPal-side telemetry, 404,628 phishing URLs over a year. First attacker test visit about 9 h 42 min before feed detection; by detection 62.7 percent of victims already lured; 37.7 percent of victim traffic after detection; browser warnings fully effective only about 7 h later.
- All sophisticated sites used server-side cloaking; 8 of top 20 campaigns minted per-visitor paths; 5 auto-translated by geo; two were live reverse proxies. 62.7 percent of victims on mobile. 96 percent of lures reached the page via redirects. Phishing pages embed brand resources and redirect back to the brand.
- Verdict: fetch within hours with a victim profile (mobile UA, residential IP later, JS executed); cluster by kit artefacts and drop endpoints, not by domain; landing page is the stable key.

### Oest et al. PhishFarm. IEEE S&P 2019
- 2,380 self-hosted PayPal clones reported to GSB, SmartScreen, APWG, PhishTank, PayPal. Cloaking cut blacklisting from 49.4 to 23.0 percent; mobile-only cloaking (Filter B) yielded zero blacklisting from every entity in 2018 (fixed by GSB after disclosure); JS-only content (Filter F) delayed most. Median first crawl about 50 min.
- Verdict: mobile profile by default; expect IP, UA, referrer and JS cloaking.

## Scam, drift and context papers

### Bitaab et al. Beyond Phish. IEEE S&P 2023. Code github.com/mbitaab/beyondphish (no licence file)
- 18 features; social-media validity dominates, then domain age, registration period, cheap TLD and registrar. XGBoost FPR 1.84, detection 91.9; NN headline F1 0.924. External set 10 months later: 83.4 percent accuracy.
- Verdict: infrastructure features are the costly-to-evade core; distrust self-labelled 98 percent numbers.

### Kotzias et al. Scamdog Millionaire. ACSAC 2023. No code
- 111 features in 5 groups; RF 150 trees F1 0.973, FPR 0.9 percent. XGBoost won cross-validation but failed on real data by leaning on TF-IDF text features. Deployment on 760 K e-shops at precision-first threshold: 10 percent flagged, manual top-100 review found 2 FPs. Drift 0 to 6 months: 95.9 to 94 percent recall.
- Verdict: cap or isolate text features in the tree model; precision-first bands; weekly top-N manual review as the drift sensor.

### Bitaab et al. ScamNet. AAAI 2025. No code
- Frozen Beyond Phish model: TPR 90.1 percent on 2021 data, 22.4 percent on mid-2024 data (two-point measurement, different collection). LoRA-tuned Llama-3-8B on raw text plus WHOIS kept 95.6 percent; a second pass on 200 curated examples helped.
- Verdict: two years without retraining is catastrophic; hand-made URL features decay fastest; small curated label sets matter.

### Beltzung et al. Real-time detection of fake-shops through machine learning. IEEE BigData 2020 (closed access; reconstructed from abstract, Beyond Phish re-implementation and the Fake-Shop Detector model card)
- Structural source-code fingerprints, about 22 K TF-IDF features, XGBoost; production risk bands with 0 to 1 percent error in the top band. Independent re-implementation: 69 percent recall at 3.7 percent FPR.
- Verdict: structural fingerprints cluster kits well; calibrated bands with auto-action only on the top band.

### Pendlebury et al. TESSERACT. USENIX Security 2019. Code github.com/s2labres/tesseract-ml
- k-fold overstates F1 by 30 to 60 points under drift. Active learning with uncertainty sampling of 1 percent of monthly objects recovers most of full monthly retraining (Table 3: 0.708 vs 0.818 AUT-F1; 5 percent gives 0.782).
- Verdict: time-ordered splits; monthly retraining; label 1 to 5 percent of monthly volume by uncertainty.

### Ejaz, Mian, Manzoor. Life-long phishing attack detection using continual learning. Scientific Reports 2023
- HTML FastText plus MLP: a half-year model loses up to 20 points on other periods; continual learning holds all periods within 2.5 points.

### Prokhorenkova et al. CatBoost. NeurIPS 2018
- Ordered target statistics for high-cardinality categoricals; the reason CatBoost is the one tree model in the design.

### Moore, Clayton. Examining the impact of website take-down on phishing. eCrime 2007
- Compromised-host share of phishing; grounds the new-FQDN-under-aged-domain rule.
