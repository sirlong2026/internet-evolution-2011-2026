# Sources and boundaries

This file lists every input of the study, its availability, and exactly what
of it is and is not part of this repository.

## 1. The 2011 snapshot (baseline archive)

An Internet-wide routing snapshot of the IPv4 space collected in 2011 by a
commercial network-mapping platform. The source is anonymized under the
provider's terms and is referred to in the paper as *the 2011 snapshot*.

- **In this repo:** derived statistics only —
  `data/routeviews/c0_compare.json` (prefix-length histograms, union address
  counts, per-/8 coverage), `data/routeviews/c0_survival.json` (survival of
  all 713,853 prefixes against the 2026 table), and the candidate/target
  tables derived from it (`data/c1/candidates_2011.json` →
  `data/c1/candidates_today.json`).
- **Not in this repo:** the raw prefix table (713,853 rows) and the DNS
  hostname map. They are not redistributable. No published number depends on
  access to the raw archive: every shipped 2011-side input is a derived table
  that can be audited on its own, and the scripts that produced those tables
  from the archive are shipped under `analysis/reference_only/` for method
  transparency (they are not executable here). Where the hostname map was
  used, only counts survive into this repository:
  `data/c1/dnsmap_feasibility.json` carries per-target record counts and the
  resolution summary, while the snapshot's hostname identities and its
  domain-to-address mapping are withheld at build time (the file says so in
  `meta.identity_withheld`).

## 2. RouteViews 2026 reference view

`rib.20261107.1600.bz2` — route-views2 RIB, University of Oregon Route Views
Project, https://archive.routeviews.org/ (route-views2, 2026-11-07 16:00 UTC).
Publicly and permanently downloadable.

- **In this repo:** the parsed calibers (`data/routeviews/rib_stats.json`,
  `rib_partial_stats.json`, `c0_compare.json`) and the zero-dependency MRT
  parser (`analysis/routeviews_rib.py`) cross-validated against bgpdump 1.6.2.
- **Not in this repo:** the 77 MB archive itself (re-download it for a full
  re-parse; `verify_paper_tables.py --refresh-rib` does this).

## 3. RIPE Atlas measurements

All active measurements were run as *public* user-defined measurements on the
RIPE Atlas platform (https://atlas.ripe.net/). None was deleted.

- **In this repo:** the registry `data/c1/campaign_msm_ids.json` (294
  measurements: ping100, trace50, scout100, sslscout34, sslcert9, anchor),
  the raw result sets `data/c1/raw/cam_<msm>.json` (fetched from the public
  results API), and all derived summaries (`phase1_summary.json`,
  `scout_prescreen.json`, `sslscout34_summary.json`, `sslcert9_judged.json`).
- **Live re-fetch:** every result set can be re-fetched without credentials
  from `https://atlas.ripe.net/api/v2/measurements/<id>/results/`.
- **Target labels:** the manuscript refers to the nine certificate-campaign
  targets as **A–I** (ordered by ascending primary measurement ID);
  `data/c1/target_labels.json` maps each label to the target domain and its
  measurement IDs, so a reviewer can trace any published row to its public
  measurement record. The mapping adds no new disclosure — these are the
  public targets of the `is_public` measurements listed in
  `data/c1/campaign_msm_ids.json`.
- **Known-answer anchor:** `ground_truth/pilot_truth.json` is the
  pre-registration (created 2026-11-03, amended 2026-11-08 to publish the two
  certificate fingerprints). The anchor endpoint is a host under the authors'
  administration; its address is deliberately not written into this
  repository (it is visible on the public measurement page, as any measured
  address is).

## 4. Third-party certificates

Certificate contents shown in raw results (subjects, issuers, validity) are
facts published by the serving parties during ordinary TLS handshakes.

One derived table withholds a name on purpose. Among the hundred addresses
that carried a 2011 organization identity, exactly one completed a TLS
handshake in 2026, and the certificate it served belonged to an **unrelated
third party** — an organization with no part in this study. Naming it would
attach a public label to a bystander for no scientific gain, so the paper
refers to it only as "a third party's certificate" and
`data/c1/scout_prescreen.json` likewise records
`CN=<third-party identity withheld; see the public measurement record>` in
place of the subject. Everything the claim depends on is still verifiable
here: the certificate fingerprint (`cert_sha256`), the issuing CA, the
validity window, and the fact that the served identity is **not** one of the
organizations measured in this study (the organization-domain lists ship in
`sslscout34_spec.json` and `sslcert9_spec.json`). The certificate itself
remains in the public measurement record it came from, encoded in the raw
result files, and can be decoded by any reviewer who wishes to check it
against the platform directly.

## 5. Prior-work search record (novelty claim)

The paper's §2 states a "to our knowledge" claim about replaying a historical
Internet-wide snapshot against the live network on the same targets. To make
that claim auditable rather than asserted, the search behind it is shipped:
`data/c1/novelty_search.json` records the database (Crossref), the date, the
five query strings, every candidate each query returned with an explicit
keep/out decision and a reason, the retained works, and the eight closest
prior works with why-close / why-different notes.

- **In this repo:** `data/c1/novelty_search.json` (decisions and notes — the
  authors' screening judgements, not third-party content).
- **Not in this repo:** nothing is withheld from this record beyond the
  bibliographic metadata itself, which is publicly retrievable from Crossref
  by the recorded query strings and DOIs. Bibliographic metadata (titles,
  authors, venues, years, DOIs) remains the property of its publishers and
  indexing services under their own terms; it is quoted here only to document
  which records were screened.

## 6. Takedown

If you believe any material here infringes your rights, open an issue on this
repository and it will be removed pending review.
