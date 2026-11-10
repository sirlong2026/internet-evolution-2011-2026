# Internet Evolution 2011→2026 — Same-Target Longitudinal Measurement (artifact)

Artifact for the paper *same-target longitudinal measurement of Internet
infrastructure evolution*: a 2011 Internet-wide routing snapshot (a commercial
network-mapping platform; source anonymized under the provider's terms) is
replayed against the live network of November 2026 through a four-layer
measurement stack — routing, address (ICMP), path (traceroute), service (TLS) —
on the RIPE Atlas platform. Every measurement is public and cited by permanent
measurement ID.

## Locked numbers (one table)

| layer | quantity | value | verified by |
|---|---|---|---|
| routing | 2011 prefixes evaluated | 713,853 | `verify.py` A |
| routing | aggregate survival (some 2026 prefix covers) | 68.8% | A |
| routing | exact survival (identical prefix still announced) | 29.0% | A |
| routing | table growth 2011→2026 | ×1.631 | B |
| routing | /8 blocks losing all covered space | 7 (214→207) | A |
| routing | 2011 snapshot vs same-day public DFZ (2011-07-02, 45 peers, 377,201 prefixes) | 91.3% of snapshot space announced (50.2% identical); 99.8% of DFZ space contained (95.0% identical) | B2 |
| routing | >24 more-specifics in same-day DFZ: covered / themselves announced | 99.3% / 2.3% (the declared caliber artifact, measured) | B2 |
| address | 2011 representative addresses ICMP-live | 35/100 | C |
| address | liveness, exact survivors vs covered-only | 44% (25/57) vs 23% (10/43) | C |
| path | probe traceroutes reaching the target | 180/500 (36%) | D |
| service | old addresses still TLS-alive | 1/100 — re-purposed to an unrelated third party (0/100 serve the 2011 organization's identity) | E |
| service | old-address failure taxonomy | 82 connect timeout / 15 refused / 1 hello timeout / 1 host unreachable | E |
| service | 2011 organizational domains still resolving | 34/48 | E/F |
| service | resolving domains still TLS-live | 15/34 (44%), incl. a fossil certificate issued 2004 | F |
| uncertainty | 95% Wilson intervals on the cohort proportions | 35/100 → 26.4–44.7; 25/57 → 31.8–56.7; 10/43 → 13.2–37.7; 178/199 → 84.4–93.0; 90/199 → 38.5–52.2; 34/48 → 56.8–81.8; 15/34 → 28.9–60.5; 0/100 identity → upper bound 3.7 | J |
| uncertainty | stratified liveness contrast (exact vs covered-only) | two-sided Fisher exact test p = 0.037 | J |

Verdict framework and known-answer anchor: `analysis/sensor_compare.py` +
`analysis/verify_paper_tables.py` sections G–H; the anchor's pre-registered
ground truth is `ground_truth/pilot_truth.json`. `analysis/README.md` maps
every shipped script to what it does.

## Reproduce in one command

```bash
python analysis/verify_paper_tables.py
```

Expected output: sections `A`–`F` print `PASS` against the locked calibers
above (offline, zero dependency); section `I` regenerates the figure data from
this package and compares it against the shipped `figures/figdata.json`;
sections `G`–`H` fetch the public measurement
results from the RIPE Atlas API (plain GETs, no key needed) and recompute the
anchor check and the per-target verdicts with the shipped engine; section `J`
recomputes every published 95% Wilson interval and the stratified-liveness
Fisher exact test from the shipped derived statistics (standard library only —
no SciPy). Use `--offline` to skip G–H. Any mismatch exits non-zero.

The 2026 routing-table calibers (section B) can additionally be re-derived
from the raw public RouteViews archive:

```bash
python analysis/verify_paper_tables.py --refresh-rib   # downloads rib.20261107.1600.bz2 (~77 MB)
python analysis/routeviews_rib.py <rib.bz2>            # standalone zero-dependency MRT parser
```

## Reproduce the three manuscript figures

```bash
python analysis/c1_figure_data.py --out figures/figdata.json   # figure data, from this package
python figures/make_figures.py                                   # renders the three figures
```

`figures/figdata.json` holds every number that appears in the paper's three
figures and a `provenance` field naming the derived-statistics file each number
came from. `figures/make_figures.py` reads that file only — it recomputes
nothing and hard-codes no value — and writes `fig1_cascade`,
`fig2_prefix_survival` and `fig3_certificate_campaign` as vector PDF, 600 dpi
TIFF and editable SVG. The rendered files ship in this package, so a reviewer
can compare their own output with the manuscript figures directly.

## Three-tier reproduction path

1. **Zero dependency** — sections A–F: `python analysis/verify_paper_tables.py --offline`.
   Everything needed ships in `data/` (including the raw per-measurement
   results in `data/c1/raw/`).
2. **Network** — full run: sections G–H fetch public measurement results from
   `atlas.ripe.net/api/v2` and recompute verdicts with the shipped engine.
3. **Credentials** — creating *new* measurements (not needed to verify this
   paper): `analysis/c1_campaign.py` with your own RIPE Atlas API key exported
   as `ATLAS_API_KEY`. Measurement-creation scripts live next to the analysis
   scripts; the non-redistributable 2011-archive-bound scripts are in
   `analysis/reference_only/` (shipped for method transparency, not executable
   here — see SOURCES.md).

## What is and is not here

- Shipped: derived statistics (`data/routeviews/`, `data/c1/`), the
  measurement registry (`data/c1/campaign_msm_ids.json`: 294 public
  measurements with IDs), raw public measurement results (`data/c1/raw/`),
  the verdict engine, the campaign drivers, the anchor pre-registration, the
  one-command verifier, and the three manuscript figures with their input data
  and plotting script (`figures/`).
- Not shipped: the 2011 snapshot archive itself and its full hostname map
  (not redistributable; all released artifacts are derived statistics — see
  SOURCES.md), and the 77 MB public RouteViews RIB archive (re-downloadable;
  URL in SOURCES.md).
- Redacted at build time: `data/c1/dnsmap_feasibility.json` ships **counts
  only** — the 2011 snapshot's per-target hostname identities
  (`per_candidate[].sample_names`) and its domain-to-address resolution map
  (`resolve.resolved_map`) are withheld, leaving the per-target record counts
  and the resolution summary (tested / resolved / nxdomain / other). The
  file records this itself in `meta.identity_withheld`.
- `data/c1/target_labels.json` maps the paper's anonymized target labels
  (**A–I**, ordered by ascending primary measurement ID) back to the target
  domain and measurement IDs. The manuscript's Table 3 uses only the labels;
  this file lets a reviewer trace every published row to its public
  measurement record. The target domains are not new disclosure — they are
  the public targets of the `is_public` RIPE Atlas measurements listed in
  `data/c1/campaign_msm_ids.json`.
- `data/c1/novelty_search.json` is the audit trail behind the paper's
  "to our knowledge" claim in §2: five Crossref bibliographic queries, every
  returned candidate with a keep/out decision and a reason, the four retained
  works, and the eight closest prior works with why-close / why-different
  notes. It records what was searched and what was rejected, so a reviewer
  can re-run the queries and disagree with a specific screening decision
  instead of having to trust the claim. Checked by section `K`.

## License

Code: MIT (see LICENSE). Derived data files: CC BY 4.0. Third-party content
(RouteViews archives, RIPE Atlas results, certificates served by third
parties) remains under its own terms and is not claimed by this license.
