# analysis/ — what each script is for

The scripts below are the measurement and analysis code behind the paper.
They are shipped for method transparency and for re-running the numbers.

**Language note.** The scripts carry their detailed documentation in Chinese
(they are the original research-line sources); this file gives the English
map. `i18n.py` renders the decision engine's Chinese output into English
inside the shipped data files, and `verify_paper_tables.py` uses the same
map when it compares a recomputed verdict with the shipped one.

## The one command a reviewer needs

| script | what it does |
|---|---|
| `verify_paper_tables.py` | Recomputes **every published number** from the shipped evidence (sections A–H) and exits non-zero on any mismatch. A–F are offline; G fetches the public RIPE Atlas results of the anchor measurements; H recomputes the per-target verdicts with the shipped engine. |
| `c1_figure_data.py` | Extracts every number that appears in the paper's three figures into `figures/figdata.json`, each with a `provenance` field naming the derived-statistics file it came from. Reads `data/` of this package; computes nothing. Feeds `figures/make_figures.py`. |

## Engine and adapters

| script | what it does |
|---|---|
| `sensor_compare.py` | The four-state decision engine (decidable / conditionally decidable / indistinguishable / unobservable) with the κ floor and the six backend hypotheses plus the two orthogonal auxiliary axes. Identical code runs on the laboratory calibration rig, on the anchor, and on the campaign targets. |
| `atlas_adapter.py` | Adapts public RIPE Atlas measurement results into the sensor bundles the engine consumes: aggregates leaf certificates per vantage, builds the compared bundles, picks the vantage pair. |
| `i18n.py` | Deterministic Chinese → English rendering map for engine output (four states, hypothesis glosses, variant-attribution note, pre-registration prose). Strings only — no structure, no numbers, no fingerprints. |

## Campaign drivers (need your own RIPE Atlas API key)

| script | what it does |
|---|---|
| `c1_campaign.py` | Creates the public Atlas measurements of the campaign (one-off ping and traceroute, recurring sslcert). Reads `ATLAS_API_KEY` from the environment; never writes it to disk. |
| `c1_judge.py` | Judges the nine organizational-domain targets with the shared engine. Per-target observation set = the union of the certificates observed in **all** campaign measurement IDs of that target (see the caliber note in the log). |
| `c1_phase1_summary.py` | Summarizes the phase-1 ping/traceroute campaign (ICMP liveness per address, traceroute reachability per destination). |
| `c1_scout_summary.py` | Summarizes the scouting measurement on the old addresses (TLS-live at 2011 representative addresses). |
| `c1_sslscout34_summary.py` | Summarizes the organizational-domain scouting measurement (TLS-live among the domains that still resolve). |
| `c1_anchor_watch.py` | Data-plane health watch on the cloud anchor measurement (per-vantage handshake counts, coverage of the two pre-registered fingerprints). |
| `routeviews_rib.py` | Zero-dependency MRT TABLE_DUMP_V2 parser for RouteViews/RIS archives; produces the prefix-level statistics of the public 2026 routing table. |

## reference_only/ — method transparency, not runnable here

These need the non-redistributable 2011 snapshot archive (or its frozen
derived tables) and are shipped as documentation of how the numbers were
produced, not as a reproduction path.

| script | what it does |
|---|---|
| `c0_compare.py` | Compares the 2011 archive with the 2026 RouteViews RIB (aggregate and exact prefix survival, /8 coverage). |
| `c0_survival.py` | Full-archive survival analysis of the 2011 prefix set. |
| `c0_2011_calibration.py` | Triangulates the 2011 snapshot against the same-day public RIB (2011-07-02, 45 peers). |
| `c1_targets.py` | Target selection: stratified sampler over registry × prefix-length strata, seeded, multi-homing-rich. |
| `c1_spec.py` | Generates the campaign measurement specifications from the target lists. |
| `c1_prescreen.py` | Local TLS prescreen of candidate addresses (zero Atlas credits; records failure modes). |
| `c1_dnsmap_feasibility.py` | Feasibility of the organizational-domain framework: snapshot hostname coverage and today's resolution of those domains. |
| `c1_phase1_spec.py` | Specification of the phase-1 ping/traceroute groups. |
| `c1_sslscout_spec.py` | Specification of the organizational-domain scouting measurement. |
| `c1_sslcert9_spec.py` | Specification of the recurring sslcert group (nine organizational targets). |
