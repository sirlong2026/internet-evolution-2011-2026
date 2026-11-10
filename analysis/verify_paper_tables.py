#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_paper_tables.py — recompute every published number from shipped evidence.

One command recomputes the paper's tables from the shipped data and fails
(exit 1) on any mismatch. Where possible the numbers are recomputed from the
raw measurement results in data/c1/raw/ (not from the shipped summaries), and
the shipped summaries are then cross-checked against the recomputation.

Sections:
  A  routing-layer survival (713,853 prefixes vs the 2026 table)     [offline]
  B  2026 RIB calibers + cross-epoch comparison                      [offline]
  C  address-layer ICMP liveness of the 100 addresses (from raw)     [offline]
  D  path-layer traceroute reachability (from raw)                   [offline]
  E  service layer at the old addresses (from raw + cert identity)   [offline]
  F  service layer at migrated organizational domains (from raw)     [offline]
  G  known-answer anchor: pre-registered RR dual-cert rig            [live API]
  H  recurring-campaign verdict recompute with the shipped engine    [offline]
  J  uncertainty: Wilson 95% intervals + Fisher exact test          [offline]
  K  prior-work search record behind the §2 novelty claim           [offline]

Usage:
  python analysis/verify_paper_tables.py             # A-H (G fetches public results)
  python analysis/verify_paper_tables.py --offline   # A-F + H from raw, skips G
  python analysis/verify_paper_tables.py --refresh-rib  # also re-download + re-parse the 2026 RIB

Caliber notes (mirroring the paper):
  - ping liveness  = any vantage received >=1 echo reply (rcvd field; NOT "received")
  - trace reached  = Atlas destination_ip_responded flag, else last responding hop == dst
  - sslcert success = top-level "cert" PEM array (fw 5130) OR result.certificates[] (fw 5120)
  - sslcert failure = top-level "err" (NOT "error")
  - RIB unique-prefix caliber = 1,164,330 (the archive contains 9 duplicate-prefix records;
    1,164,339 counts records) — the paper adopts the unique caliber.
The anchor section never prints or stores the anchor address (masked as ANCHOR_VIP).
"""
import argparse
import base64
import hashlib
import json
import math
import os
import subprocess
import sys
import tempfile
import urllib.request
from collections import Counter

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from atlas_adapter import (aggregate_certs, build_cert_bundle, pick_pair,  # noqa: E402
                           load_json_checked, _leaf_hash)
import sensor_compare  # noqa: E402
import i18n  # noqa: E402  (shipped alongside: engine-output Chinese -> English)

DATA = os.path.join(REPO, "data")
C1 = os.path.join(DATA, "c1")
RAW = os.path.join(C1, "raw")
RV = os.path.join(DATA, "routeviews")
GT = os.path.join(REPO, "ground_truth")

EXPECT_ANCHOR_FPS = {"9b03a055ff2b3613", "e4c5b5f977df46ce"}

RESULTS = []


def check(sec, name, cond, detail=""):
    ok = bool(cond)
    RESULTS.append((sec, name, ok, detail))
    print("  [%s] %-58s %s" % ("PASS" if ok else "FAIL", name, detail if not ok or detail else ""))
    return ok


def jload(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def raw(msm):
    return jload(os.path.join(RAW, "cam_%d.json" % msm))


def group_msms(group):
    return [r["msm_id"] for r in jload(os.path.join(C1, "campaign_msm_ids.json"))["measurements"]
            if r["group"] == group]


def pem_fp(pem):
    body = "".join(l for l in pem.splitlines() if "-----" not in l)
    return hashlib.sha256(base64.b64decode(body)).hexdigest()


def cert_info(pem):
    if "-----BEGIN" not in pem:
        pem = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" % pem.strip()
    try:
        fd, path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(pem)
        out = subprocess.run(
            ["openssl", "x509", "-noout", "-in", path, "-subject", "-issuer",
             "-startdate", "-enddate"], capture_output=True, text=True, timeout=15)
        os.unlink(path)
        if out.returncode != 0:
            return {}
        d = {}
        for line in out.stdout.splitlines():
            k, _, v = line.partition("=")
            d[k.strip()] = v.strip()
        return d
    except Exception:
        return {}


# ---------------------------------------------------------------- sections --

def section_a():
    print("== A  routing-layer survival (713,853 prefixes vs 2026 table) ==")
    d = jload(os.path.join(RV, "c0_survival.json"))
    n = 713853
    check("A", "routes_2011 == 713,853", d["routes_2011"] == n, str(d["routes_2011"]))
    agg_recomputed = d["aggregate_alive"] / n
    check("A", "aggregate survival 68.8% (= alive/n recomputed)",
          abs(d["aggregate_survival"] - 0.6877) < 5e-4 and abs(agg_recomputed - d["aggregate_survival"]) < 1e-12,
          "%.6f" % d["aggregate_survival"])
    ex_recomputed = d["exact_alive"] / n
    check("A", "exact survival 29.0% (= alive/n recomputed)",
          abs(d["exact_survival"] - 0.2900) < 5e-4 and abs(ex_recomputed - d["exact_survival"]) < 1e-12,
          "%.6f" % d["exact_survival"])
    check("A", "/8 blocks 214 covered in 2011, 207 still covered in 2026 (7 lost)",
          d["slash8_covered_2011"] == 214 and d["slash8_still_covered_2026"] == 207)
    buckets = {"<=16": 0.6147, "17-20": 0.4217, "21-23": 0.2065, "24": 0.3112, ">24": 0.000252}
    for k, want in buckets.items():
        b = d["by_plen_bucket"][k]
        check("A", "bucket %-5s exact rate (recomputed from counts)" % k,
              b["n"] and abs(b["exact"] / b["n"] - b["exact_rate"]) < 1e-9
              and abs(b["exact_rate"] - want) < 1e-3,
              "%.4f" % b["exact_rate"])
    check("A", "bucket denominators sum to 713,853",
          sum(b["n"] for b in d["by_plen_bucket"].values()) == n)
    # 稿件印出的 Table 2 数值（正文逐格）与复算值的**舍入一致性**。
    # 这一层此前不存在：只查数据、不查正文印出的数字，0.1 个百分点的印刷错误
    # 不会被任何检查发现（2026-11-09 发现并改正 /24 精确存活 31.2% → 31.1%）。
    printed = {  # bucket: (aggregate %, aggregate 小数位, exact %, exact 小数位)
        "<=16": (87.1, 1, 61.5, 1),
        "17-20": (82.9, 1, 42.2, 1),
        "21-23": (71.5, 1, 20.6, 1),
        "24": (66.3, 1, 31.1, 1),
        ">24": (22.8, 1, 0.03, 2),
    }

    def rounds_to(value, printed_value, decimals):
        tol = 0.5 * (10 ** -decimals) + 1e-9
        return abs(value - printed_value) <= tol

    for k, (pa, da, pe, de) in printed.items():
        b = d["by_plen_bucket"][k]
        check("A", "printed Table 2 %-5s aggregate %s%% matches recomputed %s%%"
              % (k, pa, "%.1f" % (100 * b["agg_rate"])),
              rounds_to(100 * b["agg_rate"], pa, da),
              "recomputed %.4f" % (100 * b["agg_rate"]))
        check("A", "printed Table 2 %-5s exact %s%% matches recomputed %s%%"
              % (k, pe, "%.2f" % (100 * b["exact_rate"])),
              rounds_to(100 * b["exact_rate"], pe, de),
              "recomputed %.4f" % (100 * b["exact_rate"]))
    check("A", "printed Table 2 'all' row 68.8% / 29.0% matches recomputed totals",
          rounds_to(100 * d["aggregate_survival"], 68.8, 1)
          and rounds_to(100 * d["exact_survival"], 29.0, 1),
          "recomputed %.4f / %.4f" % (100 * d["aggregate_survival"],
                                      100 * d["exact_survival"]))
    # 逐前缀长度（稿件 Fig.2 存活曲线的数据源）：与桶级口径必须自洽
    by_plen = d.get("by_plen") or {}
    check("A", "per-prefix-length counts present and sum to 713,853",
          bool(by_plen) and sum(v["n"] for v in by_plen.values()) == n,
          "%d lengths" % len(by_plen))
    if by_plen:
        def bucket_of(p):
            p = int(p)
            return ("<=16" if p <= 16 else ("17-20" if p <= 20 else
                    ("21-23" if p <= 23 else ("24" if p == 24 else ">24"))))
        for k, b in d["by_plen_bucket"].items():
            sub = [v for p, v in by_plen.items() if bucket_of(p) == k]
            check("A", "per-length rows reconcile with bucket %-5s (n, agg, exact)" % k,
                  sum(v["n"] for v in sub) == b["n"]
                  and sum(v["agg"] for v in sub) == b["agg"]
                  and sum(v["exact"] for v in sub) == b["exact"],
                  "n=%d agg=%d exact=%d" % (sum(v["n"] for v in sub),
                                            sum(v["agg"] for v in sub),
                                            sum(v["exact"] for v in sub)))
        check("A", "per-length /24 exact survival exceeds /23 (deaggregation signature)",
              by_plen["24"]["exact_rate"] > by_plen["23"]["exact_rate"],
              "/24 %.1f%% vs /23 %.1f%%" % (100 * by_plen["24"]["exact_rate"],
                                            100 * by_plen["23"]["exact_rate"]))


def section_b(refresh_rib=False):
    print("== B  2026 RIB calibers + cross-epoch comparison ==")
    rs = jload(os.path.join(RV, "rib_stats.json"))
    cmp_ = jload(os.path.join(RV, "c0_compare.json"))
    check("B", "RIB path-table entries == 18,653,467",
          rs["rib_ipv4"]["entries"] == 18653467, str(rs["rib_ipv4"]["entries"]))
    check("B", "RIB records == 1,164,339; paper (unique) caliber == 1,164,330",
          rs["rib_ipv4"]["prefixes"] == 1164339
          and cmp_["routeviews_2026"]["prefixes"] == 1164330)
    check("B", "growth factor x1.631 (= 1,164,330 / 713,853 recomputed)",
          abs(cmp_["growth_factor_prefixes"] - 1164330 / 713853) < 1e-9
          and abs(cmp_["growth_factor_prefixes"] - 1.6311) < 5e-4)
    check("B", "2011 plen histogram sums to 713,853",
          sum(cmp_["snapshot_2011"]["plen_hist"].values()) == 713853)
    check("B", "2026 plen histogram sums to 1,164,339 (record caliber; "
               "unique caliber 1,164,330 = records − 9 duplicate records)",
          sum(cmp_["routeviews_2026"]["plen_hist"].values()) == 1164339
          and cmp_["routeviews_2026"]["rib_records"] == 1164339
          and cmp_["routeviews_2026"]["prefixes"] == 1164330)
    check("B", "/8-covered 214 (2011 view) vs 221 (2026 view)",
          cmp_["snapshot_2011"]["slash8_covered"] == 214
          and cmp_["routeviews_2026"]["slash8_covered"] == 221)
    check("B", "RIB parse not truncated; bytes consumed = archive size",
          rs["truncated"] is False and cmp_["rib_truncated"] is False)
    if refresh_rib:
        print("  --refresh-rib: re-downloading + re-parsing the public RouteViews archive...")
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import routeviews_rib as rvb
        import urllib.request as ur
        url = "https://archive.routeviews.org/route-views2/bgpdata/2026.11/RIBS/rib.20261107.1600.bz2"
        dest = os.path.join(tempfile.gettempdir(), "rib.20261107.1600.bz2")
        if not os.path.exists(dest) or os.path.getsize(dest) != 77444468:
            print("     downloading %s -> %s" % (url, dest))
            ur.urlretrieve(url, dest)
        stats = rvb.parse_stats(dest) if hasattr(rvb, "parse_stats") else None
        if stats is None:
            print("     [SKIP] parser exposes no single-call stats helper; run "
                  "`python analysis/routeviews_rib.py <file>` for the full parse")
        else:
            check("B", "re-parsed entries match shipped", stats == rs["rib_ipv4"]["entries"])


def section_b2():
    print("== B2  2011 snapshot calibration against the same-day public DFZ ==")
    cal = jload(os.path.join(RV, "c0_2011_calibration.json"))
    fwd = cal["snapshot_visible_in_rib_2011"]
    tot, rev = fwd["total"], cal["rib_2011_covered_by_snapshot"]
    check("B2", "calibration run complete (2011 RIB not truncated, 45 peers, 377,201 prefixes)",
          cal["meta"]["rib"]["truncated"] is False
          and cal["meta"]["rib"]["peer_count"] == 45
          and cal["meta"]["rib"]["prefixes"] == 377201)
    check("B2", "snapshot prefix count == 713,853 and bucket n's sum to it",
          cal["meta"]["snapshot_prefixes"] == 713853
          and sum(b["n"] for b in fwd["by_bucket"].values()) == 713853)
    check("B2", "rates recomputable from counts (forward total)",
          abs(tot["exact_rate"] - tot["exact"] / tot["n"]) < 1e-6
          and abs(tot["covered_rate"] - tot["covered"] / tot["n"]) < 1e-6)
    check("B2", "paper: same-day DFZ announces 91.3% of snapshot space (covered), 50.2% identical",
          abs(tot["covered_rate"] - 0.9127) < 5e-4 and abs(tot["exact_rate"] - 0.5021) < 5e-4)
    gt24 = fwd["by_bucket"][">24"]
    check("B2", "paper: >24 bucket 99.3% covered / 2.3% exact (caliber artifact measured)",
          abs(gt24["covered_rate"] - 0.9925) < 5e-4 and abs(gt24["exact_rate"] - 0.0230) < 5e-4)
    check("B2", "paper: snapshot contains 99.8% of the same-day DFZ (covered), 95.0% exact",
          rev["n"] == 377200
          and abs(rev["covered_rate"] - 0.9981) < 5e-4
          and abs(rev["exact_rate"] - 0.9501) < 5e-4)
    check("B2", "intersection consistency: forward exact == reverse exact",
          tot["exact"] == rev["exact"])


def section_c():
    print("== C  address-layer ICMP liveness (recomputed from raw) ==")
    cand = {c["rep_ip"]: c for c in jload(os.path.join(C1, "candidates_today.json"))["final"]}
    exact_total = sum(1 for c in cand.values() if c.get("today_exact"))
    check("C", "final-100 composition: 57 exact survivors + 43 covered-only",
          exact_total == 57 and len(cand) == 100)
    live = ex_live = cv_live = 0
    for msm in group_msms("ping100"):
        rows = raw(msm)
        dst = rows[0].get("dst_name")
        c = cand.get(dst)
        if c is None:
            check("C", "ping msm %d target in final-100" % msm, False, dst)
            continue
        lv = any(r.get("rcvd", 0) > 0 for r in rows)
        live += lv
        ex_live += lv and c.get("today_exact")
        cv_live += lv and not c.get("today_exact")
    check("C", "35/100 addresses ICMP-live", live == 35, str(live))
    check("C", "exact survivors 25/57 live (44%)", ex_live == 25, str(ex_live))
    check("C", "covered-only 10/43 live (23%)", cv_live == 10, str(cv_live))
    ph = jload(os.path.join(C1, "phase1_summary.json"))
    check("C", "shipped phase1_summary ping.n_live agrees (35)",
          ph["ping"]["n_live"] == 35 and ph["ping"]["n_total"] == 100)


def section_d():
    print("== D  path-layer reachability (recomputed from raw) ==")
    reached = total = 0
    for msm in group_msms("trace50"):
        rows = raw(msm)
        if not rows:
            continue
        dst = rows[0].get("dst_name")
        for res in rows:
            total += 1
            last_from = None
            for h in (res.get("result") or []):
                for hr in (h.get("result") or []):
                    if hr.get("from"):
                        last_from = hr["from"]
            if res.get("destination_ip_responded") or (dst and last_from == dst):
                reached += 1
    check("D", "180/500 probe paths reached (36%)",
          reached == 180 and total == 500, "%d/%d" % (reached, total))
    ph = jload(os.path.join(C1, "phase1_summary.json"))
    check("D", "shipped phase1_summary trace counts agree",
          ph["trace"]["reached"] == 180 and ph["trace"]["probe_paths"] == 500)


def section_e():
    print("== E  service layer at the old addresses (recomputed from raw) ==")
    prescreen = jload(os.path.join(C1, "scout_prescreen.json"))
    alive_msms, tax = [], Counter()
    for msm in group_msms("scout100"):
        rows = raw(msm)
        ok = False
        err = ""
        for r in rows:
            if r.get("cert") or (r.get("result") or {}).get("certificates"):
                ok = True
            e = (r.get("err") or "").strip()
            if e:
                err = e
        if ok:
            alive_msms.append(msm)
        else:
            tax[err] += 1
    check("E", "exactly 1/100 old addresses TLS-alive", len(alive_msms) == 1, str(alive_msms))
    check("E", "failure taxonomy 82 timeout / 15 refused / 1 hello / 1 host-unreachable",
          tax == Counter({"connect: timeout": 82, "connect: Connection refused": 15,
                          "timeout reading hello": 1, "connect: Host is unreachable": 1}),
          str(dict(tax)))
    shipped_alive = [r for r in prescreen["results"] if r["ok"]]
    check("E", "shipped scout_prescreen.json agrees (tls_ok=1, same msm)",
          prescreen["meta"]["tls_ok"] == 1 and len(shipped_alive) == 1
          and shipped_alive[0]["msm_id"] == alive_msms[0])
    a = shipped_alive[0]
    check("E", "alive address is an exact-surviving ARIN /24",
          a["prefix"] == "195.245.226.0/24" and a["registry"] == "arin")
    msm_rows = raw(alive_msms[0])
    pem = msm_rows[0]["cert"][0]
    info = cert_info(pem)
    # 证书的 subject 域名**不在本脚本里写死**：占用该老地址的是与研究无关的第三方，
    # 稿件与公开包都不点名它（见 SOURCES.md §4）。这里改为**语义等价**的判定：
    # 通配符身份 + 公共商业 CA 签发 + 有效期落在公布窗口 + 该身份不是本研究
    # 测量的任何组织域名（组织域名清单见随包发布的 sslscout34_spec / sslcert9_spec）。
    subj = info.get("subject") or ""
    study_domains = set()
    for _rel in ("sslscout34_spec.json", "sslcert9_spec.json"):
        _spec = jload(os.path.join(C1, _rel))
        study_domains.update(_spec.get("domains") or [])
        study_domains.update((_spec.get("selection") or {}).get("selected") or [])
    subj_domain = subj.split("=", 1)[-1].strip().lower().lstrip("*.") if subj else ""
    check("E", "alive identity is a re-purposed third party (wildcard identity, public "
          "commercial CA, 2025-11-27..2026-11-26, and not one of the measured organizations)",
          subj.startswith("CN=*.")
          and subj_domain not in study_domains
          and "Certum" in (info.get("issuer") or "")
          and info.get("notBefore", "").startswith("Nov 27 08:41:13 2025")
          and info.get("notAfter", "").startswith("Nov 27 08:41:12 2026"),
          "wildcard=%s | not-a-study-domain=%s | issuer=%s | notBefore=%s" % (
              subj.startswith("CN=*."), subj_domain not in study_domains,
              info.get("issuer"), info.get("notBefore")))
    check("E", "fingerprint of raw cert == shipped cert_sha256 (fw-5130 caliber)",
          a["cert_sha256"] == pem_fp(pem))
    fps = {pem_fp(r["cert"][0]) for r in msm_rows if r.get("cert")}
    check("E", "all 3 vantages report the same certificate (variants=1)", len(fps) == 1)


def section_f():
    print("== F  service layer at migrated organizational domains (recomputed from raw) ==")
    shipped = jload(os.path.join(C1, "sslscout34_summary.json"))
    recomputed = {}
    for r in shipped["results"]:
        rows = raw(r["msm_id"])
        ok = any(x.get("cert") or (x.get("result") or {}).get("certificates") for x in rows)
        recomputed[r["domain"]] = ok
    n_ok = sum(recomputed.values())
    check("F", "15/34 resolving domains TLS-live (44%)",
          n_ok == 15 and len(recomputed) == 34, str(n_ok))
    check("F", "recomputation agrees with shipped summary",
          all(recomputed[d] == s["tls_ok"] for d, s in
              zip([x["domain"] for x in shipped["results"]], shipped["results"])))
    asp = [x for x in shipped["results"] if x["domain"] == "asp.bg"][0]
    check("F", "fossil certificate: asp.bg leaf issued 2004, still served 2026",
          asp["tls_ok"] and " 2004 " in (asp.get("notBefore") or ""),
          asp.get("notBefore", ""))


def section_g():
    print("== G  known-answer anchor (live; identities masked) ==")
    anchor_msms = group_msms("sslcert-anchor") + group_msms("sslcert-anchor-aux")
    check("G", "anchor measurements registered (primary + vantage backfill)",
          len(anchor_msms) >= 1, "n=%d" % len(anchor_msms))
    if not anchor_msms:
        return
    rows = []
    try:
        for msm in anchor_msms:
            with urllib.request.urlopen(
                    "https://atlas.ripe.net/api/v2/measurements/%d/results/" % msm,
                    timeout=180) as f:
                rows.extend(json.loads(f.read().decode()))
    except Exception as e:
        print("  [SKIP] anchor fetch failed (%s) — run again with network" % e)
        return
    per = {}
    for r in rows:
        c = r.get("cert")
        if not c:
            continue
        fp = _leaf_hash(c[0])[:16]
        e = per.setdefault(r["prb_id"], {"hands": 0, "fps": set()})
        e["hands"] += 1
        e["fps"].add(fp)
    stray = {fp for e in per.values() for fp in e["fps"]} - EXPECT_ANCHOR_FPS
    check("G", "no certificate outside the two pre-registered fingerprints", not stray,
          "stray=%s" % sorted(stray) if stray else "union=%d" % len(
              {fp for e in per.values() for fp in e["fps"]}))
    ready = [p for p, e in sorted(per.items())
             if e["hands"] >= 3 and len(e["fps"]) >= 2]
    print("     vantage state (prb: hands, distinct fps): %s" % ", ".join(
        "%s:%d/%d" % (p, e["hands"], len(e["fps"])) for p, e in sorted(per.items())))
    gt = jload(os.path.join(GT, "pilot_truth.json"))
    check("G", "pre-registration declares pool family, union=2, winner c2",
          gt["pre_registered_expect"]["verdict"] == "likely_pool"
          and gt["pre_registered_expect"]["cert_union"] == 2
          and gt["pre_registered_expect"]["winner"].startswith("c2"))
    if len(ready) >= 2:
        per_adapter = aggregate_certs(rows)
        pair = pick_pair(per_adapter)
        if len(pair) == 2:
            ra = build_cert_bundle("anchor#prb%d" % pair[0], per_adapter[pair[0]])
            rb = build_cert_bundle("anchor#prb%d" % pair[1], per_adapter[pair[1]])
            v = sensor_compare.decide_formal(ra, rb)
            v = i18n.translate(v)[0]  # engine emits Chinese states; package is English
            check("G", "anchor verdict: decidable, winner c2 (round-robin), κ=2/6=0.333 by construction",
                  v.get("V") == "decidable" and (v.get("winner") or "").startswith("c2")
                  # the engine reports kappa rounded to 3 decimals (sensor_compare.py:182),
                  # so compare against round(2/6, 3), not against 1/3
                  and abs(v.get("kappa", 0) - round(2 / 6, 3)) < 1e-9,
                  "V=%s winner=%s κ=%s family=%s" % (v.get("V"), v.get("winner"),
                                                     v.get("kappa"), v.get("family")))
        else:
            print("     [INTERIM] adapter pair not ready (%s) — window still open" % (pair,))
    else:
        print("     [INTERIM] %d/2 vantages o3-gated with both fingerprints — "
              "window still open (ends 2026-11-10)" % len(ready))


def section_h():
    print("== H  recurring-campaign verdicts (recomputed from raw with the shipped engine) ==")
    shipped = {r["msm"]: r for r in jload(os.path.join(C1, "sslcert9_judged.json"))["rows"]}
    msms = group_msms("sslcert9")
    check("H", "9 recurring organizational targets registered", len(msms) == 9 and len(shipped) == 9)
    n_match = 0
    asp_variants = None
    for msm in msms:
        dom = shipped[msm]["domain"]
        srow = shipped[msm]
        # 2026-11-09（口径变更，见日志 §5p）：目标观测集＝该靶全部战役测量 ID 的并集
        # （asp.bg = 原测量 + 信用恢复后续测），复算须按同一口径合并原始行。
        msm_list = srow.get("msms") or [msm]
        data = []
        missing = []
        for m in msm_list:
            p = os.path.join(RAW, "cam_%d.json" % m)
            if not os.path.exists(p):
                missing.append(m)
                continue
            data.extend(load_json_checked(p, "sslcert9/%s" % dom))
        if missing:
            print("     [NOTE] %s: raw rows missing locally for %s (expected while the "
                  "continuation measurement has not produced results yet)" % (dom, missing))
        per = aggregate_certs(data)
        pair = pick_pair(per)
        recomputed = None
        if len(pair) == 2:
            a = build_cert_bundle("%s#prb%d" % (dom, pair[0]), per[pair[0]])
            b = build_cert_bundle("%s#prb%d" % (dom, pair[1]), per[pair[1]])
            recomputed = sensor_compare.decide_formal(a, b)
        # 引擎输出为中文，发布包为英文：用随包发布的同一份映射归一后再比对
        recomputed = i18n.translate(recomputed)[0]
        same = (json.dumps(recomputed, sort_keys=True, ensure_ascii=False)
                == json.dumps(srow["verdict"], sort_keys=True, ensure_ascii=False))
        if recomputed is None and srow["verdict"] is None:
            same = True
        n_match += same
        if not same:
            check("H", "verdict determinism for %s" % dom, False,
                  "shipped=%s recomputed=%s" % (json.dumps(srow["verdict"], ensure_ascii=False)[:120],
                                                json.dumps(recomputed, ensure_ascii=False)[:120]))
        if dom == "asp.bg":
            asp_variants = srow
    check("H", "verdict determinism: recomputed == shipped for all 9 targets",
          n_match == 9, "%d/9" % n_match)
    check("H", "variant-attribution rule active on asp.bg (issuer-divergent, subject+validity identical)",
          asp_variants is not None and len(asp_variants.get("cert_variants", [])) >= 2
          and "vantage-side re-signing" in (asp_variants.get("variant_note") or ""),
          (asp_variants.get("variant_note") or "missing")[:120] if asp_variants else "no asp.bg row")


def section_i():
    """Figure data: regenerate it from this package and compare with the shipped file.

    The three manuscript figures are built from figures/figdata.json, which is
    extracted from the derived statistics in data/ by analysis/c1_figure_data.py.
    This section re-runs that extractor inside the package and asserts the
    payload is identical, then spot-checks the headline numbers of each figure
    against the same package's data. Nothing here trusts a shipped summary:
    the figure data is regenerated and compared.
    """
    print("== I  manuscript figure data (regenerated from this package) ==")
    fig_path = os.path.join(REPO, "figures", "figdata.json")
    if not os.path.exists(fig_path):
        check("I", "figures/figdata.json present", False, "missing")
        return
    shipped = jload(fig_path)

    gen_dir = tempfile.mkdtemp(prefix="figdata_")
    out = os.path.join(gen_dir, "figdata.json")
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "c1_figure_data.py")
    p = subprocess.run([sys.executable, script, "--out", out],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    ok = check("I", "figure data regenerates from the shipped data",
               p.returncode == 0 and os.path.exists(out),
               (p.stdout.decode("utf-8", "replace")[-200:] if p.returncode else ""))
    if not ok:
        return
    regen = jload(out)

    def payload(d):
        d = dict(d)
        d.pop("meta", None)
        return d

    check("I", "regenerated figure data == shipped figure data",
          payload(regen) == payload(shipped),
          "payload differs")
    prov_ok = all(v.startswith("artifact:") or v.startswith("c1/")
                  or v.startswith("routeviews/") for v in
                  (regen.get("meta", {}).get("provenance") or {}).values())
    check("I", "every figure number carries a source-file provenance", prov_ok)

    # headline numbers of each figure, re-read from the regenerated payload
    lin = {r["stage"]: r for r in regen["fig1"]["lineage"]}
    check("I", "Fig.1 cohort cascade 199/178/100/35/0",
          lin["2011 cohort candidates"]["n"] == 199
          and lin["routable in 2026"]["n"] == 178
          and lin["measurement set"]["n"] == 100
          and lin["ICMP-live"]["n"] == 35
          and lin["2011 organization TLS identity"]["n"] == 0)
    bridge = {r["stage"]: r["n"] for r in regen["fig1"]["bridge"]}
    check("I", "Fig.1 identity bridge 100/51/48/34/15/9",
          [bridge[k] for k in ("measured addresses",
                               "carrying 2011 hostname mappings",
                               "registrable domains",
                               "still resolving in 2026",
                               "TLS handshake completed",
                               "organization-identity leaves")] == [100, 51, 48, 34, 15, 9])
    b24 = regen["fig2"]["buckets"]["24"]
    b23 = regen["fig2"]["buckets"]["21-23"]
    check("I", "Fig.2 /24 exact survival exceeds /21-23 (31.1% vs 20.6%)",
          round(100 * b24["exact_rate"], 1) == 31.1
          and round(100 * b23["exact_rate"], 1) == 20.6)
    check("I", "Fig.2 same-day control reproduces the /24 excess",
          round(100 * regen["fig2"]["calibration"]
                ["snapshot_visible_in_rib_2011"]["by_bucket"]["24"]["exact_rate"], 1) == 50.8)
    tg = regen["fig3"]["targets"]
    check("I", "Fig.3 campaign: 9 targets, 8 single-fingerprint + 1 dual",
          len(tg) == 9
          and sum(1 for t in tg if t["union_fp"] == 1) == 8
          and sum(1 for t in tg if t["union_fp"] > 1) == 1)
    anc = regen["fig3"]["anchor"]
    check("I", "Fig.3 anchor: 2-fingerprint union, 0 strays",
          anc["union_fp16"] == 2 and anc["stray_fp16"] == 0)

    for stem in ("fig1_cascade", "fig2_prefix_survival",
                 "fig3_certificate_campaign"):
        d = os.path.join(REPO, "figures")
        pdf, svg, tif = (os.path.join(d, stem + x) for x in (".pdf", ".svg", ".tiff"))
        have = all(os.path.exists(x) and os.path.getsize(x) > 1000
                   for x in (pdf, svg, tif))
        check("I", "figure files shipped: %s (PDF/SVG/TIFF)" % stem, have)
        if os.path.exists(pdf):
            with open(pdf, "rb") as f:
                check("I", "%s.pdf is a vector PDF" % stem, f.read(4) == b"%PDF")
        if os.path.exists(tif):
            with open(tif, "rb") as f:
                magic = f.read(4)
            check("I", "%s.tiff is a TIFF raster" % stem,
                  magic in (b"II*\x00", b"MM\x00*"))


def _wilson(k, n, z=1.959963984540054):
    """Wilson score 区间（95%），纯标准库实现（不依赖 scipy）。"""
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    d = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = (z / d) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (100 * p, 100 * (centre - half), 100 * (centre + half))


def _fisher_two_sided(a, b, c, d):
    """双侧 Fisher 精确检验 p 值（超几何分布求和，纯标准库实现）。

    与 scipy.stats.fisher_exact(..., alternative="two-sided") 在本数据上一致
    （0.036604），但复现包不引入第三方依赖。
    """
    n = a + b + c + d
    r1, r2 = a + b, c + d
    c1 = a + c

    def prob(x):
        return (math.comb(r1, x) * math.comb(r2, c1 - x)) / math.comb(n, c1)

    p_obs = prob(a)
    lo, hi = max(0, c1 - r2), min(r1, c1)
    return sum(prob(x) for x in range(lo, hi + 1) if prob(x) <= p_obs * (1 + 1e-7))


def section_j():
    print("== J  uncertainty: Wilson 95% intervals + Fisher exact test ==")
    # 计数全部由随包发布的派生统计重算；原始测量结果层面的重算见 C/E/F 段。
    ph = jload(os.path.join(C1, "phase1_summary.json"))
    ping = ph["ping"]
    by_msm = ping.get("by_msm") or {}
    live = sum(1 for r in by_msm.values() if r.get("live"))
    ex_live = sum(1 for r in by_msm.values()
                  if r.get("live") and r.get("today_exact"))
    cv_live = sum(1 for r in by_msm.values()
                  if r.get("live") and not r.get("today_exact"))
    check("J", "ping cohort size 100", len(by_msm) == 100, str(len(by_msm)))
    check("J", "35/100 live, split 25 exact + 10 covered-only",
          (live, ex_live, cv_live) == (35, 25, 10),
          "%d/%d/%d" % (live, ex_live, cv_live))

    cand = jload(os.path.join(C1, "candidates_today.json"))
    n_eval = int(cand["meta"]["candidates"])
    cands = cand["candidates"]
    n_exact = sum(1 for c in cands if c.get("today_exact"))
    fin_exact = sum(1 for c in cand["final"] if c.get("today_exact"))
    check("J", "178/199 routable, 90 exact; final-100 = 57 exact + 43 covered-only",
          (n_eval, len(cands), n_exact, fin_exact, len(cand["final"]) - fin_exact)
          == (199, 178, 90, 57, 43),
          "%d/%d/%d/%d/%d" % (n_eval, len(cands), n_exact, fin_exact,
                              len(cand["final"]) - fin_exact))

    dns = jload(os.path.join(C1, "dnsmap_feasibility.json"))
    n_tested = int(dns["resolve"]["tested"])
    n_resolved = int(dns["resolve"]["resolved"])
    sc = jload(os.path.join(C1, "sslscout34_summary.json"))
    n_tls = sum(1 for r in sc["results"] if r.get("tls_ok"))

    def ci(tag, k, n, lo, hi, label):
        p, l, h = _wilson(k, n)
        ok = abs(l - lo) <= 0.05 and abs(h - hi) <= 0.05
        check("J", label, ok,
              "recomputed [%.1f, %.1f] vs published [%s, %s]" % (l, h, lo, hi))
        return p

    ci("ping", live, len(by_msm), 26.4, 44.7,
       "35/100 ICMP-live: 95% CI 26.4-44.7")
    ci("exact", ex_live, 57, 31.8, 56.7,
       "25/57 exact survivors live: 95% CI 31.8-56.7")
    ci("covered", cv_live, 43, 13.2, 37.7,
       "10/43 covered-only live: 95% CI 13.2-37.7")
    ci("routable", len(cands), n_eval, 84.4, 93.0,
       "178/199 candidates routable: 95% CI 84.4-93.0")
    ci("exact_cand", n_exact, n_eval, 38.5, 52.2,
       "90/199 candidates exact-surviving: 95% CI 38.5-52.2")
    ci("resolve", n_resolved, n_tested, 56.8, 81.8,
       "34/48 domains still resolving: 95% CI 56.8-81.8")
    ci("tls34", n_tls, len(sc["results"]), 28.9, 60.5,
       "15/34 resolving domains complete TLS: 95% CI 28.9-60.5")
    ci("identity", 0, 100, 0.0, 3.7,
       "0/100 old addresses serve the 2011 TLS identity: 95% upper bound 3.7")

    p_exact = _fisher_two_sided(ex_live, 57 - ex_live, cv_live, 43 - cv_live)
    check("J", "stratified liveness contrast: Fisher two-sided p = 0.037",
          abs(p_exact - 0.037) <= 0.0005, "recomputed p = %.6f" % p_exact)
    check("J", "Fisher table is 25/32 vs 10/33 (exact vs covered-only)",
          (ex_live, 57 - ex_live, cv_live, 43 - cv_live) == (25, 32, 10, 33))


def section_k():
    """首创性检索留档（§2 的 "to our knowledge" 主张的可审计依据）。

    校验点：记录文件在包内存在、schema 正确、5 条检索式齐全、逐条候选都有
    keep/out 判定与理由、留用条目数与筛除条目数自洽、留用条目的 DOI 在检索
    候选里确实出现过、最近邻清单每条都带 why-close/why-different。
    """
    print("== K  novelty-search record (auditable basis of the §2 claim) ==")
    p = os.path.join(C1, "novelty_search.json")
    if not os.path.exists(p):
        check("K", "novelty_search.json ships with the package", False, p)
        return
    d = jload(p)
    check("K", "novelty_search.json ships with the package", True, os.path.relpath(p, REPO))
    check("K", "record schema is cline_novelty_search/1",
          d.get("schema") == "cline_novelty_search/1", str(d.get("schema")))
    check("K", "database and query date recorded",
          bool(d.get("database")) and bool(d.get("queried_utc")),
          "%s @ %s" % (d.get("database"), d.get("queried_utc")))

    qs = d.get("queries") or []
    check("K", "five query strings recorded",
          len(qs) == 5 and [q.get("id") for q in qs] == ["NQ1", "NQ2", "NQ3", "NQ4", "NQ5"],
          ",".join(str(q.get("id")) for q in qs))
    check("K", "every query string is non-empty",
          all(str(q.get("query", "")).strip() for q in qs),
          "%d/%d non-empty" % (sum(1 for q in qs if str(q.get("query", "")).strip()), len(qs)))

    cands = []
    for q in qs:
        for c in q.get("candidates") or []:
            cands.append(c)
    bad_dec = [c.get("title") for c in cands
               if c.get("decision") not in ("kept", "out") or not str(c.get("reason", "")).strip()]
    check("K", "every screened candidate carries a keep/out decision and a reason",
          not bad_dec, "%d candidates, %d malformed" % (len(cands), len(bad_dec)))
    n_out = sum(1 for c in cands if c.get("decision") == "out")
    n_kept = sum(1 for c in cands if c.get("decision") == "kept")
    check("K", "screened_out_count matches the per-candidate decisions",
          d.get("screened_out_count") == n_out,
          "declared %s vs counted %d" % (d.get("screened_out_count"), n_out))

    kept = d.get("retained_candidates") or []
    kept_dois = sorted(c.get("doi") for c in kept)
    EXPECT_KEPT = sorted([
        "10.1109/comst.2015.2418435",     # platform survey
        "10.1145/2805789.2805796",        # RIPE Atlas lessons learned
        "10.23919/inm.2017.7987262",       # vantage point selection
        "10.1145/2815675.2815710",        # measurement interference
    ])
    check("K", "retained set is the four platform-machinery works (DOIs)",
          kept_dois == EXPECT_KEPT, ", ".join(str(x) for x in kept_dois))
    check("K", "retained count is consistent (kept decisions == retained list)",
          n_kept == len(kept), "%d decisions vs %d retained" % (n_kept, len(kept)))
    cand_dois = set(c.get("doi") for c in cands)
    check("K", "every retained DOI also occurs among the screened candidates",
          set(kept_dois) <= cand_dois,
          "%d/%d found" % (len(set(kept_dois) & cand_dois), len(set(kept_dois))))

    cpw = d.get("closest_prior_work") or []
    check("K", "closest prior work list carries why-close and why-different per entry",
          bool(cpw) and all(str(c.get("why_close", "")).strip()
                            and str(c.get("why_different", "")).strip() for c in cpw),
          "%d entries" % len(cpw))
    check("K", "closest prior work entries all carry a DOI",
          all(str(c.get("doi", "")).strip() for c in cpw),
          "%d entries" % len(cpw))
    check("K", "verdict and limitations are recorded",
          bool(d.get("verdict")) and bool(d.get("limitations")),
          "verdict %d chars, limitations %d chars"
          % (len(d.get("verdict") or ""), len(d.get("limitations") or "")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="skip the live anchor fetch (G)")
    ap.add_argument("--refresh-rib", action="store_true",
                    help="re-download and re-parse the public 2026 RIB (~77 MB)")
    args = ap.parse_args()
    section_a()
    section_b(refresh_rib=args.refresh_rib)
    section_b2()
    section_c()
    section_d()
    section_e()
    section_f()
    section_h()
    section_i()
    section_j()
    section_k()
    if args.offline:
        print("== G  skipped (--offline) ==")
        print("     anchor check needs the live public results API; run without --offline")
    else:
        section_g()
    fails = [r for r in RESULTS if not r[2]]
    print("\n==== %d checks, %d failed ====" % (len(RESULTS), len(fails)))
    for sec, name, _, detail in fails:
        print("  FAIL %s %s %s" % (sec, name, detail))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
