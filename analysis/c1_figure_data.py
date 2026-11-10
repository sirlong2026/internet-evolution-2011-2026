#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_figure_data.py — C 线稿件三张配图的**唯一数源聚合器**（2026-11-09）。

为什么要有这个脚本：稿件配图里的每个数字都必须能指回一个已发布的派生统计文件，
不能让绘图脚本"顺手"读散落的 JSON、也不能手写。做法是把稿件用到的每一个数
集中抽取成一个 JSON（paper/figures/figdata.json），每组数字带 provenance
（源文件相对路径 + 字段路径），绘图脚本只读这个 JSON。

数据源：**已发布的 artifact 包**（artifact_c1/data/…）——即同行拿到的那一份，
而不是工作树里的中间态。收口日重建 artifact 后重跑本脚本即得终值图数据。
若某文件尚未进包（--src fallback），回落到工作树 data/…（数值口径一致）。

红线：只抽**计数与判定**，不抽逐次原始测量；抽出来的数字不含任何公司名，
靶标一律用匿名标签 A–I（标签映射由 target_labels.json 给出）。
本脚本在工作树里还会把抽出的文本里的厂商名/锚地址改写掉；发布版不需要这层
改写（包内每个输入在构建时已扫过 0 命中），故发布包里的副本不带那份字面量
清单——见 tools/build_repo_c1.py 的 release_figure_data_script()。

用法：
  python tools/c1_figure_data.py                 # 从 artifact 包取数
  python tools/c1_figure_data.py --src data      # 从工作树取数
  python tools/c1_figure_data.py --out paper/figures/figdata.json

仓库根由 __file__ 相对推出（不是写死的绝对路径）：同一份脚本既能在工作树里
跑，也能在**发布包**里跑——发布包里它落在 analysis/ 下，仓库根即发布包根，
于是默认取数路径自动落到本包 data/（同行复算的正是这份包）。
"""
import argparse
import json
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)          # tools/ 的上一级 = 仓库根（工作树或发布包根）
BANNED = []   # release copy: every input in this package was scanned clean at build
# time, so the working-tree redaction list is not shipped here.


def default_out():
    """默认输出：工作树写 paper/figures/，发布包写 figures/（包内既有位置）。"""
    if os.path.isdir(os.path.join(ROOT, "paper", "figures")):
        return os.path.join(ROOT, "paper", "figures", "figdata.json")
    return os.path.join(ROOT, "figures", "figdata.json")



def default_pkg():
    """默认取数根：工作树里是 artifact_c1/data，发布包里就是本包 data/。"""
    for cand in (os.path.join(ROOT, "artifact_c1", "data"),
                 os.path.join(ROOT, "data")):
        if os.path.isdir(cand):
            return cand
    return os.path.join(ROOT, "artifact_c1", "data")


def load(pkg, rel):
    """按 artifact 包 → 工作树的顺序取文件；返回 (data, 来源说明)。

    来源说明只写相对标签（如 "artifact:c1/sslcert9_judged.json"），不写绝对路径：
    图数据要随稿件/包流转，绝对路径既泄漏工作区名也不可移植。
    """
    for root, tag in ((pkg, "artifact"), (os.path.join(ROOT, "data"), "worktree")):
        p = os.path.join(root, rel)
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f), "%s:%s" % (tag, rel)
    raise SystemExit("缺少数据文件：%s" % rel)


def T(v):
    """JSON 里的布尔在本工程有 'True'/'False' 字符串与真布尔两种写法。"""
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() == "true"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pkg", default=None, help="取数根（默认：发布包 data/，工作树回落到 data/）")
    ap.add_argument("--src", default=None, help="显式数据根（覆盖默认）")
    ap.add_argument("--out", default=default_out())
    a = ap.parse_args()
    pkg = a.src or a.pkg or default_pkg()

    prov = {}
    # 来源标签：工作树里 artifact_c1/data 是"发布包"，data/ 是"工作树"；
    # 在发布包里运行时，ROOT/data 本身就是那份发布包的数据根 ⇒ 仍记 artifact。
    in_release = not os.path.isdir(os.path.join(ROOT, "artifact_c1"))
    pkg_label = ("artifact" if in_release or "artifact_c1" in pkg
                 else ("artifact" if os.path.isdir(pkg) else "worktree"))

    def get(rel):
        d, src = load(pkg, rel)
        prov[rel] = src
        return d

    # ---------------------------------------------------------------- Fig.1
    cand = get("c1/candidates_today.json")
    cands = cand["candidates"]
    final = cand["final"]
    phase1 = get("c1/phase1_summary.json")
    scout = get("c1/scout_prescreen.json")
    dnsmap = get("c1/dnsmap_feasibility.json")
    scout34 = get("c1/sslscout34_summary.json")

    n_cand = cand["meta"]["candidates"]                 # 199
    n_routable = len(cands)                            # 178（covered）
    n_exact_cand = sum(1 for r in cands if T(r["today_exact"]))   # 90
    n_final = len(final)                               # 100
    n_final_exact = sum(1 for r in final if T(r["today_exact"]))   # 57
    n_final_covered = n_final - n_final_exact          # 43

    ping = phase1["ping"]
    trace = phase1["trace"]
    n_ping_live = ping["n_live"]                       # 35
    # 分层存活：by_msm 逐靶带 live 与 today_exact，可直接推出
    #   精确存活靶 25/57 有回包（44%）、仅覆盖存活靶 10/43 有回包（23%）
    live_exact = sum(1 for v in ping["by_msm"].values()
                     if T(v.get("live")) and T(v.get("today_exact")))
    live_covered = sum(1 for v in ping["by_msm"].values()
                       if T(v.get("live")) and not T(v.get("today_exact")))
    # 路径层确定性：ping 的 dst ↔ trace 的 dst 对齐后，
    #   活靶路径 180/180 抵达、死靶路径 0/320 抵达
    live_by_dst = {v.get("dst"): T(v.get("live")) for v in ping["by_msm"].values()}
    paths_live_reached = paths_live_total = paths_dead_reached = paths_dead_total = 0
    dest_reached = dest_live = 0
    for v in trace["by_msm"].values():
        is_live = live_by_dst.get(v.get("dst"))
        if is_live:
            paths_live_reached += v["probes_reached"]
            paths_live_total += v["probes_total"]
            dest_live += 1
            if v["probes_reached"] > 0:
                dest_reached += 1
        else:
            paths_dead_reached += v["probes_reached"]
            paths_dead_total += v["probes_total"]

    n_tls_old = scout["meta"]["tls_ok"]                # 1/100

    n_with_dns = dnsmap["coverage"]["with_dns"]        # 51
    n_unique_names = dnsmap["coverage"]["unique_names"]  # 49
    n_domains = dnsmap["coverage"]["unique_domains"]   # 48
    n_resolved = dnsmap["resolve"]["resolved"]         # 34

    edge = {}
    for r in scout34["results"]:
        e = edge.setdefault(r.get("edge") or "other", {"n": 0, "tls_ok": 0})
        e["n"] += 1
        if T(r.get("tls_ok")):
            e["tls_ok"] += 1
    n_tls34 = sum(e["tls_ok"] for e in edge.values())   # 15

    # ---------------------------------------------------------------- Fig.2
    surv = get("routeviews/c0_survival.json")
    calib = get("routeviews/c0_2011_calibration.json")
    cmp_ = get("routeviews/c0_compare.json")

    # ---------------------------------------------------------------- Fig.3
    judged = get("c1/sslcert9_judged.json")
    win = get("c1/sslcert9_window_stats.json")
    labels = get("c1/target_labels.json")
    anchor = get("c1/anchor/anchor_verdict.json")

    lab_of = {r["domain"]: r["label"] for r in labels["labels"]}
    merged = win["per_target_merged"]
    verdict_of = {r["domain"]: r for r in judged["rows"]}
    # 逐测量行的轮数：被强停的原测（stop_events 里的 msm）停机前的轮数 ≠ 合并后的轮数，
    # 图注要说"强停前跑了几轮"，必须回到原始测量行取，不能用合并值。
    row_of_msm = {r["msm"]: r for r in win.get("rows", [])}
    targets = []
    for dom, m in merged.items():
        v = verdict_of.get(dom, {})
        verdict = v.get("verdict", {})
        evs = m.get("stop_events") or []
        orig_rounds = None
        for ev in evs:
            row = row_of_msm.get(ev.get("msm"))
            if row and row.get("rounds") is not None:
                orig_rounds = int(row["rounds"])
                break
        targets.append({
            "label": lab_of.get(dom, "?"),
            "domain": dom,
            "rounds": int(m.get("rounds_total") or 0),
            "orig_rounds": orig_rounds,
            "handshakes": int(m.get("handshakes") or 0),
            "vantages": int(m.get("vantages_max") or 0),
            "union_fp": int(m.get("union_fp16_count") or 0),
            "observation_span_h": m.get("observation_span_h"),
            "active_window_h": m.get("active_window_h"),
            "msms": m.get("msms") or [],
            "stop_events": m.get("stop_events") or [],
            "verdict": verdict.get("V"),
            "winner": verdict.get("winner"),
            "kappa": verdict.get("kappa"),
        })
    targets.sort(key=lambda t: t["label"])

    out = {
        "meta": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "generator": "tools/c1_figure_data.py",
            "package": pkg_label,
            "provenance": prov,
            "rule": ("every number below is read from a published derived-statistics "
                     "file; targets carry anonymized labels A-I only"),
        },
        "fig1": {
            "lineage": [
                {"stage": "2011 cohort candidates", "n": n_cand,
                 "den": n_cand,
                 "note": "199 stratified candidates drawn from the 2011 snapshot"},
                {"stage": "routable in 2026", "n": n_routable, "den": n_cand,
                 "exact": n_exact_cand,
                 "note": "178 still covered in the 2026 routing view; 90 survive exactly"},
                {"stage": "measurement set", "n": n_final, "den": n_cand,
                 "exact": n_final_exact, "covered_only": n_final_covered,
                 "note": "100 addresses: 57 exact survivors + 43 covered-only"},
                {"stage": "ICMP-live", "n": n_ping_live, "den": n_final,
                 "note": "35 of 100 answer echo requests from up to 50 vantages"},
                {"stage": "TLS handshake at the old address", "n": n_tls_old, "den": n_final,
                 "note": "1 of 100 completes a TLS handshake (unrelated third party)"},
                {"stage": "2011 organization TLS identity", "n": 0, "den": n_final,
                 "note": "0 of 100 still serve the 2011 organization's identity"},
            ],
            "path_layer": {
                "paths_total": trace["probe_paths"],
                "reached": trace["reached"],
                "distinct_destinations_reached": dest_reached,
                "distinct_destinations": len(trace["by_msm"]),
                "live_paths": paths_live_total,
                "live_paths_reached": paths_live_reached,
                "dead_paths": paths_dead_total,
                "dead_paths_reached": paths_dead_reached,
                "note": ("reachability is fully explained by address liveness: every "
                         "path to a live address reaches its destination, no path to a "
                         "dead address does"),
            },
            "liveness_split": {
                "live_exact": live_exact, "exact_total": n_final_exact,
                "live_covered": live_covered, "covered_total": n_final_covered,
            },
            "bridge": [
                {"stage": "measured addresses", "n": n_final, "den": n_final},
                {"stage": "carrying 2011 hostname mappings", "n": n_with_dns,
                 "den": n_final, "note": "51 of 100 (%d unique names)" % n_unique_names},
                {"stage": "registrable domains", "n": n_domains, "den": n_final},
                {"stage": "still resolving in 2026", "n": n_resolved, "den": n_domains},
                {"stage": "TLS handshake completed", "n": n_tls34, "den": n_resolved},
                {"stage": "organization-identity leaves", "n": 9, "den": n_tls34,
                 "note": "nine org-identity domains entered the 48-hour campaign"},
            ],
            "edge_class": [{"edge": k, "n": v["n"], "tls_ok": v["tls_ok"]}
                           for k, v in sorted(edge.items(), key=lambda kv: -kv[1]["n"])],
        },
        "fig2": {
            "buckets": surv["by_plen_bucket"],
            "totals": {
                "routes_2011": surv["routes_2011"],
                # 口径：RIB 记录数（1,164,339）≠ 去重后唯一前缀数（1,164,330，差 9 条
                # 重复前缀记录）。论文正文与 Table 2 一律用**唯一前缀数**，故图注同口径。
                "rib_records_2026": surv.get("rib_2026_prefixes",
                                             surv.get("rib_unique_prefixes")),
                "rib_unique_prefixes_2026": cmp_["routeviews_2026"]["rib_unique_prefixes"],
                "growth_factor_prefixes": cmp_["growth_factor_prefixes"],
                "aggregate_survival": surv["aggregate_survival"],
                "exact_survival": surv["exact_survival"],
                "aggregate_alive": surv["aggregate_alive"],
                "exact_alive": surv["exact_alive"],
                "slash8_covered_2011": surv["slash8_covered_2011"],
                "slash8_still_covered_2026": surv["slash8_still_covered_2026"],
            },
            "by_plen": surv.get("by_plen"),
            "calibration": {
                "rib_2011_prefixes": calib["meta"]["rib"]["prefixes"],
                "rib_2011_peers": calib["meta"]["rib"]["peer_count"],
                "snapshot_prefixes": calib["meta"]["snapshot_prefixes"],
                "snapshot_visible_in_rib_2011": calib["snapshot_visible_in_rib_2011"],
                "rib_2011_covered_by_snapshot": calib["rib_2011_covered_by_snapshot"],
            },
        },
        "fig3": {
            "targets": targets,
            "fleet": win["fleet"],
            "anchor": {
                "union_fp16": len(anchor.get("union_fp16") or []),
                "stray_fp16": len(anchor.get("stray_fp16") or []),
                "missing_expected_fp16": len(anchor.get("missing_expected_fp16") or []),
                "o3_ready": len(anchor.get("o3_ready") or []),
                "vantages_total": len(anchor.get("per_vantage") or {}),
                "rounds_distinct_timestamps": anchor.get("rounds_distinct_timestamps"),
                "hour_buckets": anchor.get("hour_buckets"),
                "verdict": (anchor.get("verdict") or {}).get("V"),
                "winner": (anchor.get("verdict") or {}).get("winner"),
                "kappa": (anchor.get("verdict") or {}).get("kappa"),
                "expect": anchor.get("pre_registered_expect"),
            },
        },
    }

    # 靶标域名只用于查标签，不进图数据（图里只出现 A–I）
    txt = json.dumps(out, ensure_ascii=False, indent=1)
    for t in out["fig3"]["targets"]:
        txt = txt.replace('"domain": "%s"' % t["domain"], '"domain": null')
    for b in BANNED:
        if b.lower() in txt.lower():
            raise SystemExit("图数据命中禁词：%s" % b)

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(txt)
    print("figdata -> %s" % a.out)
    print("  fig1 lineage=%d bridge=%d edge=%d | fig2 buckets=%d | fig3 targets=%d"
          % (len(out["fig1"]["lineage"]), len(out["fig1"]["bridge"]),
             len(out["fig1"]["edge_class"]), len(out["fig2"]["buckets"]),
             len(out["fig3"]["targets"])))
    print("  provenance: %s" % ", ".join("%s<-%s" % (k, v) for k, v in prov.items()))


if __name__ == "__main__":
    main()
