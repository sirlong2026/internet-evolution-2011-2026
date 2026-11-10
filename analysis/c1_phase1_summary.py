#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_phase1_summary.py —— phase1（ping100+trace50）结果汇总（2026-11-08）。

预注册问题：2011 代表地址的路由层存活（C0 已出 89.4% 覆盖/56% 精确）之后，
  - ping：地址级 ICMP 活性（received≥1 为活；按 registry/stratum/today_exact 分层）
  - traceroute：路径级（完成到达率、最大响应跳、死在哪一跳）
口径：one-off；Failed 测量（trace50 有 4 个排期失败）按缺失计，不进分母详情表但记录。
输出：data/c1/phase1_summary.json ＋ 控制台表。
"""
import json
import os
from collections import Counter, defaultdict

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
C1 = os.path.join(BASE, "data", "c1")
RAW = os.path.join(C1, "raw")


def load_final():
    with open(os.path.join(C1, "candidates_today.json"), encoding="utf-8") as f:
        return {c["rep_ip"]: c for c in json.load(f)["final"]}


def load_group(ids, group):
    recs = [r for r in ids["measurements"] if r["group"] == group]
    return {r["msm_id"]: r for r in recs}


def main():
    with open(os.path.join(C1, "campaign_msm_ids.json"), encoding="utf-8") as f:
        ids = json.load(f)
    final = load_final()
    out = {"meta": {"date": "2026-11-08", "note": "one-off ping/traceroute vs 2011 representative addresses"}}

    # ---- ping100 ----
    ping = {}
    liveness_counter = Counter()
    by_reg = defaultdict(lambda: [0, 0, 0.0, 0])  # live, total, sent_ratio_sum, n
    by_exact = defaultdict(lambda: [0, 0])
    failed_msm = []
    for msm, rec in load_group(ids, "ping100").items():
        path = os.path.join(RAW, "cam_%d.json" % msm)
        raw = json.load(open(path, encoding="utf-8")) if os.path.exists(path) else []
        tgt = rec.get("target") or (raw[0].get("dst_name") if raw else None)
        # target 从 msm id 对齐 candidates（ping spec targets 顺序 = final[:100]）
        # Atlas ping 字段：回包数是 rcvd（不是 received）；sent=3
        sent = sum(r.get("sent", 0) for r in raw)
        recv = sum(r.get("rcvd", 0) for r in raw)
        live = any(r.get("rcvd", 0) > 0 for r in raw)
        ping[msm] = {"n_results": len(raw), "sent": sent, "recv": recv,
                     "live": live, "resp_ratio": (recv / sent if sent else None)}
        liveness_counter["live" if live else "dead"] += 1
        liveness_counter["results"] += len(raw)

    # target 对齐：spec 顺序 = final 前 100（重读 spec 拿顺序）
    with open(os.path.join(C1, "campaign_spec_phase1.json"), encoding="utf-8") as f:
        spec = json.load(f)
    # target 对齐不用 spec 顺序：raw 里 dst_name 即实际靶 IP，直接对齐 candidates
    for msm, d in ping.items():
        raw = json.load(open(os.path.join(RAW, "cam_%d.json" % msm), encoding="utf-8"))
        dst = raw[0].get("dst_name") if raw else None
        c = final.get(dst)
        if not c:
            d["stratum"] = d["registry"] = None
            continue
        d["dst"] = dst
        d["registry"] = c["registry"]
        d["stratum"] = c.get("stratum")
        d["today_exact"] = c.get("today_exact")
        b = by_reg[c["registry"]]
        b[0] += 1 if d["live"] else 0
        b[1] += 1
        b[2] += d["resp_ratio"] or 0.0
        b[3] += 1
        e = by_exact["exact" if c.get("today_exact") else "covered"]
        e[0] += 1 if d["live"] else 0
        e[1] += 1

    n_live = liveness_counter["live"]
    n_tot = liveness_counter["live"] + liveness_counter["dead"]
    print("== ping100 ==")
    print("targets=%d live=%d (%.1f%%) results=%d" % (n_tot, n_live, 100 * n_live / max(1, n_tot),
                                                      liveness_counter["results"]))
    for reg, b in sorted(by_reg.items()):
        print("  %-8s live %2d/%2d (%.0f%%)  mean_resp_ratio=%.3f" % (
            reg, b[0], b[1], 100 * b[0] / max(1, b[1]), b[2] / max(1, b[3])))
    for k, e in sorted(by_exact.items()):
        print("  %-8s live %2d/%2d (%.0f%%)" % (k, e[0], e[1], 100 * e[0] / max(1, e[1])))
    out["ping"] = {"by_msm": ping, "n_live": n_live, "n_total": n_tot,
                   "by_registry": {k: {"live": v[0], "total": v[1], "mean_resp_ratio": v[2] / max(1, v[3])}
                                   for k, v in by_reg.items()},
                   "by_exact": {k: {"live": v[0], "total": v[1]} for k, v in by_exact.items()}}

    # ---- trace50 ----
    print("== trace50 ==")
    tr = {}
    hop_stats = Counter()
    die_hops = []
    reached = 0
    total = 0
    for msm, rec in load_group(ids, "trace50").items():
        path = os.path.join(RAW, "cam_%d.json" % msm)
        if not os.path.exists(path):
            tr[msm] = {"missing": True}
            continue
        raw = json.load(open(path, encoding="utf-8"))
        dst = raw[0].get("dst_name") if raw else None
        c = final.get(dst)
        probes_reached = 0
        probes_any = 0
        max_hops = []
        last_hop_list = []
        for res in raw:
            hops = res.get("result") or []
            probes_any += 1
            last_from = None
            last_hop = 0
            nhop = 0
            for h in hops:
                nhop = h.get("hop", nhop)
                for hr in (h.get("result") or []):
                    if hr.get("from"):
                        last_from = hr["from"]
                        last_hop = nhop
            if last_from:
                max_hops.append(nhop)
                last_hop_list.append(last_hop)
            # destination_ip_responded 是 Atlas 权威到达标志；缺省时退回 last_from==dst
            if res.get("destination_ip_responded") or (dst and last_from == dst):
                probes_reached += 1
        reached += probes_reached
        total += probes_any
        die_hops.extend(last_hop_list)
        tr[msm] = {"dst": dst, "n_results": len(raw), "probes_reached": probes_reached,
                   "probes_total": probes_any,
                   "registry": c["registry"] if c else None,
                   "today_exact": c.get("today_exact") if c else None}
        hop_stats["reached" if probes_reached else ("partial" if probes_any else "no_probes")] += 1
    print("targets_with_results=%d  probe_paths=%d  reached_dst=%d (%.1f%%)" % (
        sum(1 for v in tr.values() if v.get("n_results")), total, reached, 100 * reached / max(1, total)))
    if die_hops:
        dh = Counter(die_hops)
        print("last-responding hop distribution:", dict(sorted(dh.items())[:15]))
    out["trace"] = {"by_msm": tr, "probe_paths": total, "reached": reached,
                    "last_hop_dist": dict(Counter(die_hops))}

    with open(os.path.join(C1, "phase1_summary.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print("->", os.path.join(C1, "phase1_summary.json"))


if __name__ == "__main__":
    main()
