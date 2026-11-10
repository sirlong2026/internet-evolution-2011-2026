#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# REFERENCE-ONLY — not executable in this release: requires the
# non-redistributable 2011 routing archive (SOURCES.md §1) and/or the
# author-internal workspace (paths renamed to "workspace" here).
# Shipped for method transparency.
"""c0_2011_calibration.py —— 2011 快照 × 同期公开 RIB 三角互证（2026-11-08）。

目的：把 §3.2/§3.5 声明的"快照保留 DFZ 过滤的 more-specifics、口径差异记为
threats-to-validity"从**假设变成实测**——2011-07-02 当天 RouteViews
route-views2 RIB（公开档案）对 713,853 条快照前缀的可见率。

口径（前缀级，IPv4 unicast）：
  - **exact**：快照前缀 (net,plen) 在 2011 RIB 中以同一 (net,plen) 宣告；
  - **covered**：存在 RIB 前缀 p'⊇p（plen'≤plen、net 按 plen' 对齐）覆盖其全部空间；
  - **反向完整性**：2011 RIB 前缀被快照 exact/covered 的比例（快照对当年 DFZ 的覆盖完备性）；
  - 分桶 ≤16 / 17-20 / 21-23 / 24 / >24（与 c0_survival 同桶，便于并读）。
匹配网络地址统一 mask 归一（容忍快照内宿位残留）。
输入：data/routeviews/rib.20110702.0600.bz2（先 routeviews_rib.py --dump-prefixes）
  ＋ workspace/build/ireg.duckdb routes（只读，冻结资产零写入）。
输出：data/routeviews/c0_2011_calibration.json ＋ 控制台表。
红线：快照原始前缀行不随论文/repo 发布——本 JSON 只含派生统计（计数↔比率可互算）。
用法：python c0_2011_calibration.py <rib_2011_stats.json> <rib_2011_prefixes_dump.txt>
"""
import json
import os
import sys
from collections import Counter

import duckdb

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
IREG = os.path.join(BASE, "workspace", "build", "ireg.duckdb")
OUT = os.path.join(BASE, "data", "routeviews", "c0_2011_calibration.json")
BUCKETS = [("<=16", lambda p: p <= 16), ("17-20", lambda p: 17 <= p <= 20),
           ("21-23", lambda p: 21 <= p <= 23), ("24", lambda p: p == 24),
           (">24", lambda p: p > 24)]


def mask(plen):
    return ((1 << plen) - 1) << (32 - plen) if plen else 0


def bucket_of(plen):
    for name, pred in BUCKETS:
        if pred(plen):
            return name
    return "?"


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    stats_path, dump_path = sys.argv[1], sys.argv[2]
    with open(stats_path, encoding="utf-8") as f:
        st = json.load(f)
    assert st["truncated"] is False, "2011 RIB 解析截断——正式互证必须完整"
    rib_by_plen = {}   # plen -> set(net)
    rib_list = []      # (net, plen) 反向用（排除默认路由 /0）
    with open(dump_path, encoding="utf-8") as f:
        for ln in f:
            s, p = ln.split()
            net, plen = int(s), int(p)
            rib_by_plen.setdefault(plen, set()).add(net)
            if plen > 0:
                rib_list.append((net, plen))
    rib_n = len(rib_list)
    print("2011 RIB: peers=%d view=%s prefixes=%d entries=%d /8covered=%d" % (
        st["peer_count"], st["view_name"], st["rib_ipv4"]["prefixes"],
        st["rib_ipv4"]["entries"], st["ipv4_slash8_covered"]))

    # 快照前缀（只读连接，统一 mask 归一）
    con = duckdb.connect(IREG, read_only=True)
    try:
        rows = con.execute("SELECT range_start, prefix_len FROM routes").fetchall()
    finally:
        con.close()
    assert len(rows) == 713853, "快照行数异常：%d" % len(rows)
    snap_by_plen = {}   # plen -> set(net)
    snap_norm = []
    for start, plen in rows:
        net = start & mask(plen)
        snap_by_plen.setdefault(plen, set()).add(net)
        snap_norm.append((net, plen))
    print("snapshot: %d prefixes" % len(snap_norm))

    # 正向：快照 → 2011 RIB 可见性
    vis = {b[0]: {"n": 0, "exact": 0, "covered": 0} for b in BUCKETS}
    tot = {"n": 0, "exact": 0, "covered": 0}
    covering_plen_hist = Counter()  # 被覆盖时"最长覆盖者"的 plen
    for net, plen in snap_norm:
        b = vis[bucket_of(plen)]
        b["n"] += 1
        tot["n"] += 1
        if plen in rib_by_plen and net in rib_by_plen[plen]:
            b["exact"] += 1
            tot["exact"] += 1
        cov_plen = None
        for p2 in range(plen, 7, -1):
            s2 = rib_by_plen.get(p2)
            if s2 and (net & mask(p2)) in s2:
                cov_plen = p2
                break
        if cov_plen is not None:
            b["covered"] += 1
            tot["covered"] += 1
            covering_plen_hist[cov_plen] += 1

    # 反向：2011 RIB → 快照（快照对 DFZ 的覆盖完备性）
    rev = {"n": rib_n, "exact": 0, "covered": 0}
    for net, plen in rib_list:
        if plen in snap_by_plen and net in snap_by_plen[plen]:
            rev["exact"] += 1
        hit = False
        for p2 in range(plen, 7, -1):
            s2 = snap_by_plen.get(p2)
            if s2 and (net & mask(p2)) in s2:
                hit = True
                break
        if hit:
            rev["covered"] += 1

    for b in list(vis.values()) + [tot, rev]:
        b["exact_rate"] = round(b["exact"] / max(1, b["n"]), 6)
        b["covered_rate"] = round(b["covered"] / max(1, b["n"]), 6)

    out = {
        "meta": {
            "date": "2026-11-08",
            "purpose": "calibrate the 2011 snapshot against the same-day public DFZ view "
                       "(derived statistics only; snapshot rows are not redistributable)",
            "rib": {"source_file": st["source_file"], "view_name": st["view_name"],
                    "peer_count": st["peer_count"], "prefixes": st["rib_ipv4"]["prefixes"],
                    "entries": st["rib_ipv4"]["entries"], "truncated": st["truncated"]},
            "snapshot_prefixes": len(snap_norm),
            "snapshot_source": "ireg.duckdb routes (2011-07 snapshot; same as c0_compare)",
        },
        "snapshot_visible_in_rib_2011": {"by_bucket": vis, "total": tot},
        "rib_2011_covered_by_snapshot": rev,
        "covering_plen_hist": dict(sorted(covering_plen_hist.items())),
        "slash8_covered_2011_rib": st["ipv4_slash8_covered"],
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)

    print("\n== 快照前缀在 2011 RIB 的可见率 ==")
    print("%-8s %9s %8s %8s %10s %10s" % ("bucket", "n", "exact", "covered", "exact%", "covered%"))
    for name, _ in BUCKETS:
        b = vis[name]
        print("%-8s %9d %8d %8d %9.1f%% %9.1f%%" % (
            name, b["n"], b["exact"], b["covered"], 100 * b["exact_rate"], 100 * b["covered_rate"]))
    print("%-8s %9d %8d %8d %9.1f%% %9.1f%%" % (
        "TOTAL", tot["n"], tot["exact"], tot["covered"], 100 * tot["exact_rate"], 100 * tot["covered_rate"]))
    print("\n== 反向：2011 RIB %d 条被快照 exact %d (%.1f%%) / covered %d (%.1f%%) ==" % (
        rev["n"], rev["exact"], 100 * rev["exact_rate"], rev["covered"], 100 * rev["covered_rate"]))
    print("\n->", OUT)


if __name__ == "__main__":
    main()
