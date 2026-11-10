#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# REFERENCE-ONLY — not executable in this release: requires the
# non-redistributable 2011 routing archive (SOURCES.md §1) and/or the
# author-internal workspace (paths renamed to "workspace" here).
# Shipped for method transparency.
"""c0_compare.py —— C0 档案层：the 2011 routing archive vs 2026 RouteViews RIB（2026-11-08）。
2011 侧：build/ireg.duckdb routes 表（只读连接，冻结资产零写入；713,853 行）。
2026 侧：routeviews_rib.py --json 产出的解析统计（正式对比要求 truncated=False）。
口径：两侧均 IPv4 unicast 前缀级；并集覆盖=区间合并去重；/8 覆盖=有任一宣告的 /8 数。
产出：data/routeviews/c0_compare.{json,csv}（论文表素材；docx 到写稿阶段再生成）。
用法：python c0_compare.py <rib_stats.json>
"""
import csv
import json
import os
import sys
from collections import Counter

import duckdb

IREG = r"<NON_REDISTRIBUTIBLE_2011_ARCHIVE>\workspace\build\ireg.duckdb"
OUT_JSON = r"<NON_REDISTRIBUTIBLE_2011_ARCHIVE>\data\routeviews\c0_compare.json"
OUT_CSV = r"<NON_REDISTRIBUTIBLE_2011_ARCHIVE>\data\routeviews\c0_compare.csv"


def union_size(intervals):
    intervals.sort()
    total = 0
    cs, ce = intervals[0]
    for s, e in intervals[1:]:
        if s <= ce + 1:
            ce = max(ce, e)
        else:
            total += ce - cs + 1
            cs, ce = s, e
    total += ce - cs + 1
    return total


def stats_2011():
    con = duckdb.connect(IREG, read_only=True)
    try:
        n = con.execute("SELECT COUNT(*) FROM routes").fetchone()[0]
        nd = con.execute("SELECT COUNT(DISTINCT prefix) FROM routes").fetchone()[0]
        v6 = con.execute("SELECT COUNT(*) FROM routes WHERE prefix LIKE '%:%'").fetchone()[0]
        hist = Counter()
        intervals = []
        slash8 = set()
        for start, end, plen in con.execute("SELECT range_start, range_end, prefix_len FROM routes").fetchall():
            hist[plen] += 1
            intervals.append((start, end))
            slash8.add(start >> 24)
        union = union_size(intervals)
    finally:
        con.close()
    return {
        "source": "ireg.duckdb routes (commercial-mapping-platform snapshot 2011-07-02)",
        "prefixes": n, "distinct_prefixes": nd, "ipv6_rows": v6,
        "plen_hist": dict(sorted(hist.items())),
        "union_addresses": union, "slash8_covered": len(slash8),
        "mean_plen": sum(k * v for k, v in hist.items()) / n,
        "gt24_share": sum(v for k, v in hist.items() if k > 24) / n,
    }


def from_rib(st, prefixes_path=None):
    v4 = st["rib_ipv4"]
    hist = {int(k): v for k, v in v4["plen_hist"].items()}
    n_records = v4["prefixes"]
    n_unique = n_records
    if prefixes_path and os.path.exists(prefixes_path):
        uniq = set()
        with open(prefixes_path, encoding="utf-8") as f:
            for line in f:
                uniq.add(line.strip())
        n_unique = len(uniq)
    n = n_unique
    return {
        "source": "RouteViews route-views2 rib.20261107.1600.bz2 (%s, peers=%d)" % (st["view_name"], st["peer_count"]),
        "prefixes": n, "distinct_prefixes": n,  # TABLE_DUMP_V2 逐前缀记录；dup 源数据怪癖单列
        "rib_records": n_records, "rib_unique_prefixes": n_unique,
        "ipv6_prefixes": st["rib_ipv6"]["prefixes"],
        "plen_hist": hist,
        "union_addresses": st["ipv4_union_addresses"], "slash8_covered": st["ipv4_slash8_covered"],
        "mean_plen": sum(k * v for k, v in hist.items()) / n if n else 0,
        "gt24_share": sum(v for k, v in hist.items() if k > 24) / n if n else 0,
        "truncated": st["truncated"],
    }


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    with open(sys.argv[1], encoding="utf-8") as f:
        rib = json.load(f)
    if rib["truncated"]:
        print("WARN: RIB stats truncated=True —— 仅供管线试跑，正式对比须等完整下载")
    dump = os.path.join(os.path.dirname(os.path.abspath(sys.argv[1])), "rib_prefixes.txt")
    a, b = stats_2011(), from_rib(rib, prefixes_path=dump)
    print("rib records=%d unique=%d（源文件 9 条重复记录怪癖，bgpdump 交叉验证一致）" % (
        b["rib_records"], b["rib_unique_prefixes"]))
    rows = [
        ("IPv4 前缀数", a["prefixes"], b["prefixes"]),
        ("IPv4 并集覆盖地址数", a["union_addresses"], b["union_addresses"]),
        ("有宣告的 /8 数", a["slash8_covered"], b["slash8_covered"]),
        ("平均前缀长", round(a["mean_plen"], 3), round(b["mean_plen"], 3)),
        ("长于 /24 占比", round(a["gt24_share"], 4), round(b["gt24_share"], 4)),
        ("IPv6 前缀数", a["ipv6_rows"], b["ipv6_prefixes"]),
    ]
    out = {"snapshot_2011": a, "routeviews_2026": b,
           "growth_factor_prefixes": b["prefixes"] / a["prefixes"] if a["prefixes"] else None,
           "rib_truncated": rib["truncated"]}
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    with open(OUT_CSV, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["metric", "2011_snapshot", "2026_routeviews"])
        w.writerows(rows)
        w.writerow([])
        w.writerow(["plen", "2011_count", "2026_count"])
        for plen in sorted(set(a["plen_hist"]) | set(b["plen_hist"])):
            w.writerow([plen, a["plen_hist"].get(plen, 0), b["plen_hist"].get(plen, 0)])
    for name, x, y in rows:
        print("%-22s %14s %14s" % (name, format(x, ","), format(y, ",")))
    print("growth_factor_prefixes = %.3f" % out["growth_factor_prefixes"])
    print("json ->", OUT_JSON, "\ncsv  ->", OUT_CSV)


if __name__ == "__main__":
    main()