#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# REFERENCE-ONLY — not executable in this release: requires the
# non-redistributable 2011 routing archive (SOURCES.md §1) and/or the
# author-internal workspace (paths renamed to "workspace" here).
# Shipped for method transparency.
"""c0_survival.py —— C0 全量前缀存活分析（2026-11-08）。
2011 ireg routes 全量 713,853 条 vs 今日 RouteViews RIB 1,164,339 条：
  聚合存活 = 2011 前缀网络地址今日被任一 RIB 前缀覆盖（可被更粗聚合罩住）；
  精确存活 = 2011 (start,plen) 原样存在于今日 RIB。
口径注意：2011 routes 来源是 商业测绘平台 vantage（含其自身发现的更具体由），
  今日 RIB 是 DFZ 收集点（默认过滤 >/24）——精确存活在长前缀上会低估，
  两侧口径差异（来源/过滤策略）作为 threats-to-validity 记录。
产出：data/routeviews/c0_survival.json（含按 plen 桶与按 /8 的分层存活率）。
用法：python c0_survival.py
"""
import bisect
import json
import os
from collections import Counter, defaultdict

import duckdb

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
IREG = os.path.join(BASE, "workspace", "build", "ireg.duckdb")
RIB = os.path.join(BASE, "data", "routeviews", "rib_prefixes.txt")
OUT = os.path.join(BASE, "data", "routeviews", "c0_survival.json")


def main():
    starts, ends = [], []
    exact = set()
    with open(RIB, encoding="utf-8") as f:
        for line in f:
            s, p = map(int, line.split())
            e = s + ((1 << (32 - p)) - 1 if p else (1 << 32) - 1)
            starts.append(s)
            ends.append(e)
            exact.add((s, p))
    # RIB 同址多条更细前缀：按 start 排序后同 start 取最长 end
    order = sorted(range(len(starts)), key=lambda i: (starts[i], -ends[i]))
    starts = [starts[i] for i in order]
    ends = [ends[i] for i in order]

    def covered(x):
        i = bisect.bisect_right(starts, x) - 1
        return i >= 0 and x <= ends[i]

    con = duckdb.connect(IREG, read_only=True)
    rows = con.execute("SELECT range_start, prefix_len FROM routes").fetchall()
    con.close()
    agg = 0
    ex = 0
    by_bucket = defaultdict(Counter)
    by_plen = defaultdict(Counter)
    by8_agg = Counter()
    by8_total = Counter()
    for s, p in rows:
        c = covered(s)
        e = (s, p) in exact
        agg += c
        ex += e
        b = "<=16" if p <= 16 else ("17-20" if p <= 20 else ("21-23" if p <= 23 else ("24" if p == 24 else ">24")))
        by_bucket[b]["agg"] += c
        by_bucket[b]["exact"] += e
        by_bucket[b]["n"] += 1
        # 逐前缀长度（稿件 Fig.2 的存活曲线用；桶级口径见 by_plen_bucket）
        by_plen[p]["agg"] += c
        by_plen[p]["exact"] += e
        by_plen[p]["n"] += 1
        o8 = s >> 24
        by8_agg[o8] += c
        by8_total[o8] += 1
    out = {
        "routes_2011": len(rows),
        "rib_2026_prefixes": len(starts),
        "aggregate_survival": agg / len(rows),
        "exact_survival": ex / len(rows),
        "aggregate_alive": agg, "exact_alive": ex,
        "by_plen_bucket": {b: {**d, "agg_rate": d["agg"] / d["n"], "exact_rate": d["exact"] / d["n"]}
                           for b, d in sorted(by_bucket.items())},
        # 逐前缀长度：派生统计（只含计数与比率，不含任何前缀本体）
        "by_plen": {str(p): {**d, "agg_rate": d["agg"] / d["n"], "exact_rate": d["exact"] / d["n"]}
                    for p, d in sorted(by_plen.items())},
        "slash8_covered_2011": len(by8_total),
        "slash8_still_covered_2026": sum(1 for o8 in by8_total if by8_agg[o8] > 0),
        "caliber": ("2011=commercial-mapping-vantage routes; 2026=RouteViews route-views2 DFZ collector; "
                    "source/filter-policy difference recorded as threats-to-validity"),
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print("2011 routes=%d | agg alive=%d (%.1f%%) | exact alive=%d (%.1f%%)" % (
        len(rows), agg, 100 * agg / len(rows), ex, 100 * ex / len(rows)))
    for b, d in sorted(out["by_plen_bucket"].items()):
        print("  plen %-5s n=%7d agg=%5.1f%% exact=%5.1f%%" % (b, d["n"], 100 * d["agg_rate"], 100 * d["exact_rate"]))
    print("/8: 2011 covered=%d, still covered today=%d" % (
        out["slash8_covered_2011"], out["slash8_still_covered_2026"]))
    print("->", OUT)


if __name__ == "__main__":
    main()