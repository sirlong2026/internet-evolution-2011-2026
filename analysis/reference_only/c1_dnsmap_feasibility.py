#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# REFERENCE-ONLY — not executable in this release: requires the
# non-redistributable 2011 routing archive (SOURCES.md §1) and/or the
# author-internal workspace (paths renamed to "workspace" here).
# Shipped for method transparency.
"""c1_dnsmap_feasibility.py —— sslcert 换靶框架（组织域名）零成本可行性检查（2026-11-08）。

背景：Atlas 侦察 100 靶（2011 代表地址）全球 0/100 TLS 存活——路由存活 ≠ 服务存活，
2011 地址上服务层已灭绝。sslcert 组换靶框架：**2011 dnsmap 域名 → 今日解析 → 今日 TLS**
（组织连续性框架：2011 在档 org 的今日公网服务，而非 2011 地址的今日服务）。
本脚本纯本地档案 + 公共 DoH，零 credits：
  1. 2011 dnsmap 在 100 终样前缀上的覆盖与构成（记录数/unique 名字/www 比例）
  2. 可注册域提取（末 2-3 标签，带常见二级后缀表）→ 公共 DoH 批量解析 A 记录 → 今日解析存活率
口径注意：解析走中国公共 DoH（alidns→doh.pub 回退），污染风险低但存在；
  解析存活 ≠ TLS 存活（443 是否开、证书身份归谁，由后续 Atlas sslcert 侦察定）。
输出：data/c1/dnsmap_feasibility.json ＋ 控制台统计。
"""
import bisect
import json
import os
import urllib.request
from collections import Counter

import duckdb

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
DB = os.path.join(BASE, "workspace", "build", "ireg.duckdb")
C1 = os.path.join(BASE, "data", "c1")
DOH_BASES = ["https://dns.alidns.com/resolve", "https://doh.pub/dns-query"]
RESOLVE_CAP = 600  # 解析上限（防失控；超出部分记录 skipped）

# 常见"二级可注册后缀"（ccTLD 下的 com/co/org/edu/gov/ac/net 等）
SLD_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.cn", "net.cn", "org.cn", "edu.cn", "gov.cn", "ac.cn",
    "com.tw", "org.tw", "edu.tw", "gov.tw", "net.tw",
    "co.kr", "or.kr", "ne.kr", "re.kr", "go.kr",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.sg", "com.my", "com.hk", "com.tr", "com.mx", "com.ar", "co.in",
    "co.nz", "org.nz", "net.nz", "co.za", "org.za", "com.pl", "com.ru",
}


def registrable(name):
    """从主机名提取可注册域（末 2-3 标签）；返回 None 表示无法提取（IP 字面量/空）。"""
    n = name.strip().lower().rstrip(".")
    if not n or n.replace(".", "").isdigit():  # 疑似 IPv4 字面量
        return None
    labels = n.split(".")
    if len(labels) < 2:
        return None
    if "." + ".".join(labels[-2:]) in {"." + s for s in SLD_SUFFIX} or \
            ".".join(labels[-2:]) in SLD_SUFFIX:
        return ".".join(labels[-3:]) if len(labels) >= 3 else None
    return ".".join(labels[-2:])


def doh_resolve(name, base):
    url = base + "?name=" + name + "&type=A"
    req = urllib.request.Request(url, headers={"accept": "application/dns-json",
                                               "user-agent": "c1-feasibility/1.0"})
    with urllib.request.urlopen(req, timeout=12) as r:
        d = json.loads(r.read().decode("utf-8"))
    return d


def main():
    with open(os.path.join(C1, "candidates_today.json"), encoding="utf-8") as f:
        today = json.load(f)
    final = today["final"]

    con = duckdb.connect(DB, read_only=True)
    rows = con.execute(
        "SELECT range_start, range_end, prefix, dns FROM dnsmap ORDER BY range_start"
    ).fetchall()
    starts = [r[0] for r in rows]
    ends = [r[1] for r in rows]
    print("dnsmap rows=%d" % len(rows))

    per_cand = []
    all_names = set()
    n_prefix_with_dns = 0
    for c in final:
        s, e = c["start"], c["start"] + (1 << (32 - c["plen"])) - 1
        i = bisect.bisect_right(starts, s) - 1
        if i < 0:
            i = 0
        names = []
        j = i
        while j < len(rows) and rows[j][0] <= e:
            if rows[j][1] >= s:
                names.append(rows[j][3])
            j += 1
        uniq = sorted(set(n for n in names if n))
        if uniq:
            n_prefix_with_dns += 1
        www = sum(1 for n in uniq if n.lower().startswith("www."))
        all_names.update(uniq)
        per_cand.append({
            "prefix": c["prefix"], "registry": c["registry"], "stratum": c.get("stratum"),
            "n_dns_records": len(names), "n_unique_names": len(uniq),
            "n_www": www, "sample_names": uniq[:12],
        })

    domains = sorted(set(x for x in (registrable(n) for n in all_names) if x))
    print("candidates=%d with_dns=%d (%.0f%%) unique_names=%d unique_domains=%d www_names=%d" % (
        len(final), n_prefix_with_dns, 100 * n_prefix_with_dns / len(final),
        len(all_names), len(domains),
        sum(1 for n in all_names if n.lower().startswith("www."))))

    # DoH 批量解析（A 记录）
    base = DOH_BASES[0]
    try:
        doh_resolve("example.com", base)
    except Exception:
        base = DOH_BASES[1]
        doh_resolve("example.com", base)
    resolved, nxd, dead, skipped = {}, 0, 0, 0
    errors = Counter()
    for d in domains[:RESOLVE_CAP]:
        try:
            j = doh_resolve(d, base)
            st = j.get("Status")
            ans = j.get("Answer") or []
            ips = [a.get("data") for a in ans if a.get("type") == 1]
            if st == 0 and ips:
                resolved[d] = ips
            elif st == 3:
                nxd += 1
            else:
                dead += 1
        except Exception as ex:
            errors[type(ex).__name__ + ":" + str(ex)[:60]] += 1
    skipped = max(0, len(domains) - RESOLVE_CAP)

    print("DoH base=%s resolve_cap=%d: resolved=%d nxdomain=%d other=%d skipped=%d errors=%s" % (
        base, min(len(domains), RESOLVE_CAP), len(resolved), nxd, dead, skipped,
        dict(errors) if errors else "{}"))
    print("resolve survival = %d/%d = %.1f%%" % (
        len(resolved), min(len(domains), RESOLVE_CAP) - (0 if not errors else sum(errors.values())),
        100 * len(resolved) / max(1, min(len(domains), RESOLVE_CAP) - sum(errors.values()))))

    out = {
        "meta": {
            "date": "2026-11-08", "doh_base": base,
            "caliber": ("dnsmap = 2011 archive names on candidate prefixes; resolve survival via "
                        "Chinese public DoH (pollution risk small, noted); resolve-alive != TLS-alive"),
            "dnsmap_rows": len(rows),
        },
        "coverage": {"candidates": len(final), "with_dns": n_prefix_with_dns,
                     "unique_names": len(all_names), "unique_domains": len(domains),
                     "www_names": sum(1 for n in all_names if n.lower().startswith("www."))},
        "resolve": {"cap": RESOLVE_CAP, "tested": min(len(domains), RESOLVE_CAP),
                    "resolved": len(resolved), "nxdomain": nxd, "other": dead,
                    "skipped": skipped, "errors": dict(errors),
                    "resolved_map": resolved},
        "per_candidate": per_cand,
    }
    outp = os.path.join(C1, "dnsmap_feasibility.json")
    with open(outp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print("->", outp)

    # 供换靶用的解析存活域样本（前 20）
    print("resolved sample:", sorted(resolved)[:20])


if __name__ == "__main__":
    main()
