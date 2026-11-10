#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# REFERENCE-ONLY — not executable in this release: requires the
# non-redistributable 2011 routing archive (SOURCES.md §1) and/or the
# author-internal workspace (paths renamed to "workspace" here).
# Shipped for method transparency.
"""c1_spec.py —— 生成 C1 战役 spec（评估文档 §4.1 预算表的落地，2026-11-08）。
输入：data/c1/candidates_today.json（阶段 B 终样 100）＋ data/c1/prescreen.json（云 TLS 预筛）。
分组（与评估预算表一致，总 49,200 credits）：
  ping one-off      100 靶 × 50 视角 = 5,000 结果 × 3  = 15,000
  traceroute one-off 50 靶 × 10 视角 = 500 结果 × 30 = 15,000（靶 ⊂ ping 100，同靶跨信号）
  sslcert recurring  10 靶 × 4 视角 × 1h × 48h = 1,920 × 10 = 19,200
    **10 靶 = 9 研究靶（预筛 TLS 成功，registry 均衡、每 AS ≤2）＋ 1 云锚（环境变量注入）**
    ——锚占一个名额而非追加，预算恰守 49,200；锚组排除本机探针标签（同机偏置登记）。
输出：data/c1/campaign_spec.json → c1_campaign.py --dry-run/--create。
用法：python c1_spec.py
"""
import json
import os
from collections import defaultdict

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
C1 = os.path.join(BASE, "data", "c1")
N_SSL_RESEARCH = 9


def main():
    with open(os.path.join(C1, "candidates_today.json"), encoding="utf-8") as f:
        today = json.load(f)
    with open(os.path.join(C1, "prescreen.json"), encoding="utf-8") as f:
        pre = json.load(f)
    final = today["final"]
    assert len(final) >= 100, "终样不足 100（阶段 B 候选损耗过大，须扩样）"
    ping_targets = [c["rep_ip"] for c in final[:100]]
    trace_targets = ping_targets[:50]

    ok = [r for r in pre["results"] if r["ok"]]
    by_reg = defaultdict(list)
    for r in ok:
        by_reg[r["registry"]].append(r)
    # registry 轮转均衡 + 每 AS ≤2（防单一 org 主导 sslcert 判卷）
    ssl_sel = []
    as_count = defaultdict(int)
    regs = sorted(by_reg, key=lambda r: -len(by_reg[r]))
    while len(ssl_sel) < N_SSL_RESEARCH and any(by_reg.values()):
        for reg in regs:
            if len(ssl_sel) >= N_SSL_RESEARCH:
                break
            while by_reg[reg]:
                r = by_reg[reg].pop(0)
                a = r["as_names"][0] if r["as_names"] else "?"
                if as_count[a] >= 2:
                    continue
                as_count[a] += 1
                ssl_sel.append(r)
                break
    if len(ssl_sel) < N_SSL_RESEARCH:
        raise RuntimeError("预筛 TLS 成功靶不足 %d（实际 %d）——须扩候选池重筛" % (N_SSL_RESEARCH, len(ssl_sel)))

    spec = {
        "campaign": "c1-evolution-202611",
        "note": ("targets from the 2011 frozen snapshot, stratified multihomed-enriched; "
                 "anchor target injected via env C1_ANCHOR_TARGET (zero infra-IP on disk); "
                 "all measurements public; never Delete; probe tag c2-host excluded "
                 "from sslcert group (same-machine bias, tag applied after probe registration)"),
        "groups": [
            {"name": "ping100", "type": "ping", "is_oneoff": True, "unit_cost": 3,
             "probes": {"type": "area", "value": "WW", "requested": 50},
             "targets": ping_targets},
            {"name": "trace50", "type": "traceroute", "protocol": "ICMP", "is_oneoff": True, "unit_cost": 30,
             "probes": {"type": "area", "value": "WW", "requested": 10},
             "targets": trace_targets},
            {"name": "sslcert10", "type": "sslcert", "port": 443, "is_oneoff": False,
             "interval": 3600, "duration_hours": 48, "unit_cost": 10,
             "probes": {"type": "area", "value": "WW", "requested": 4},
             "probe_tags_exclude": ["c2-host"],
             "anchor_from_env": "C1_ANCHOR_TARGET",
             "targets": [r["rep_ip"] for r in ssl_sel]},
        ],
    }
    out = os.path.join(C1, "campaign_spec.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(spec, f, ensure_ascii=False, indent=1)
    print("ping=%d trace=%d sslcert=%d(+1 anchor) spec -> %s" % (
        len(ping_targets), len(trace_targets), len(ssl_sel), out))
    print("sslcert research targets:", [(r["rep_ip"], r["registry"], r["subject"][:40]) for r in ssl_sel])


if __name__ == "__main__":
    main()