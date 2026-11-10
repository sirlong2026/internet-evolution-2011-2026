#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# REFERENCE-ONLY — not executable in this release: requires the
# non-redistributable 2011 routing archive (SOURCES.md §1) and/or the
# author-internal workspace (paths renamed to "workspace" here).
# Shipped for method transparency.
"""c1_phase1_spec.py —— C1 phase1 spec：ping100 + trace50（30,000 credits，2026-11-08）。

背景：Atlas 侦察判定 2011 代表地址 0/100 全球 TLS 存活（路由存活 ≠ 服务存活）→
sslcert 组换靶框架待拍板；ping/traceroute 两组与 sslcert 框架无关（路由/路径层存活，
预注册于 AC线重启评估 §4.1 预算表），参数不变，先发。

分组（与评估预算表逐项一致）：
  ping one-off       100 靶 × 50 视角 = 5,000 结果 × 3  = 15,000 credits
  traceroute one-off  50 靶 × 10 视角 =   500 结果 × 30 = 15,000 credits（靶 ⊂ ping 100，同靶跨信号）
输出：data/c1/campaign_spec_phase1.json → c1_campaign.py --dry-run/--create
"""
import json
import os

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
C1 = os.path.join(BASE, "data", "c1")


def main():
    with open(os.path.join(C1, "candidates_today.json"), encoding="utf-8") as f:
        today = json.load(f)
    final = today["final"]
    assert len(final) >= 100, "终样不足 100"
    ping_targets = [c["rep_ip"] for c in final[:100]]
    trace_targets = ping_targets[:50]
    spec = {
        "campaign": "c1-evolution-202611-phase1",
        "note": ("phase1 = frame-independent groups only (ping/traceroute: routing/path-layer "
                 "survival of 2011 addresses); sslcert group held pending target-frame decision "
                 "after scout 0/100 TLS-live finding; targets from the 2011 frozen snapshot; "
                 "all measurements public; never Delete"),
        "groups": [
            {"name": "ping100", "type": "ping", "is_oneoff": True, "unit_cost": 3,
             "probes": {"type": "area", "value": "WW", "requested": 50},
             "targets": ping_targets},
            {"name": "trace50", "type": "traceroute", "protocol": "ICMP", "is_oneoff": True, "unit_cost": 30,
             "probes": {"type": "area", "value": "WW", "requested": 10},
             "targets": trace_targets},
        ],
    }
    out = os.path.join(C1, "campaign_spec_phase1.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(spec, f, ensure_ascii=False, indent=1)
    print("ping=%d trace=%d spec -> %s" % (len(ping_targets), len(trace_targets), out))


if __name__ == "__main__":
    main()
