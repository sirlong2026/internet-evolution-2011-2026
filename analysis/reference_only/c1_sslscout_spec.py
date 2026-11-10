#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# REFERENCE-ONLY — not executable in this release: requires the
# non-redistributable 2011 routing archive (SOURCES.md §1) and/or the
# author-internal workspace (paths renamed to "workspace" here).
# Shipped for method transparency.
"""c1_sslscout_spec.py —— 组织域名换靶侦察 spec（sslscout34，2026-11-08）。

背景：2011 代表地址 0/100 全球 TLS 存活（98 connect 拒连=服务灭绝）→ sslcert 组换靶：
组织域名框架（2011 dnsmap 域名 → 今日解析 → 今日 TLS）。dnsmap 可行性查出 34 个
今日仍解析的 2011 组织域名（data/c1/dnsmap_feasibility.json resolve.resolved_map）。
本侦察：34 域名 × 1 视角 one-off sslcert（target=域名，探针自带解析与 SNI）
= 34 × 20（one-off 单价 2×10）= 680 credits，回答"34 个里多少 TLS 存活"，
TLS 存活者进 sslcert10 组的 9 研究靶池。
输出：data/c1/sslscout34_spec.json → c1_campaign.py --dry-run/--create
"""
import json
import os

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
C1 = os.path.join(BASE, "data", "c1")


def main():
    with open(os.path.join(C1, "dnsmap_feasibility.json"), encoding="utf-8") as f:
        feas = json.load(f)
    # IP 靶：Atlas API 侧对域名靶做预解析校验（"This target cannot be resolved"，400 code 102，
    # resolve_on_probe=True 也不豁免）→ 用 DoH 已解析的首个 A 记录。
    # 代价：CDN 靶（Cloudflare 等）无 SNI 时握到边缘默认证书——活性判定不受影响，
    # 深测组（sslcert10）对入选靶再用域名靶或按解析 IP 挂 SNI 处理。
    res = feas["resolve"]["resolved_map"]
    domains = sorted(res)
    targets = [res[d][0] for d in domains]
    assert targets, "无解析存活域名"
    spec = {
        "campaign": "c1-sslscout34-20261108",
        "note": ("org-domain pivot scout: 2011 dnsmap domains that still resolve today (DoH "
                 "alidns 2026-11-08); target = first resolved A record (API rejects unresolvable "
                 "hostname targets, 400 code 102; SNI lost on CDN edges, liveness unaffected); "
                 "one-off sslcert 1 probe = liveness only, depth comes later in sslcert10; "
                 "all measurements public; never Delete"),
        "domains": domains,  # IP 与域名的对齐表（targets[i] 对应 domains[i]）
        "groups": [
            {"name": "sslscout34", "type": "sslcert", "port": 443, "is_oneoff": True,
             "unit_cost": 20,
             "probes": {"type": "area", "value": "WW", "requested": 1},
             "targets": targets},
        ],
    }
    out = os.path.join(C1, "sslscout34_spec.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(spec, f, ensure_ascii=False, indent=1)
    print("sslscout34 domains=%d unit=20cr/target -> %d credits spec -> %s" % (
        len(domains), len(domains) * 20, out))


if __name__ == "__main__":
    main()
