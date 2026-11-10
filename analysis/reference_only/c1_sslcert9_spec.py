#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# REFERENCE-ONLY — not executable in this release: requires the
# non-redistributable 2011 routing archive (SOURCES.md §1) and/or the
# author-internal workspace (paths renamed to "workspace" here).
# Shipped for method transparency.
"""c1_sslcert9_spec.py —— sslcert 研究组 spec（组织域名框架，9 靶 recurring，2026-11-08）。

选靶（sslscout34_summary.json 的 15 个 TLS-live 中，按"组织身份证书＋直连边缘"挑 9）：
  asp.bg（2004 化石证书·旗舰标本）、ctm.net（澳门电信）、iprimus.com.au（Vocus 并购痕迹）、
  jump.ro、plusline.de、tikona.in、tpgi.com.au（TPG 并购痕迹）、vnet.sk、zorgring.nl
替补：ixirhost.com（自有域证书）、farm.de/greennet.ge（托管身份）、tatanova.com（托管身份）。
排除：tele.dk（k8s 假证书）、wi-tribe.ph（CN=example.com 占位）。
靶型：**域名优先**（探针带 SNI——托管/CDN 案例才有正确 vhost 证书）；Atlas API 侧预解析
校验逐靶隔离（--chunk 1），解不了的域名退回其已解析 IP（sslscout34_spec.json 有映射）。
锚点不占本批：云锚（1,920cr）待用户打标 c2-host＋提供 C1_ANCHOR_TARGET 后单独发起。
预算：9 × 4 视角 × 48 轮 × 10cr（recurring 实价）= 17,280。
输出：data/c1/sslcert9_spec.json → c1_campaign.py --spec ... --create --chunk 1
"""
import json
import os

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
C1 = os.path.join(BASE, "data", "c1")

SEL = ["asp.bg", "ctm.net", "iprimus.com.au", "jump.ro", "plusline.de",
       "tikona.in", "tpgi.com.au", "vnet.sk", "zorgring.nl"]
ALTERNATES = ["ixirhost.com", "farm.de", "greennet.ge", "tatanova.com"]
EXCLUDED = {"tele.dk": "Kubernetes Ingress Fake Certificate（占位身份）",
            "wi-tribe.ph": "CN=example.com（占位身份）"}


def main():
    spec34 = json.load(open(os.path.join(C1, "sslscout34_spec.json"), encoding="utf-8"))
    dom2ip = dict(zip(spec34["domains"], spec34["groups"][0]["targets"]))
    summ = json.load(open(os.path.join(C1, "sslscout34_summary.json"), encoding="utf-8"))
    tls_ok = {d["domain"] for d in summ["results"] if d["tls_ok"]}
    missing = [d for d in SEL if d not in tls_ok]
    assert not missing, "选中的靶不在 TLS-live 名单: %s" % missing

    spec = {
        "campaign": "c1-sslcert9-orgdomain-20261108",
        "note": ("org-domain frame (user-approved 2026-11-08): 9 TLS-live 2011 org domains, "
                 "recurring sslcert 4 probes x 1h x 48h; domain targets preferred (SNI), "
                 "fallback to resolved IP on API pre-resolution reject (map in domain_ip_fallback); "
                 "anchor NOT in this batch (standalone later after probe tagging + C1_ANCHOR_TARGET); "
                 "all measurements public; never Delete"),
        "domain_ip_fallback": {d: dom2ip[d] for d in SEL},
        "selection": {"selected": SEL, "alternates": ALTERNATES, "excluded": EXCLUDED},
        "groups": [
            {"name": "sslcert9", "type": "sslcert", "port": 443, "is_oneoff": False,
             "interval": 3600, "duration_hours": 48, "unit_cost": 10,
             "probes": {"type": "area", "value": "WW", "requested": 4},
             "targets": SEL},
        ],
    }
    out = os.path.join(C1, "sslcert9_spec.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(spec, f, ensure_ascii=False, indent=1)
    n = len(SEL)
    print("sslcert9: %d 域名靶 × 4 视角 × 48 轮 × 10cr = %d credits spec -> %s" % (
        n, n * 4 * 48 * 10, out))


if __name__ == "__main__":
    main()
