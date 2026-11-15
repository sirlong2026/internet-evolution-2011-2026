#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_round2_candidates_build.py —— 从第一轮 scout 结果派生 S1 筛查的候选名单（离线，零 Atlas 写入）。

背景（2026-11-11）：第二轮要 6 个**异质**靶，异质性只能测出来。候选池不需要"扩容"——
第一轮已 scout 34 个 2011 域名，其中 9 个进了 48 h 战役，**剩下正好 25 个**，
与 campaign_spec 里 `s1_screen.target_count_expect = "20-25"` 吻合。
本脚本把那 25 个连同先验标注写成 `targets_candidates.json`，供 S1 筛查读取。

为什么不再按"组织归属"筛一遍：实测过，`as_names` 只覆盖候选前缀的一小部分，
按"AS 名 token 出现在证书 subject"重判只多命中 1 个域名（且它已在战役里）。
硬凑名单会把"归属"变成猜测，所以本脚本**只做标注、不做取舍**：
把 2011 前缀与 AS 名、今日 SNI-less 侦察结果、边缘类型、先验身份类别逐条写清，
筛不筛由预注册 §4 的纳入/排除规则在 S1 之后决定。

新增的一个认识（影响候选资格）：第一轮 scouts 是**无 SNI**的，所以 `tls_less_ok=false`
**不等于靶已死**——很可能只是服务端要求 SNI（§4.5 的 alert 40/80）。
本轮 S1 用身份名条件重测，正是要给这批"无 SNI 拒握手"的靶一次公平机会。
因此本文件不因 `tls_less_ok=false` 剔除任何靶，只标注。

纪律：靶域名/IP 只进 data/；锚点地址不在本文件；写盘前过禁词闸。
用法：python tools/c1_round2_candidates_build.py [--dry-run]
"""
import argparse
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
C1 = os.path.join(ROOT, "data", "c1")
OUT = os.path.join(C1, "round2", "targets_candidates.json")

BANNED = [re.compile(p, re.I) for p in ("ip" "sonar", "lum" "eta", "umg" "dy")]
ANCHOR_IP = os.environ.get("C1_ANCHOR_TARGET", "").strip()

PLACEHOLDER_HINTS = ("kubernetes ingress", "example.com", "default backend")
HOSTING_HINTS = ("siteground", "plutex", "strategicts", "hosting", "tpmwebsite")


def load(p):
    with io.open(p, encoding="utf-8", newline="") as f:
        return json.load(f)


def registrable_label(domain):
    return domain.split(".")[0].lower()


def id_class(subject, domain):
    """先验身份类别（只看第一轮无 SNI 侦察到手的那张证书）。仅作标注，不作判决。"""
    if not subject:
        return "none"
    s = subject.lower()
    if any(h in s for h in PLACEHOLDER_HINTS):
        return "placeholder"
    if any(h in s for h in HOSTING_HINTS):
        return "hosting"
    lab = registrable_label(domain)
    if lab in s:
        return "org"
    return "unknown"


def build(dry=False):
    scout = load(os.path.join(C1, "sslscout34_summary.json"))["results"]
    used = set(load(os.path.join(C1, "sslcert9_spec.json"))["selection"]["selected"])

    # 2011 侧：域名 → 前缀 → AS 名（域名的 2011 归属证据）
    try:
        import duckdb
        import glob
        hits = [x for x in glob.glob(os.path.join(ROOT, "**", "ireg.duckdb"), recursive=True)]
        if not hits:
            raise RuntimeError("找不到 2011 档案库 ireg.duckdb")
        con = duckdb.connect(hits[0], read_only=True)
        doms = [r["domain"] for r in scout]
        rows = con.execute(
            "select dns, prefix from dnsmap where " + " or ".join(["dns ilike ?"] * len(doms)),
            ["%" + d for d in doms]).fetchall()
        con.close()
        pfx = {}
        for dns, prefix in rows:
            low = dns.lower()
            for d in doms:
                if low == d or low.endswith("." + d):
                    pfx.setdefault(d, set()).add(prefix)
    except Exception as ex:
        print("  [warn] 2011 dnsmap 不可用（%s）⇒ prefix 留空，不阻断" % ex, flush=True)
        pfx = {}

    cand = {}
    for f in ("candidates_2011.json", "candidates_today.json"):
        for c in load(os.path.join(C1, f))["candidates"]:
            cand.setdefault(c["prefix"], {"org": c.get("org"), "as_names": c.get("as_names") or []})

    pool = []
    for r in scout:
        d = r["domain"]
        if d in used:
            continue
        allp = sorted(pfx.get(d, []), key=lambda x: (-int(x.split("/")[1]), x))
        asn = sorted({n for p in allp for n in (cand.get(p, {}).get("as_names") or [])})
        prefixes = allp[:8]          # 只留最具体的 8 个，避免 /8 级噪声把文件撑到 100 KB+
        pool.append({
            "domain": d,
            "ip_at_scout_20261108": r.get("ip"),
            "needs_fresh_resolution": True,
            "edge_prior": r.get("edge"),
            "tls_less_ok_prior": bool(r.get("tls_ok")),
            "cert_variants_prior": r.get("cert_variants"),
            "subject_prior": r.get("subject"),
            "identity_class_prior": id_class(r.get("subject"), d),
            "n_prefixes_2011": len(allp),
            "prefixes_2011_top8": prefixes,
            "as_names_2011": asn,
            "_tls_less_false_means": ("SNI-less 握手失败：既可能是靶已下线，也可能是服务端要求 SNI"
                                      "（§4.5 的 40/80）；本轮用身份名重测后再判，不据此剔除"),
        })

    obj = {
        "at": "2026-11-11",
        "purpose": "S1 筛查候选池（供 campaign_spec.s1_screen 读取）",
        "derived_from": ["data/c1/sslscout34_summary.json", "data/c1/sslcert9_spec.json",
                         "data/c1/candidates_2011.json", "data/c1/candidates_today.json",
                         "local 2011 archive DB: ireg.duckdb, read_only, table dnsmap"],
        "pool_size": len(pool),
        "excluded": {"in_round1_campaign": sorted(used), "n": len(used)},
        "attribution_note": ("as_names 仅覆盖部分候选前缀；按'AS 名 token 出现在 subject'重判只多命中 1 个域名，"
                             "且它已在战役内 ⇒ 本名单**不做归属取舍**，只标注，筛不筛交给 prereg §4"),
        "targets": pool,
    }
    text = json.dumps(obj, ensure_ascii=False, indent=1)
    hits = [p.pattern for p in BANNED if p.search(text)]
    if ANCHOR_IP and ANCHOR_IP in text:
        hits.append("<anchor-ip-from-env>")
    if hits:
        raise SystemExit("[拒写] 候选名单命中禁词 %s" % hits)
    print("targets_candidates.json  %d 字符，禁词 0 命中（分母=%d）" % (len(text), len(text)))
    if not dry:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with io.open(OUT, "w", encoding="utf-8", newline="") as f:
            f.write(text)
    return pool


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    pool = build(a.dry_run)
    from collections import Counter
    print("候选 %d 个 | 先验身份 %s | 边缘 %s | 无 SNI 曾成功 %d/%d" % (
        len(pool),
        dict(Counter(p["identity_class_prior"] for p in pool)),
        dict(Counter(p["edge_prior"] for p in pool)),
        sum(1 for p in pool if p["tls_less_ok_prior"]), len(pool)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
