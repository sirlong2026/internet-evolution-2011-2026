#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_round2_hetero_select.py —— 由 S1 筛查结果选异质靶（prereg §4 的纳入规则，逐条照做）。

纳入（异质）：**跨视角出现 ≥2 张叶子指纹**，或 **TTL 集合基数 > 1**。
排除（判决前固定）：placeholder 身份；对比名臂整片被拒（o₄ 结构性不可观测，见 §2 判读规则）。
不做取舍的：CDN 边缘（本轮用身份名重测，SNI 缺失论据已不适用，只标注）。

选取：在达标靶里按（指纹数降序 → TTL 种数降序 → 成功视角数降序 → 域名字典序）取前 N（默认 6）。

输出：data/c1/round2/hetero_selection.json（逐靶表 ＋ 选中列表 ＋ 依据）
并用真实异质靶数算剩余 campaign 的钱，直接打印。
用法：python tools/c1_round2_hetero_select.py [--n 6] [--cached]
"""
import argparse
import collections
import hashlib
import io
import json
import os
import re
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R2 = os.path.join(ROOT, "data", "c1", "round2")
RAW = os.path.join(R2, "screen_raw")
REG = os.path.join(R2, "msm_ids.json")
CAND = os.path.join(R2, "targets_candidates.json")
OUT = os.path.join(R2, "hetero_selection.json")

# 实测单价（来自流水）：recurring sslcert 10 / ping 3(推算) ；one-off 20 / 6
PRICE_REC = {"sslcert": 10, "ping": 3}
ROUNDS_48H = 48
PROBES = 4


def load(p):
    with io.open(p, encoding="utf-8", newline="") as f:
        return json.load(f)


def fetch(msm, cached):
    os.makedirs(RAW, exist_ok=True)
    p = os.path.join(RAW, "sc_%d.json" % msm)
    # 空缓存必须重取：Specified/Ongoing 期间拉到的 [] 会落盘，
    # 原写法"文件存在即命中"把整份筛查冻结在半成品快照上（2026-11-12 实测踩到）。
    if os.path.exists(p):
        got = load(p)
        if got:
            return got
    url = "https://atlas.ripe.net/api/v2/measurements/%d/results/?page_size=1000" % msm
    req = urllib.request.Request(url, headers={"User-Agent": "c1-round2-hetero/1.0"})
    for _ in range(3):
        try:
            d = json.loads(urllib.request.urlopen(req, timeout=180).read().decode())
            io.open(p, "w", encoding="utf-8", newline="").write(json.dumps(d, ensure_ascii=False))
            return d
        except Exception:
            time.sleep(5)
    return []


def leaf_fp(cert):
    if not cert:
        return None
    items = cert if isinstance(cert, list) else [cert]
    for x in items:
        if isinstance(x, str) and "BEGIN CERTIFICATE" in x:
            m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", x, re.S)
            if m:
                return hashlib.sha256(m.group(0).encode()).hexdigest()[:16]
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=6)
    ap.add_argument("--cached", action="store_true")
    a = ap.parse_args()

    reg = load(REG)["measurements"]
    cands = {t["domain"]: t for t in load(CAND)["targets"]}
    # TTL 判据只能由试点供给（同一探针跨轮次）；筛查单轮不可评估。
    pilot = {}
    pilot_msm = {}
    pp = os.path.join(R2, "ttl_pilot.json")
    if os.path.exists(pp):
        _p = load(pp)
        pilot = _p.get("summary", {})
        pilot_msm = {r["domain"]: r["msm_id"] for r in _p.get("rows", []) if r.get("domain")}

    # 登记里只有 group 没有目标标签 ⇒ 用 msm 的 target IP 反查域名。
    # IP→域名 的来源是"今天解析一次候选域"，缓存到 screen_raw/ip2dom.json。
    ip2dom = {}
    cache = os.path.join(RAW, "ip2dom.json")
    os.makedirs(RAW, exist_ok=True)
    if os.path.exists(cache):
        ip2dom = load(cache)
    else:
        import socket
        socket.setdefaulttimeout(8)
        for d in cands:
            try:
                for ip in set(socket.gethostbyname_ex(d)[2]):
                    ip2dom[ip] = d
            except Exception:
                pass
        io.open(cache, "w", encoding="utf-8", newline="").write(json.dumps(ip2dom, ensure_ascii=False))
    by = collections.defaultdict(list)
    for r in reg:
        if not str(r.get("group", "")).startswith(("tls_scout", "ping_scout")):
            continue
        dom = r.get("target_label")
        if not dom:
            try:
                q = urllib.request.Request(
                    "https://atlas.ripe.net/api/v2/measurements/%d/?fields=target" % r["msm_id"],
                    headers={"User-Agent": "c1-round2-hetero/1.0"})
                ip = json.loads(urllib.request.urlopen(q, timeout=30).read().decode()).get("target")
                dom = ip2dom.get(ip)
            except Exception:
                dom = None
        if dom:
            by[dom].append(r)

    rows = []
    for dom in sorted(cands):
        ent = by.get(dom, [])
        if not ent:
            continue
        fps = collections.defaultdict(set)      # probe -> fingerprints
        n_cert = 0
        n_contrast = 0
        ttl = set()
        n_ping = 0
        for r in ent:
            data = fetch(r["msm_id"], a.cached)
            if r["group"] == "tls_scout":
                for row in data:
                    f = leaf_fp(row.get("cert"))
                    if f:
                        fps[row.get("prb_id")].add(f)
                        n_cert += 1
            elif r["group"] == "tls_scout_contrast":
                for row in data:
                    if leaf_fp(row.get("cert")):
                        n_contrast += 1
            elif r["group"] == "ping_scout":
                for row in data:
                    n_ping += 1
                    for v in (row.get("ttl"), (row.get("reply") or {}).get("ttl")):
                        if isinstance(v, int) and v > 0:
                            ttl.add(v)
        all_fp = set().union(*fps.values()) if fps else set()
        # 修正（2026-11-11）：**跨视角 TTL 不同不等于异质**——TTL 是"到达时的剩余跳数"，
        # 不同视角路径长度不同，单机也会给出多个值。真正的 o₁ 异质是**同一探针跨轮次**的
        # TTL 集合基数 >1，筛查只有 1 轮 ⇒ 该判据由 12 轮 ping 试点（ttl_pilot.json）供给。
        pv = pilot.get(dom) or {}
        by_ttl = bool(pv.get("hetero"))
        hetero = len(all_fp) >= 2 or by_ttl
        rows.append({
            "domain": dom,
            "edge_prior": cands[dom].get("edge_prior"),
            "identity_class_prior": cands[dom].get("identity_class_prior"),
            "probes_with_cert": len(fps),
            "handshakes": n_cert,
            "distinct_leaf_fingerprints": len(all_fp),
            "ttl_values": sorted(ttl),
            "ttl_cardinality": len(ttl),
            "ping_rows": n_ping,
            "contrast_handshakes": n_contrast,
            "hetero_by_fingerprint": len(all_fp) >= 2,
            "hetero_by_ttl": by_ttl,
            "ttl_strength": pv.get("strength"),
            "ttl_persistent_probes": pv.get("n_persistent_probes"),
            "ttl_pilot_msm": pilot_msm.get(dom),
            "target_ip_pilot": pv.get("target_ip"),
            "ttl_across_vantages_note": "跨视角 TTL 差异是路径长度差异，不作为异质证据",
            "hetero": hetero,
            "excl_placeholder": (cands[dom].get("identity_class_prior") == "placeholder"),
            "excl_contrast_rejected": (n_contrast == 0),
        })

    srank = {"strong": 3, "medium": 2, "weak": 1, None: 0}
    elig = [r for r in rows if r["hetero"] and not r["excl_placeholder"] and not r["excl_contrast_rejected"]]
    elig.sort(key=lambda r: (-srank[r["ttl_strength"]], -r["distinct_leaf_fingerprints"],
                             -(r["ttl_persistent_probes"] or 0), -r["probes_with_cert"], r["domain"]))
    picked = elig[:a.n]

    out = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "rule": "prereg §4: >=2 leaf fingerprints across vantages OR same-probe TTL cardinality >1 across rounds（后者由 12 轮 ping 试点供给）",
           "n_candidates_screened": len(rows), "n_hetero_eligible": len(elig),
           "picked": [r["domain"] for r in picked], "rows": rows,
           "excluded": {"placeholder": [r["domain"] for r in rows if r["excl_placeholder"]],
                        "contrast_rejected": [r["domain"] for r in rows if r["excl_contrast_rejected"]]}}
    io.open(OUT, "w", encoding="utf-8", newline="").write(json.dumps(out, ensure_ascii=False, indent=1))

    # 战役靶表：地址取**试点实测的 dst_addr**，保证与 TTL 证据同一地址；今日解析只做漂移体检。
    import socket
    socket.setdefaulttimeout(8)
    ht = []
    for r in picked:
        ip = r.get("target_ip_pilot") or cands[r["domain"]].get("ip_at_scout_20261108")
        try:
            today = sorted(set(socket.gethostbyname_ex(r["domain"])[2]))
        except Exception:
            today = []
        ht.append({"domain": r["domain"], "identity_name": r["domain"], "target_ip": ip,
                   "needs_fresh_resolution": False, "ip_source": "ttl_pilot_dst_addr",
                   "today_a_records": today, "ip_drift": bool(today) and ip not in today,
                   "hetero_evidence": {"by_fingerprint": r["hetero_by_fingerprint"],
                                       "by_ttl": r["hetero_by_ttl"], "ttl_strength": r["ttl_strength"],
                                       "persistent_probes": r["ttl_persistent_probes"],
                                       "pilot_msm": r["ttl_pilot_msm"]},
                   "screen": {"handshakes": r["handshakes"],
                              "contrast_handshakes": r["contrast_handshakes"],
                              "distinct_leaf_fingerprints": r["distinct_leaf_fingerprints"]}})
    hp = os.path.join(R2, "targets_hetero.json")
    io.open(hp, "w", encoding="utf-8", newline="").write(json.dumps(
        {"at": out["at"], "arm": "hetero_sni", "role": "round2_hetero_targets", "rule": out["rule"],
         "targets": ht,
         "note": "地址=试点实测 dst_addr；ip_drift=true 须作者裁决是否换址后再开战役"},
        ensure_ascii=False, indent=1))

    print("%-20s %-11s %-4s %-4s %-4s %-6s %-7s %-5s %s"
          % ("domain", "edge", "prb", "fp", "ttl", "ttlset", "strength", "hetero", "flags"))
    for r in rows:
        flags = []
        if r["excl_placeholder"]:
            flags.append("placeholder")
        if r["excl_contrast_rejected"]:
            flags.append("contrast=0")
        print("%-20s %-11s %-4d %-4d %-4d %-6d %-7s %-5s %s" % (
            r["domain"], r["edge_prior"] or "-", r["probes_with_cert"],
            r["distinct_leaf_fingerprints"], r["ping_rows"], r["ttl_cardinality"],
            r["ttl_strength"] or "-", "YES" if r["hetero"] else "-", ",".join(flags) or ""))
    print("\n可筛 %d 个；异质可达标 %d 个；选中 %d：%s"
          % (len(rows), len(elig), len(picked), [r["domain"] for r in picked]))
    for t in ht:
        if t["ip_drift"]:
            print("  ⚠ %s 今日解析不含试点地址（漂移）——开战役前须裁决" % t["domain"])

    k = len(picked)
    rec = k * ROUNDS_48H * PROBES * (2 * PRICE_REC["sslcert"] + PRICE_REC["ping"])
    print("异质臂 48 h（%d 靶、双 SNI ＋ ping、4 视角）≈ %d credits（含 1 条推算价的 ping）" % (k, rec))
    print("-> %s\n-> %s" % (OUT, hp))
    return 0


if __name__ == "__main__":
    sys.exit(main())
