#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_round2_judge.py —— 第二轮战役判卷（只读；复用 B 线引擎，不复制）。

口径（与预注册 §2/§5 逐条对应）：
  * 每个靶两条测量：tls_sni_a（身份名）与 tls_sni_b（对比名）。**o₃/o₆ 只用身份名一侧**
    （对比名的握手绝不进 tls.hashes，否则 o₆ 会把 SNI 分岔误记成时间轮换）。
  * o₄：两条测量的 `sni_map` ＝ {名字: 该名字下见过的叶指纹}；引擎按"两个名字是否给出
    不同指纹"判 positive/negative。这里额外**逐探针**复核，并单列 mixed（两名字指纹集合有交集
    但不相等）——mixed 不进 sni_map（宁缺勿错），只作报告。
  * 代表对（o₃ 闸）：沿用第一轮 pick_pair（每靶成功轮次 ≥3 的探针取两两配对）。
  * H2：阴性对照中被判 family=single 的比例（Wilson 95%）。
  * H1：异质靶中 decidable/conditionally decidable 的比例，n 很小 ⇒ **只报描述值＋区间**，
    正文按 D7 写"功效不足"，不作推断。

输出 data/c1/round2/campaign_judged.json（含 window 覆盖块：平台 stop_time、是否已收窗、
逐对 last_ts 是否覆盖到 stop−2×interval）。**默认每次重拉原始结果**——战役是窗口测量，
命中旧缓存等于用半窗数据判卷；`--cached` 才离线读缓存。
用法：python tools/c1_round2_judge.py [--cached] [--limit N]
"""
import argparse
import collections
import hashlib
import io
import json
import math
import os
import re
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB = os.path.join(ROOT, "workspace", "lab")
sys.path.insert(0, LAB)
sys.path.insert(0, os.path.join(ROOT, "workspace", "tools"))
from atlas_adapter import aggregate_certs, build_cert_bundle, pick_pair  # noqa: E402
import sensor_compare  # noqa: E402

R2 = os.path.join(ROOT, "data", "c1", "round2")
RAW = os.path.join(R2, "campaign_raw")
REG = os.path.join(R2, "msm_ids.json")
TH = os.path.join(R2, "targets_hetero.json")
TP = os.path.join(R2, "targets_control_positive.json")
TS = os.path.join(R2, "targets_control_single.json")
OUT = os.path.join(R2, "campaign_judged.json")
CUT = 1794488000
HOUR = 3600


def load(p):
    with io.open(p, encoding="utf-8", newline="") as f:
        return json.load(f)


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


def fetch(msm, cached):
    """默认**每次重拉**：战役是 48 h 窗口测量，缓存命中即等于用旧窗口判卷。

    --cached 才读本地缓存（离线复算用）。网络失败时退回缓存并出声，
    由窗口覆盖闸（window/coverage_ok）拦住陈旧读数，不静默当满窗。
    """
    os.makedirs(RAW, exist_ok=True)
    p = os.path.join(RAW, "jr_%d.json" % msm)
    if cached and os.path.exists(p):
        return load(p)
    url = ("https://atlas.ripe.net/api/v2/measurements/%d/results/?page_size=1000" % msm)
    req = urllib.request.Request(url, headers={"User-Agent": "c1-round2-judge/1.0"})
    for _ in range(3):
        try:
            d = json.loads(urllib.request.urlopen(req, timeout=180).read().decode())
            io.open(p, "w", encoding="utf-8", newline="").write(json.dumps(d, ensure_ascii=False))
            return d
        except Exception:
            time.sleep(5)
    if os.path.exists(p):
        print("[WARN] msm %d 拉取失败，退回本地缓存（可能陈旧）" % msm)
        return load(p)
    return []


def fetch_meta(ids):
    """一次列表请求取权威 status/stop_time（registry 里没存 stop_time）。"""
    url = ("https://atlas.ripe.net/api/v2/measurements/?id__in=%s&page_size=100"
           % ",".join(str(i) for i in sorted(ids)))
    req = urllib.request.Request(url, headers={"User-Agent": "c1-round2-judge/1.0"})
    try:
        d = json.loads(urllib.request.urlopen(req, timeout=120).read().decode())
    except Exception:
        return {}
    return {m["id"]: {"status": (m.get("status") or {}).get("name"),
                      "stop_time": m.get("stop_time"),
                      "interval": m.get("interval")}
            for m in d.get("results", []) if m["id"] in set(ids)}


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / float(n)
    c = (p + z * z / (2 * n)) / (1 + z * z / n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def label_map():
    """{target_ip: label}：第三轮靶表已含显式地址，直接建反查。"""
    m = {}
    for p in (TS, TP, TH):
        if not os.path.exists(p):
            continue
        for t in load(p)["targets"]:
            lab = t.get("identity_name") or t.get("domain")
            if lab and t.get("target_ip"):
                m[t["target_ip"]] = lab
    return m


def fps_by_probe(data):
    """{prb: sorted set of leaf fps}（跨轮次的集合）。"""
    per = collections.defaultdict(set)
    for r in data:
        f = leaf_fp(r.get("cert"))
        if f:
            per[r.get("prb_id")].add(f)
    return {p: sorted(s) for p, s in per.items()}


def pair_rows(cut=CUT, limit=0, cached=False):
    reg = [r for r in load(REG)["measurements"] if int(r.get("start_time") or 0) >= cut]
    by = collections.defaultdict(dict)
    for r in reg:
        if r["type"] != "sslcert":
            continue
        side = "a" if r["group"].endswith("_a") else ("b" if r["group"].endswith("_b") else None)
        if side:
            by[(r["arm"], r["msm_id"])][side] = r          # 先按 msm 分组
    # 目标配对：同 arm 下 a/b 按 (start_time 最近) 配对——战役里每个靶只有一对
    pairs = collections.defaultdict(dict)
    for (arm, msm), ab in by.items():
        if "a" in ab:
            pairs[arm]["a"] = pairs[arm].get("a", []) + [ab["a"]]
        if "b" in ab:
            pairs[arm]["b"] = pairs[arm].get("b", []) + [ab["b"]]
    labs = label_map()
    out = []
    for arm, ab in pairs.items():
        al = sorted(ab.get("a", []), key=lambda r: r["msm_id"])
        bl = sorted(ab.get("b", []), key=lambda r: r["msm_id"])
        for A, B in zip(al, bl):
            out.append({"arm": arm, "a": A, "b": B})
    return out[:limit] if limit else out


def judge_one(pair, cached):
    A, B = pair["a"], pair["b"]
    da, db = fetch(A["msm_id"], cached), fetch(B["msm_id"], cached)
    per_a = aggregate_certs(da)
    per_b = aggregate_certs(db)
    fa, fb = fps_by_probe(da), fps_by_probe(db)
    common = sorted(set(fa) & set(fb))

    # 逐探针 o4 复核
    votes = collections.Counter()
    mixed = []
    for p in common:
        sa, sb = fa[p], fb[p]
        if sa == sb:
            votes["negative"] += 1
        elif not (set(sa) & set(sb)):
            votes["positive"] += 1
        else:
            votes["mixed"] += 1
            mixed.append({"prb": p, "a": sa, "b": sb})
    o4 = (votes.most_common(1)[0][0] if votes else "unobservable")

    # 目标级 sni_map（唯一指纹用字符串；多值用元组）；mixed 不给值
    def val(s):
        return s[0] if len(s) == 1 else tuple(s)
    sni = {}
    if common:
        id_name = A.get("label") or "identity"
        ct_name = "sni-control.invalid"
        sid = set().union(*[set(fa[p]) for p in common])
        sct = set().union(*[set(fb[p]) for p in common])
        if sid == sct:
            sni = {id_name: val(sorted(sid)), ct_name: val(sorted(sct))}
        elif not (sid & sct):
            sni = {id_name: val(sorted(sid)), ct_name: val(sorted(sct))}
        else:
            sni = {id_name: val(sorted(sid)), ct_name: val(sorted(sct & sid))}

    lab = None
    ips = (label_map().keys())
    for src in (da, db):
        for r in src[:1]:
            if r.get("dst_addr") in label_map():
                lab = label_map()[r["dst_addr"]]
                break
        if lab:
            break
    if not lab:
        lab = "<rig>" if pair["arm"] in ("rig_rotation", "rig_middlebox") else "?"
    pair_p = pick_pair(per_a)
    # rounds＝小时槽数（每槽 4 个探针各一条结果）；results＝原始行数，两者不可混用
    ts_a = sorted({r["timestamp"] for r in da if r.get("timestamp")})
    ts_b = sorted({r["timestamp"] for r in db if r.get("timestamp")})
    row = {"arm": pair["arm"], "msm_a": A["msm_id"], "msm_b": B["msm_id"],
           "label": lab,
           "handshakes_a": sum(len(e["hashes"]) for e in per_a.values()),
           "probes_a": sum(1 for e in per_a.values() if e["hashes"]),
           "probes_b": sum(1 for e in per_b.values() if e["hashes"]),
           "common_probes": len(common),
           "rounds_a": len({t // HOUR for t in ts_a}),
           "rounds_b": len({t // HOUR for t in ts_b}),
           "results_a": len(da), "results_b": len(db),
           "last_ts": max(ts_a + ts_b) if (ts_a or ts_b) else 0,
           "o4_votes": dict(votes), "o4": o4, "o4_mixed": mixed[:4],
           "fp_sets": {str(p): {"identity": fa[p], "contrast": fb.get(p, [])} for p in common},
           "verdict": None}
    if len(pair_p) == 2:
        a = build_cert_bundle("%s#prb%d" % (row["label"], pair_p[0]), per_a[pair_p[0]], sni_map=sni)
        b = build_cert_bundle("%s#prb%d" % (row["label"], pair_p[1]), per_a[pair_p[1]], sni_map=sni)
        row["verdict"] = sensor_compare.decide_formal(a, b)
    else:
        row["verdict_note"] = "o3 代表对未满（≥3 轮成功的探针不足 2）"
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cached", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()

    pairs = pair_rows(limit=a.limit)
    rows = [judge_one(p, a.cached) for p in pairs]

    # 窗口覆盖：stop_time 取自平台（权威），不靠 start+48h 推算。
    # 取**全部 36 条战役测量**（含 ping），close_at 才是整场战役的收窗时刻。
    ids = sorted({int(r["msm_id"]) for r in load(REG)["measurements"]
                  if int(r.get("start_time") or 0) >= CUT})
    meta = fetch_meta(ids)
    now = int(time.time())
    for r in rows:
        sa = (meta.get(r["msm_a"]) or {}).get("stop_time") or 0
        sb = (meta.get(r["msm_b"]) or {}).get("stop_time") or 0
        iv = (meta.get(r["msm_a"]) or {}).get("interval") or 3600
        stop = max(sa, sb)
        r["stop_time"] = stop
        r["coverage_ok"] = bool(stop and r["last_ts"] >= stop - 2 * iv)
    stops = [v["stop_time"] for v in meta.values() if v.get("stop_time")]
    window = {"close_at": max(stops) if stops else None,
              "closed": bool(stops and now >= max(stops)),
              "status": dict(collections.Counter(v.get("status") for v in meta.values())),
              "n_msm": len(meta),
              "coverage_ok_pairs": sum(1 for r in rows if r["coverage_ok"]),
              "min_rounds_a": min([r["rounds_a"] for r in rows]) if rows else 0}

    # 结局归类
    def fam(v):
        return (v or {}).get("family")
    single = [r for r in rows if r["arm"] == "control_single_sni"]
    pos = [r for r in rows if r["arm"] == "control_positive_sni"]
    het = [r for r in rows if r["arm"] == "hetero_sni"]
    rig = [r for r in rows if r["arm"] == "rig_rotation"]

    n_single_ok = sum(1 for r in single if fam(r["verdict"]) == "single")
    h2 = {"n": len(single), "single": n_single_ok,
          "share": round(n_single_ok / len(single), 4) if single else None,
          "wilson95": wilson(n_single_ok, len(single))}
    # 引擎四态是中文串；这里必须用中文比较，英文只在发布包里由 i18n 归一
    dec = ("决定可判", "条件可判")
    h1 = {"n": len(het),
          "decidable": sum(1 for r in het if ((r["verdict"] or {}).get("V") in dec)),
          "share": None, "wilson95": None}
    if het:
        k = sum(1 for r in het if ((r["verdict"] or {}).get("V") in dec))
        h1["share"] = round(k / len(het), 4)
        h1["wilson95"] = wilson(k, len(het))

    out = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "rule": "o3/o6 只用身份名一侧；o4 逐探针集合比较＋目标级 sni_map；H1 描述性（D7）",
           "n_pairs": len(rows), "rows": rows, "window": window,
           "H2": h2, "H1": h1,
           "o4_dist": dict(collections.Counter(r["o4"] for r in rows)),
           "positive_control": [{"label": r["label"], "family": fam(r["verdict"]), "o4": r["o4"]}
                                for r in pos],
           "rig": [{"family": fam(r["verdict"]), "o4": r["o4"], "verdict": r["verdict"]} for r in rig]}
    io.open(OUT, "w", encoding="utf-8", newline="").write(json.dumps(out, ensure_ascii=False, indent=1))

    print("%-22s %-16s %-6s %-4s %-6s %-10s %s" % ("arm", "label", "hand", "prb", "rnd", "o4", "verdict"))
    for r in rows:
        v = r["verdict"] or {}
        print("%-22s %-16s %-6d %-4d %-6d %-10s %s / %s%s" % (
            r["arm"], (r["label"] or "?")[:16], r["handshakes_a"], r["probes_a"], r["rounds_a"],
            r["o4"], v.get("V", "-"), fam(r["verdict"]) or "-",
            "" if r["coverage_ok"] else "  [窗口未满]"))
    print("\no4 分布:", out["o4_dist"])
    print("H2: %d/%d = %s  Wilson %s" % (h2["single"], h2["n"], h2["share"], h2["wilson95"]))
    print("H1: %d/%d = %s  Wilson %s（描述性，勿作推断）" % (h1["decidable"], h1["n"], h1["share"], h1["wilson95"]))
    if window["close_at"]:
        print("窗口: 收窗 %s  已收=%s  覆盖达标 %d/%d 对  最少轮次 %d  状态 %s" % (
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(window["close_at"])),
            window["closed"], window["coverage_ok_pairs"], len(rows),
            window["min_rounds_a"], window["status"]))
    else:
        print("窗口: 未取到平台 stop_time（--cached 或列表请求失败）——覆盖闸不可用")
    print("-> %s" % OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
