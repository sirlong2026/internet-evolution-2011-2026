#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_judge.py —— sslcert9 组织域名靶四态判卷（复用 B 线引擎，2026-11-08）。

复用：atlas_adapter.aggregate_certs / build_cert_bundle / pick_pair（**顶层 cert PEM 格式
原生支持**——B 线与 C1 的 sslcert 记录同构，早前"两代格式"判断有误，result.certificates
并非 sslcert 成功格式）＋ tools/sensor_compare.decide_formal（含 κ 精确分数修复，4l）。
预注册=协议级（引擎、闸、κ floor 1/3、lead≥2 与 B 线同源，非新拟）；不对新靶逐个预登记
四态期望；唯一显式预期：asp.bg 化石证书（2004）→ 预期 decidable single、union=1，
判不中如实记录。
msm→域名映射：GET /measurements/<id>/ 的 target（本批全是域名靶，detail 即权威）。
用法：python c1_judge.py          # 用已取回 raw 判卷
      python c1_judge.py --fetch  # 先重取 9 个 msm 结果再判
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
LAB = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, LAB)
from atlas_adapter import (aggregate_certs, build_cert_bundle, pick_pair,
                           load_json_checked, _leaf_hash)  # noqa: E402
import sensor_compare  # noqa: E402  (判定引擎，单源不复制)

C1 = os.path.join(BASE, "data", "c1")
RAW1 = os.path.join(C1, "raw")
OUT = os.path.join(C1, "sslcert9_judged.json")


def sslcert9_msms():
    """战役靶测量：9 个 sslcert9 ＋ 1 个信用截断续测（sslcert9-cont）。

    2026-11-09 起口径变更（取数前固定，见日志 §5p）：**目标观测集＝该靶全部
    战役测量 ID 的并集**；asp.bg 的原测量（234182558，Force to Stop）与续测
    （234657473，信用恢复后补建）合并后判型。
    """
    recs = json.load(open(os.path.join(C1, "campaign_msm_ids.json"), encoding="utf-8"))["measurements"]
    return [r["msm_id"] for r in recs if r.get("group") in ("sslcert9", "sslcert9-cont")]


def msm_domain(msm):
    with urllib.request.urlopen("https://atlas.ripe.net/api/v2/measurements/%d/" % msm,
                                timeout=30) as f:
        d = json.loads(f.read().decode())
    return d["target"]


def fetch_all(msms):
    for m in msms:
        with urllib.request.urlopen(
                "https://atlas.ripe.net/api/v2/measurements/%d/results/" % m, timeout=120) as f:
            raw = json.loads(f.read().decode())
        with open(os.path.join(RAW1, "cam_%d.json" % m), "w", encoding="utf-8") as f:
            json.dump(raw, f, ensure_ascii=False)
        print("[fetch] %d -> %d results" % (m, len(raw)))
        time.sleep(0.4)


def cert_meta(pem):
    """openssl 读取 subject/issuer/有效期（每指纹一次，失败返空表）。"""
    if "-----BEGIN" not in pem:
        pem = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" % pem.strip()
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(pem)
        path = f.name
    try:
        out = subprocess.run(["openssl", "x509", "-in", path, "-noout",
                              "-subject", "-issuer", "-startdate", "-enddate"],
                             capture_output=True, text=True).stdout
        d = {}
        for ln in out.strip().splitlines():
            k, _, v = ln.partition("=")
            d[k.strip()] = v.strip()
        return d
    except Exception:
        return {}
    finally:
        os.unlink(path)


def cert_variants(data):
    """同一靶内不同叶证书指纹 → 视角集 + 元数据；哈希分岔时用于归因
    （subject+有效期一致而 issuer 不同 ⇒ 视角侧中间盒重签，非服务器轮换）。"""
    variants = {}
    for r in data:
        c = r.get("cert")
        if not c:
            continue
        fp = _leaf_hash(c[0])
        v = variants.setdefault(fp, {"vantages": set()})
        v["vantages"].add(r["prb_id"])
        if not v.get("subject"):
            meta = cert_meta(c[0])
            for k in ("subject", "issuer", "notBefore", "notAfter"):
                if meta.get(k):
                    v[k] = meta[k]
    rows = [{"fp": fp, "vantages": sorted(v["vantages"]),
             "subject": v.get("subject", ""), "issuer": v.get("issuer", ""),
             "notBefore": v.get("notBefore", ""), "notAfter": v.get("notAfter", "")}
            for fp, v in sorted(variants.items())]
    note = ""
    if len(rows) > 1:
        subs = {r["subject"] for r in rows}
        vals = {(r["notBefore"], r["notAfter"]) for r in rows}
        iss = {r["issuer"] for r in rows}
        if len(subs) == 1 and len(vals) == 1 and len(iss) > 1:
            note = "subject+有效期一致、issuer 不同 → 视角侧重签（中间盒 TLS 检查），非服务器轮换"
        else:
            note = "subject/有效期有差异 → 服务器侧多证书/轮换"
    return rows, note


def judge(msms, domains):
    # 2026-11-09（口径变更，日志 §5p）：同一靶可对应多个战役测量 ID
    # （asp.bg = 原测量 234182558 + 信用恢复后续测 234657473），
    # 目标观测集＝该靶全部测量 ID 的并集，按靶出一行。
    merged = {}
    for msm, dom in zip(msms, domains):
        merged.setdefault(dom, []).append(msm)
    rows = []
    for dom, msm_list in merged.items():
        data = []
        for msm in msm_list:
            path = os.path.join(RAW1, "cam_%d.json" % msm)
            try:
                data.extend(load_json_checked(path, "sslcert9/%s" % dom))
            except Exception as ex:
                print("  [warn] msm %d 尚无本地原始行（%s）——先跑 --fetch" % (msm, ex))
        per = aggregate_certs(data)
        pair = pick_pair(per)
        row = {"msm": msm_list[0], "msms": msm_list, "domain": dom,
               "results_total": len(data),
               "probes_with_cert": sum(1 for e in per.values() if e["hashes"]),
               "handshakes_total": sum(len(e["hashes"]) for e in per.values()),
               "pair": pair}
        union = set()
        for e in per.values():
            union |= {h for _, h in e["hashes"]}
        row["fleet"] = {"union_certs": len(union),
                        "probes_multi_cert": sum(1 for e in per.values()
                                                 if len({h for _, h in e["hashes"]}) >= 2)}
        variants, vnote = cert_variants(data)
        row["cert_variants"] = variants
        if vnote:
            row["variant_note"] = vnote
        if len(pair) == 2:
            a = build_cert_bundle("%s#prb%d" % (dom, pair[0]), per[pair[0]])
            b = build_cert_bundle("%s#prb%d" % (dom, pair[1]), per[pair[1]])
            row["verdict"] = sensor_compare.decide_formal(a, b)
        else:
            row["verdict"] = None
            row["verdict_note"] = "o3 代表对未满（成功轮次 ≥3 的探针不足 2）——轮次不足，未判"
        rows.append(row)
        v = row["verdict"]
        vtxt = json.dumps(v, ensure_ascii=False)[:160] if v else "未判（o3 不足）"
        if vnote:
            vtxt += " 〔%s〕" % vnote
        print("%-18s msm %d 握手%3d 视角%2d 并集%d | %s" % (
            dom, msm, row["handshakes_total"], row["probes_with_cert"],
            row["fleet"]["union_certs"], vtxt))
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"meta": {"date": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "protocol": "B-line engine (sensor_compare.decide_formal), "
                                        "gates o3>=3, kappa floor 1/3 exact-fraction",
                            "expected": {"asp.bg": "decidable single, union=1 (fossil 2004 cert)"}},
                   "rows": rows}, f, ensure_ascii=False, indent=1)
    print("->", OUT)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fetch", action="store_true")
    args = ap.parse_args()
    msms = sslcert9_msms()
    assert len(msms) == 10, "sslcert9 应有 10 个 msm（9 靶 + 1 续测，实际 %d）" % len(msms)
    domains = [msm_domain(m) for m in msms]
    print("targets:", domains)
    if args.fetch:
        fetch_all(msms)
    judge(msms, domains)


if __name__ == "__main__":
    main()
