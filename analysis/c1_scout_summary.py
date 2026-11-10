#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_scout_summary.py —— 汇总侦察测量结果 → c1_spec 可用的 prescreen 格式（2026-11-08）。

v2（2026-11-08 晚）：**修复 fw 5130 格式漏判 bug**。v1 只数 result.certificates[]（fw 5120
格式），漏计 fw 5130 one-off sslcert 的**顶层 `cert` PEM 字符串数组**——曾把 1/100 存活
（msm 234165928，靶 195.245.226.1）误报成 0/100。TLS-live 判据改为：
    顶层 cert 非空 ∪ result.certificates 非空
（与 c1_sslscout34_summary.py 同判据，那里从一开始就写对了）。
证书指纹：fw 5120 记录直接取 sha256fingerprint；fw 5130 对 PEM 去壳后 sha256(DER) 自算，
两路等价（pem_fp 与引擎 _leaf_hash 同口径）。
输入：data/c1/campaign_msm_ids.json（scout100 有序 id）＋ data/c1/candidates_today.json（final 有序靶）
  ＋ data/c1/raw/cam_<id>.json（--fetch-batch 取回）。
对齐：ids 顺序 = definitions 提交顺序 = final 靶序；另取 /measurements/<id>/ 详情核对 target。
输出：data/c1/scout_prescreen.json ＋统计打印。
"""
import base64
import hashlib
import json
import os
import subprocess
import tempfile
import urllib.request
from collections import Counter

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
C1 = os.path.join(BASE, "data", "c1")
RAW = os.path.join(C1, "raw")


def pem_fp(pem):
    body = "".join(l for l in pem.splitlines() if "-----" not in l)
    return hashlib.sha256(base64.b64decode(body)).hexdigest()


def cert_info(pem):
    """openssl x509 解析 subject/issuer/validity；失败返回 None。"""
    try:
        fd, path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(pem)
        out = subprocess.run(
            ["openssl", "x509", "-noout", "-in", path, "-subject", "-issuer",
             "-startdate", "-enddate"],
            capture_output=True, text=True, timeout=10)
        os.unlink(path)
        if out.returncode != 0:
            return None
        d = {}
        for line in out.stdout.splitlines():
            k, _, v = line.partition("=")
            d[k.strip()] = v.strip()
        return d
    except Exception:
        return None


def main():
    ids = json.load(open(os.path.join(C1, "campaign_msm_ids.json"), encoding="utf-8"))["measurements"]
    scout_ids = [r["msm_id"] for r in ids if r["group"] == "scout100"]
    cand = json.load(open(os.path.join(C1, "candidates_today.json"), encoding="utf-8"))
    final = cand["final"]
    assert len(scout_ids) == len(final), "ids(%d) 与终样靶(%d)数不一致" % (len(scout_ids), len(final))

    results = []
    n_ok = 0
    mismatch = 0
    for i, msm in enumerate(scout_ids):
        raw = json.load(open(os.path.join(RAW, "cam_%d.json" % msm), encoding="utf-8"))
        # 详情核对 target（一次性 100 个 GET，公开免鉴权）
        with urllib.request.urlopen("https://atlas.ripe.net/api/v2/measurements/%d/" % msm, timeout=30) as r:
            det = json.loads(r.read().decode("utf-8"))
        ok = False
        certs = set()
        pem0 = None
        errs = []
        for res in raw:
            # fw 5120 / B 线格式：result.certificates[]（含 sha256fingerprint）
            for c in (res.get("result") or {}).get("certificates") or []:
                ok = True
                fp = c.get("sha256fingerprint")
                if fp:
                    certs.add(fp.lower())
            # fw 5130 one-off 格式：顶层 cert PEM 数组（无 result 块）
            pemarr = res.get("cert") or []
            if pemarr:
                ok = True
                certs.add(pem_fp(pemarr[0]))
                for pem in pemarr:
                    certs.add(pem_fp(pem))
                if pem0 is None:
                    pem0 = pemarr[0]
            e = (res.get("err") or "").strip()  # Atlas sslcert 失败在顶层 err（如 connect: Connection refused）
            if e:
                errs.append(e)
        err = errs[-1] if errs else ""  # 最后一条非空 err（成功记录无 err 字段）
        c = final[i]
        if det.get("target") != c["rep_ip"]:
            mismatch += 1
            print("MISMATCH msm %d target=%s vs candidate %s" % (msm, det.get("target"), c["rep_ip"]))
        n_ok += ok
        info = cert_info(pem0) if pem0 else None
        results.append({
            "msm_id": msm, "rep_ip": c["rep_ip"], "prefix": c["prefix"],
            "registry": c["registry"], "as_names": c["as_names"],
            "multihomed_org": c.get("multihomed_org"),
            "ok": ok, "cert_sha256": sorted(certs)[0] if certs else None,
            "n_cert_variants": len(certs),
            "subject": info.get("subject") if info else None,
            "issuer": info.get("issuer") if info else None,
            "notBefore": info.get("notBefore") if info else None,
            "notAfter": info.get("notAfter") if info else None,
            "n_results": len(raw),
            "last_err": err,
        })
    out = {"meta": {"source": "atlas scout msms (scout100)", "probed": len(results), "tls_ok": n_ok,
                    "target_mismatch": mismatch,
                    "tls_live_criterion": "top-level cert PEM array (fw 5130) ∪ result.certificates (fw 5120); "
                                          "worldwide Atlas vantages (no China-egress bias)",
                    "v2_note": "regenerated 2026-11-08 evening after fixing fw-5130 miss in v1 "
                               "(v1 counted only result.certificates → reported 0/100; true 1/100)"},
           "results": results}
    with open(os.path.join(C1, "scout_prescreen.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print("probed=%d TLS-live=%d (%.1f%%) target_mismatch=%d" % (
        len(results), n_ok, 100 * n_ok / len(results), mismatch))
    errtax = Counter(r["last_err"].split(":")[0] if r["last_err"] else ("tls-ok" if r["ok"] else "?")
                     for r in results)
    print("failure taxonomy:", dict(errtax))
    for r in results:
        if r["ok"]:
            print("ALIVE msm=%d ip=%s prefix=%s reg=%s variants=%d" % (
                r["msm_id"], r["rep_ip"], r["prefix"], r["registry"], r["n_cert_variants"]))
            print("      subject=%s" % r["subject"])
            print("      issuer =%s" % r["issuer"])
            print("      valid  =%s .. %s" % (r["notBefore"], r["notAfter"]))
    print("->", os.path.join(C1, "scout_prescreen.json"))


if __name__ == "__main__":
    main()
