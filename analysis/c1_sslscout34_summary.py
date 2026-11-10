#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_sslscout34_summary.py —— sslscout34（组织域名 TLS 存活侦察）汇总 v2（2026-11-08）。

**结果格式两代并存（实测教训）**：
  - fw 5120 / B 线格式：成功 = result.certificates[]（含 sha256fingerprint）；失败 = 顶层 err。
  - fw 5130 one-off 格式（本批）：成功 = **顶层 `cert` PEM 字符串数组**（无 result 块！）；
    SNI 缺失被拒 = 顶层 alert {level,description}（40=handshake_failure，80=internal_error）。
TLS-live 判据 = 顶层 cert 非空 ∪ result.certificates 非空。
证书元数据（subject/validity）用 openssl x509 解析（本机 3.5.6 可用）。
输出：data/c1/sslscout34_summary.json ＋ 控制台 TLS 存活名单。
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


def edge_kind(ip):
    o = [int(x) for x in ip.split(".")]
    if o[0] == 104 and 16 <= o[1] <= 31:
        return "cloudflare"
    if o[0] == 172 and 64 <= o[1] <= 71:
        return "cloudflare"
    if o[0] == 162 and o[1] == 159:
        return "cloudflare"
    if o[0] in (34, 35):
        return "gcp"
    if o[0] in (3, 13, 18, 52, 54):
        return "aws"
    return "direct"


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
             "-startdate", "-enddate", "-serial"],
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
    spec = json.load(open(os.path.join(C1, "sslscout34_spec.json"), encoding="utf-8"))
    domains = spec["domains"]
    ips = spec["groups"][0]["targets"]
    ip2dom = dict(zip(ips, domains))
    recs = [r for r in json.load(open(os.path.join(C1, "campaign_msm_ids.json"),
                                      encoding="utf-8"))["measurements"] if r["group"] == "sslscout34"]
    assert len(recs) == len(ips) == len(domains)

    results = []
    for r in recs:
        msm = r["msm_id"]
        with urllib.request.urlopen("https://atlas.ripe.net/api/v2/measurements/%d/" % msm,
                                    timeout=30) as f:
            det = json.loads(f.read().decode())
        tgt = det.get("target")
        dom = ip2dom.get(tgt)
        raw = json.load(open(os.path.join(RAW, "cam_%d.json" % msm), encoding="utf-8"))
        leaf_fps = set()   # 叶子证书指纹（每记录 cert[0]）——变体计数用
        chain_fps = set()  # 全链指纹（信息性）
        pem0 = None
        errs = []
        alerts = []
        for res in raw:
            rcs = (res.get("result") or {}).get("certificates") or []
            if rcs:
                fp = rcs[0].get("sha256fingerprint")
                if fp:
                    leaf_fps.add(fp.lower())
                for c in rcs:
                    fp = c.get("sha256fingerprint")
                    if fp:
                        chain_fps.add(fp.lower())
            pemarr = res.get("cert") or []  # fw 5130 one-off：顶层 PEM 数组
            if pemarr:
                leaf_fps.add(pem_fp(pemarr[0]))
                for pem in pemarr:
                    chain_fps.add(pem_fp(pem))
                if pem0 is None:
                    pem0 = pemarr[0]
            e = (res.get("err") or "").strip()
            if e:
                errs.append(e)
            if res.get("alert"):
                alerts.append("%d/%d" % (res["alert"].get("level", -1), res["alert"].get("description", -1)))
        info = cert_info(pem0) if pem0 else None
        certs = leaf_fps  # TLS-live 判据 = 叶子证书非空
        results.append({
            "msm_id": msm, "domain": dom, "ip": tgt, "edge": edge_kind(tgt) if tgt else None,
            "tls_ok": bool(certs), "cert_variants": len(certs),
            "leaf_fps": sorted(certs),
            "subject": info.get("subject") if info else None,
            "issuer": info.get("issuer") if info else None,
            "notBefore": info.get("notBefore") if info else None,
            "notAfter": info.get("notAfter") if info else None,
            "last_err": errs[-1] if errs else "",
            "alerts": alerts, "n_results": len(raw),
        })

    ok = [d for d in results if d["tls_ok"]]
    print("sslscout34: %d/%d TLS-live (%.0f%%)  edges(all): %s" % (
        len(ok), len(results), 100 * len(ok) / len(results),
        dict(Counter(d["edge"] for d in results))))
    print("TLS-live list:")
    for d in ok:
        print("  %-20s %-16s %-11s variants=%d %s | %s .. %s" % (
            d["domain"], d["ip"], d["edge"], d["cert_variants"],
            (d["subject"] or "")[:70], (d["notBefore"] or "?")[:11], (d["notAfter"] or "?")[:11]))
    dead = [d for d in results if not d["tls_ok"]]
    print("dead err taxonomy:", dict(Counter(d["last_err"].split(":")[0] if d["last_err"] else "?" for d in dead)))
    print("dead alert taxonomy:", dict(Counter(a for d in dead for a in d["alerts"]) or "{}"))
    out = {"meta": {"date": "2026-11-08",
                    "note": ("org-domain TLS liveness scout (frame a); fw 5130 success format = "
                             "top-level cert PEM array (NOT result.certificates); "
                             "IP targets without SNI — alert 40/80 = vhost rejection, server alive"),
                    "tls_live_criterion": "top-level cert array ∪ result.certificates"},
           "results": results}
    with open(os.path.join(C1, "sslscout34_summary.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print("->", os.path.join(C1, "sslscout34_summary.json"))


if __name__ == "__main__":
    main()
