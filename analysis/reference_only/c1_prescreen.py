#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# REFERENCE-ONLY — not executable in this release: requires the
# non-redistributable 2011 routing archive (SOURCES.md §1) and/or the
# author-internal workspace (paths renamed to "workspace" here).
# Shipped for method transparency.
"""c1_prescreen.py —— C1 sslcert 靶预筛（在云 VM 上跑，标准库零依赖，2026-11-08）。
对候选代表 IP 做一次 TCP443+TLS 握手：成功者才进 sslcert recurring 10 靶
（避免把 credits 花在无 TLS 服务的靶上）；失败模式（timeout/refused/tls_error）
本身是"服务存活"测量数据，全部记录。证书取 DER sha256＋subject（不校验合法性，
自签/过期都要——引擎判卷用的是证书身份多样性，不是 PKI 信任）。
用法（云 VM）：python3 c1_prescreen.py <candidates_today.json> <prescreen.json> [workers]
纪律：靶是第三方研究靶；本机无凭据；每靶单次握手（预筛非测量战役，不计 credits）。
**选择偏置口径（云 VM 在中国大陆出口）**：国际裸 IP 直连受出口过滤影响，
  阳性=确认 TLS 存活（无假阳性，可用于选靶）；阴性=不定（可能真死也可能被墙），
  **不得把预筛失败率当服务死亡率**——存活率统计须由 Atlas 全球视角测量承担。
"""
import concurrent.futures as cf
import hashlib
import json
import socket
import ssl
import sys
import time


def probe_one(c):
    ip = c["rep_ip"]
    r = {"rep_ip": ip, "prefix": c["prefix"], "registry": c["registry"],
         "as_names": c["as_names"], "ok": False}
    t0 = time.time()
    try:
        with socket.create_connection((ip, 443), timeout=6) as s:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(s, server_hostname=None) as ts:
                der = ts.getpeercert(binary_form=True)
                r["ok"] = True
                r["cert_sha256"] = hashlib.sha256(der).hexdigest()
                cert = ts.getpeercert()
                subj = cert.get("subject", ())
                r["subject"] = "/".join(x[0][1] for x in subj if x and x[0][0] == "commonName")
                r["tls_version"] = ts.version()
    except socket.timeout:
        r["error"] = "timeout"
    except ConnectionRefusedError:
        r["error"] = "refused"
    except ssl.SSLError as e:
        r["error"] = "tls_error:%s" % str(e)[:80]
    except OSError as e:
        r["error"] = "oserror:%s" % str(e)[:80]
    r["rtt_ms"] = round((time.time() - t0) * 1000, 1)
    return r


def main():
    src, dst = sys.argv[1], sys.argv[2]
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    with open(src, encoding="utf-8") as f:
        data = json.load(f)
    cands = data.get("final") or data["candidates"]
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(probe_one, cands))
    ok = [r for r in results if r["ok"]]
    out = {"meta": {"source": src, "probed": len(results), "tls_ok": len(ok),
                    "elapsed_sec": round(time.time() - t0, 1),
                    "caliber": "single TCP443+TLS handshake per candidate from China-egress cloud VM; CERT_NONE; positive=confirmed TLS-live (selection only), negative=inconclusive (NOT a death statistic; survival rates require Atlas worldwide vantages)"},
           "results": results}
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    from collections import Counter
    print("probed=%d tls_ok=%d (%.1f%%) errors=%s" % (
        len(results), len(ok), 100 * len(ok) / len(results) if results else 0,
        dict(Counter(r.get("error", "ok") for r in results))))
    print("->", dst)


if __name__ == "__main__":
    main()