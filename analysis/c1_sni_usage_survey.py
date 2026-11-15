#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_sni_usage_survey.py —— 公开 sslcert 语料里 SNI 控制的使用率（只读，可复算）。

为什么要重做：原 `atlas_sni_evidence.json` 里的 n=200 是临时抓的，只留了汇总、没留
抽样框与 id 清单，无法按"每句话都能复算"的标准复核。本脚本给一个**冻结可复现**的抽样：

  抽样框 = 公开（is_public=true）且 type=sslcert 的测量，id ∈ [234000000, 234200000)
           （该 id 段对应 2026-11-08..11-10，与本轮第一轮同期；用 id 段而非"最新 N 条"，
            因为 id 段不随新测量增加而变化）
  剔除   = 我们自己创建的测量（data/c1/own_msm_ids.json）
  抽样   = random.Random(20261112).sample(ids, 200)  ← 固定种子，任何人可复现
  判读   = 该测量的 definitions[0].hostname 是否有值（有值 ⇒ ClientHello 会带 server_name）

输出 data/c1/round2/sni_usage_survey.json（含抽样 id 清单与逐条判读，不含他人靶地址）。
用法：python tools/c1_sni_usage_survey.py [--n 200] [--seed 20261112] [--lo 234000000 --hi 234200000]
"""
import argparse
import io
import json
import math
import os
import random
import re
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R2 = os.path.join(ROOT, "data", "c1", "round2")
OWN = os.path.join(ROOT, "data", "c1", "own_msm_ids.json")
OUT = os.path.join(R2, "sni_usage_survey.json")
API = "https://atlas.ripe.net/api/v2/measurements/"
UA = {"User-Agent": "c1-sni-survey/1.0"}
IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def load(p):
    with io.open(p, encoding="utf-8", newline="") as f:
        return json.load(f)


def get(url):
    req = urllib.request.Request(url, headers=UA)
    for _ in range(4):
        try:
            return json.loads(urllib.request.urlopen(req, timeout=120).read().decode())
        except Exception:
            time.sleep(3)
    raise RuntimeError("fetch failed: %s" % url)


def wilson(k, n, z=1.96):
    if n == 0:
        return None
    p = k / float(n)
    c = (p + z * z / (2 * n)) / (1 + z * z / n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def frame_ids(lo, hi):
    """该 id 段内所有公开 sslcert 测量的 id（分页）。"""
    ids, url = [], API + ("?id__gte=%d&id__lt=%d&type=sslcert&is_public=true"
                          "&page_size=500&fields=id" % (lo, hi))
    pages = 0
    while url:
        d = get(url)
        ids += [r["id"] for r in d.get("results", [])]
        url = d.get("next") or (d.get("meta") or {}).get("next")
        pages += 1
        if pages > 60:
            break
    return sorted(set(ids)), pages


def hostname_of(mid):
    d = get(API + "%d/" % mid)
    defs = d.get("definitions") or [d]
    h = defs[0].get("hostname") or d.get("hostname")
    return (str(h).strip() if h else None), (defs[0].get("target") or d.get("target")), d.get("start_time") or 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--seed", type=int, default=20261112)
    ap.add_argument("--lo", type=int, default=234000000)
    ap.add_argument("--hi", type=int, default=234200000)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()

    own = set(load(OWN)) if os.path.exists(OWN) else set()
    all_ids, pages = frame_ids(a.lo, a.hi)
    pool = [i for i in all_ids if i not in own]
    ex_own = len(all_ids) - len(pool)
    print("抽样框 id∈[%d,%d)：%d 条（%d 页）；其中我方 %d 条已剔除；可用 %d"
          % (a.lo, a.hi, len(all_ids), pages, ex_own, len(pool)))

    rnd = random.Random(a.seed)
    picked = sorted(rnd.sample(pool, min(a.n, len(pool))))

    rows = []
    for i, mid in enumerate(picked, 1):
        try:
            h, tgt, st = hostname_of(mid)
        except Exception as e:
            rows.append({"id": mid, "error": str(e)[:60]})
            continue
        kind = "ipv4" if IPV4.match(tgt or "") else "domain"
        rows.append({"id": mid, "target_kind": kind, "has_hostname": bool(h),
                     "hostname_equals_target": bool(h) and (h.lower() == (tgt or "").lower()),
                     "start_time": st})
        if i % 50 == 0:
            print("  … %d/%d" % (i, len(picked)))

    ok = [r for r in rows if "error" not in r]
    n = len(ok)
    dom = [r for r in ok if r["target_kind"] == "domain"]
    dom_null = [r for r in dom if not r["has_hostname"]]
    ip = [r for r in ok if r["target_kind"] == "ipv4"]
    seth = [r for r in ok if r["has_hostname"]]

    out = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "frame": {"id_gte": a.lo, "id_lt": a.hi, "type": "sslcert", "is_public": True,
                     "frame_size": len(all_ids), "excluded_own": ex_own,
                     "pool_size": len(pool), "seed": a.seed, "n_requested": a.n,
                     "n_scored": n, "errors": len(rows) - n,
                     "note": "用 id 段而非'最新 N 条'：id 段不随新测量增加而变化，可复算"},
           "result": {"hostname_set": len(seth), "hostname_null": n - len(seth),
                      "ipv4_targets": len(ip), "domain_targets": len(dom),
                      "domain_targets_null_hostname": len(dom_null),
                      "domain_null_share": round(len(dom_null) / len(dom), 4) if dom else None,
                      "domain_null_wilson95": wilson(len(dom_null), len(dom)) if dom else None,
                      "hostname_equals_target_among_set": sum(1 for r in seth if r["hostname_equals_target"])},
           "era": {"start_time_min": min([r["start_time"] for r in ok], default=0),
                   "start_time_max": max([r["start_time"] for r in ok], default=0)},
           "rows": rows,
           "reproduce": "python tools/c1_sni_usage_survey.py --n 200 --seed 20261112"}

    os.makedirs(R2, exist_ok=True)
    io.open(a.out, "w", encoding="utf-8", newline="").write(json.dumps(out, ensure_ascii=False, indent=1))

    r = out["result"]
    print("\n判读 %d 条：hostname 有值 %d / 为 null %d" % (n, r["hostname_set"], r["hostname_null"]))
    print("靶类型：IPv4 %d / 域名 %d；域名靶中 hostname=null：%d（%.1f%%，Wilson 95%% %s）"
          % (r["ipv4_targets"], r["domain_targets"], r["domain_targets_null_hostname"],
             100 * (r["domain_null_share"] or 0), r["domain_null_wilson95"]))
    print("设了 hostname 的 %d 条中，hostname==target 的 %d 条"
          % (r["hostname_set"], r["hostname_equals_target_among_set"]))
    import time as _t
    print("时间跨度：%s → %s" % (_t.strftime("%Y-%m-%d", _t.gmtime(out["era"]["start_time_min"])),
                            _t.strftime("%Y-%m-%d", _t.gmtime(out["era"]["start_time_max"]))))
    print("-> %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
