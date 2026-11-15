#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_round2_ttl_pilot.py —— TTL 异质试点判读（o₁ 的真实判据：同一探针跨轮次）。

口径（写死）：
  * 每个 (靶, 探针) 在 12 轮里收集 `ttl` 值（ping 结果每行一个 ttl，代表该轮首个回包）；
  * **异质** = 存在某个探针，其 TTL 集合基数 > 1（同一路径的剩余跳数变了 ⇒ 后端/路径换了）；
  * 跨视角 TTL 不同**不算**（那是路径长度差异）；
  * 报告每靶：探针数、每探针轮次数、TTL 集合、以及"任一探针多值"的判定。

输出 data/c1/round2/ttl_pilot.json ＋ 控制台表。
用法：python tools/c1_round2_ttl_pilot.py [--cached]
"""
import argparse
import collections
import io
import json
import os
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R2 = os.path.join(ROOT, "data", "c1", "round2")
RAW = os.path.join(R2, "pilot_raw")
REG = os.path.join(R2, "msm_ids.json")
CAND = os.path.join(R2, "targets_candidates.json")
OUT = os.path.join(R2, "ttl_pilot.json")


def load(p):
    with io.open(p, encoding="utf-8", newline="") as f:
        return json.load(f)


def fetch(msm, cached):
    os.makedirs(RAW, exist_ok=True)
    p = os.path.join(RAW, "pl_%d.json" % msm)
    if os.path.exists(p) and cached:
        return load(p)
    url = "https://atlas.ripe.net/api/v2/measurements/%d/results/?page_size=1000" % msm
    req = urllib.request.Request(url, headers={"User-Agent": "c1-round2-ttl/1.0"})
    try:
        d = json.loads(urllib.request.urlopen(req, timeout=180).read().decode())
        io.open(p, "w", encoding="utf-8", newline="").write(json.dumps(d, ensure_ascii=False))
        return d
    except Exception:
        return load(p) if os.path.exists(p) else []


def classify(seq):
    """seq = [(ttl, rtt_mean)]，按时间排序。返回该探针的跳变形态。

    persistent      = 偏离众数 TTL 的**独立区段 ≥2**（反复离开又回来 ⇒ 多后端候选）
    sustained_shift = 只有两段且各 ≥2 轮（一次性平移后稳定 ⇒ 更像路由变化）
    single_excursion= 只偏离一次（单轮毛刺，证据最弱）
    这是叠加在预注册二值判据（TTL 集合基数 >1）之上的**报告分层**，不改变纳入判定。
    """
    vals = [t for t, _ in seq if t is not None]
    if len(set(vals)) < 2:
        return None
    runs = []
    for t in vals:
        if runs and runs[-1][0] == t:
            runs[-1][1] += 1
        else:
            runs.append([t, 1])
    modal = collections.Counter(vals).most_common(1)[0][0]
    exc = [r for r in runs if r[0] != modal]
    if len(exc) >= 2:
        kind = "persistent"
    elif len(runs) == 2 and min(runs[0][1], runs[1][1]) >= 2:
        kind = "sustained_shift"
    else:
        kind = "single_excursion"
    by = collections.defaultdict(list)
    for t, r in seq:
        if t is not None and r is not None:
            by[t].append(r)
    means = {t: sum(v) / len(v) for t, v in by.items() if v}
    flat = None
    if len(means) >= 2 and min(means.values()) > 0:
        lo, hi = min(means.values()), max(means.values())
        flat = (hi - lo) / lo < 0.10
    return {"kind": kind, "n_runs": len(runs), "n_excursions": len(exc),
            "runs": runs, "rtt_mean_by_ttl": {str(t): round(m, 1) for t, m in sorted(means.items())},
            "rtt_flat": flat}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cached", action="store_true")
    a = ap.parse_args()

    reg = load(REG)["measurements"]
    ip2dom = {}
    cache = os.path.join(R2, "screen_raw", "ip2dom.json")
    if os.path.exists(cache):
        ip2dom = load(cache)
    rows = []
    for r in reg:
        if r.get("group") != "ping_ttl_pilot":
            continue
        data = fetch(r["msm_id"], a.cached)
        # 两个量必须分开：rounds = 该探针回了几轮；ttls = 其中出现过的不同 TTL。
        # 早期版本把 len(set(ttl)) 当轮次，恒定 TTL 的探针会永远显示"1 轮"，严重低估分母。
        per = collections.defaultdict(set)
        rounds = collections.Counter()
        seq = collections.defaultdict(list)
        for row in sorted(data, key=lambda x: x.get("timestamp", 0)):
            pid = row.get("prb_id")
            if pid is None:
                continue
            rounds[pid] += 1
            t = row.get("ttl")
            ok = t if isinstance(t, int) and t > 0 else None
            if ok is not None:
                per[pid].add(ok)
            rs = row.get("result") or []
            rtts = [x.get("rtt") for x in rs if isinstance(x, dict) and x.get("rtt")]
            seq[pid].append((ok, sum(rtts) / len(rtts) if rtts else None))
        ip = data[0].get("dst_addr") if data else None
        dom = ip2dom.get(ip) if ip else None
        multi = {p: sorted(s) for p, s in per.items() if len(s) > 1}
        classes = {p: c for p in sorted(seq) if (c := classify(seq[p]))}
        n_pers = sum(1 for c in classes.values() if c["kind"] == "persistent")
        strength = "strong" if n_pers >= 2 else ("medium" if n_pers == 1 else ("weak" if classes else None))
        rows.append({"msm_id": r["msm_id"], "domain": dom, "target_ip": ip,
                     "probes": len(per),
                     "rounds_per_probe": sorted(rounds[p] for p in per)[:8],
                     "rounds_total": sum(rounds.values()),
                     "ttl_multi_probes": multi,
                     "probe_classes": {str(p): c for p, c in classes.items()},
                     "n_persistent_probes": n_pers, "strength": strength,
                     "hetero": bool(multi)})

    doms = collections.defaultdict(list)
    for x in rows:
        if x["domain"]:
            doms[x["domain"]].append(x)
    rank = {"strong": 3, "medium": 2, "weak": 1, None: 0}
    summary = {d: {"msms": len(v), "hetero": any(x["hetero"] for x in v),
                   "probes": sum(x["probes"] for x in v),
                   "n_persistent_probes": sum(x["n_persistent_probes"] for x in v),
                   "strength": max((x["strength"] for x in v), key=lambda s: rank[s]),
                   "target_ip": next((x["target_ip"] for x in v if x["target_ip"]), None),
                   "multi": {str(x["msm_id"]): x["ttl_multi_probes"] for x in v if x["ttl_multi_probes"]}}
               for d, v in doms.items()}

    out = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "rule": "same probe, TTL set cardinality > 1 across rounds",
           "strength_rule": "persistent=偏离众数 TTL 的独立区段>=2；strong>=2 个 persistent 探针，medium=1，weak=0",
           "n_targets": len(summary), "n_hetero": sum(1 for v in summary.values() if v["hetero"]),
           "n_by_strength": dict(collections.Counter(v["strength"] for v in summary.values() if v["hetero"])),
           "summary": summary, "rows": rows}
    io.open(OUT, "w", encoding="utf-8", newline="").write(json.dumps(out, ensure_ascii=False, indent=1))

    print("%-22s %-5s %-6s %-6s %-8s %s" % ("domain", "msm", "probes", "hetero", "strength", "persistent/形态"))
    for d in sorted(summary):
        v = summary[d]
        kinds = collections.Counter(c["kind"] for x in doms[d] for c in x["probe_classes"].values())
        print("%-22s %-5d %-6d %-6s %-8s %s" % (d, v["msms"], v["probes"], "YES" if v["hetero"] else "-",
                                              v["strength"] or "-", dict(kinds) or ""))
    print("\n%d 个靶，异质 %d 个（强度 %s）-> %s"
          % (len(summary), out["n_hetero"], out["n_by_strength"], OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
