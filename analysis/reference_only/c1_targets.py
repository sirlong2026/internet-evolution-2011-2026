#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# REFERENCE-ONLY — not executable in this release: requires the
# non-redistributable 2011 routing archive (SOURCES.md §1) and/or the
# author-internal workspace (paths renamed to "workspace" here).
# Shipped for method transparency.
"""c1_targets.py —— C1 选靶器（2026-11-08，评估文档 §4.1 C1 落地）。
阶段 A（2011 侧，现在可跑）：targets ∩ routes（LPM 覆盖即"2011 有公告"），
  asmap/netmap LPM 取 AS/org，assrc 取 AS 注册局；多宿主 org = netmap⋈asmap
  精确前缀连接后 org 对应 ≥2 个 as_name。分层 = registry × plen 桶（≤16/17–20/21–24），
  固定种子 20261108 抽约 200 候选（2 倍于所需 100，预筛损耗兜底），层内多宿主优先
  （样本为多宿主富集设计；无偏总体基线由 C0 全档案对比承担，论文须声明此口径）。
  代表 IP = 前缀首个可用地址（start+1；/31、/32 取 start）——口径写死，论文声明。
阶段 B（--today，RIB 下完后）：今日 RIB 前缀并集区间覆盖代表 IP = "今日仍公告"；
  同时记精确前缀存活（2011 前缀串原样在今日 RIB）vs 聚合覆盖（被更粗前缀罩住）。
  产出存活率分层表（C0/C1 头条数字）+ 100 靶终样。
纪律：ireg 只读；候选是第三方研究靶（2011 公开数据集），可落盘 data/c1/；
  我方基础设施 IP 不出现。云锚点不在选靶器里（c1_campaign.py 走环境变量注入）。
用法：
  python c1_targets.py                        # 阶段 A → data/c1/candidates_2011.json
  python c1_targets.py --today <prefixes.txt> # 阶段 B → data/c1/candidates_today.json
"""
import bisect
import ipaddress
import json
import os
import random
import sys
from collections import Counter, defaultdict

import duckdb

sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))
from workspace.lpm import LpmIndex  # noqa: E402

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
IREG = os.path.join(BASE, "workspace", "build", "ireg.duckdb")
LPM = os.path.join(BASE, "workspace", "build", "ireg.lpm")
OUT_DIR = os.path.join(BASE, "data", "c1")
SEED = 20261108
N_CANDIDATES = 200
N_FINAL = 100


def plen_bucket(plen):
    return "<=16" if plen <= 16 else ("17-20" if plen <= 20 else "21-24")


RIR = {"arin", "ripe", "apnic", "lacnic", "afrinic"}
NIR_TO_RIR = {"jpnic": "apnic", "krnic": "apnic", "apnici": "apnic"}  # apnici=源数据拼写变体


def norm_registry(r):
    """assrc.registry 是路由注册表来源（含 radb/altdb/ISP 库），归一到 RIR 层。"""
    if r in RIR:
        return r
    if r in NIR_TO_RIR:
        return NIR_TO_RIR[r]
    return "other"


def pick_registry(as_names, assrc):
    regs = {norm_registry(assrc[a]) for a in as_names if a in assrc}
    for pri in ("arin", "ripe", "apnic", "lacnic", "afrinic", "other"):
        if pri in regs:
            return pri
    return "unknown"


def stage_a():
    idx = LpmIndex.load(LPM)
    con = duckdb.connect(IREG, read_only=True)
    assrc = dict(con.execute("SELECT key, registry FROM assrc").fetchall())
    # 多宿主 org：org 的前缀精确连接 asmap 后对应 ≥2 个 AS 名
    mh_rows = con.execute(
        "SELECT n.org, COUNT(DISTINCT a.as_name) AS nas FROM netmap n "
        "JOIN asmap a ON n.prefix = a.prefix GROUP BY n.org HAVING nas >= 2").fetchall()
    multihomed = {org for org, _ in mh_rows}
    targets = con.execute("SELECT range_start, range_end, prefix_len, prefix FROM targets").fetchall()
    con.close()

    cands = []
    n_announced = 0
    for start, end, plen, prefix in targets:
        if not idx.contains("routes", start):
            continue
        n_announced += 1
        ash = idx.probe("asmap", start, first_only=True)
        as_names = list(ash[0].values) if ash else []
        nh = idx.probe("netmap", start, first_only=True)
        org = nh[0].values[0] if nh and nh[0].values else None
        registry = pick_registry(as_names, assrc)
        rep = start + 1 if plen <= 30 else start
        cands.append({
            "prefix": prefix, "start": start, "plen": plen,
            "rep_ip": str(ipaddress.IPv4Address(rep)),
            "org": org, "as_names": as_names, "registry": registry,
            "multihomed_org": bool(org and org in multihomed),
            "stratum": "%s|%s" % (registry, plen_bucket(plen)),
        })

    by_stratum = defaultdict(list)
    for c in cands:
        by_stratum[c["stratum"]].append(c)
    rng = random.Random(SEED)
    # 两级名额：RIR 组保底 10（池不足则全取），余额按池比例；组内按 plen 桶比例（每桶≥1）。
    # 2011 靶群本身 arin 占绝对多数——保底是横截面外部效度设计，meta 记池规模供重加权。
    by_rir = defaultdict(list)
    for s, v in by_stratum.items():
        by_rir[s.split("|")[0]].extend(v)
    rir_quota = {}
    floor_total = 0
    for r, v in by_rir.items():
        q = min(10, len(v))
        rir_quota[r] = q
        floor_total += q
    remain = N_CANDIDATES - floor_total
    big = sorted(by_rir, key=lambda r: -len(by_rir[r]))
    pool_total = sum(len(v) for v in by_rir.values())
    for r in big:  # 余额按池比例（最大者先取，末位吃剩余，确定性）
        extra = remain * len(by_rir[r]) // pool_total
        rir_quota[r] += extra
    assigned = sum(rir_quota.values())
    if assigned < N_CANDIDATES and big:
        rir_quota[big[0]] += N_CANDIDATES - assigned

    quota = {}
    sample = []
    for r, v in sorted(by_rir.items()):
        cells = defaultdict(list)
        for c in v:
            cells[c["stratum"]].append(c)
        cq = {s: max(1, rir_quota[r] * len(cv) // len(v)) for s, cv in cells.items()}
        for s, cv in sorted(cells.items()):
            cv.sort(key=lambda c: (not c["multihomed_org"], rng.random()))
            sample.extend(cv[:cq[s]])
            quota[s] = cq[s]
    sample = sample[:N_CANDIDATES]

    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, "candidates_2011.json")
    meta = {"seed": SEED, "targets_total": len(targets), "announced_2011": n_announced,
            "multihomed_orgs": len(multihomed), "candidates": len(sample),
            "stratum_quota": quota,
            "stratum_pool": {s: len(v) for s, v in sorted(by_stratum.items())},
            "rir_quota": rir_quota,
            "stratum_sampled": dict(Counter(c["stratum"] for c in sample)),
            "rep_ip_caliber": "first usable address of 2011 target prefix (start+1; /31,/32=start)",
            "registry_caliber": "assrc source normalized to RIR; NIR jpnic/krnic/apnici->apnic; radb/ISP registries->other; multi-source AS takes first RIR by fixed priority"}
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "candidates": sample}, f, ensure_ascii=False, indent=1)
    print("targets=%d announced_2011=%d (%.1f%%) multihomed_orgs=%d" % (
        len(targets), n_announced, 100 * n_announced / len(targets), len(multihomed)))
    print("sample=%d strata=%d" % (len(sample), len(by_stratum)))
    for s, n in sorted(meta["stratum_sampled"].items()):
        print("  %-22s %d" % (s, n))
    print("->", out)


def stage_b(today_path):
    with open(os.path.join(OUT_DIR, "candidates_2011.json"), encoding="utf-8") as f:
        data = json.load(f)
    cands = data["candidates"]
    intervals = []
    exact = set()
    with open(today_path, encoding="utf-8") as f:
        for line in f:
            s, p = line.split()
            s, p = int(s), int(p)
            intervals.append((s, s + (1 << (32 - p)) - 1 if p else s + (1 << 32) - 1))
            exact.add((s, p))
    intervals.sort()
    starts = [a for a, _ in intervals]
    # 合并重叠区间供覆盖查询
    merged = []
    for s, e in intervals:
        if merged and s <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    mstarts = [a for a, _ in merged]

    def covered(x):
        i = bisect.bisect_right(mstarts, x) - 1
        return i >= 0 and x <= merged[i][1]

    stats = Counter()
    today = []
    for c in cands:
        ip = int(ipaddress.IPv4Address(c["rep_ip"]))
        cov = covered(ip)
        ex = (c["start"], c["plen"]) in exact
        c["today_covered"] = cov
        c["today_exact"] = ex
        stats[(c["stratum"], "covered" if cov else "withdrawn")] += 1
        if cov:
            today.append(c)
    # 终样 100：层比例保持，多宿主优先（阶段 A 已排序，按原序取）
    final = today[:N_FINAL]
    out = {"meta": {**data["meta"], "today_source": os.path.basename(today_path),
                    "candidates_today": len(today), "final": len(final),
                    "survival_rate": len(today) / len(cands) if cands else None},
           "survival_by_stratum": {"%s|%s" % k: v for k, v in sorted(stats.items())},
           "candidates": today, "final": final}
    outp = os.path.join(OUT_DIR, "candidates_today.json")
    with open(outp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print("today RIB prefixes=%d (merged intervals=%d)" % (len(intervals), len(merged)))
    print("candidates covered=%d/%d (%.1f%%) exact-prefix alive=%d final=%d" % (
        len(today), len(cands), 100 * len(today) / len(cands),
        sum(1 for c in today if c["today_exact"]), len(final)))
    print("->", outp)


def main():
    if "--today" in sys.argv:
        stage_b(sys.argv[sys.argv.index("--today") + 1])
    else:
        stage_a()


if __name__ == "__main__":
    main()