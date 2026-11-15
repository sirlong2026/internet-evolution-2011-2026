#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_round2_whitelist.py —— 由 pretest 结果算白名单（prereg §4 的 D5 规则，逐条照做）。

规则（预注册原文）：
  * 取"在全部 9 个对照靶上、两种名字条件下都完成握手"的探针 **交集**；
  * 交集 ≥4 ⇒ 直接用（每靶 4，可选 6）；
  * 不足 4 ⇒ 按"达标靶数降序 → 该靶握手数降序 → prb_id 升序"补齐，
    补齐个数与理由写 `deviations.md`（论文里如实报）。

输入：
  data/c1/round2/msm_ids.json      —— 发起器登记（arm/group/type/msm_id）
  data/c1/round2/targets_controls_all.json —— 靶表（已去重、含 identity_name）
输出：
  data/c1/round2/probe_whitelist.json      —— {prb_ids, per_target, source, rule}
  data/c1/round2/deviations.md             —— 追加一段（若发生补齐/剔除）

纪律：结果里的靶地址只在内存里用于映射，写盘只写域名标签与 prb_id。
用法：python tools/c1_round2_whitelist.py [--cached]
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
RAW = os.path.join(ROOT, "data", "c1", "round2", "pretest_raw")
MSM = os.path.join(R2, "msm_ids.json")
TARGETS = os.path.join(R2, "targets_controls_all.json")
OUT = os.path.join(R2, "probe_whitelist.json")
DEV = os.path.join(R2, "deviations.md")
WANT = 4


def load(p):
    with io.open(p, encoding="utf-8", newline="") as f:
        return json.load(f)


def fetch(msm, cached):
    os.makedirs(RAW, exist_ok=True)
    p = os.path.join(RAW, "pt_%d.json" % msm)
    # 空缓存必须重取：测量处于 Specified 时拉到的 [] 会被落盘，
    # 若按"文件存在即命中"短路，白名单会永久停在 5/9 靶（2026-11-12 实测踩到）。
    if os.path.exists(p):
        got = load(p)
        if got and (cached or os.path.getsize(p) > 2):
            return got
    url = "https://atlas.ripe.net/api/v2/measurements/%d/results/?page_size=1000" % msm
    req = urllib.request.Request(url, headers={"User-Agent": "c1-round2-whitelist/1.0"})
    for _ in range(3):
        try:
            data = json.loads(urllib.request.urlopen(req, timeout=180).read().decode())
            with io.open(p, "w", encoding="utf-8", newline="") as f:
                f.write(json.dumps(data, ensure_ascii=False))
            return data
        except Exception:
            time.sleep(5)
    return []


def has_cert(row):
    c = row.get("cert")
    if not c:
        return False
    if isinstance(c, list):
        return any("BEGIN CERTIFICATE" in str(x) for x in c)
    return "BEGIN CERTIFICATE" in str(c)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cached", action="store_true")
    a = ap.parse_args()

    reg = load(MSM)["measurements"]
    tgts = load(TARGETS)["targets"]
    ip2dom = {t["target_ip"]: t["identity_name"] for t in tgts}

    # arm → {(domain, name_condition): {prb: handshakes}}
    hands = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
    for r in reg:
        if not str(r.get("group", "")).startswith("tls_pretest"):
            continue
        cond = "identity" if r["group"].endswith("identity") else "contrast"
        data = fetch(r["msm_id"], a.cached)
        # 靶：结果行里有 dst_addr；msm 级 target 也要，二者任一
        for row in data:
            ip = row.get("dst_addr") or row.get("dst_ip")
            dom = ip2dom.get(ip)
            if not dom:
                continue
            if has_cert(row):
                hands[dom][cond][row.get("prb_id")] += 1

    domains = sorted({t["identity_name"] for t in tgts})
    missing = [d for d in domains if d not in hands]
    # 每靶两条件下的成功探针集合
    per_target = {}
    for d in domains:
        per_target[d] = {
            cond: sorted(p for p, n in hands.get(d, {}).get(cond, {}).items() if n >= 1)
            for cond in ("identity", "contrast")
        }

    # 交集：9 靶 × 2 条件全部成功
    full = [d for d in domains if per_target[d]["identity"] and per_target[d]["contrast"]]
    # 修复（2026-11-11）：原写法 set(full[0]) 取的是**域名字符**不是探针集合，
    # 导致交集恒为 0、误触发补齐。正确起点是首个双条件达标靶的两条件交集。
    inter = (set(per_target[full[0]]["identity"]) & set(per_target[full[0]]["contrast"])) if full else set()
    for d in full[1:]:
        inter &= set(per_target[d]["identity"]) & set(per_target[d]["contrast"])
    inter = sorted(inter)

    rule = "intersection"
    chosen = inter[:WANT]
    if len(inter) < WANT:
        rule = "backfill"
        cover = collections.Counter()
        total = collections.Counter()
        for d in full:
            ok = set(per_target[d]["identity"]) & set(per_target[d]["contrast"])
            for p in ok:
                cover[p] += 1
            for p, n in hands[d]["identity"].items():
                total[p] += n
        ranked = sorted(cover, key=lambda p: (-cover[p], -total[p], p))
        chosen = ranked[:WANT]

    out = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "rule": rule, "want": WANT,
        "prb_ids": chosen,
        "intersection_size": len(inter),
        "targets_with_both_conditions": len(full),
        "targets_missing_results": missing,
        "per_target": per_target,
        "note": "prereg §4/D5：交集 >=4 直接用；不足 4 按达标靶数降序补齐并写 deviations",
    }
    with io.open(OUT, "w", encoding="utf-8", newline="") as f:
        f.write(json.dumps(out, ensure_ascii=False, indent=1))
    print("白名单 %d 个（规则=%s，交集=%d，双条件达标靶=%d/%d）"
          % (len(chosen), rule, len(inter), len(full), len(domains)))
    print("  prb_ids =", chosen)
    if missing:
        print("  ⚠ 无结果的靶：%s" % ", ".join(missing))

    if rule == "backfill" or missing:
        with io.open(DEV, "a", encoding="utf-8", newline="") as f:
            f.write("\n## pretest 白名单（%s）\n\n" % out["at"])
            f.write("- 规则：%s；交集 %d 个；双条件达标靶 %d/%d\n"
                    % (rule, len(inter), len(full), len(domains)))
            f.write("- 选定 prb：%s\n" % chosen)
            if missing:
                f.write("- 无结果的靶：%s\n" % ", ".join(missing))
            f.write("- 按 prereg §4 如实报：补齐/缺失均不隐藏\n")
        print("  → 已追加 deviations.md")
    print("-> %s" % OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
