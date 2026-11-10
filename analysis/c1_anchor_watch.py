#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_anchor_watch.py —— 云锚 msm 234216930 轮换进度监视（v2，2026-11-08）。

已知答案（pilot_truth.json 预注册）：RR 双证书轮换——合法叶指纹只有
  A=9b03a055ff2b3613 (CN=pilot-a.local) / B=e4c5b5f977df46ce (CN=pilot-b.local)，
预期：每视角 ≥3 握手后轮换命中（o₃ positive）、跨视角并集=2（o₆ positive）、
  无第三指纹、判定 c2/likely_pool/decidable、κ=2/6=0.333（sslcert-only 恰过闸）。
本监视只做数据面健康检查（不替代 c1_judge 判卷）：
  - 每视角握手数 / 双指纹覆盖进度；
  - 出现合法集之外指纹 → 立即告警（指纹集漂移）；
  - 连续 alert（如 40 handshake_failure）→ 告警（后端可达性）。
o₃ 成对闸（≥2 视角各 ≥3 握手且双指纹齐，够 pick_pair）满足时打印 PAIR-READY 并退出；
~11h 未齐则超时退出（届时若仍 <2 有效视角 → 补位测量决策，新花费需用户确认）。
"""
import json
import sys
import time
import urllib.request

LAB = r"<NON_REDISTRIBUTIBLE_2011_ARCHIVE>\workspace\lab"
sys.path.insert(0, LAB)
from atlas_adapter import _leaf_hash  # noqa: E402

MSM = 234216930
EXPECT_FP = {"9b03a055ff2b3613", "e4c5b5f977df46ce"}   # A / B
VANTAGES = (28, 81, 6349, 234)

state = {}      # prb -> {"hands": n, "fps": set(), "alerts": n}
last_len = 0
for i in range(45):        # 15min × 45 ≈ 11h
    try:
        with urllib.request.urlopen(
                "https://atlas.ripe.net/api/v2/measurements/%d/results/" % MSM,
                timeout=60) as f:
            raw = json.loads(f.read().decode())
    except Exception as ex:
        print("check %d transport err: %s" % (i, ex))
        time.sleep(900)
        continue
    for r in raw:
        prb = r.get("prb_id")
        st = state.setdefault(prb, {"hands": 0, "fps": set(), "alerts": 0})
        if r.get("cert"):
            st["hands"] += 1
            st["fps"].add(_leaf_hash(r["cert"][0])[:16])
        if r.get("alert"):
            st["alerts"] += 1
    if len(raw) != last_len:
        last_len = len(raw)
        union = set().union(*[s["fps"] for s in state.values()]) if state else set()
        stray = union - EXPECT_FP
        ready = sum(1 for p in VANTAGES
                    if state.get(p, {}).get("hands", 0) >= 3
                    and len(state.get(p, {}).get("fps", set())) >= 2) >= 2
        print("[%s] results=%d | %s | union=%d %s" % (
            time.strftime("%H:%M UTC", time.gmtime()), len(raw),
            " ".join("p%d:%d%s%s" % (p, state.get(p, {}).get("hands", 0),
                                     "/A" if "9b03a055ff2b3613" in state.get(p, {}).get("fps", set()) else "",
                                     "/B" if "e4c5b5f977df46ce" in state.get(p, {}).get("fps", set()) else "")
                     for p in VANTAGES),
            len(union), "stray=" + ",".join(sorted(stray)) if stray else "no-stray"))
        alerts = {p: s["alerts"] for p, s in state.items() if s["alerts"]}
        if alerts:
            print("  alerts:", alerts)
        if ready:
            print("PAIR-READY: 两视角 ≥3 握手且双指纹齐——可进 c1_judge 正式判定（预期 c2/likely_pool）")
            sys.exit(0)
    time.sleep(900)
print("timeout: ~11h 未成对齐全——若仍 <2 有效视角，考虑补位测量（新花费需用户确认）")
