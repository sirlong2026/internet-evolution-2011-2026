#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_r2_fill.py —— 第二轮四个 TBD 槽的**机械填充器**（只读判卷结果，不写稿件）。

为什么单独做一个：收窗后填数必须"一个数只从一处来"，不能手抄。本脚本从
data/c1/round2/campaign_judged.json 直接生成四段英文句子，逐条对应 §4.8 的槽位：

  [TBD-R2-1] o₄ 结果分布在 12 对上的分布
  [TBD-R2-2] 阴性对照被判 single-backend 的比例 ＋ Wilson 95%
  [TBD-R2-3] 两个异质靶的判词
  [TBD-R2-4] 轮换 rig 在两名条件下的已知答案判词

**闸**：判卷不满额一律拒绝出句（缺对、缺判词、rig 缺席、异质不足、**窗口未收/覆盖不足**）——
宁可让收口停下，也不让半成品数字进稿。`--force` 仅供草稿预览，输出会带 DRAFT 标记。

用法：
  python tools/c1_r2_fill.py            # 满了才输出；不满则列出缺什么并退出 2
  python tools/c1_r2_fill.py --force    # 草稿预览（带 DRAFT 前缀）
"""
import argparse
import io
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R2 = os.path.join(ROOT, "data", "c1", "round2")
JUDGED = os.path.join(R2, "campaign_judged.json")
EXPECT_PAIRS = 12
EXPECT_SINGLE = 8
V_EN = {"决定可判": "decidable", "条件可判": "conditionally decidable",
        "不可分辨": "indistinguishable", "不可观测": "unobservable"}


def en(v):
    return V_EN.get(v, v) if v else "n/a"


def load(p):
    with io.open(p, encoding="utf-8", newline="") as f:
        return json.load(f)


def wil_str(w):
    return "%.1f%%–%.1f%%" % (100 * w[0], 100 * w[1]) if w else "n/a"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--out", default=os.path.join(R2, "r2_sentences.json"))
    a = ap.parse_args()

    j = load(JUDGED)
    rows = j.get("rows") or []
    by = {"control_single_sni": [], "control_positive_sni": [],
          "hetero_sni": [], "rig_rotation": []}
    for r in rows:
        if r.get("arm") in by:
            by[r["arm"]].append(r)

    def st(r):
        return (r.get("verdict") or {}).get("V")

    problems = []
    if len(rows) != EXPECT_PAIRS:
        problems.append("配对 %d 条（应 %d）" % (len(rows), EXPECT_PAIRS))
    if len(by["control_single_sni"]) != EXPECT_SINGLE:
        problems.append("阴性对照 %d 条（应 %d）" % (len(by["control_single_sni"]), EXPECT_SINGLE))
    for arm in ("control_single_sni", "control_positive_sni", "hetero_sni", "rig_rotation"):
        miss = [r.get("label") for r in by[arm] if not st(r)]
        if miss:
            problems.append("%s 有 %d 条未判：%s" % (arm, len(miss), ", ".join(map(str, miss))))

    # 窗口闸：判卷器必须已重拉到收窗（半窗数据即使"每对都有判词"也不得进稿）
    win = j.get("window") or {}
    if not win.get("closed"):
        problems.append("窗口未收（平台 stop_time=%s，closed=%s）"
                        % (win.get("close_at"), win.get("closed")))
    short = [r.get("label") for r in rows if not r.get("coverage_ok")]
    if short:
        problems.append("窗口覆盖不足 %d 对：%s" % (len(short), ", ".join(map(str, short))))

    rows_ok = [r for r in rows if st(r)]
    o4 = {"negative": sum(1 for r in rows_ok if r.get("o4") == "negative"),
          "positive": sum(1 for r in rows_ok if r.get("o4") == "positive"),
          "unobservable": sum(1 for r in rows_ok if r.get("o4") not in ("negative", "positive"))}
    neg = [r for r in by["control_single_sni"] if st(r)]
    n_single = sum(1 for r in neg if (r["verdict"] or {}).get("family") == "single")
    het = [r for r in by["hetero_sni"] if st(r)]
    rig = [r for r in by["rig_rotation"] if st(r)]

    if problems and not a.force:
        print("拒绝出句（收窗未满或判卷不全）：")
        for p in problems:
            print("  - " + p)
        return 2

    pre = "[DRAFT] " if problems else ""
    FAM = {"single": "single-backend", "multi": "multi-backend", "undecided": "undecided"}
    fam = lambda r: FAM.get((r.get("verdict") or {}).get("family"),
                            (r.get("verdict") or {}).get("family"))
    h2 = j.get("H2") or {}
    s = []
    s.append("%sOf the twelve address pairs, %d returned the same leaf certificate under "
             "both names and %d returned a different one%s."
             % (pre, o4["negative"], o4["positive"],
                ("; %d were unobservable" % o4["unobservable"]) if o4["unobservable"] else ""))
    s.append("%sOf the eight negative controls, %d (%.1f%%, 95%% Wilson interval %s) were "
             "judged single-backend, and the positive control returned %s under the %s family."
             % (pre, n_single, 100.0 * n_single / (len(by["control_single_sni"]) or 1),
                wil_str(h2.get("wilson95")),
                en(st(by["control_positive_sni"][0])) if by["control_positive_sni"] else "n/a",
                fam(by["control_positive_sni"][0]) if by["control_positive_sni"] else "n/a"))
    sts = [en(st(r)) for r in het]
    if len(set(sts)) == 1:
        s.append("%sBoth heterogeneous targets were judged %s under the %s family."
                 % (pre, sts[0], fam(het[0])))
    else:
        s.append("%sThe two heterogeneous targets were judged %s respectively."
                 % (pre, " and ".join(sts)))
    if rig:
        v = rig[0]["verdict"] or {}
        s.append("%sThe rotation rig returned %s under the %s family at κ = %s, %s under the two names."
                 % (pre, en(v.get("V")), fam(rig[0]), v.get("kappa"),
                    "presenting the same set of leaf certificates"
                    if rig[0].get("o4") == "negative"
                    else "presenting different leaf certificates"))
    else:
        s.append("%sThe rotation rig did not return a verdict." % pre)

    labels = ["[TBD-R2-1]", "[TBD-R2-2]", "[TBD-R2-3]", "[TBD-R2-4]"]
    payload = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "draft": bool(problems), "problems": problems,
               "slots": dict(zip(labels, s)),
               "H2": h2, "H1": j.get("H1"), "window": j.get("window"),
               "positive_control": (by["control_positive_sni"][0] if by["control_positive_sni"] else None),
               "rig_o4": (rig[0].get("o4") if rig else None)}
    io.open(a.out, "w", encoding="utf-8", newline="").write(
        json.dumps(payload, ensure_ascii=False, indent=1))
    print("槽 → 句子（数字全部来自 campaign_judged.json）\n")
    for lb, line in zip(labels, s):
        print(lb)
        print("  " + line + "\n")
    print("机读句子 -> %s" % a.out)
    if problems:
        print("⚠ 仍缺：")
        for p in problems:
            print("  - " + p)
        return 0 if a.force else 2
    print("满额，可填。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
