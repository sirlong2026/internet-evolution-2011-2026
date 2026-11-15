#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_table5.py — 生成 Table 5（第二轮逐对审计表）的 Markdown 块。

为什么单独生成：Table 5 的 12 行全部来自判卷产物，手抄一次就多一处漂移风险。
本脚本从 `campaign_judged.json` 逐字段取数，输出可直接粘进
`paper/cline_results_draft_v0.1.md` §4.8 的表块；装配器会把它摘到
"## Tables" 节（编号必须连续，故放在 Table 4 之后）。

红线：靶标匿名 A–L（按主测量 ID 升序），表内零域名；标签映射随 artifact 发布。
窗口未闭合时默认拒跑；预演加 `--draft`（此时输出到 `_postclose/`，不碰稿件）。

用法：
  python tools/c1_table5.py                       # 收窗后：写 staging 文件
  python tools/c1_table5.py --draft --out <path>   # 预演
"""
import argparse
import io
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
JUDGED = os.path.join(ROOT, "data", "c1", "round2", "campaign_judged.json")

VERDICT_EN = {"决定可判": "decidable", "不可分辨": "indistinguishable",
              "条件可判": "conditionally decidable"}
# 稿件是 Markdown→docx，不跑 LaTeX：下标必须用 Unicode（与 Table 3 的 c₃ 同款），
# 写成 $c_5$ 会原样印出美元符。
WINNER_EN = {"single": "single backend", "c1": "c₁", "c2": "c₂ (round-robin)",
             "c3": "c₃", "c4": "c₄", "c5": "c₅ (name-conditioned)",
             "c8": "c₈"}
ARM_EN = {"control_single_sni": "negative control", "control_positive_sni": "positive control",
          "hetero_sni": "heterogeneous", "rig_rotation": "rotation rig"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "data", "c1", "round2",
                                                  "_postclose", "table5.md"))
    ap.add_argument("--draft", action="store_true")
    a = ap.parse_args()

    with io.open(JUDGED, encoding="utf-8") as f:
        d = json.load(f)
    closed = bool((d.get("window") or {}).get("closed"))
    if not closed and not a.draft:
        raise SystemExit("判卷窗口未收窗——拒绝生成终稿表；预演请加 --draft")

    rows = sorted(d["rows"], key=lambda r: int(r["msm_a"]))
    letters = "ABCDEFGHIJKL"
    assert len(rows) <= len(letters), "匿名标签不够用：%d 对" % len(rows)

    cov = all(r.get("coverage_ok") for r in rows)
    rounds = sorted({r["rounds_a"] for r in rows})
    head = ("**[DRAFT] Table 5 — Round-2 per-pair outcomes, mid-window.** " if not closed
            else "**Table 5 — Round-2 per-pair outcomes at the data close.** ")
    legend = (head + "All twelve pairs share the same four probes, staggered by at "
              "least 60 s between the own-name and the reserved-name arm. Fingerprints "
              "are the distinct leaf certificates observed over the whole window under "
              "each name condition. " +
              ("All pairs satisfy the window-coverage gate" if cov
               else "[DRAFT] the window-coverage gate is not yet satisfied for every pair") +
              (" (%s hourly rounds per pair). " % ("/".join(str(x) for x in rounds))
               if len(rounds) == 1 else " (rounds %d–%d per pair). " % (rounds[0], rounds[-1])) +
              "o₄ is the name-condition observation (positive when the certificate "
              "returned depends on the presented name). Pairs are anonymized as A–L, "
              "ordered by ascending primary measurement ID; the label-to-target mapping "
              "is released with the artifact package. The rotation rig's deployment is "
              "the known answer: round-robin over two registered certificates.")
    out = [legend, ""]
    out.append("| Pair | Arm | Handshakes | Hourly rounds | o₄ | Leaf fingerprints "
               "(own / reserved) | Verdict | Winning family |")
    out.append("|---|---|---|---|---|---|---|---|")
    for i, r in enumerate(rows):
        ident, contrast = set(), set()
        for v in (r.get("fp_sets") or {}).values():
            ident.update(v.get("identity") or [])
            contrast.update(v.get("contrast") or [])
        v = r.get("verdict") or {}
        arm = "rotation rig (known: multi)" if r["arm"] == "rig_rotation" \
            else ARM_EN.get(r["arm"], r["arm"])
        out.append("| %s | %s | %d | %d | %s | %d / %d | %s | %s |" % (
            letters[i], arm, r["handshakes_a"], r["rounds_a"], r.get("o4") or "—",
            len(ident), len(contrast),
            VERDICT_EN.get(v.get("V"), v.get("V")),
            WINNER_EN.get(v.get("winner"), v.get("winner")) or "—"))
    out.append("")
    out.append("")

    text = "\n".join(out)
    p = a.out
    if not os.path.isdir(os.path.dirname(p)):
        os.makedirs(os.path.dirname(p))
    with io.open(p, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    print(text)
    print("-> %s  (window closed: %s)" % (p, closed))


if __name__ == "__main__":
    main()
