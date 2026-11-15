# Release copy (built by tools/build_repo_c1.py).
# make_figures.py reads figdata.json here and writes Figs. 1-3 next to it;
# regenerate its data with:  python ../analysis/c1_figure_data.py --out figdata.json
# c1_round2_figures.py reads ../data/c1/round2/campaign_judged.json and
# fig5_ci.json here, and writes Figs. 4-5 next to it.
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""c1_round2_figures.py — 第二轮证据配图（Fig. 4 四联 + Fig. 5 Wilson 森林图）。

为什么单独一个脚本：`make_figures.py` 是收口链第 5 步直接调用的文件，收口当天
不能带新代码（一处 bug 就停链）。本脚本独立成文件、独立输出名，收口链跑完再接入。

数据来源与红线
--------------
* Fig. 4：`data/c1/round2/campaign_judged.json`（判卷产物，字段级取数）。
* Fig. 5：`tools/lock_paper_c1.LOCKED_NUMBERS`——稿件数字的**唯一合法来源**。
  解析失败即抛错，绝不回落到手写数字。
* 靶标一律匿名 A–L（按主测量 ID 升序），标签映射随 artifact 发布；
  图里不出现任何域名。

窗口闸
------
判卷产物带 `window.closed`。未收窗时默认拒绝出终稿图；确需预演加 `--draft`，
此时图上打 DRAFT 水印，且输出目录应指向草稿处（不覆盖 paper/figures）。

用法
----
  python tools/c1_round2_figures.py --draft --out data/c1/round2/_figpreview
  python tools/c1_round2_figures.py                 # 收窗后出终稿（paper/figures）
"""
import argparse
import io
import json
import os
import re
import sys
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
JUDGED = os.path.join(ROOT, "data", "c1", "round2", "campaign_judged.json")
# 同一份脚本既跑工作树（tools/）也跑 artifact 包（figures/）：输出目录跟随布局，
# 包内没有 paper/figures，就落在脚本自己所在目录。
_OUT_WORKTREE = os.path.join(ROOT, "paper", "figures")
DEFAULT_OUT = _OUT_WORKTREE if os.path.isdir(_OUT_WORKTREE) else HERE

# ---- publication style（与 make_figures.py 同版式，跨图一致）------------------
plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.sans-serif"] = ["Arial", "DejaVu Sans", "Liberation Sans"]
plt.rcParams.update({"svg.fonttype": "none", "pdf.fonttype": 42, "ps.fonttype": 42})
plt.rcParams["mathtext.fontset"] = "custom"
plt.rcParams["mathtext.rm"] = "Arial"
plt.rcParams["mathtext.it"] = "Arial:italic"
plt.rcParams["mathtext.default"] = "it"
plt.rcParams["font.size"] = 7.5
plt.rcParams["axes.linewidth"] = 0.8
plt.rcParams["axes.spines.right"] = False
plt.rcParams["axes.spines.top"] = False
plt.rcParams["legend.frameon"] = False
plt.rcParams["xtick.major.width"] = 0.8
plt.rcParams["ytick.major.width"] = 0.8
plt.rcParams["xtick.major.size"] = 2.5
plt.rcParams["ytick.major.size"] = 2.5
plt.rcParams["xtick.direction"] = "out"
plt.rcParams["ytick.direction"] = "out"
plt.rcParams["savefig.facecolor"] = "white"

GRAY = {"dark": "0.15", "mid": "0.45", "light": "0.72", "pale": "0.90"}

VERDICT_EN = {"决定可判": "decidable", "不可分辨": "indistinguishable",
              "条件可判": "conditionally decidable"}
WINNER_EN = {"single": "single backend", "c1": "$c_1$", "c2": "$c_2$ (round-robin)",
             "c3": "$c_3$", "c4": "$c_4$", "c5": "$c_5$ (name-conditioned)",
             "c8": "$c_8$"}
# 图注进 Markdown→docx 的正文，不能用 mathtext（pandoc 会把 $c_2$ 当公式吞掉，
# Word 里只剩空括号）。图上标题仍用 WINNER_EN（matplotlib 渲染真下标）。
WINNER_PLAIN = {"single": "single backend", "c1": "c₁", "c2": "c₂ (round-robin)",
                "c3": "c₃", "c4": "c₄", "c5": "c₅ (name-conditioned)", "c8": "c₈"}
ARM_EN = {"control_single_sni": "negative control", "control_positive_sni": "positive control",
          "hetero_sni": "heterogeneous", "rig_rotation": "rotation rig"}


def load_judged():
    with io.open(JUDGED, encoding="utf-8") as f:
        return json.load(f)


def anonymize(rows):
    """按主测量 ID 升序给 A–L；返回 (rows, label_map)。"""
    order = sorted(rows, key=lambda r: int(r["msm_a"]))
    letters = "ABCDEFGHIJKL"
    assert len(order) <= len(letters), "匿名标签不够用：%d 对" % len(order)
    mapped = []
    for i, r in enumerate(order):
        rr = dict(r)
        rr["anon"] = letters[i]
        mapped.append(rr)
    return mapped, {letters[i]: int(r["msm_a"]) for i, r in enumerate(order)}


def fp_summary(r):
    """每对在两种名字条件下的去重指纹集：union over probes。"""
    ident, contrast = set(), set()
    for v in (r.get("fp_sets") or {}).values():
        ident.update(v.get("identity") or [])
        contrast.update(v.get("contrast") or [])
    return ident, contrast


def save(fig, out_dir, name, dpi=600):
    paths = []
    for ext, kw in (("pdf", {}), ("svg", {}), ("png", {"dpi": 300})):
        p = os.path.join(out_dir, "%s.%s" % (name, ext))
        fig.savefig(p, bbox_inches="tight", **kw)
        paths.append(p)
    # TIFF：投稿位图要求 RGB、无 alpha、LZW；matplotlib 直出带 alpha，故经 PNG 中转
    from PIL import Image
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=dpi, bbox_inches="tight")
    buf.seek(0)
    im = Image.open(buf).convert("RGB")
    p = os.path.join(out_dir, "%s.tiff" % name)
    im.save(p, format="TIFF", compression="tiff_lzw", dpi=(dpi, dpi))
    paths.append(p)
    return paths


# --------------------------------------------------------------- Fig. 4 -----

def fig4(rows, top, draft_note=None):
    n = len(rows)
    fig = plt.figure(figsize=(7.0, 6.1))
    gs = fig.add_gridspec(2, 3, height_ratios=[1.45, 1.0], hspace=0.55, wspace=0.42)

    # ---- (a) 逐对名字条件结果 -------------------------------------------
    ax = fig.add_subplot(gs[0, :])
    y = list(range(n))[::-1]
    for yy, r in zip(y, rows):
        ident, contrast = fp_summary(r)
        same = ident == contrast
        x = 0.0 if same else 1.0
        ax.scatter([x], [yy], s=36, marker="o" if same else "s",
                   facecolors="white" if same else GRAY["dark"],
                   edgecolors=GRAY["dark"], linewidths=0.9, zorder=3)
        ax.text(1.55, yy, "%d / %d" % (len(ident), len(contrast)),
                ha="left", va="center", fontsize=6.8, color=GRAY["mid"])
    ax.set_yticks(y)
    ax.set_yticklabels(["%s  %s" % (r["anon"], ARM_EN.get(r["arm"], r["arm"])) for r in rows],
                       fontsize=6.8)
    ax.set_xticks([0.0, 1.0])
    ax.set_xticklabels(["identical\n(both names)", "different\n(name-dependent)"])
    ax.set_xlim(-0.55, 2.35)
    ax.set_ylim(-0.8, n - 0.2)
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.text(1.55, n - 0.35, "leaf fingerprints\n(own name / reserved)",
            ha="left", va="bottom", fontsize=6.6, color=GRAY["mid"])
    ax.set_xlabel("fingerprint set under the two name conditions", fontsize=7.2)
    ax.set_title("(a)  Name-condition outcome across the twelve pairs", loc="left",
                 fontsize=8.0, pad=4)

    # ---- (b) 阴性对照：单后端比例 + Wilson 区间 -------------------------
    ax = fig.add_subplot(gs[1, 0])
    h2 = top["H2"]
    lo, hi = h2["wilson95"]
    ax.bar([0], [h2["share"] * 100], width=0.42, color=GRAY["pale"],
           edgecolor=GRAY["dark"], linewidth=0.9, hatch="///")
    ax.errorbar([0], [h2["share"] * 100],
                yerr=[[h2["share"] * 100 - lo * 100], [hi * 100 - h2["share"] * 100]],
                fmt="none", ecolor=GRAY["dark"], elinewidth=0.9, capsize=3)
    ax.text(0, hi * 100 + 3, "%d/%d" % (h2["single"], h2["n"]), ha="center", fontsize=7.0)
    ax.set_xticks([0])
    ax.set_xticklabels(["negative\ncontrols"], fontsize=7.0)
    ax.set_ylim(0, 118)
    ax.set_xlim(-0.62, 0.62)
    ax.set_ylabel("judged single-backend (%)", fontsize=7.2)
    ax.set_title("(b)  Single-backend verdicts", loc="left", fontsize=8.0, pad=4)

    # ---- (c) 机制分离：o4 × 胜出族 --------------------------------------
    ax = fig.add_subplot(gs[1, 1])
    xs = {"negative": 0, "positive": 1}
    ys = {"single": 0, "c5": 1, "c2": 2}
    marks = {"control_single_sni": ("o", "white"), "control_positive_sni": ("o", "none"),
             "hetero_sni": ("s", GRAY["mid"]), "rig_rotation": ("^", GRAY["dark"])}
    cell = {}
    for r in rows:
        k = (r.get("o4"), r["verdict"].get("winner"))
        cell[k] = cell.get(k, 0) + 1
    for (o4, win), cnt in cell.items():
        x, yy = xs[o4], ys.get(win, 0)
        ax.scatter([x], [yy], s=40 + 46 * cnt, marker="o",
                   facecolors=GRAY["pale"], edgecolors=GRAY["dark"], linewidths=0.9, zorder=2)
        ax.text(x, yy, str(cnt), ha="center", va="center", fontsize=7.0, zorder=3)
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["$o_4$ negative", "$o_4$ positive"], fontsize=6.8)
    ax.set_yticks([0, 1, 2])
    ax.set_yticklabels(["single", "$c_5$", "$c_2$"], fontsize=6.8)
    ax.set_xlim(-0.5, 1.5)
    ax.set_ylim(-1.0, 2.6)
    ax.set_ylabel("winning family", fontsize=7.2)
    ax.set_title("(c)  Mechanism separation", loc="left", fontsize=8.0, pad=4)

    # ---- (d) 已知答案 rig：支持度剖面 -----------------------------------
    ax = fig.add_subplot(gs[1, 2])
    rig = top["rig"][0]
    neg = next((r for r in rows if r["arm"] == "control_single_sni"
                and r["verdict"].get("winner") == "single"), None)
    het = next((r for r in rows if r["arm"] == "hetero_sni"), None)
    series = []
    if neg:
        series.append(("neg. control %s" % neg["anon"], neg["verdict"].get("support") or {}, "///"))
    if het:
        series.append(("hetero %s" % het["anon"], het["verdict"].get("support") or {}, "\\\\\\"))
    series.append(("rig (known: multi)", rig["verdict"].get("support") or {}, ""))
    keys = ["c1", "c2", "c3", "c4", "c5", "c8"]
    width = 0.26
    for i, (lab, sup, hatch) in enumerate(series):
        vals = [sup.get(k, 0) for k in keys]
        ax.bar([j + (i - 1) * width for j in range(len(keys))], vals, width=width,
               color=["white", GRAY["light"], GRAY["dark"]][i], edgecolor=GRAY["dark"],
               linewidth=0.7, hatch=hatch, label=lab)
    ax.set_xticks(range(len(keys)))
    ax.set_xticklabels(["$c_1$", "$c_2$", "$c_3$", "$c_4$", "$c_5$", "$c_8$"], fontsize=6.8)
    ax.set_ylabel("supporting observations", fontsize=7.2)
    ax.set_ylim(0, 7.0)
    ax.legend(fontsize=5.9, loc="upper right", bbox_to_anchor=(1.02, 0.86),
              handlelength=1.2, borderaxespad=0.0)
    ax.set_title("(d)  Known-answer rig", loc="left", fontsize=8.0, pad=4)
    ax.text(0.02, 0.97, "%s · %s\n$\\kappa$ = %.2f" %
            (VERDICT_EN.get(rig["verdict"].get("V"), rig["verdict"].get("V")),
             WINNER_EN.get(rig["verdict"].get("winner"), rig["verdict"].get("winner")).split(" (")[0],
             rig["verdict"].get("kappa", float("nan"))),
            transform=ax.transAxes, ha="left", va="top", fontsize=6.2, color=GRAY["mid"])

    if draft_note:
        fig.text(0.5, 0.012, draft_note, ha="center", va="bottom",
                 fontsize=7.0, color="0.55")
    return fig


# --------------------------------------------------------------- Fig. 5 -----

FOREST = [
    # (lock key, 显示名, 分组)
    ("ci_cand_routable", "candidates routable", "routing"),
    ("ci_cand_exact", "candidates exact", "routing"),
    ("ci_resolve", "mapped domains resolving", "service"),
    ("ci_ping_live", "addresses ICMP-live (all 100)", "address"),
    ("ci_ping_exact", "live: exact survivors", "address"),
    ("ci_ping_covered", "live: covered-only", "address"),
    ("ci_tls34", "resolving domains with TLS", "service"),
]
CI_RE = re.compile(r"(\d+)\s*/\s*(\d+)\s*=\s*([\d.]+)%.*?95% CI ([\d.]+)\s*[-\u2013]\s*([\d.]+)")


# 工作树：paper/figures/fig5_ci.json；artifact 包：与脚本同目录的 fig5_ci.json
CI_JSON = next((p for p in (os.path.join(_OUT_WORKTREE, "fig5_ci.json"),
                            os.path.join(HERE, "fig5_ci.json"))
                if os.path.exists(p)),
               os.path.join(_OUT_WORKTREE, "fig5_ci.json"))


def _parse_locked():
    """工作树里从锁模块取（唯一合法数字源），解析失败即报错。"""
    sys.path.insert(0, HERE)
    import lock_paper_c1 as L
    table = dict(L.LOCKED_NUMBERS)
    pts = []
    for key, label, layer in FOREST:
        raw = table.get(key)
        if raw is None:
            raise SystemExit("LOCKED_NUMBERS 缺 %s" % key)
        m = CI_RE.search(raw)
        if not m:
            raise SystemExit("%s 无法解析出 CI：%r" % (key, raw))
        k, n, pct, lo, hi = m.groups()
        pts.append({"key": key, "label": label, "layer": layer, "k": int(k),
                    "n": int(n), "pct": float(pct), "lo": float(lo), "hi": float(hi),
                    "raw": raw})
    return pts


def forest_points():
    """优先级：锁模块（工作树）> fig5_ci.json（artifact 包内没有锁模块）。

    两者都在时必须逐项一致，不一致直接退出——宁可不出图，也不出与锁不符的图。
    """
    try:
        pts = _parse_locked()
    except ImportError:
        if not os.path.exists(CI_JSON):
            raise SystemExit("既无锁模块也无 %s" % CI_JSON)
        with io.open(CI_JSON, encoding="utf-8") as f:
            return json.load(f)
    if os.path.exists(CI_JSON):
        with io.open(CI_JSON, encoding="utf-8") as f:
            cached = json.load(f)
        if [(p["key"], p["k"], p["n"], p["pct"], p["lo"], p["hi"]) for p in pts] != \
           [(p["key"], p["k"], p["n"], p["pct"], p["lo"], p["hi"]) for p in cached]:
            raise SystemExit("%s 与 LOCKED_NUMBERS 不一致——先 --emit-ci 重出" % CI_JSON)
    return pts


def fig5(pts, draft_note=None):
    order = {"routing": 0, "address": 1, "service": 2}
    # 同层内保持 FOREST 叙事顺序（总体→分层），不按比例重排
    pts = sorted(pts, key=lambda p: order[p["layer"]])
    fig, ax = plt.subplots(figsize=(6.4, 3.0))
    fig.subplots_adjust(bottom=0.26)
    y = list(range(len(pts)))[::-1]
    for yy, p in zip(y, pts):
        ax.plot([p["lo"], p["hi"]], [yy, yy], color=GRAY["dark"], lw=1.0, zorder=2)
        ax.scatter([p["pct"]], [yy], s=30, marker="o", facecolors="white",
                   edgecolors=GRAY["dark"], linewidths=1.0, zorder=3)
        ax.text(104, yy, "%d/%d" % (p["k"], p["n"]), va="center", fontsize=6.8)
        ax.text(114, yy, "%.1f (%.1f–%.1f)" % (p["pct"], p["lo"], p["hi"]),
                va="center", fontsize=6.5, color=GRAY["mid"])
    ax.set_yticks(y)
    ax.set_yticklabels([p["label"] + "  [%s]" % p["layer"] for p in pts], fontsize=6.9)
    # 层间分隔线（routing|address|service），让分组一眼可见
    for i in range(1, len(pts)):
        if pts[i]["layer"] != pts[i - 1]["layer"]:
            ax.axhline(y[i] + 0.5, color=GRAY["light"], lw=0.6, zorder=1)
    ax.set_xlim(0, 100)
    ax.set_xlabel("proportion (%),  point estimate with 95% Wilson score interval", fontsize=7.2)
    ax.axvline(0, color=GRAY["light"], lw=0.6, zorder=1)
    ax.tick_params(axis="y", length=0)
    ax.spines["left"].set_visible(False)
    ax.set_ylim(-0.7, len(pts) - 0.3)
    ax.text(104, len(pts) - 0.35, "k/n", fontsize=6.8, va="bottom")
    ax.text(114, len(pts) - 0.35, "estimate (95% CI)", fontsize=6.5,
            color=GRAY["mid"], va="bottom")
    if draft_note:
        fig.text(0.5, 0.005, draft_note, ha="center", va="bottom", fontsize=6.8, color="0.55")
    return fig


def legends(rows, top):
    h2, h1 = top["H2"], top["H1"]
    rig = top["rig"][0]
    n_diff = sum(1 for r in rows if fp_summary(r)[0] != fp_summary(r)[1])
    return """### Figure 4 | Second round: the name condition made explicit

**(a)** Fingerprint-set outcome for each of the twelve measurement pairs. Each pair ran two TLS arms against the same explicit address with the same four probes, staggered by at least 60 s: one presenting the target's own name, one presenting the reserved name `sni-control.invalid`. An open circle marks a pair whose leaf-fingerprint set was identical under both conditions (the name-conditioned hypothesis c₅ is eliminated); a filled square marks a pair whose set differed (the name selects the certificate). The pair labels A–L are assigned by ascending primary measurement ID; the label-to-target mapping is released with the artifact package. Numbers at the right give the number of distinct leaf fingerprints under the own-name and the reserved-name condition.

**(b)** Share of the %d negative controls judged single-backend: %d/%d (%.1f%%, 95%% Wilson score interval %.1f–%.1f%%). The heterogeneous arm is reported descriptively: %d/%d decidable, 95%% CI %.1f–%.1f%%, with n = %d fixed by the inclusion criteria.

**(c)** Separation of the two mechanisms by the name axis. Each point counts pairs at a combination of the name-condition observation o₄ and the winning behavioral family; area is proportional to the number of pairs. Eight pairs sit at (o₄ negative, single backend) — the seven single-backend negative controls and the positive control — while the three name-dependent pairs (one negative control and the two heterogeneous targets) sit at (o₄ positive, c₅), and the rotation rig sits at (o₄ negative, c₂).

**(d)** Support profile (number of supporting observations per backend-behavior hypothesis) for one representative negative control, one heterogeneous target, and the rotation rig. The rig's deployment is known in advance (round-robin over two registered certificates); the engine returns *%s*, won by %s, at κ = %.2f, reproducing the known answer from certificate observations alone.

*Source data:* judged round-2 campaign (derived statistics and per-pair verdicts of the artifact package); labels anonymized.

### Figure 5 | Cohort proportions with 95%% Wilson score intervals

Point estimates and intervals for the measured proportions, ordered by the layer they belong to (routing, address, service). Intervals are 95%% Wilson score intervals on the cohort proportion; an interval is shown for every cohort proportion plotted. The address-layer pair (live: exact survivors 44%%, covered-only 23%%) is the contrast tested by the two-sided Fisher exact test (p = 0.037); the two intervals do not overlap.

*Source data:* cohort survival, address-layer and service-layer summaries of the artifact package.
""" % (h2["n"], h2["single"], h2["n"], h2["share"] * 100,
       h2["wilson95"][0] * 100, h2["wilson95"][1] * 100,
       h1["decidable"], h1["n"], h1["wilson95"][0] * 100, h1["wilson95"][1] * 100, h1["n"],
       VERDICT_EN.get(rig["verdict"].get("V"), rig["verdict"].get("V")),
       WINNER_PLAIN.get(rig["verdict"].get("winner"), rig["verdict"].get("winner")),
       rig["verdict"].get("kappa", float("nan")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--draft", action="store_true", help="未收窗时预演：打水印")
    ap.add_argument("--emit-ci", action="store_true",
                    help="只把 Fig. 5 的区间数据落到 fig5_ci.json（artifact 包内据此重绘）")
    a = ap.parse_args()

    if a.emit_ci:
        pts = _parse_locked()
        with io.open(CI_JSON, "w", encoding="utf-8", newline="") as f:
            json.dump(pts, f, ensure_ascii=False, indent=1)
        print("ci -> %s (%d 项)" % (CI_JSON, len(pts)))
        return

    top = load_judged()
    closed = bool((top.get("window") or {}).get("closed"))
    if not closed and not a.draft:
        raise SystemExit("判卷窗口未收窗——拒绝出终稿图；预演请加 --draft")
    rows, label_map = anonymize(top["rows"])
    note = None
    if not closed:
        note = ("DRAFT — mid-window data read at %s; values change at the close"
                % time.strftime("%Y-%m-%dT%H:%MZ", time.gmtime()))

    if not os.path.isdir(a.out):
        os.makedirs(a.out)
    p4 = save(fig4(rows, top, note), a.out, "fig4_round2")
    p5 = save(fig5(forest_points(), note), a.out, "fig5_ci_forest")
    lg = os.path.join(a.out, "figure_legends_r2.md")
    with io.open(lg, "w", encoding="utf-8", newline="") as f:
        f.write(legends(rows, top))
    print("fig4 -> %s" % ", ".join(os.path.basename(p) for p in p4))
    print("fig5 -> %s" % ", ".join(os.path.basename(p) for p in p5))
    print("legends -> %s" % lg)
    print("labels: %s" % ", ".join("%s=%d" % (k, v) for k, v in label_map.items()))
    print("window closed: %s" % closed)


if __name__ == "__main__":
    main()
