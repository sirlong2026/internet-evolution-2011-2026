# Release copy (built by tools/build_repo_c1.py): reads figdata.json in this
# directory and writes the three figure files next to it. Regenerate the
# figure data first with:  python ../analysis/c1_figure_data.py --out figdata.json
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""make_figures.py — C 线稿件配图（IJNM 投稿规格：矢量 PDF + 600 dpi TIFF + 可编辑 SVG）。

图数据唯一来源：paper/figures/figdata.json（由 tools/c1_figure_data.py 从**已发布
artifact 包**的派生统计抽取，每个数带 provenance）。本脚本不读原始测量、不算数、
不手写任何数字：图里出现的每个数都从 figdata.json 取。

三张图各自守住一个主张（figure contract）：
  Fig.1 四层存活性级联 —— 主张：路由→地址→服务三层逐级衰减，到服务层 2011 的
         组织身份已完全消失（0/100 仍以旧地址提供该组织身份）；而身份经由
         "域名解析桥"迁移，只保留 15 个可握手域名、9 个进入 48 小时证书战役；
         路径层对可达性不提供额外信息（活靶 180/180 抵达、死靶 0/320 抵达）。
  Fig.2 前缀长度存活曲线 —— 主张：存活率随前缀变长而下降，但 /24 的"精确存活"
         明显高于 /21–/23（31.1% vs 20.6%），且同一形态在**同日**公开 DFZ 对照里
         同样出现（50.8% vs 45.0%）⇒ 是宣告粒度的结构效应而非 15 年内的变化；
         >/24 桶的低存活是商业 vantage 保留更多特定前缀的口径伪影（同日对照里
         覆盖率为 99.3%）。
  Fig.3 逐靶证书战役 —— 主张：9 个战役靶里 8 个只出现 1 个叶子指纹（结构上
         不可分辨），1 个出现 2 个指纹（同一 subject/有效期、issuer 不同 ⇒
         vantage 侧重签），条件可判（c₃）；锚点与实验室复现用已知轮询部署
         校准出"两指纹 ⇒ 可判（c₂），κ = 1/3"。

灰度可读：每张图同时用**亮度差 + 标记形状 + 线型/填充纹理**编码系列，
去掉颜色仍可分辨（IJNM 印刷版为灰度）。
"""
import argparse
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DATA = os.path.join(HERE, "figdata.json")
OUT = HERE

# ---- publication style (skill: api.md 强制三行 + 期刊版式) --------------------
plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.sans-serif"] = ["Arial", "DejaVu Sans", "Liberation Sans"]
# SVG 文字保持可编辑；PDF 内嵌 TrueType（字体可嵌入、可检索）
plt.rcParams.update({"svg.fonttype": "none", "pdf.fonttype": 42, "ps.fonttype": 42})
# Arial 缺 ⇒ 与 Unicode 下标（₁₂₃…）：下标改用 mathtext（custom + Arial，
# 保证与正文 Arial 同族且是真下标），⇒ 改为 Arial 自带的 →。
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

BLUE = "#0F4D92"     # 覆盖（aggregate）
TEAL = "#42949E"     # 精确（exact）
RED = "#B64342"      # 强调（双指纹靶 / 零值）
GREY = "#767676"
LGREY = "#CFCECE"
DGREY = "#4D4D4D"
FILL_LIGHT = "#DCE7F4"

V_STATE_EN = {"决定可判": "decidable", "条件可判": "conditionally decidable",
              "不可分辨": "indistinguishable", "不可观测": "unobservable"}
HYP_EN = {"c1": "c1 single host", "c2": "c2 round-robin pool",
          "c3": "c3 source-sticky pool", "c4": "c4 multi-egress",
          "c5": "c5 SNI front end", "c8": "c8 camouflaged cluster"}


def en_verdict(v):
    return V_STATE_EN.get(v, v)


def save(fig, name, dpi=600):
    """导出：矢量 PDF（投稿主用）+ 600 dpi TIFF（印刷位图备选）+ 可编辑 SVG。"""
    outs = []
    p_pdf = os.path.join(OUT, "%s.pdf" % name)
    p_svg = os.path.join(OUT, "%s.svg" % name)
    p_tiff = os.path.join(OUT, "%s.tiff" % name)
    p_png = os.path.join(OUT, "%s.png" % name)
    fig.savefig(p_pdf, bbox_inches="tight")
    fig.savefig(p_svg, bbox_inches="tight")
    fig.savefig(p_png, bbox_inches="tight", dpi=300)
    # TIFF（投稿位图）：matplotlib 直出的 TIFF 带 alpha 通道，编辑部常拒收；
    # 而 Agg writer 在同进程内锁住 .tiff 路径，无法就地改写。
    # 故改为内存里渲染 PNG → 白底 RGB → LZW TIFF，不落任何临时文件。
    try:
        import io
        from PIL import Image
        buf = io.BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight", dpi=dpi)
        buf.seek(0)
        with Image.open(buf) as im:
            rgba = im.convert("RGBA")
        flat = Image.new("RGB", rgba.size, (255, 255, 255))
        flat.paste(rgba, mask=rgba.split()[-1])
        flat.save(p_tiff, dpi=(dpi, dpi), compression="tiff_lzw")
    except Exception as exc:                                   # pragma: no cover
        sys.stderr.write("[warn] TIFF 压平为 RGB 失败：%s\n" % exc)
    outs += [p_pdf, p_svg, p_tiff, p_png]
    plt.close(fig)
    return outs


def panel_label(ax, label, x=-0.02, y=1.04):
    ax.text(x, y, label, transform=ax.transAxes, fontsize=9,
            fontweight="bold", ha="left", va="bottom")


def pct(x, den):
    return 0.0 if not den else 100.0 * x / den


# =============================================================== Fig. 1 ======
# -*- coding: utf-8 -*-
"""fig1 新实现（临时模块，由 tools/_patch_fig1.py 拼接进 make_figures.py）。

四个面板各自守住一个主张：
  (a) 地址血缘级联 —— 路由→地址→服务三层逐级衰减，到服务层 2011 的组织身份
      归零（0/100）；前两行按"精确幸存 / 仅覆盖"分段显示。
  (b) 身份桥 —— 100 个实测地址 → 48 个可注册域名 → 34 个仍解析 → 15 个握手
      → 9 个组织身份叶子进入 48 小时战役。
  (c) 边类型 —— 直连/CDN/GCP/AWS 的握手完成率（CDN 拒绝无 SNI 握手）。
  (d) 路径层 —— 可达性完全由地址活性决定（活靶 180/180 抵达、死靶 0/320）。

布局纪律（修掉上一版的碰撞）：
  * 百分比一律放进 y 轴刻度标签的第二行，不再往绘图区右侧溢出（否则压住
    相邻面板的 y 刻度标签）；
  * 面板字母只出现在标题里，不再另有独立字母标注（上一版 a/b/c/d 出现两次）；
  * 每个面板的说明文字都换行到不超过该面板宽度，避免左右两个面板的注释互压。
所有数字一律从 figdata 取，不写死。
"""


def _pctstr(v, den):
    return "%.1f%% of %d" % (pct(v, den), den)


def fig1(d):
    lin = d["fig1"]["lineage"]
    br = d["fig1"]["bridge"]
    path = d["fig1"]["path_layer"]
    edge = d["fig1"]["edge_class"]

    fig = plt.figure(figsize=(7.0, 5.95))
    gs = fig.add_gridspec(2, 2, height_ratios=[1.0, 0.92], width_ratios=[1.06, 1.0],
                          hspace=0.60, wspace=0.46,
                          left=0.105, right=0.985, top=0.945, bottom=0.10)

    # ---- (a) address-lineage cascade ----------------------------------------
    ax = fig.add_subplot(gs[0, 0])
    stages = [s["stage"] for s in lin]
    vals = [s["n"] for s in lin]
    dens = [s["den"] for s in lin]
    y = list(range(len(lin)))[::-1]
    xmax = max(vals) * 1.18
    for yi, s, v in zip(y, lin, vals):
        col = RED if v == 0 else BLUE
        ex = s.get("exact")
        if v > 0:
            if ex is not None:
                cov = v - ex
                ax.barh(yi, ex, height=0.62, color=col, edgecolor=DGREY,
                        linewidth=0.7, zorder=3)
                ax.barh(yi, cov, left=ex, height=0.62, color="white",
                        edgecolor=DGREY, linewidth=0.7, hatch="///", zorder=3)
            else:
                ax.barh(yi, v, height=0.62, color=col, edgecolor=DGREY,
                        linewidth=0.7, zorder=3)
            ax.text(v + xmax * 0.012, yi, "%d" % v, va="center", ha="left",
                    fontsize=7.5, color=DGREY)
        else:
            ax.plot([xmax * 0.012], [yi], marker="v", markersize=5.5, color=RED,
                    zorder=4)
            ax.text(xmax * 0.035, yi, "0", va="center", ha="left",
                    fontsize=7.5, color=RED)
    ax.set_yticks(y)
    ax.set_yticklabels(["%s\n%s" % (s["stage"], _pctstr(s["n"], s["den"]))
                         for s in lin], fontsize=6.6)
    ax.set_ylim(-0.75, len(lin) - 0.25)
    ax.set_xlim(0, xmax)
    ax.set_xlabel("targets (count)", fontsize=7)
    ax.set_title("a  Address lineage: routing to service",
                 loc="left", fontsize=8.2, fontweight="bold", pad=6)
    ax.text(0.0, -0.235,
            "filled = exact survivor (identical prefix); hatched = covered only\n"
            "measurement set: %d exact + %d covered-only"
            % (lin[2]["exact"], lin[2]["covered_only"]),
            transform=ax.transAxes, fontsize=6.2, color=GREY, va="top")

    # ---- (b) identity bridge -------------------------------------------------
    ax = fig.add_subplot(gs[0, 1])
    y = list(range(len(br)))[::-1]
    vals = [s["n"] for s in br]
    xmax = max(vals) * 1.20
    for i, (yi, s, v) in enumerate(zip(y, br, vals)):
        # 最后一行（组织身份叶子）是 2011 身份真正存活的阶段，用实心；
        # TLS 握手阶段用浅色斜纹，强调该层多数身份已属第三方。
        col = FILL_LIGHT if i == 4 else BLUE
        ax.barh(yi, v, height=0.6, color=col, edgecolor=DGREY, linewidth=0.7,
                hatch="//" if col == FILL_LIGHT else None, zorder=3)
        ax.text(v + xmax * 0.015, yi, "%d" % v, va="center", ha="left",
                fontsize=7.5, color=DGREY)
    ax.set_yticks(y)
    ax.set_yticklabels(["%s\n%s" % (s["stage"], _pctstr(s["n"], s["den"]))
                         for s in br], fontsize=6.6)
    ax.set_ylim(-0.75, len(br) - 0.25)
    ax.set_xlim(0, xmax)
    ax.set_xlabel("targets (count)", fontsize=7)
    ax.set_title("b  Identity bridge: where the 2011 identity reappears",
                 loc="left", fontsize=8.2, fontweight="bold", pad=6)
    ax.text(0.0, -0.235,
            "the 2011 identity survives only through name resolution;\n"
            "of the %d TLS handshakes, %d keep the 2011 organization identity"
            % (br[4]["n"], br[5]["n"]),
            transform=ax.transAxes, fontsize=6.2, color=GREY, va="top")

    # ---- (c) edge class ------------------------------------------------------
    ax = fig.add_subplot(gs[1, 0])
    names = [EDGE_LABEL.get(e["edge"], e["edge"]) for e in edge]
    tot = [e["n"] for e in edge]
    ok = [e["tls_ok"] for e in edge]
    xmax = max(tot) * 1.34
    y = list(range(len(edge)))[::-1]
    for yi, e, t, o in zip(y, edge, tot, ok):
        ax.barh(yi, o, height=0.58, color=BLUE, edgecolor=DGREY, linewidth=0.7,
                zorder=3)
        ax.barh(yi, t - o, left=o, height=0.58, color="white", edgecolor=DGREY,
                linewidth=0.7, hatch="xx", zorder=3)
        ax.text(t + xmax * 0.025, yi, "%d / %d" % (o, t), va="center", ha="left",
                fontsize=7, color=DGREY)
    ax.set_yticks(y)
    ax.set_yticklabels(names, fontsize=7)
    ax.set_ylim(-0.7, len(edge) - 0.3)
    ax.set_xlim(0, xmax)
    ax.set_xlabel("resolving domains (count)", fontsize=7)
    ax.set_title("c  Bridge survivors by edge class",
                 loc="left", fontsize=8.2, fontweight="bold", pad=6)
    ax.text(0.0, -0.185,
            "filled = handshake completed;\nhatched = refused / no handshake",
            transform=ax.transAxes, fontsize=6.2, color=GREY, va="top")

    # ---- (d) path layer determinism -----------------------------------------
    ax = fig.add_subplot(gs[1, 1])
    groups = [("paths to ICMP-live\ndestinations", path["live_paths_reached"],
               path["live_paths"], BLUE),
              ("paths to ICMP-dead\ndestinations", path["dead_paths_reached"],
               path["dead_paths"], LGREY)]
    xmax = max(g[2] for g in groups) * 1.48
    y = [1, 0]
    for yi, (lab, r, t, col) in zip(y, groups):
        ax.barh(yi, t, height=0.5, color="white", edgecolor=DGREY, linewidth=0.7,
                hatch="xx" if col is LGREY else None, zorder=3)
        if r:
            ax.barh(yi, r, height=0.5, color=col, edgecolor=DGREY, linewidth=0.7,
                    zorder=3)
        ax.text(t + xmax * 0.02, yi, "%d / %d reached" % (r, t), va="center",
                ha="left", fontsize=7, color=DGREY)
    ax.set_yticks(y)
    ax.set_yticklabels([g[0] for g in groups], fontsize=7)
    ax.set_ylim(-0.7, 1.7)
    ax.set_xlim(0, xmax)
    ax.set_xlabel("executed probe paths (count)", fontsize=7)
    ax.set_title("d  Path layer: reachability follows liveness",
                 loc="left", fontsize=8.2, fontweight="bold", pad=6)
    ax.text(0.0, -0.185,
            "%d of %d traced destinations reached\n(all of them live)"
            % (path["distinct_destinations_reached"], path["distinct_destinations"]),
            transform=ax.transAxes, fontsize=6.2, color=GREY, va="top")

    return save(fig, "fig1_cascade")


# =============================================================== Fig. 2 ======
BUCKET_ORDER = ["<=16", "17-20", "21-23", "24", ">24"]
BUCKET_LABEL = {"<=16": "≤ /16", "17-20": "/17–/20", "21-23": "/21–/23",
                "24": "/24", ">24": "> /24"}
# 边缘类显示名：artifact 里的原始键不直接上图，与正文措辞一致
EDGE_LABEL = {"direct": "direct", "cloudflare": "major CDN", "gcp": "Google Cloud",
              "aws": "AWS"}


# -*- coding: utf-8 -*-
"""fig2 新实现（临时模块，由 tools/_patch_fig2.py 拼接进 make_figures.py）。

设计：三面板
  (a) 主面板 —— 逐前缀长度存活曲线（aggregate + exact），
  (b) aggregate 存活：2026 视图 vs 同日 DFZ 对照（暴露 >/24 口径伪影），
  (c) exact 存活：2026 视图 vs 同日 DFZ 对照（暴露 /24 反常在两个纪元同时出现）。
所有数字一律从 figdata 取，不写死。
"""

MIN_N = 500   # 逐前缀长度曲线的最小样本量（低于此值的长度不入曲线）


def _compress_ints(xs):
    """[8,9,10,31] -> '8–10, 31'"""
    runs = []
    for x in sorted(xs):
        if runs and x == runs[-1][1] + 1:
            runs[-1][1] = x
        else:
            runs.append([x, x])
    return ", ".join("%d" % a if a == b else "%d–%d" % (a, b) for a, b in runs)


def _fmt_pct(v):
    """小值保留两位，避免 0.03 被显示成 0.0。"""
    return ("%.1f" % v) if v >= 0.1 else ("%.2f" % v)


def _plength_ticks(lens):
    """稀疏刻度；/24 必须落在刻度上（它是论点所在的前缀长度）。"""
    ticks = []
    for L in lens:
        if abs(L - 24) <= 1:
            continue
        if (L - lens[0]) % 2 == 0:
            ticks.append(L)
    if 24 in lens:
        ticks.append(24)
    return sorted(ticks)


def fig2(d):
    b = d["fig2"]["buckets"]
    bp = d["fig2"]["by_plen"]
    cal = d["fig2"]["calibration"]["snapshot_visible_in_rib_2011"]["by_bucket"]
    tot = d["fig2"]["totals"]

    lens = sorted(int(k) for k in bp if bp[k]["n"] >= MIN_N)
    dropped = sorted(int(k) for k in bp if bp[k]["n"] < MIN_N)
    agg = [100.0 * bp[str(L)]["agg_rate"] for L in lens]
    exc = [100.0 * bp[str(L)]["exact_rate"] for L in lens]

    fig = plt.figure(figsize=(7.0, 4.90))
    # 右列三行：第 0 行是 b/c 共用的图例条（避免图例压住面板标题）
    gs = fig.add_gridspec(3, 2, width_ratios=[1.32, 1.0],
                          height_ratios=[0.115, 1.0, 1.0],
                          wspace=0.34, hspace=1.15,
                          left=0.085, right=0.985, top=0.935, bottom=0.145)

    # ---------------------------------------------------------------- (a) ----
    ax = fig.add_subplot(gs[:, 0])
    xmax = max(lens) + 0.6
    ax.axvspan(24.5, xmax, color="#F2F2F2", zorder=0)
    ax.text((24.5 + xmax) / 2.0, 100.5, "declared caliber\nartifact",
            ha="center", va="top", fontsize=6.1, color=GREY)
    ax.plot(lens, agg, color=BLUE, lw=1.7, marker="o", ms=4.6, mfc=BLUE,
            mec=BLUE, zorder=3, label="covered (aggregate)")
    ax.plot(lens, exc, color=TEAL, lw=1.7, ls="--", marker="s", ms=4.2,
            mfc="white", mec=TEAL, zorder=3,
            label="identical prefix (exact)")
    ax.axvline(24, color=RED, lw=0.7, ls=":", zorder=1)

    i24 = lens.index(24)
    e24, e23 = exc[i24], exc[i24 - 1]
    ax.plot([24], [e24], marker="o", ms=8.5, mfc="none", mec=RED, mew=1.0, zorder=4)
    ax.annotate("/24 breaks the monotone descent:\nexact %.1f%% at /24 vs %.1f%% at /23"
                % (e24, e23),
                xy=(23.7, e24 - 2.0), xytext=(13.2, 5.0),
                fontsize=6.3, color=RED, ha="left",
                arrowprops=dict(arrowstyle="->", color=RED, lw=0.8,
                                connectionstyle="arc3,rad=-0.30"))

    ticks = _plength_ticks(lens)
    ax.set_xticks(ticks)
    ax.set_xticklabels(["/%d" % L for L in ticks], fontsize=6.4)
    ax.set_xlim(lens[0] - 0.8, lens[-1] + 0.8)
    ax.set_ylim(0, 103)
    ax.set_xlabel("2011 prefix length", fontsize=7)
    ax.set_ylabel("2011 prefixes surviving in 2026 (%)", fontsize=7)
    ax.set_title("a  Survival by 2011 prefix length (2026 routing view)",
                 loc="left", fontsize=8.2, fontweight="bold", pad=6)
    # 图例放在两条曲线之间的空白带（aggregate 与 exact 之间的中段），不压任何数据
    ax.legend(loc="center left", fontsize=6.4, handlelength=2.2,
              bbox_to_anchor=(0.02, 0.30))
    ax.text(0.0, -0.115,
            "lengths with fewer than %d snapshot prefixes are omitted (/%s);\n"
            "per-length counts are published in the artifact package"
            % (MIN_N, _compress_ints(dropped)),
            transform=ax.transAxes, fontsize=6.2, color=GREY, va="top")

    # ---------------------------------------------------------------- (b) ----
    axb = fig.add_subplot(gs[1, 1])
    x = list(range(len(BUCKET_ORDER)))
    w = 0.38
    v26 = [100.0 * b[bk]["agg_rate"] for bk in BUCKET_ORDER]
    vct = [100.0 * cal[bk]["covered_rate"] for bk in BUCKET_ORDER]
    axb.axvspan(3.6, 4.4, color="#F2F2F2", zorder=0)
    axb.bar([i - w / 2.0 for i in x], v26, width=w, color=BLUE, edgecolor=DGREY,
            linewidth=0.6, zorder=3, label="2026 routing view")
    axb.bar([i + w / 2.0 for i in x], vct, width=w, color="white", edgecolor=DGREY,
            linewidth=0.6, hatch="///", zorder=3, label="same-day DFZ control (2011)")
    for i, v in zip(x, v26):
        axb.text(i - w / 2.0, v + 1.5, _fmt_pct(v), ha="center", va="bottom",
                 fontsize=5.8, color=BLUE)
    for i, v in zip(x, vct):
        axb.text(i + w / 2.0, v + 1.5, _fmt_pct(v), ha="center", va="bottom",
                 fontsize=5.8, color=DGREY)
    axb.set_xticks(x)
    axb.set_xticklabels([BUCKET_LABEL[bk] for bk in BUCKET_ORDER], fontsize=6.4)
    axb.set_ylim(0, 114)
    axb.set_ylabel("2011 prefixes covered (%)", fontsize=7)
    axb.set_xlabel("2011 prefix-length bucket", fontsize=7)
    axb.set_title("b  Aggregate survival: 2026 view vs same-day control",
                  loc="left", fontsize=8.2, fontweight="bold", pad=6)
    axb.text(0.0, -0.40,
             "> /24: %.1f%% (2026) vs %.1f%% (same-day control) → the drop is a\n"
             "collector filter-policy artifact, not decay"
             % (v26[4], vct[4]),
             transform=axb.transAxes, fontsize=6.2, color=GREY, va="top")

    # ---------------------------------------------------------------- (c) ----
    axc = fig.add_subplot(gs[2, 1])
    v26e = [100.0 * b[bk]["exact_rate"] for bk in BUCKET_ORDER]
    vcte = [100.0 * cal[bk]["exact_rate"] for bk in BUCKET_ORDER]
    axc.axvspan(2.6, 3.4, color="#FBEAEA", zorder=0)
    axc.bar([i - w / 2.0 for i in x], v26e, width=w, color=BLUE, edgecolor=DGREY,
            linewidth=0.6, zorder=3, label="2026 routing view")
    axc.bar([i + w / 2.0 for i in x], vcte, width=w, color="white", edgecolor=DGREY,
            linewidth=0.6, hatch="///", zorder=3, label="same-day DFZ control (2011)")
    for i, v in zip(x, v26e):
        axc.text(i - w / 2.0, v + 1.2, _fmt_pct(v), ha="center", va="bottom",
                 fontsize=5.8, color=BLUE)
    for i, v in zip(x, vcte):
        axc.text(i + w / 2.0, v + 1.2, _fmt_pct(v), ha="center", va="bottom",
                 fontsize=5.8, color=DGREY)
    axc.set_xticks(x)
    axc.set_xticklabels([BUCKET_LABEL[bk] for bk in BUCKET_ORDER], fontsize=6.4)
    axc.set_ylim(0, 100)
    axc.set_ylabel("2011 prefixes exactly re-announced (%)", fontsize=7)
    axc.set_xlabel("2011 prefix-length bucket", fontsize=7)
    axc.set_title("c  Exact survival: 2026 view vs same-day control",
                  loc="left", fontsize=8.2, fontweight="bold", pad=6)
    axc.text(0.0, -0.40,
             "/24 exact %.1f%% vs %.1f%% at /21–/23 (2026); %.1f%% vs %.1f%% (control)\n"
             "→ deaggregation granularity, present in both epochs"
             % (v26e[3], v26e[2], vcte[3], vcte[2]),
             transform=axc.transAxes, fontsize=6.2, color=GREY, va="top")

    # -- b/c 共用图例：放在右列顶部的独立图例条，避免压住任一面板标题 ----------
    axleg = fig.add_subplot(gs[0, 1])
    axleg.axis("off")
    handles, labels = axb.get_legend_handles_labels()
    axleg.legend(handles, labels, loc="upper right", ncol=2, fontsize=6.3,
                 handlelength=1.6, columnspacing=1.6)

    return save(fig, "fig2_prefix_survival")


# =============================================================== Fig. 3 ======
# -*- coding: utf-8 -*-
"""fig3 新实现（临时模块，由 tools/_patch_fig3.py 拼接进 make_figures.py）。

两个面板：
  (a) 逐靶战役剖面 —— 成功握手数、轮数、视角数；target A（两个叶子指纹）用
      红色斜纹标出。
  (b) 指纹集合与判定 —— 四行示意：战役 8 靶（单指纹 → 不可分辨）、
      target A（两指纹、同 subject/有效期、不同 issuer → 条件可判 c3）、
      云锚（两枚预注册部署证书 → 可判 c2，κ=1/3）、实验室复现（同 → 可判 c2）。

布局纪律（修掉上一版的碰撞）：
  * 面板字母只出现在标题里；
  * (a) 的"轮数 · 视角数"改到 y 轴刻度标签第二行，不再压在条末数字上；
  * (b) 的行标题与指纹盒分行排布，行标题不再被盒子压住；
  * (b) 判定文字右对齐留出稳定列宽，不再越界。
所有数字一律从 figdata 取，不写死。
"""


def fig3(d):
    tg = d["fig3"]["targets"]
    anc = d["fig3"]["anchor"]
    fleet = d["fig3"]["fleet"]

    fig = plt.figure(figsize=(7.0, 4.60))
    gs = fig.add_gridspec(1, 2, width_ratios=[1.18, 1.0], wspace=0.40,
                          left=0.085, right=0.985, top=0.915, bottom=0.145)

    # ---- (a) per-target campaign profile -------------------------------------
    ax = fig.add_subplot(gs[0, 0])
    y = list(range(len(tg)))[::-1]
    hs = [t["handshakes"] for t in tg]
    xmax = max(hs) * 1.30
    for yi, t, h in zip(y, tg, hs):
        two = t["union_fp"] > 1
        ax.barh(yi, h, height=0.6, color=RED if two else BLUE, edgecolor=DGREY,
                linewidth=0.7, hatch="//" if two else None, zorder=3)
        ax.text(h + xmax * 0.015, yi, "%d" % h, va="center", ha="left",
                fontsize=7, color=DGREY)
    ax.set_yticks(y)
    ax.set_yticklabels(["%s\n%d rounds · %d vantages"
                         % (t["label"], t["rounds"], t["vantages"]) for t in tg],
                        fontsize=7, fontweight="bold", multialignment="right")
    ax.set_ylim(-0.7, len(tg) - 0.3)
    ax.set_xlim(0, xmax)
    ax.set_xlabel("successful TLS handshakes (merged observation set)", fontsize=7)
    ax.set_title("a  Per-target certificate campaign (48 h recurring)",
                 loc="left", fontsize=8.2, fontweight="bold", pad=6)
    ax.text(0.0, -0.175,
            "filled = one leaf fingerprint;  hatched = two leaf fingerprints\n"
            "(target A: vantage-side re-signing)",
            transform=ax.transAxes, fontsize=6.2, color=GREY, va="top")

    # ---- (b) fingerprint-set schematic ----------------------------------------
    ax = fig.add_subplot(gs[0, 1])
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    n1 = fleet.get("union_eq_1")
    rows = [
        ("Campaign, %s targets" % n1, 1, "one leaf fingerprint",
         "indistinguishable", GREY),
        ("Campaign, target A", 2, "same subject, different issuers",
         "conditionally\ndecidable ($c_3$)", RED),
        ("Cloud anchor", 2, "two pre-registered certificates (known round-robin)",
         "decidable ($c_2$)\nκ = 1/3", BLUE),
        ("Laboratory replication", 2, "two rig certificates (known round-robin)",
         "decidable ($c_2$)\nκ = 1/3", BLUE),
    ]
    # 行内元素自上而下：行标题(1 行) -> 指纹盒 -> 注释(1 行)；
    # dy 必须 >= 标题+盒+注释+行间隙，否则相邻行会压字。
    ytop = 0.79
    dy = 0.215
    for i, (name, nfp, fpnote, verdict, col) in enumerate(rows):
        yc = ytop - i * dy
        ax.text(0.0, yc + 0.105, name, fontsize=7.0, fontweight="bold", va="top",
                color=DGREY)
        for k in range(nfp):
            x0 = 0.02 + k * 0.26
            ax.add_patch(FancyBboxPatch((x0, yc - 0.025), 0.23, 0.085,
                                         boxstyle="round,pad=0.008,rounding_size=0.012",
                                         linewidth=0.8, edgecolor=col,
                                         facecolor="white",
                                         hatch="//" if (nfp > 1 and col is RED) else None))
            ax.text(x0 + 0.115, yc + 0.017, "FP%d" % (k + 1), ha="center", va="center",
                    fontsize=6.4, color=col)
        ax.text(0.02, yc - 0.048, fpnote, fontsize=6.0, va="top", color=GREY)
        ax.text(0.99, yc + 0.017, verdict, fontsize=6.6, va="center", ha="right",
                color=col, linespacing=1.2)
    ax.text(0.99, 0.015, "engine output and winning hypothesis", fontsize=6.0,
            color=GREY, ha="right")
    ax.set_title("b  Fingerprint set and engine verdict", loc="left",
                 fontsize=8.2, fontweight="bold", pad=6)

    return save(fig, "fig3_certificate_campaign")


# =============================================================== legends =====
def legends(d):
    lin = d["fig1"]["lineage"]
    br = d["fig1"]["bridge"]
    path = d["fig1"]["path_layer"]
    edge = d["fig1"]["edge_class"]
    tg = d["fig3"]["targets"]
    anc = d["fig3"]["anchor"]
    fleet = d["fig3"]["fleet"]
    b = d["fig2"]["buckets"]
    cal = d["fig2"]["calibration"]
    tot = d["fig2"]["totals"]

    L = []
    L.append("### Figure 1 | Four-layer survival cascade from the 2011 snapshot to the "
             "2026 live network\n")
    L.append("**(a)** Address lineage of the stratified cohort. Of %d candidate prefixes "
             "drawn from the 2011 snapshot, %d (%.1f%%) remain covered in the 2026 "
             "routing view, %d of them survive as identical prefixes; the measurement "
             "set comprises %d addresses (%d exact survivors and %d covered-only). "
             "%d of the %d answer ICMP echo requests (%d of the %d exact survivors, "
             "%d of the %d covered-only). %d address completes a TLS handshake, and its "
             "certificate belongs to an unrelated third party, so %d of the %d still "
             "serve the 2011 organization's TLS identity. Bars show absolute counts; "
             "the red marker marks the empty terminal stage."
             % (lin[0]["n"], lin[1]["n"], pct(lin[1]["n"], lin[0]["n"]), lin[1]["exact"],
                lin[2]["n"], lin[2]["exact"], lin[2]["covered_only"],
                lin[3]["n"], lin[2]["n"], d["fig1"]["liveness_split"]["live_exact"],
                d["fig1"]["liveness_split"]["exact_total"],
                d["fig1"]["liveness_split"]["live_covered"],
                d["fig1"]["liveness_split"]["covered_total"],
                lin[4]["n"], lin[5]["n"], lin[2]["n"]))
    L.append("**(b)** Identity bridge. Of the %d measured addresses, %d carry 2011 "
             "hostname mappings, yielding %d registrable domains; %d (%.1f%%) still "
             "resolve in 2026 and %d (%.1f%%) complete a TLS handshake, of which %d are "
             "organization-identity leaves that entered the 48-hour recurring campaign."
             % (br[0]["n"], br[1]["n"], br[2]["n"], br[3]["n"],
                pct(br[3]["n"], br[2]["n"]), br[4]["n"], pct(br[4]["n"], br[3]["n"]),
                br[5]["n"]))
    L.append("**(c)** Bridge survivors by edge class: %s. CDN-fronted domains reject the "
             "SNI-less handshake, which is why the campaign is restricted to direct and "
             "cloud edges. Filled bars count completed handshakes; hatched bars count "
             "domains that refused or failed to handshake."
             % "; ".join("%s %d/%d" % (EDGE_LABEL.get(e["edge"], e["edge"]),
                                       e["tls_ok"], e["n"]) for e in edge))
    L.append("**(d)** Path layer. Of %d executed probe paths, %d reach the target "
             "address; every path to an ICMP-live destination reaches its destination "
             "(%d/%d) and no path to an ICMP-dead destination does (%d/%d), so "
             "reachability carries no information beyond address liveness. %d of %d "
             "traced destinations were reached, all of them live."
             % (path["paths_total"], path["reached"], path["live_paths_reached"],
                path["live_paths"], path["dead_paths_reached"], path["dead_paths"],
                path["distinct_destinations_reached"], path["distinct_destinations"]))
    L.append("\n*Source data:* published derived statistics of the artifact package "
             "(cohort survival, address-layer summary, path-layer summary, DNS-bridge "
             "feasibility, TLS scout summary).\n")

    calb = cal["snapshot_visible_in_rib_2011"]["by_bucket"]
    L.append("### Figure 2 | Prefix-length survival of the 2011 snapshot in the 2026 "
             "routing view\n")
    L.append("**(a)** Survival of the %s prefixes of the 2011 snapshot in the %s-unique-"
             "prefix 2026 routing view (×%.3f growth) as a function of the 2011 prefix "
             "length. Aggregate survival (covered by any 2026 prefix) falls "
             "monotonically with length, from %.1f%% for /16 and shorter to %.1f%% at "
             "/24, but exact survival (the identical prefix still announced) does not: "
             "it is %.1f%% for /21–/23 and rises to %.1f%% at /24, because deaggregation "
             "makes /24 the stable unit of end-site announcement. The collapse beyond "
             "/24 is a caliber artifact rather than decay, because the 2011 vantage "
             "retained more-specifics that the 2026 DFZ collector filters. Prefix "
             "lengths with fewer than %d snapshot prefixes are omitted."
             % ("{:,}".format(tot["routes_2011"]),
                "{:,}".format(tot["rib_unique_prefixes_2026"]),
                tot["growth_factor_prefixes"],
                100 * b["<=16"]["agg_rate"], 100 * b["24"]["agg_rate"],
                100 * b["21-23"]["exact_rate"], 100 * b["24"]["exact_rate"], MIN_N))
    L.append("**(b)** Aggregate survival in the 2026 routing view against the same-day "
             "control, the public DFZ view collected on the snapshot's own date (%s "
             "prefixes, %d peers). The > /24 bucket is %.1f%% covered in the 2026 view "
             "against %.1f%% in the same-day control, so the collapse is a collector "
             "filter-policy artifact rather than decay."
             % ("{:,}".format(cal["rib_2011_prefixes"]), cal["rib_2011_peers"],
                100 * b[">24"]["agg_rate"], 100 * calb[">24"]["covered_rate"]))
    L.append("**(c)** Exact survival against the same-day control. The /24 excess is "
             "present in both epochs (%.1f%% against %.1f%% for /21–/23 in the 2026 "
             "view; %.1f%% against %.1f%% in the control), which places the effect in "
             "announcement granularity rather than in fifteen years of change."
             % (100 * b["24"]["exact_rate"], 100 * b["21-23"]["exact_rate"],
                100 * calb["24"]["exact_rate"], 100 * calb["21-23"]["exact_rate"]))
    L.append("\n*Source data:* published survival and same-day calibration statistics of "
             "the artifact package. Percentages are rounded to one decimal; the bucket "
             "denominators are given in Table 2 of the manuscript.\n")

    L.append("### Figure 3 | Per-target certificate campaign and fingerprint-set "
             "verdicts\n")
    L.append("**(a)** Per-target outcome of the 48-hour recurring certificate "
             "campaign. Bars count successful TLS handshakes over the merged "
             "observation set of each target (the union of all its measurement IDs); "
             "labels give the number of hourly rounds and the number of "
             "certificate-carrying vantages. Eight targets show a fleet-wide union of "
             "exactly one leaf certificate (filled bars); target A shows two leaf "
             "fingerprints with identical subject and validity interval but different "
             "issuers (hatched bar), which the variant-attribution rule classifies as "
             "vantage-side re-signing. Target A's measurement was force-stopped after "
             "%d hourly rounds on credit exhaustion and resumed under a second "
             "measurement ID, leaving a gap in its observation window."
             % next((t.get("orig_rounds") or 0 for t in tg
                     if t["union_fp"] > 1 and t["stop_events"]), 0))
    L.append("**(b)** Fingerprint set and engine verdict. A single leaf fingerprint is "
             "the structural terminal state (indistinguishable). Two fingerprints "
             "permit a verdict only when the observations separate the hypotheses: the "
             "cloud anchor, whose two pre-registered deployment certificates are "
             "known, yields %s with the round-robin hypothesis at κ = 1/3 exactly, "
             "replicated on the laboratory deployment; target A yields %s with the "
             "source-sticky two-backend hypothesis. The anchor measurement shows a "
             "union of %d fingerprints with %d stray observations across %d hourly "
             "slots."
             % (en_verdict(anc["verdict"]), "conditionally decidable",
                anc["union_fp16"], anc["stray_fp16"], anc["hour_buckets"]))
    L.append("\n*Source data:* published per-target judgment, window statistics, target "
             "labels and anchor verdict of the artifact package. Targets are reported "
             "by anonymized label A–I; the label-to-target mapping is released with the "
             "package.\n")
    return "\n".join(L)


def main():
    global DATA, OUT
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=DATA, help="图数据 JSON（默认与本脚本同目录）")
    ap.add_argument("--out", default=OUT, help="图与图注的输出目录（默认与本脚本同目录）")
    a = ap.parse_args()
    DATA, OUT = a.data, a.out
    if not os.path.exists(DATA):
        raise SystemExit("缺少 %s（先跑 tools/c1_figure_data.py）" % DATA)
    if not os.path.isdir(OUT):
        os.makedirs(OUT, exist_ok=True)
    with open(DATA, encoding="utf-8") as f:
        d = json.load(f)
    outs = []
    outs += fig1(d)
    outs += fig2(d)
    outs += fig3(d)
    lg = os.path.join(OUT, "figure_legends.md")
    with open(lg, "w", encoding="utf-8", newline="\n") as f:
        f.write(legends(d))
    outs.append(lg)
    for p in outs:
        print("  -> %s" % os.path.relpath(p, ROOT))


if __name__ == "__main__":
    main()
