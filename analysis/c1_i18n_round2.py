#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""c1_i18n_round2.py —— 第二轮发布包的中文串英译表（被 c1_i18n.py 合并）。

为什么单独一份：第一轮的 EN_EXACT 已达 ~80 条，第二轮又有 ~90 条（规格模板的设计注记、
判卷/审计的机器注记）。分文件便于逐条审阅，合并在 c1_i18n.py 顶部完成。

纪律沿用 c1_i18n：**只翻字符串，不动结构/数值/指纹**；未覆盖的串原样保留并上报，
不猜、不意译。含 msm 编号的审计注记用正则（EN 侧按整句重写）。
"""
import re

# --- 引擎四态与判卷注记 ------------------------------------------------
_ENGINE = {
    "决定可判": "decidable",
    "条件可判": "conditionally decidable",
    "不可分辨": "indistinguishable",
    "不可观测": "unobservable",
    "negative（两条件同一张）": "negative (same certificate under both names)",
    "positive（两条件指纹互不相同）": "positive (different fingerprints under the two names)",
    "unobservable（a侧无证书）": "unobservable (no certificate on the identity-name side)",
    "o3 代表对未满（≥3 轮成功的探针不足 2）":
        "o3 representative pair not formed (fewer than two probes with >=3 successful rounds)",
    "负向读数×3 支持单后端；等价类内含 c8 锚（完美伪装集群与单机在本组观测下不可分辨）":
        ("three negative readings support a single backend; the equivalence class retains the c8 "
         "anchor, because a perfect camouflage cluster is indistinguishable from a single host "
         "under this sensor set"),
    "c5 支持度 3，其余存活假设持平度不足":
        "c5 support 3; the remaining surviving hypotheses tie below it",
    "o3/o6 只用身份名一侧；o4 逐探针集合比较＋目标级 sni_map；H1 描述性（D7）":
        ("o3/o6 from the identity-name side only; o4 by per-probe fingerprint-set comparison plus "
         "a target-level sni_map; H1 reported descriptively (D7)"),
}

# --- 预注册 / 规格模板的设计注记 ---------------------------------------
_SPEC = {
    "第二轮证书战役的测量规格模板。所有靶/探针用角色名或引用文件，不写真实域名与 IP。提交前必须把 prereg.sha256 填实；预算脚本读本文件即可给出三档成本。":
        ("Measurement specification template for the round-2 certificate campaign. Targets and "
         "probes are referenced by role names or files; no real domains or addresses are written "
         "here. prereg.sha256 must be filled before submission; the budget script reads this file "
         "to produce the cost tiers."),
    "1.1 修订：o4 由可选提为必测（c5 只能由 o4 证伪）；o1 降为附加轴（L1SP/L2S6 档位带 ping 时点亮）":
        ("Amendment 1.1: o4 is promoted from optional to mandatory (only o4 can falsify c5); o1 is "
         "demoted to an optional axis, lit in the L1SP/L2S6 tiers that carry ping"),
    "每小时一轮；Atlas recurring 最小间隔受限，按平台允许值取整":
        ("one round per hour, using the smallest recurring interval the platform permits"),
    "不同测量的起始时刻互相错开 >=60 s，避免串行服务端被并发打满（第一轮锚点教训）":
        ("start times are staggered by >=60 s across measurements so that a serial server is not "
         "saturated concurrently (a round-1 anchor lesson)"),
    "RFC 6761 保留域：永不解析、永不被签发，因此它不指向任何第三方虚主机。只贡献 sni_map 第二个条目，绝不进 tls.hashes":
        ("RFC 6761 reserved domain: it never resolves and is never issued, so it points at no "
         "third-party virtual host. It contributes only the second sni_map entry and never enters "
         "tls.hashes"),
    "取该靶在第一轮里据以做身份主张的那个域名（同一显式 IP 的 A 记录名）；写在 targets 文件里，不写进本模板":
        ("the domain on which the round-1 identity claim rested (the A-record name of the same "
         "explicit address); stored in the targets file, not in this template"),
    "c5 是按名字选证书的前端。两条都不出示真名字时它会连回同一张默认证书，检验失去功效（假阴性）":
        ("c5 is a front end that selects certificates by name. If neither arm presents a real name "
         "it returns the same default certificate and the test loses its power (false negative)"),
    "把对比名的握手并入 tls.hashes": "merge contrast-name handshakes into tls.hashes",
    "把两个名字的结果写到不同探针上": "write the two name conditions to different probes",
    "必须用显式 prb_id 数组：新建用户标签不被 selection 立即接受（15min 级滞后），且三类测量必须落在同一批探针上才能合并 bundle":
        ("an explicit prb_id array is required: a newly created user tag is not accepted by probe "
         "selection immediately (about a 15-minute lag), and all three measurement types must land "
         "on the same probes before their bundles can be merged"),
    "绝不 Delete；只 Stop。论文与回应信引用 msm ID":
        "never delete; stop only. The paper and the response letter cite the measurement IDs",
    "实验臂：S1 判为异质、参与 H1 统计":
        "experimental arm: heterogeneous targets from S1, feeding the H1 statistic",
    "域名靶会被 API 侧预解析校验拒绝；须先 DoH 解析出 IP 再用 IP 靶 + SNI 名":
        ("a domain target is rejected by the API's pre-resolution check; resolve it over DoH first, "
         "then target the address and present the name"),
    "阴性对照：第一轮 8 个已知单证书舰队，验证 H2 特异度":
        "negative controls: the eight known single-certificate fleets of round 1, testing H2 specificity",
    "阳性对照：第一轮目标 A（已知两指纹、已知再签名）":
        "positive control: round-1 target A (two known fingerprints, known re-signing)",
    "受控轮换 rig（实验室，已知 pool），验证 H3/H4":
        "controlled rotation rig (laboratory, known pool), testing H3/H4",
    "受控再签名 rig（新增：TLS 检查代理，保留 subject/validity 换 issuer）":
        ("controlled re-signing rig (new: a TLS-inspecting proxy that preserves subject and "
         "validity and swaps the issuer)"),
    "2026-11-12 修正：rig 臂原为无 SNI 单臂，违反 meta.prereg.axes_required=[o3,o4,o6] 且被发起器闸 2 拒。rig 是已知答案校准，必须走与主线相同的两名字仪器，否则 H3/H4 校准不到 o4。":
        ("Fix of 2026-11-12: the rig arm was a single SNI-less arm, violating "
         "meta.prereg.axes_required=[o3,o4,o6], and was rejected by launcher gate 2. The rig is the "
         "known-answer calibration and must run the same two-name instrument as the main line; "
         "otherwise H3/H4 cannot calibrate o4."),
    "同 rig_rotation：2026-11-12 补成双 SNI，满足 axes_required；再签名 rig 的 o4 正控是 H4 的已知答案。":
        ("As rig_rotation: extended to two names on 2026-11-12 to satisfy axes_required. The "
         "re-signing rig's o4 positive control is H4's known answer."),
    "阴性对照（o4 修正版）：8 个第一轮单证书舰队，同 IP 双 SNI 条件 → 验 H2":
        ("negative controls (o4-corrected): the eight round-1 single-certificate fleets under two "
         "names on the same address, testing H2"),
    "2026-11-11 离线预检（data/c1/round2/preflight.json）证明：TLS+ping 只把 κ 提到 0.5，c5 仍与 c1/c8 同权 ⇒ 8/8 仍不可分辨。c5 只能由 o4 证伪，故必须加同 IP 双 SNI 臂。o4 可部署性已取证：atlas_sni_evidence.json（hostname 字段 read_only=false，help_text=Server Name Indication (SNI) hostname）。":
        ("The offline preflight of 2026-11-11 (data/c1/round2/preflight.json) shows that TLS+ping "
         "lifts kappa only to 0.5, where c5 still ties with c1/c8, so 8/8 remain indistinguishable. "
         "Only o4 can falsify c5, hence the same-address two-name arm. Deployability of o4 is "
         "documented in atlas_sni_evidence.json (hostname is read_only=false with help_text "
         "'Server Name Indication (SNI) hostname')."),
    "本臂握手序列进 tls.hashes，o3/o6 口径与第一轮完全一致":
        "this arm's handshakes feed tls.hashes; the o3/o6 calibers are identical to round 1",
    "本臂只贡献 sni_map 的第二个条目，绝不进 tls.hashes——否则 o6 会把 SNI 分岔误记成时间轮换":
        ("this arm contributes only the second sni_map entry and never enters tls.hashes; "
         "otherwise o6 would record name divergence as rotation in time"),
    "两臂 target 必须是同一个显式 IP、同一批 prb_id、起始错开 >=60 s；hostname 取两个真实身份名（待作者拍板）":
        ("both arms must target the same explicit address with the same prb_ids and starts >=60 s "
         "apart; hostname takes two real identity names (author decision pending)"),
    "阳性对照（o4 修正版）：第一轮目标 A，同 IP 双 SNI 条件":
        "positive control (o4-corrected): round-1 target A under two names on the same address",
    "对照臂的 o1 附加测量（9 靶）：把 κ 从 0.5 提到 0.667；H2 不依赖它":
        "o1 supplement for the control arms (9 targets): lifts kappa from 0.5 to 0.667; H2 does not depend on it",
    "实验臂（o4 修正版）：异质靶同 IP 双 SNI ＋ ping，H1 主统计":
        ("experimental arm (o4-corrected): heterogeneous targets under two names on the same "
         "address plus ping; the H1 statistic"),
    "预检证明 o1 不能拆开 {c1,c5,c8}；异质靶若只跑 TLS+ping，H1 的'可分辨'会被结构性压到接近 0。o4 是唯一判别轴，故主线必须带双 SNI 臂。":
        ("The preflight shows that o1 cannot separate {c1,c5,c8}; if heterogeneous targets ran "
         "TLS+ping only, H1's decidability would be structurally driven toward zero. o4 is the only "
         "discriminating axis, so the main line must carry the two-name arm."),
    "身份名：握手序列进 tls.hashes，o3/o6 与第一轮同口径":
        "identity name: handshakes feed tls.hashes; o3/o6 as in round 1",
    "对比名：只进 sni_map，绝不进 tls.hashes": "contrast name: feeds sni_map only, never tls.hashes",
    "两臂同一显式 IP、同一批 prb_id、起始错开 >=60 s":
        "both arms: same explicit address, same prb_ids, starts >=60 s apart",
    "与两条 sslcert 同一 prb 集合，供 build_merged_bundle 合并":
        "same probe set as the two sslcert arms, for build_merged_bundle",
    "2026-11-12 实测：24 候选经排除条件 1–5 后仅 2 靶双条件可达（greennet.ge strong / tatanova.com weak）；预注册 H1 的 n 因此为 2，须作者裁决口径。":
        ("Measured on 2026-11-12: after exclusion criteria 1-5 only two targets pass under both "
         "names (one strong, one weak), so the pre-registered H1 has n=2 and its caliber needs the "
         "author's decision."),
    "o5 附加臂（仅 3 靶 × 12 轮）：证明 o5 可得，不进主线判据":
        "o5 add-on arm (3 targets x 12 rounds): shows o5 is obtainable; not part of the main criteria",
    "S1 异质性筛查（战役前）：one-off，多视角 × 3 时段":
        "S1 heterogeneity screen (pre-campaign): one-off, many vantages across three time bands",
    "筛查就用与战役同名的条件（显式 IP ＋ 身份名），否则'筛过了'不代表战役里还能握上手；域名靶会被 API 侧预解析校验拒绝":
        ("the screen uses the same name condition as the campaign (explicit address plus identity "
         "name); otherwise 'screened' does not imply 'still handshakes in the campaign'. Domain "
         "targets are rejected by the API's pre-resolution check."),
    "prereg §4 排除条件 5：战役前先测出该靶会不会因未知 SNI 直接拒握手；被拒的靶不进 48h，省窗口也省信用":
        ("prereg §4 exclusion 5: test before the campaign whether the target rejects an unknown "
         "name outright; rejected targets do not enter the 48-hour window, saving window and credits"),
    "视角能力预检（D5 扩样版）：9 个对照靶 × 24 候选探针 × 2 个名字，one-off":
        "vantage capability pre-test (D5 expanded): 9 control targets x 24 candidate probes x 2 names, one-off",
    "第一轮握手 >=3 次的探针共 24 个，跨靶覆盖数全部为 1 ⇒ 交集 = 0（data/c1/round2/probe_seed.json）。白名单不能从第一轮继承，也不能只在自己 rig 上预检——那证明不了这些探针对第三方协议栈能握手。战役要求 TLS 与 ping 落在同一批探针上，所以白名单必须是'9 靶两名字都达标'的交集。":
        ("In round 1, 24 probes produced >=3 handshakes, each at exactly one target, so the "
         "intersection is empty (data/c1/round2/probe_seed.json). The whitelist cannot be inherited "
         "from round 1, and a rig-only pre-test cannot show that these probes handshake against "
         "third-party stacks. The campaign needs TLS and ping on the same probes, so the whitelist "
         "is the intersection of probes that qualify at all nine targets under both names."),
    "取'在全部 9 靶上两种名字都完成握手'的 prb 交集；交集 >=4 直接用，每靶取 4（可选 6）。不足 4 个则按'达标靶数降序、该靶握手数降序、prb_id 升序'补齐，并在 deviations.md 记补齐个数与理由（论文里如实写）。":
        ("Take the intersection of probes that complete a handshake at all nine targets under both "
         "names; when the intersection is >=4 use it directly (4 per target, optionally 6). Below 4, "
         "backfill by descending number of qualifying targets, then descending handshakes at those "
         "targets, then ascending prb_id, and record the backfill and its reason in deviations.md."),
    "o1 异质的跨轮次试点（筛查扩展，不进任何 H 判定）：同一探针 12 轮 TTL 是否变化":
        ("cross-round pilot for o1 heterogeneity (a screening extension, not part of any hypothesis "
         "test): whether a probe's TTL changes across 12 rounds"),
    "单轮筛查无法评估 o1：ping 的 ttl 是回包剩余跳数，跨视角不同是路径长度差异。真正的异质是同一探针跨轮次 TTL 集合基数>1。":
        ("a single-round screen cannot assess o1: the ttl of an echo reply is the remaining hop "
         "count, and cross-vantage differences are path-length differences. True heterogeneity is a "
         "same-probe TTL set of cardinality greater than one across rounds"),
    "area=WW 抽 4 视角；轮次 12 ⇒ 判据看每个(靶,探针)在这 12 轮里的 TTL 集合":
        "four vantages drawn with area=WW over 12 rounds; the criterion reads each (target, probe) TTL set across them",
    "三档原案（L1/L2/L3）＋两档 o4 修正案（L1S/L1SP）。L1 只验 G2；未通过 L1 不得开 L2。⚠ 2026-11-11 离线预检判定：原案 L1/L2/L3 的 TLS+ping 组合无法证伪 c5，H2 结构上不可达（8/8 仍不可分辨），故验 G2 必须走 L1S/L1SP。原案保留仅为对照与审计，不得据此发起测量。":
        ("Three original tiers (L1/L2/L3) plus two o4-corrected tiers (L1S/L1SP). L1 tests G2 only; "
         "without passing L1, L2 must not start. The offline preflight of 2026-11-11 found that the "
         "TLS+ping combination of the original tiers cannot falsify c5, so H2 is structurally "
         "unreachable (8/8 remain indistinguishable); G2 must therefore be tested via L1S/L1SP. The "
         "original tiers are retained for audit only and must not be launched."),
    "24h，9 个现有靶（8 阴性对照 + A），TLS+ping〔原案：预检判定 H2 不可达，勿用〕":
        "24 h, the nine existing targets (eight negative controls plus A), TLS+ping [original tier: preflight found H2 unreachable; do not use]",
    "24h，9 靶 × 同 IP 双 SNI 条件（o3/o4/o6，κ=0.5）＋视角预检 —— 验 G2 的最小可交付":
        "24 h, nine targets x two names on the same address (o3/o4/o6, kappa=0.5) plus the vantage pre-test: the minimum deliverable for G2",
    "L1S ＋ 对照臂 ping（o1/o3/o4/o6，κ=0.667）—— 同时给 H1 的 TTL 异质判据留观测":
        "L1S plus the control-arm ping (o1/o3/o4/o6, kappa=0.667), which also leaves observations for H1's TTL heterogeneity criterion",
    "48h，8 对照 + 8~10 异质 + 阳性，TLS+ping":
        "48 h, eight controls plus 8-10 heterogeneous plus the positive control, TLS+ping",
    "对 H1 无判别力（同 L1 问题）：异质臂缺 o4。保留作对照与审计，不得据此发起测量。":
        "No power for H1 (the L1 problem): the heterogeneous arm lacks o4. Retained for audit only; must not be launched.",
    "48h，o4 修正版主线：8 对照 + 8~10 异质 + 阳性全部带同 IP 双 SNI（+异质靶 ping），两 rig 验 H3/H4":
        "48 h, the o4-corrected main line: eight controls plus 8-10 heterogeneous plus the positive control, all under two names on the same address (plus ping on heterogeneous targets); two rigs for H3/H4",
    "D5 后重投：合计 102,576、上界 108,912、停手线 10,891 ⇒ 需预充 113,467，对基线 113,573 只剩 106＝没有缓冲，不建议；已选档是 L2S6（合计 84,912，需 93,806）":
        "Re-budgeted after D5: total 102,576, upper bound 108,912, stop line 10,891, so 113,467 must be pre-charged against a 113,573 baseline, leaving 106 and no buffer; not recommended. The selected tier is L2S6 (total 84,912, needs 93,806).",
    "L2S 砍异质靶到 6 个（省 4 靶 × 48 h × 双 SNI ＋ ping）—— 余额内唯一可跑的 o4 主线":
        "L2S trims the heterogeneous arm to six targets (saving four targets x 48 h x two names plus ping): the only o4 main line that fits the balance",
    "砍靶必须与对照臂同窗口，否则 H2 与 H1 不可比；异质靶数下降只影响 H1 的 Wilson 区间宽度":
        "Target trimming must share the control arms' window, otherwise H2 and H1 are not comparable; fewer heterogeneous targets only widens H1's Wilson interval",
    "已选档（作者 2026-11-11 决定）：合计 84,912、上界 88,944、停手线 8,894 ⇒ 需预充 93,806，对基线 113,573 余 19,767。含 D5 预检 8,640 与 S1 筛查 10,800":
        "Selected tier (author decision, 2026-11-11): total 84,912, upper bound 88,944, stop line 8,894, so 93,806 must be pre-charged, leaving 19,767 against the 113,573 baseline. Includes the D5 pre-test (8,640) and the S1 screen (10,800).",
    "L2S 去掉 48 h 阴性对照臂（复用 L1S 的 24 h 对照结果）—— 省钱但两段窗口不同，只能作敏感性分析":
        "L2S drops the 48-hour negative-control arm and reuses the 24-hour control results of L1S: cheaper, but the windows differ, so it serves as a sensitivity analysis only",
    "预注册 §8 明确'不同长度的靶不合并统计'；此档的 H2 只能用 L1S 窗口单独报，不得与 H1 同表":
        "prereg §8 states that targets with different window lengths are not pooled; this tier's H2 can only be reported for the L1S window and may not share a table with H1",
    "L2 + o5 附加臂（3 靶 × 12 轮 traceroute）": "L2 plus the o5 add-on arm (3 targets x 12 rounds of traceroute)",
    "24 候选 × 4 视角 × 12 轮 recurring ping（3,456 credits）—— 先在钱少的层面回答 H1 有没有靶":
        "24 candidates x 4 vantages x 12 rounds of recurring ping (3,456 credits): answers cheaply whether H1 has any targets at all",
    "prereg §4/D5：交集 >=4 直接用；不足 4 按达标靶数降序补齐并写 deviations":
        "prereg §4/D5: use the intersection directly when >=4; below 4, backfill by descending qualifying targets and record it in deviations",
    "阴性对照：第一轮 8 个单证书舰队": "negative controls: the eight single-certificate fleets of round 1",
    "阳性对照：第一轮那唯一有信息量的靶": "positive control: the only informative round-1 target",
    "对照臂的 o1 附加测量（同一批 IP 靶）": "o1 supplement for the control arms (same address targets)",
    "地址=试点实测 dst_addr；ip_drift=true 须作者裁决是否换址后再开战役":
        "address = the dst_addr observed in the pilot; when ip_drift=true the author decides whether to re-address before the campaign",
    "受控 rig：靶地址不落盘，运行时从 env 解析":
        "controlled rig: the target address is never stored; it is resolved from the environment at run time",
    "用 id 段而非'最新 N 条'：id 段不随新测量增加而变化，可复算":
        "an id interval rather than a 'latest N' list: an id interval does not change as new measurements are added, so the sample is reproducible",
    "persistent=偏离众数 TTL 的独立区段>=2；strong>=2 个 persistent 探针，medium=1，weak=0":
        "persistent = at least two separate excursions from the modal TTL; strong = at least two persistent probes, medium = one, weak = none",
    "跨视角 TTL 差异是路径长度差异，不作为异质证据":
        "cross-vantage TTL differences reflect path length and are not treated as heterogeneity evidence",
    "只进 sni_map，不进 tls.hashes": "feeds sni_map only, never tls.hashes",
    "prereg §4: >=2 leaf fingerprints across vantages OR same-probe TTL cardinality >1 across rounds（后者由 12 轮 ping 试点供给）":
        "prereg §4: >=2 leaf fingerprints across vantages OR same-probe TTL cardinality >1 across rounds (the latter supplied by the 12-round ping pilot)",
}

R2_EXACT = {}
R2_EXACT.update(_ENGINE)
R2_EXACT.update(_SPEC)

# --- 含编号的机器注记（正则）--------------------------------------------
_RX_PARTIAL = re.compile(r"^(\S+) (\d+) 本轮回包不全（(\d)/4 探针）$")
_RX_SPECIFIED = re.compile(r"^(\S+) (\d+) 仍在 Specified（排队，稍后复核）$")
_RX_ELIM = re.compile(r"^(o\d)=(negative|positive) ⇌ 预测 ([+-])（证伪淘汰）$")


def _partial(m):
    return "%s %s: partial round in this audit (%s/4 probes)" % (m.group(1), m.group(2), m.group(3))


def _specified(m):
    return "%s %s: still Specified (queued; re-check later)" % (m.group(1), m.group(2))


def _elim(m):
    return "%s=%s against a predicted %s (falsified)" % (m.group(1), m.group(2), m.group(3))


R2_PATTERNS = [(_RX_PARTIAL, _partial), (_RX_SPECIFIED, _specified), (_RX_ELIM, _elim)]
