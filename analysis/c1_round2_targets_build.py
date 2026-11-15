#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_round2_targets_build.py —— 把第一轮靶表派生成第二轮 o4 双臂战役的 targets 文件（离线，零 Atlas 写入）。

为什么要这个脚本：L2S6/L2S 的臂都要求 **显式 IP 靶 ＋ hostname 字段**（域名靶会被 API 侧
预解析校验拒绝，而 o4 必须由 `hostname` 提供）。第一轮用的是域名靶，`hostname` 全为 null
（见 data/c1/round2/atlas_sni_evidence.json），所以 IP 与身份名的对应关系现在还没有落盘的文件。
本脚本把那层关系一次算清并写成 spec 引用的 targets_*.json，使"授权之后"只剩"提交"一步。

口径（写死，不得随手改）：
  * 靶 IP 取**第一轮实际连接的地址**（raw 行里按靶统计的多数 dst_addr），
    这样第二轮与第一轮是同一个地址条件；今天的 A 记录只作**注记**，不换靶。
    若一轮地址已不在今天的 A 记录里 ⇒ 打 `ip_drift=true`，由作者决定是否换新地址。
  * 身份名 = 第一轮的靶域名（只进 data/，不进稿件与公开仓）。
  * 对比名 = spec 的 defaults.sni.contrast_name（不在本脚本里硬编码）。
  * rig 靶**不落盘**：只写 env 变量名，运行时解析（锚点地址零落盘纪律）。
  * 探针白名单：本脚本只出**候选种子**（第一轮真正握上手 ≥3 次的 prb），
    最终白名单必须由战役前的能力预检（花钱）在两个名字条件下分别确认。

用法：python tools/c1_round2_targets_build.py [--dry-run]
"""
import argparse
import collections
import io
import json
import os
import re
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
C1 = os.path.join(ROOT, "data", "c1")
RAW = os.path.join(C1, "raw")
OUT = os.path.join(C1, "round2")

SPEC1 = os.path.join(C1, "sslcert9_spec.json")
JUDGED = os.path.join(C1, "sslcert9_judged.json")

# 禁词：产品名拆片（脚本自身要能被公开扫描），锚点地址只走 env
BANNED = [re.compile(p, re.I) for p in ("ip" "sonar", "lum" "eta", "umg" "dy")]
ANCHOR_IP = os.environ.get("C1_ANCHOR_TARGET", "").strip()

DOH = "https://cloudflare-dns.com/dns-query?name=%s&type=A"
DOH_TIMEOUT = 6      # 本机 DoH 常被网络策略卡住；探测一次即放弃，不逐靶重试
SYS_TIMEOUT = 8


def load(p):
    with io.open(p, encoding="utf-8", newline="") as f:
        return json.load(f)


def doh_a(domain, timeout=DOH_TIMEOUT):
    try:
        req = urllib.request.Request(DOH % domain,
                                     headers={"Accept": "application/dns-json",
                                            "User-Agent": "c1-round2-targets/1.0"})
        d = json.load(urllib.request.urlopen(req, timeout=timeout))
        return sorted({x["data"] for x in (d.get("Answer") or [])
                       if x.get("type") == 1})
    except Exception:
        return None


def sys_a(domain):
    """本机递归解析（DoH 不可达时的注记源；来源要写清，不冒充 DoH）。"""
    import socket
    try:
        socket.setdefaulttimeout(SYS_TIMEOUT)
        return sorted(set(socket.gethostbyname_ex(domain)[2]))
    except Exception:
        return None


def resolver_probe():
    """DoH 只在第一发上试一次；通了才对全靶用，否则整批走本机解析。"""
    return doh_a(next(iter(PROBE_ORDER)), timeout=DOH_TIMEOUT) is not None


PROBE_ORDER = ("atlas.ripe.net",)


def observed_for_row(row):
    """一轮靶的全部战役测量 → 实际连接地址的多数字 + 每探针握手次数。"""
    addrs = collections.Counter()
    per_prb = collections.Counter()
    for msm in row["msms"]:
        path = os.path.join(RAW, "cam_%d.json" % msm)
        if not os.path.exists(path):
            continue
        for r in load(path):
            a = r.get("dst_addr") or r.get("dst_ip")
            if a:
                addrs[a] += 1
            if r.get("cert"):
                per_prb[r.get("prb_id")] += 1
    top = addrs.most_common(1)
    return (top[0][0] if top else None), dict(per_prb)


def build(dry=False):
    spec1, judged = load(SPEC1), load(JUDGED)
    fallback = spec1["domain_ip_fallback"]
    rows = judged["rows"]

    use_doh = resolver_probe()
    resolver = "doh:cloudflare" if use_doh else "system_recursive"
    print("  解析注记来源：%s（DoH 本机不可达时自动降级，来源随文件记录，不冒充）" % resolver)

    controls, positive, entries, seed = [], [], {}, collections.Counter()
    for row in rows:
        dom = row["domain"]
        obs_ip, prb_hands = observed_for_row(row)
        ip = obs_ip or fallback.get(dom)
        if not ip:
            raise SystemExit("靶 %s 既无 raw 连接地址也无 fallback，拒绝猜" % dom)
        today = doh_a(dom) if use_doh else sys_a(dom)
        e = {"target_ip": ip,
             "identity_name": dom,
             "ip_source": ("raw_dst_addr_majority" if obs_ip else "round1_fallback"),
             "resolver_today": (resolver if today else "unresolved"),
             "today_a_records": today,
             "ip_drift": (False if today is None else ip not in today),
             "round1_verdict": row.get("verdict", {}).get("V"),
             "probes_with_ge3_handshakes": sorted(p for p, n in prb_hands.items() if n >= 3)}
        entries[dom] = e
        for p in e["probes_with_ge3_handshakes"]:
            seed[p] += 1
        if row.get("verdict", {}).get("V") == "不可分辨":
            controls.append(dom)
        else:
            positive.append(dom)

    summary = {"arms": {"controls": len(controls), "positive": len(positive)},
               "resolver": resolver,
               "drift": sorted(d for d, e in entries.items() if e["ip_drift"]),
               "unresolved": sorted(d for d, e in entries.items() if e["today_a_records"] is None)}

    files = {}
    files["targets_control_single.json"] = {
        "arm": "control_single_sni", "role": "阴性对照：第一轮 8 个单证书舰队",
        "derived_from": ["data/c1/sslcert9_spec.json", "data/c1/sslcert9_judged.json",
                         "data/c1/raw/cam_<msm>.json"],
        "resolver_today": resolver,
        "contrast_name_ref": "defaults.sni.contrast_name",
        "targets": [entries[d] for d in controls]}
    files["targets_control_positive.json"] = {
        "arm": "control_positive_sni", "role": "阳性对照：第一轮那唯一有信息量的靶",
        "resolver_today": resolver,
        "contrast_name_ref": "defaults.sni.contrast_name",
        "targets": [entries[d] for d in positive]}
    files["targets_controls_all.json"] = {
        "arm": "controls_ping", "role": "对照臂的 o1 附加测量（同一批 IP 靶）",
        "resolver_today": resolver,
        "targets": [entries[d] for d in controls + positive]}
    files["targets_rig.json"] = {
        "arm": "rig_rotation / rig_middlebox / probe_pretest",
        "role": "受控 rig：靶地址不落盘，运行时从 env 解析",
        "targets": [{"target_ip_from_env": "C1_ANCHOR_TARGET",
                     "identity_name_from_env": "C1_ANCHOR_IDENTITY_NAME",
                     "contrast_name_ref": "defaults.sni.contrast_name"}]}
    files["probe_seed.json"] = {
        "note": "第一轮真正握上手 >=3 次的探针计数（跨靶出现次数）。**只是候选种子**："
                "最终白名单必须由战役前的能力预检在**两个名字条件下分别**确认（花钱动作）。",
        "contrast_name_ref": "defaults.sni.contrast_name",
        "ranked": [{"prb_id": p, "targets_with_ge3": n}
                   for p, n in sorted(seed.items(), key=lambda x: (-x[1], x[0]))[:24]]}

    for fn, obj in files.items():
        text = json.dumps(obj, ensure_ascii=False, indent=1)
        hits = [p.pattern for p in BANNED if p.search(text)]
        if ANCHOR_IP and ANCHOR_IP in text:
            hits.append("<anchor-ip-from-env>")
        if hits:
            raise SystemExit("[拒写] %s 命中禁词 %s" % (fn, hits))
        print("%-34s %6d 字符，禁词 0 命中（分母=%d）" % (fn, len(text), len(text)))
        if not dry:
            os.makedirs(OUT, exist_ok=True)
            with io.open(os.path.join(OUT, fn), "w", encoding="utf-8", newline="") as f:
                f.write(text)
    return summary, entries


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="只打印不落盘")
    a = ap.parse_args()
    print("离线派生第二轮 targets 文件（零 Atlas 写入；靶地址只在进程内与 data/ 里）")
    summary, entries = build(a.dry_run)
    print("\n对照 %d / 阳性 %d；解析来源=%s；ip_drift=%s；未解析=%s" % (
        summary["arms"]["controls"], summary["arms"]["positive"], summary["resolver"],
        summary["drift"] or "无", summary["unresolved"] or "无"))
    if summary["drift"]:
        print("  ⚠ 这些靶的第一轮地址已不在今天的 A 记录里：战役仍按第一轮地址打（同条件），"
              "但论文里要写明可能测到已下线服务 ⇒ 握手为零会触发停手规则 S4。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
