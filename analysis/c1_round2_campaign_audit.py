#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_round2_campaign_audit.py —— 战役落地审计（只读，不创建/停止/修改任何测量）。

审什么（逐条对照预注册与 spec）：
  1. 条数与臂配比：control_single_sni 16、control_positive_sni 2、hetero_sni 6、
     controls_ping 9、rig_rotation 3（本次 --exclude rig_middlebox）。
  2. 每条：status、participant_count、interval=3600、stop-start=172800、is_oneoff=False。
  3. sslcert：hostname 必须存在；_a = 该靶身份名、_b = 对比名（sni-control.invalid）。
  4. o4 配对：同一靶的 _a 与 _b 必须**同一 target IP、同一批 prb_id、起始错开 >=60 s**。
  5. 首轮结果：_a 应有证书行；_b 多数应被拒（无证书）——但不得据此改判据，只作健康度。
  6. 探针：白名单 4 个必须在每条测量里都出现（participant_count 与 prb 集合）。

纪律：
  * rig 臂的靶地址是锚点 ⇒ **不落盘、不打印**，只记 "<rig>"；
  * 第三方靶地址只在内存里用于配对，写盘只写域名标签；
  * 结果是只读 GET，不触发计费。

用法：python tools/c1_round2_campaign_audit.py [--cut 1794488000]
输出：data/c1/round2/campaign_audit.json ＋ 控制台表
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
REG = os.path.join(R2, "msm_ids.json")
WL = os.path.join(R2, "probe_whitelist.json")
TG = os.path.join(R2, "targets_controls_all.json")
TH = os.path.join(R2, "targets_hetero.json")
OUT = os.path.join(R2, "campaign_audit.json")
CUT = 1794488000          # 2026-11-12T12:53Z 之后创建的才是本轮战役
EXPECT = {"control_single_sni": 16, "control_positive_sni": 2, "hetero_sni": 6,
          "controls_ping": 9, "rig_rotation": 3}
RIG_ARMS = {"rig_rotation", "rig_middlebox"}


def load(p):
    with io.open(p, encoding="utf-8", newline="") as f:
        return json.load(f)


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "c1-round2-audit/1.0"})
    return json.loads(urllib.request.urlopen(req, timeout=120).read().decode())


def leaf_fp(cert):
    """取叶证书指纹（PEM 块 sha256 前 16 位），与 hetero_select 同口径。"""
    import hashlib
    import re
    if not cert:
        return None
    items = cert if isinstance(cert, list) else [cert]
    for x in items:
        if isinstance(x, str) and "BEGIN CERTIFICATE" in x:
            m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", x, re.S)
            if m:
                return hashlib.sha256(m.group(0).encode()).hexdigest()[:16]
    return None


def cert_rows(data):
    n = 0
    errs = collections.Counter()
    fps = collections.Counter()
    for r in data:
        f = leaf_fp(r.get("cert"))
        if f:
            n += 1
            fps[f] += 1
        else:
            e = str(r.get("error") or "")
            errs[e[:44] or "no-cert-no-error"] += 1
    return n, fps, dict(errs.most_common(3))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cut", type=int, default=CUT)
    a = ap.parse_args()

    wl = set(load(WL)["prb_ids"])
    ip2lab = {}
    for p, key in ((TG, "targets"), (TH, "targets")):
        if os.path.exists(p):
            for t in load(p)[key]:
                ip2lab[t.get("target_ip")] = t.get("identity_name") or t.get("domain")
    rig_ip = None

    reg = [r for r in load(REG)["measurements"]
           if int(r.get("start_time") or 0) >= a.cut]
    rows = []
    for r in reg:
        m = r["msm_id"]
        try:
            meta = get("https://atlas.ripe.net/api/v2/measurements/%d/" % m)
        except Exception as e:
            rows.append({"msm_id": m, "arm": r["arm"], "group": r["group"], "error": str(e)[:80]})
            continue
        d = (meta.get("definitions") or [meta])[0]
        is_rig = r["arm"] in RIG_ARMS
        tgt = d.get("target")
        if is_rig:
            rig_ip = tgt if rig_ip is None else rig_ip
            lab = "<rig>"
        else:
            lab = ip2lab.get(tgt, "?")
        res = []
        try:
            res = get("https://atlas.ripe.net/api/v2/measurements/%d/results/?page_size=1000" % m)
        except Exception:
            pass
        ncert, fps, errs = cert_rows(res)
        prbs = sorted({x.get("prb_id") for x in res if x.get("prb_id") is not None})
        rows.append({
            "msm_id": m, "arm": r["arm"], "group": r["group"], "type": r["type"],
            "label": lab,
            "status": (meta.get("status") or {}).get("name"),
            "participants": meta.get("participant_count"),
            "hostname": d.get("hostname"), "port": d.get("port"),
            "interval": d.get("interval"), "is_oneoff": meta.get("is_oneoff"),
            "start_time": meta.get("start_time"), "stop_time": meta.get("stop_time"),
            "span_h": round((meta.get("stop_time", 0) - meta.get("start_time", 0)) / 3600.0, 2),
            "result_rows": len(res), "cert_rows": ncert, "cert_fps": dict(fps),
            "errors_top": errs,
            "prb_seen": prbs,
            "_ip": tgt,          # 仅内存，写盘前剥掉（rig 恒不写）
        })

    # ---- 检查 ----
    issues = []
    health = []
    by_score = collections.Counter((x["arm"], x["group"]) for x in rows if "error" not in x)
    for arm, exp in EXPECT.items():
        got = sum(n for (a2, g2), n in by_score.items() if a2 == arm)
        if got != exp:
            issues.append("%s 应有 %d 条，实到 %d" % (arm, exp, got))

    for x in rows:
        tag = "%s/%s %d" % (x.get("arm"), x.get("group"), x.get("msm_id", 0))
        if "error" in x:
            issues.append("%s 读不到：%s" % (tag, x["error"]))
            continue
        if x["type"] == "sslcert":
            if not x.get("hostname"):
                issues.append("%s 缺 hostname" % tag)
            want = "sni-control.invalid" if x["group"].endswith("_b") else None
            if want and x["hostname"] != want:
                issues.append("%s 对比名应为 %s，实为 %s" % (tag, want, x["hostname"]))
            if x["group"].endswith("_a") and x["hostname"] == "sni-control.invalid":
                issues.append("%s 身份名被写成了对比名" % tag)
            if x["interval"] != 3600:
                issues.append("%s interval=%s（应 3600）" % (tag, x["interval"]))
        if x["is_oneoff"]:
            issues.append("%s 是 one-off（应为 recurring）" % tag)
        if abs(x["span_h"] - 48.0) > 0.1:
            issues.append("%s 窗口 %.2f h（应 48）" % (tag, x["span_h"]))
        if (x.get("status") or "") == "Specified":
            health.append("%s 仍在 Specified（排队，稍后复核）" % tag)
        elif x["participants"] in (None, 0):
            issues.append("%s 状态 %s 但无探针" % (tag, x.get("status")))
        elif x["participants"] != 4:
            issues.append("%s 探针 %s（应 4）" % (tag, x["participants"]))
        if x["prb_seen"] and not wl.issubset(set(x["prb_seen"])):
            extra = sorted(set(x["prb_seen"]) - wl)
            if extra:
                issues.append("%s 出现非白名单回包探针：%s" % (tag, extra))
            else:
                health.append("%s 本轮回包不全（%d/4 探针）" % (tag, len(x["prb_seen"])))

    # o4 配对：同靶同 IP、同探针集、起始错开 >=60 s
    pairs = collections.defaultdict(dict)
    for x in rows:
        if x.get("type") != "sslcert" or x.get("arm") not in EXPECT:
            continue
        side = "a" if x["group"].endswith("_a") else ("b" if x["group"].endswith("_b") else None)
        if side:
            pairs[(x["arm"], x["label"])][side] = x
    pair_ok = 0
    o4 = []
    for (arm, lab), ab in sorted(pairs.items()):
        if "a" not in ab or "b" not in ab:
            issues.append("o4 配对缺失 %s/%s（有 %s）" % (arm, lab, sorted(ab)))
            continue
        A, B = ab["a"], ab["b"]
        if A["_ip"] != B["_ip"]:
            issues.append("o4 配对不同 IP %s/%s" % (arm, lab))
        dt = abs(A["start_time"] - B["start_time"])
        if dt < 60:
            issues.append("o4 起始仅错开 %d s %s/%s（应 >=60）" % (dt, arm, lab))
        if A["prb_seen"] and B["prb_seen"] and not set(A["prb_seen"]) & set(B["prb_seen"]):
            issues.append("o4 两条没有共同回包探针 %s/%s" % (arm, lab))
        pair_ok += 1
        # o4 真正的判读：两条件下的**叶指纹集合**。同 ⇒ negative；互不相同 ⇒ positive。
        fa, fb = set(A["cert_fps"]), set(B["cert_fps"])
        if not fa or not fb:
            verdict = "unobservable（%s侧无证书）" % ("a" if not fa else "b")
        elif fa == fb:
            verdict = "negative（两条件同一张）" if len(fa) == 1 else "negative（两条件指纹集合相同）"
        elif fa & fb:
            verdict = "mixed（有交集也有各自独有）"
        else:
            verdict = "positive（两条件指纹互不相同）"
        o4.append({"arm": arm, "label": lab, "a_fps": sorted(fa), "b_fps": sorted(fb),
                   "a_n": A["cert_rows"], "b_n": B["cert_rows"], "verdict": verdict})

    for x in rows:
        if x.get("type") != "sslcert":
            continue
        if x["group"].endswith("_a") and x["result_rows"] and x["cert_rows"] == 0:
            health.append("%s 身份名尚未拿到任何证书（%s）" % (x["label"], x["errors_top"]))
        if x["group"].endswith("_b") and x["result_rows"] and x["cert_rows"] == 0:
            health.append("%s 对比名无证书（o4 暂不可观测；%s）" % (x["label"], x["errors_top"]))

    for x in rows:
        x.pop("_ip", None)          # 地址不落盘
    out = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "cut": a.cut, "n_measurements": len(rows),
           "by_score": {"%s|%s" % k: v for k, v in sorted(by_score.items())},
           "o4_pairs_checked": pair_ok, "o4_first_round": o4,
           "issues": issues, "health_notes": health, "rows": rows}
    io.open(OUT, "w", encoding="utf-8", newline="").write(json.dumps(out, ensure_ascii=False, indent=1))

    print("审计 %d 条（cut=%d）\n" % (len(rows), a.cut))
    print("%-22s %-12s %-5s %-4s %-6s %-6s %-6s" %
          ("arm", "group", "状态", "探针", "窗口h", "结果", "证书"))
    for x in rows:
        if "error" in x:
            print("%-22s %-12s ERROR %s" % (x["arm"], x["group"], x["error"]))
            continue
        print("%-22s %-12s %-5s %-4s %-6s %-6d %-6d" % (
            x["arm"], x["group"], (x["status"] or "?")[:5], x["participants"],
            x["span_h"], x["result_rows"], x["cert_rows"]))
    print("\no4 配对已核 %d 对；首轮指纹判定：" % pair_ok)
    for o in o4:
        print("  %-22s %-16s a=%-3d b=%-3d %s" % (o["arm"], o["label"], o["a_n"], o["b_n"], o["verdict"]))
    print("\n问题 %d 条：" % len(issues))
    for s in issues:
        print("  ! " + s)
    print("\n健康提示 %d 条：" % len(health))
    for s in health:
        print("  - " + s)
    print("\n-> %s" % OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
