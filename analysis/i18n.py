#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""c1_i18n.py —— 发布包英文化映射（构建期与复算期共用一份）。

为什么需要：判定引擎（sensor_compare.py）与判卷脚本是中文产线，引擎输出的
四态、族码说明与归因注记都是中文串；公开包面向英文读者，直接发布会让审稿人
在 `data/c1/sslcert9_judged.json` 与 `ground_truth/pilot_truth.json` 里读到中文。

纪律：
  * **只翻译字符串，不改结构、不改数值、不改指纹**——映射表逐条写死，可审计；
  * 翻译在**构建期**施加于发布包的 JSON（源侧 JSON 保持原样以备复算），
    `analysis/i18n.py` 随包发布，复算脚本用同一份映射把"重算结果"归一到英文，
    于是"发布值 == 重算值"的确定性检查在两种语言下都成立；
  * 映射表未覆盖且仍含中文的串，**原样保留并被统计上报**（不猜、不意译）。

用法：
  python tools/c1_i18n.py data/c1/sslcert9_judged.json   # 预览翻译
"""
import json
import re
import sys

CJK = re.compile(r"[\u4e00-\u9fff]")

# --- 精确映射（引擎输出、预注册说明）----------------------------------------
EN_EXACT = {
    # 引擎四态
    "决定可判": "decidable",
    "条件可判": "conditionally decidable",
    "不可分辨": "indistinguishable",
    "不可观测": "unobservable",
    # 归因注记（视角侧重签）
    "subject+有效期一致、issuer 不同 → 视角侧重签（中间盒 TLS 检查），非服务器轮换":
        ("same subject and validity, different issuer => vantage-side re-signing "
         "(middlebox TLS inspection), not server-side rotation"),
    # 规格文件里的占位身份标注
    "CN=example.com（占位身份）": "CN=example.com (placeholder identity)",
    "Kubernetes Ingress Fake Certificate（占位身份）":
        "Kubernetes Ingress Fake Certificate (placeholder identity)",
    # 锚点预注册文件
    "<云 VM 公网 IP>:443（值只走对话/环境变量，零落盘）":
        "<cloud VM public IP>:443 (value passed only via chat/environment, never stored)",
    ("单云 VM：root netns RR 代理(0.0.0.0:443) 每连接交替 -> be_a(10.90.1.2, cert A "
     "pilot-a.local, ttl 64) / be_b(10.90.2.2, cert B pilot-b.local, ttl 255)"):
        ("single cloud VM: root-netns round-robin proxy on 0.0.0.0:443 alternating per "
         "connection -> be_a(10.90.1.2, cert A pilot-a.local, ttl 64) / "
         "be_b(10.90.2.2, cert B pilot-b.local, ttl 255)"),
    "positive（若同靶补建 ping 测量：64/255 双 TTL；sslcert-only 时 unobservable）":
        ("positive (if a ping measurement is added for the same target: the two TTLs "
         "64/255 are separable; unobservable with sslcert only)"),
    "unobservable（Atlas 无 ICMP Timestamp）":
        "unobservable (Atlas offers no ICMP Timestamp option)",
    "positive（≥3 握手/视角后证书轮换命中）":
        "positive (certificate rotation hit after >=3 handshakes per vantage)",
    "unobservable（单 SNI 名）": "unobservable (single SNI name)",
    "unobservable（无 trace）": "unobservable (no traceroute)",
    "positive（跨视角证书并集 = 2）":
        "positive (cross-vantage certificate union = 2)",
    "2/6=0.333（sslcert-only，恰好过闸）；0.5（加 ping 测量）":
        "2/6=0.333 (sslcert only, exactly at the floor); 0.5 (with a ping measurement)",
    ("2026-11-08：补充双证书公开指纹（sha256(DER) 前 16 hex，openssl 与引擎 _leaf_hash "
     "双路一致）；预注册预期本身不变。"):
        ("2026-11-08: the two public fingerprints of the dual certificate were added "
         "(first 16 hex of sha256(DER); openssl and the engine's _leaf_hash agree); the "
         "pre-registered expectation itself is unchanged."),
    ("预期 = M2 的首个公开数据四态判定。若 realized ≠ 预期：如实记录偏差（判卷纪律："
     "拒判也入结果，不硬凑）。"):
        ("expectation = the four-state verdict of the first public data of M2. If the "
         "realized verdict differs from the expectation, record the deviation honestly "
         "(judging discipline: a refusal to decide is still a reported result; never "
         "force a verdict)."),
}

# --- 模式映射（引擎按参数拼出的串）-------------------------------------------
EN_PATTERNS = [
    (re.compile(r"^o(\d+)=(negative|positive|unobservable) ⇌ 预测 ([+−-])（证伪淘汰）$"),
     lambda m: ("o%s=%s ⇌ predicted %s (falsified, eliminated)"
                 % (m.group(1), m.group(2),
                    {"+": "+", "−": "-", "-": "-"}[m.group(3)]))),
    (re.compile(r"^c(\d+) 支持度 (\d+)，其余存活假设持平度不足$"),
     lambda m: ("c%s support %s; the remaining surviving hypotheses tie below the "
                "threshold" % (m.group(1), m.group(2)))),
    (re.compile(r"^等价类 \[(.*?)\] 同权同分（支持度 (\d+)），现有观测无法分离$"),
     lambda m: ("equivalent class [%s] ties on support (%s); the current observations "
                "cannot separate them" % (m.group(1), m.group(2)))),
]


def translate_string(s):
    if not isinstance(s, str) or not CJK.search(s):
        return s
    if s in EN_EXACT:
        return EN_EXACT[s]
    for rx, fn in EN_PATTERNS:
        m = rx.match(s)
        if m:
            return fn(m)
    return s


def translate(obj):
    """递归翻译 dict/list/str；返回 (翻译后对象, 仍含中文的串列表)。"""
    residual = []

    def walk(o):
        if isinstance(o, str):
            t = translate_string(o)
            if CJK.search(t):
                residual.append(t)
            return t
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        return o

    return walk(obj), residual


def translate_file(path, out_path=None):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    t, residual = translate(d)
    out = out_path or path
    with open(out, "w", encoding="utf-8") as f:
        json.dump(t, f, ensure_ascii=False, indent=1)
    return residual


if __name__ == "__main__":
    for p in sys.argv[1:]:
        res = translate_file(p, p + ".en.json")
        print("%s -> residual CJK strings: %d" % (p, len(res)))
        for r in res[:10]:
            print("   %s" % r[:100])
