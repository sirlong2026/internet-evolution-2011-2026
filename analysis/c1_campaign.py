#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_campaign.py —— C1 Atlas 批量测量驱动（2026-11-08，云 VM 出口发起）。
API 契约（已从 RIPE-NCC 官方客户端 ripe-atlas-cousteau 源码逐字核实）：
  POST https://atlas.ripe.net/api/v2/measurements/
  鉴权头 `Authorization: Key <api_key>`（不是 Api-Auth-Key，也不是 ApiKey）
  载荷 {"definitions": [...], "probes": [{"type":"area","value":"WW","requested":N}],
        "is_oneoff": bool, "start_time": unix, "stop_time": unix}
  **一个 POST 可含多条 definitions**（每条=一个独立测量=一个靶）→ 160 个测量对象
  按组批发起只需 3–5 个 POST（评估文档"160 创建动作"指测量对象数，非 HTTP 请求数）。
  traceroute 必填 protocol；one-off 无 interval/stop_time。
纪律：
  - ATLAS_API_KEY 只走环境变量，绝不落盘；本脚本标准库零依赖，可直接在云 VM python3 跑。
  - 靶标来自 2011 冻结研究数据集（第三方公网研究靶，可落盘 data/c1/）；
    **C2 云锚点靶值只走环境变量 C1_ANCHOR_TARGET**（我方基础设施 IP 零落盘）。
  - 测量一律 is_public（论文引用 msm id）；绝不 Delete（B 线纪律同）。
  - 同机偏置：含锚点的组用 probe_tags_exclude 排除本机探针标签（注册后打标）。
用法：
  python c1_campaign.py --spec <spec.json> --dry-run     # 只构造校验，不联网不花钱
  python c1_campaign.py --spec <spec.json> --create      # 真实发起（须 ATLAS_API_KEY）
  python c1_campaign.py --fetch <msm_id>                 # 取结果（公开测量无需 key）
  python c1_campaign.py --status <msm_id>                # 查测量状态
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

API = "https://atlas.ripe.net/api/v2/measurements/"
CHUNK = 50          # 每 POST 最多 definitions 数（保守分批，防服务端上限）
SLEEP_BETWEEN = 3   # POST 间隔秒（限速礼貌）
OUT_IDS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "c1", "campaign_msm_ids.json")


def api_call(url, key=None, payload=None, method="GET"):
    headers = {"Accept": "application/json"}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    if key:
        headers["Authorization"] = "Key " + key   # 官方 cousteau 契约
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")[:500]
            if e.code == 429:
                wait = int(e.headers.get("Retry-After", "30"))
                print("[429] rate limited, wait %ds" % wait, flush=True)
                time.sleep(wait)
                continue
            raise RuntimeError("HTTP %d: %s" % (e.code, body))
    raise RuntimeError("rate limited beyond 5 attempts")


def build_group_payload(g, now):
    targets = list(g["targets"])
    if g.get("anchor_from_env"):
        anchor = os.environ.get(g["anchor_from_env"], "")
        if not anchor:
            raise RuntimeError("group %s: env %s empty（锚点靶值只走环境变量）" % (g["name"], g["anchor_from_env"]))
        targets.append(anchor)
    defs = []
    for t in targets:
        d = {"type": g["type"], "target": t, "af": g.get("af", 4),
             "is_public": True,  # definition 级字段（2026-11-08 实测：顶层会被 400 拒绝；msm 234165716 验证 definition 级生效）
             # 2026-11-09 更正：匿名红线——公开页禁出现 the 2011 snapshot/the mapping platform 等来源名，统一 "2011 snapshot"
             "description": "C1 longitudinal evolution measurement (2011 snapshot vs 2026), group=%s" % g["name"]}
        if g["type"] == "sslcert":
            d["port"] = g.get("port", 443)
        if g["type"] == "traceroute":
            d["protocol"] = g.get("protocol", "ICMP")
        if g.get("resolve_on_probe"):
            d["resolve_on_probe"] = True  # 域名靶：探针侧解析（API 侧预解析校验会拒解不了的域名）
        if not g.get("is_oneoff", True):
            d["interval"] = g["interval"]
        defs.append(d)
    probes = dict(g["probes"])
    if g.get("probe_tags_exclude"):
        probes["tags"] = {"exclude": g["probe_tags_exclude"]}
    payload = {"definitions": defs, "probes": [probes],
               "is_oneoff": g.get("is_oneoff", True)}
    if not payload["is_oneoff"]:
        payload["start_time"] = now
        payload["stop_time"] = now + g["duration_hours"] * 3600
    return payload, len(targets)


def estimate_credits(g, n_targets):
    nprobe = g["probes"]["requested"]
    if g.get("is_oneoff", True):
        results = n_targets * nprobe
    else:
        results = n_targets * nprobe * g["duration_hours"] * 3600 // g["interval"]
    return results, results * g.get("unit_cost", 0)


def create(spec_path, chunk_size=CHUNK):
    key = os.environ.get("ATLAS_API_KEY", "")
    if not key:
        print("ATLAS_API_KEY 未设置（只走环境变量）"); sys.exit(2)
    with open(spec_path, encoding="utf-8") as f:
        spec = json.load(f)
    out = os.path.normpath(OUT_IDS)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    prev = []
    if os.path.exists(out):
        with open(out, encoding="utf-8") as f:
            prev = json.load(f).get("measurements", [])
    ids = []
    failures = []
    try:
        for g in spec["groups"]:
            # 服务器时钟可能快于本机：每 POST 重取 now+15s（"start time in future" 教训）
            _, n_defs = build_group_payload(g, int(time.time()) + 15)
            for i in range(0, n_defs, chunk_size):
                payload, n = build_group_payload(g, int(time.time()) + 15)
                chunk = dict(payload)
                chunk["definitions"] = payload["definitions"][i:i + chunk_size]
                tgt = chunk["definitions"][0]["target"] if chunk["definitions"] else "?"
                try:
                    resp = api_call(API, key=key, payload=chunk, method="POST")
                except Exception as ex:
                    print("[failed] group=%s chunk=%d target=%s -> %s"
                          % (g["name"], i // chunk_size, tgt, str(ex)[:160]), flush=True)
                    failures.append({"group": g["name"], "target": tgt,
                                     "error": str(ex)[:300]})
                    continue
                new = resp.get("measurements", [])
                print("[created] group=%s chunk=%d target=%s -> msm ids %s"
                      % (g["name"], i // chunk_size, tgt, new), flush=True)
                ids.extend({"msm_id": m, "group": g["name"], "type": g["type"]} for m in new)
                time.sleep(SLEEP_BETWEEN)
    finally:
        with open(out, "w", encoding="utf-8") as f:
            json.dump({"created_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
                       "measurements": prev + ids}, f, ensure_ascii=False, indent=1)
        print("msm ids ->", out, ("(%d failures)" % len(failures)) if failures else "")
        if failures:
            print("failures:", json.dumps(failures, ensure_ascii=False)[:1200])


def dry_run(spec_path):
    with open(spec_path, encoding="utf-8") as f:
        spec = json.load(f)
    now = int(time.time())
    total_cr = 0
    total_msm = 0
    for g in spec["groups"]:
        try:
            payload, n = build_group_payload(g, now)
        except RuntimeError as ex:
            if g.get("anchor_from_env") and g["anchor_from_env"] in str(ex):
                # dry-run 时 env 未设：降级为不含锚点估算（零泄漏，不读值）
                payload, n = None, len(g["targets"])
            else:
                raise
        results, cr = estimate_credits(g, n)
        total_cr += cr
        total_msm += n
        npost = 0 if payload is None else (len(payload["definitions"]) + CHUNK - 1) // CHUNK
        print("group=%-12s type=%-11s targets=%3d probes=%2d oneoff=%s -> %d POST, %d results, %d credits"
              % (g["name"], g["type"], n, g["probes"]["requested"], g.get("is_oneoff", True), npost, results, cr))
        if g.get("anchor_from_env") and not os.environ.get(g["anchor_from_env"], ""):
            print("  NOTE: env %s 未设——dry-run 靶数不含锚点；--create 前必须设置" % g["anchor_from_env"])
    print("TOTAL: %d 测量对象, %d credits（预算闸 50,000）" % (total_msm, total_cr))
    if total_cr > 50000:
        print("WARN: 超预算，须缩规模或等探针补给")
    print("dry-run 未联网、未花钱。")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec")
    ap.add_argument("--chunk", type=int, default=CHUNK, help="每 POST definitions 数（1=逐靶隔离解析/额度失败）")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--create", action="store_true")
    ap.add_argument("--fetch")
    ap.add_argument("--fetch-batch", metavar="IDS_JSON", nargs="?", const="default",
                    help="批量取回 group 的全部 msm 结果（无参用 campaign_msm_ids.json）")
    ap.add_argument("--group", default=None, help="配合 --fetch-batch：只取指定 group")
    ap.add_argument("--status")
    args = ap.parse_args()
    if args.fetch:
        msm = int(args.fetch)
        raw = api_call(API + "%d/results/" % msm)
        out_dir = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "c1", "raw"))
        os.makedirs(out_dir, exist_ok=True)
        out = os.path.join(out_dir, "cam_%d.json" % msm)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(raw, f, ensure_ascii=False)
        print("[fetch] %d results -> %s" % (len(raw), out))
        return
    if args.fetch_batch:
        # 批量取回：ids 文件（campaign_msm_ids.json）里指定 group 的所有 msm；公开测量免鉴权
        ids_path = args.fetch_batch if os.path.exists(args.fetch_batch) else os.path.normpath(OUT_IDS)
        with open(ids_path, encoding="utf-8") as f:
            recs = json.load(f)["measurements"]
        grp = args.group
        todo = [r["msm_id"] for r in recs if (not grp or r["group"] == grp)]
        out_dir = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "c1", "raw"))
        os.makedirs(out_dir, exist_ok=True)
        done = empty = 0
        for i, msm in enumerate(todo):
            try:
                st = api_call(API + "%d/" % msm)
                raw = api_call(API + "%d/results/" % msm)
                with open(os.path.join(out_dir, "cam_%d.json" % msm), "w", encoding="utf-8") as f:
                    json.dump(raw, f, ensure_ascii=False)
                n = len(raw)
                tag = st.get("status", {}).get("name", "?")
                done += 1 if n else 0
                empty += 1 if not n else 0
                print("[%3d/%3d] msm %d status=%s results=%d" % (i + 1, len(todo), msm, tag, n), flush=True)
            except Exception as ex:
                print("[%3d/%3d] msm %d ERROR %s" % (i + 1, len(todo), msm, str(ex)[:120]), flush=True)
            time.sleep(0.5)
        print("sweep done: %d with results, %d empty yet" % (done, empty))
        return
    if args.status:
        print(json.dumps(api_call(API + args.status + "/"), ensure_ascii=False, indent=1)[:2000])
        return
    if not args.spec:
        ap.print_help()
        sys.exit(2)
    if args.dry_run:
        dry_run(args.spec)
    elif args.create:
        create(args.spec, chunk_size=args.chunk)
    else:
        print("指定 --dry-run 或 --create")
        sys.exit(2)


if __name__ == "__main__":
    main()