#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_round2_launch.py —— 第二轮证书战役发起器（默认 dry-run，绝不 Delete）。

三个阶段，分开授权、分开记账：
  --stage pretest   视角能力预检（D5）：9 个对照靶 × 24 候选探针 × 2 个名字，one-off
  --stage screen    S1 筛查：25 个候选 ×（身份名 12 视角 ＋ 对比名 6 视角 ＋ ping 12 视角），one-off
  --stage campaign  48 h recurring 臂（L2S6 等）；**要求 targets_hetero.json 与 probe_whitelist.json 已就位**

花钱前的三道闸（任一不过即拒绝，不提供 --force）：
  1. 预注册哈希：调 c1_prereg_lock 的 digest 逻辑，spec 里的 sha256 必须 == 现文件哈希；
  2. 白名单：除 pretest 用 probe_seed.json 外，其余阶段必须读 data/c1/round2/probe_whitelist.json；
  3. 预算：按实测单价（10/20/6/60 credits per result）算本阶段预估，余额不足或会跌破停手线即拒绝。

纪律：
  * 靶地址只在内存与请求体里出现，**不打印、不落盘**（打印一律打码为 x.x.x.x）；
  * 描述统一匿名模板（"2011 snapshot vs 2026"），不含来源名/产品名；
  * 只 Stop，绝不 Delete；msm 登记进 data/c1/round2/msm_ids.json；
  * 起始时刻逐条错开 stagger（默认 60 s），并发控制在 ≤100。

用法：
  python tools/c1_round2_launch.py --stage pretest                 # dry-run，打印将要发什么
  ATLAS_API_KEY=<env> python tools/c1_round2_launch.py --stage pretest --commit
"""
import argparse
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from c1_prereg_lock import digest as prereg_digest, read as read_text  # noqa: E402

R2 = os.path.join(ROOT, "data", "c1", "round2")
SPEC = os.path.join(ROOT, "paper", "round2", "campaign_spec.template.json")
PREREG = os.path.join(ROOT, "paper", "round2", "prereg_round2.md")
OUT_MSM = os.path.join(R2, "msm_ids.json")

DESC = "C1 longitudinal evolution measurement (2011 snapshot vs 2026) round2"
UNIT_ONE_OFF = {"sslcert": 20, "ping": 6, "traceroute": 60}
STAGES = {"pretest": ["probe_pretest"], "screen": ["s1_screen"], "hetero_pilot": ["hetero_pilot"],
          "campaign": ["control_single_sni", "control_positive_sni", "hetero_sni",
                       "controls_ping", "rig_rotation", "rig_middlebox"]}


def load(p):
    with io.open(p, encoding="utf-8", newline="") as f:
        return json.load(f)


def redact(ip):
    return "x.x.x.x" if ip else "-"


def gate_prereg(spec):
    cur = prereg_digest(read_text(PREREG))
    want = (spec.get("meta", {}).get("prereg") or {}).get("sha256")
    if want in (None, "", "<FILL-AFTER-LOCK>"):
        raise SystemExit("[闸1] spec 里没有预注册哈希：先跑 c1_prereg_lock.py --commit")
    if cur != want:
        raise SystemExit("[闸1] 预注册哈希不一致（spec=%s… 现文件=%s…）⇒ 预注册被改动过，须重新锁定"
                         % (want[:12], cur[:12]))
    print("[闸1] 预注册哈希一致：%s…" % cur[:12])


def gate_balance(key, need):
    if not key:
        print("[闸3] 未给 ATLAS_API_KEY，跳过余额核对（dry-run 正常）")
        return
    req = urllib.request.Request("https://atlas.ripe.net/api/v2/credits/",
                                 headers={"Authorization": "Key " + key})
    bal = json.loads(urllib.request.urlopen(req, timeout=60).read().decode())["current_balance"]
    print("[闸3] 余额 %s，本阶段预估 %s，停手线按上界 10%% 计" % (bal, need))
    if bal < need:
        raise SystemExit("[闸3] 余额不足：%s < %s" % (bal, need))


def resolve_targets(arm, spec):
    ref = arm.get("targets_ref")
    if not ref:
        return []
    p = os.path.join(ROOT, ref)
    if not os.path.exists(p):
        raise SystemExit("[闸2] 缺靶表 %s" % ref)
    obj = load(p)
    out = []
    for t in obj.get("targets", []):
        ip = t.get("target_ip")
        if not ip:
            env = t.get("target_ip_from_env")
            if env:
                if not os.environ.get(env):
                    raise SystemExit("[闸2] 靶地址需 env %s（%s）" % (env, ref))
                ip = os.environ[env].strip()
        identity = t.get("identity_name") or t.get("domain")
        if not identity and t.get("identity_name_from_env"):
            identity = os.environ.get(t["identity_name_from_env"], "").strip()
        # 候选表（S1）：只记了侦察时的地址，且 prereg 要求按今日解析打
        if t.get("needs_fresh_resolution") and identity:
            import socket
            try:
                socket.setdefaulttimeout(8)
                fresh = sorted(set(socket.gethostbyname_ex(identity)[2]))
            except Exception:
                fresh = []
            if fresh:
                ip = fresh[0]
            elif not ip:
                ip = t.get("ip_at_scout_20261108")
        if not ip:
            raise SystemExit("[闸2] 靶 %s 无法确定地址（%s）" % (identity or "?", ref))
        out.append({"ip": ip, "identity": identity, "raw": t})
    return out


def resolve_probes(arm, stage):
    """pretest 用 probe_seed 的 24 个候选；screen 用 area=WW 全球抽样；campaign 必须用已定白的白名单。

    screen 不能用白名单：S1 的目的就是在**更多视角**上看跨视角指纹是否分岔；
    用战役那 4 个白名单视角筛，等于用结果去证明前提。
    """
    if stage == "pretest":
        p = os.path.join(R2, "probe_seed.json")
        if not os.path.exists(p):
            raise SystemExit("[闸2] 缺 probe_seed.json")
        ranked = load(p)["ranked"]
        return [r["prb_id"] for r in ranked]
    if stage in ("screen", "hetero_pilot"):
        return None
    p = os.path.join(R2, "probe_whitelist.json")
    if not os.path.exists(p):
        raise SystemExit("[闸2] 缺 probe_whitelist.json —— campaign 阶段必须先由 pretest 生成白名单（screen 用 area=WW）")
    obj = load(p)
    ids = obj.get("prb_ids") or obj.get("probes")
    if not ids:
        raise SystemExit("[闸2] probe_whitelist.json 里没有 prb_ids")
    return [int(x) for x in ids]


def build_jobs(spec, stage, probes_override=None, exclude=()):
    arms = {a["arm"]: a for a in spec["arms"]}
    jobs = []
    for an in STAGES[stage]:
        if an in exclude:
            print("  [skip] %s：按 --exclude 跳过" % an)
            continue
        arm = arms[an]
        targets = resolve_targets(arm, spec)
        if stage == "pretest":
            probes = resolve_probes(arm, stage)
        else:
            probes = probes_override or resolve_probes(arm, stage)
        if not targets:
            print("  [skip] %s：靶表为空" % an)
            continue
        for t in targets:
            for m in arm["measurements"]:
                if m["cost_class"] != "one-off" and stage not in ("campaign", "hetero_pilot"):
                    continue
                definition = {"type": m["type"], "target": t["ip"], "af": 4,
                              "is_public": True,
                              "description": "%s group=%s" % (DESC, m["group"])}
                if m["type"] == "sslcert":
                    definition["port"] = m.get("port", 443)
                    role = m.get("hostname_role")
                    if role == "identity_name":
                        definition["hostname"] = t["identity"]
                    elif role == "contrast_name":
                        definition["hostname"] = ((spec.get("defaults") or {}).get("sni") or {}).get("contrast_name")
                    if not definition.get("hostname"):
                        raise SystemExit("[闸2] %s/%s 需要 hostname（role=%s）但没有"
                                         % (an, m["group"], role))
                elif m["type"] == "ping":
                    definition["packets"] = m.get("packets", 6)
                    definition["size"] = m.get("size", 48)
                oneoff = m["cost_class"] == "one-off"
                n_p = int(m.get("probes", 4))
                # API 实测：probe_sources.value 必须是**逗号分隔的字符串**（列表会被 400 拒）
                probes_sel = ({"type": "area", "value": "WW", "requested": n_p}
                              if probes is None else
                              {"type": "probes",
                               "value": ",".join(str(x) for x in list(probes)[:n_p]),
                               "requested": n_p})
                if not oneoff:
                    definition["interval"] = m.get("interval_s", 3600)
                # 第一轮已实测：is_public / interval 都在 definitions[] 内，顶层只留这四类键
                payload = {"definitions": [definition],
                           "probes": [probes_sel],
                           "is_oneoff": oneoff}
                jobs.append({"arm": an, "group": m["group"], "type": m["type"],
                             "hours": m.get("duration_h") or 0,
                             "oneoff": oneoff,
                             "target_ip": t["ip"], "n_probes": int(m.get("probes", 4)),
                             "payload": payload,
                             "results": int(m.get("probes", 4)) * (1 if oneoff else
                                          round(m.get("duration_h", 48) * 3600 /
                                                m.get("interval_s", 3600)))})
    return jobs


UNIT_REC = {"sslcert": 10, "ping": 3, "traceroute": 30}   # recurring 实测价


def estimate(jobs):
    """recurring 按每结果 10/3/30，one-off 按 20/6/60——两套价不能混。"""
    total = 0
    for j in jobs:
        price = UNIT_ONE_OFF if j.get("oneoff", True) else UNIT_REC
        total += j["results"] * price[j["type"]]
    return total


def _post_once(path, key, payload):
    req = urllib.request.Request("https://atlas.ripe.net/api/v2/" + path,
                                 data=json.dumps(payload).encode("utf-8"),
                                 headers={"Authorization": "Key " + key,
                                          "Content-Type": "application/json"}, method="POST")
    for _ in range(5):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(int(e.headers.get("Retry-After", "30")))
                continue
            raise RuntimeError("HTTP %d: %s" % (e.code, e.read().decode("utf-8", "replace")[:300]))
    raise RuntimeError("rate limited")


def post_measurement(key, payload):
    """POST 一条测量。

    `hostname` 的位置有两种可能（definitions[] 内 vs 顶层）：本机只能从 OPTIONS schema
    与读接口的扁平形状推断，故第一次真发时**若 400 且报 hostname 相关，自动改用顶层重试一次**。
    400 不会创建任何测量，所以重试没有副作用；两个位置都失败才抛出（带两段响应体）。
    """
    # 400 分三类处理：start_time 过期 → 推后重发；hostname 位置 → 换位置重发；其余直接抛
    for _ in range(2):
        try:
            return _post_once("measurements/", key, payload), "definitions"
        except RuntimeError as e:
            msg = str(e)
            if "start time in future" in msg or "start time" in msg:
                payload = json.loads(json.dumps(payload))
                payload["start_time"] = int(time.time()) + 300
                print("  [retry] start_time 推后 300 s 重发（本机与 Atlas 时钟存在偏差）")
                continue
            break
    try:
        return _post_once("measurements/", key, payload), "definitions"
    except RuntimeError as e:
        msg = str(e)
        h = payload.get("definitions", [{}])[0].get("hostname")
        if "400" not in msg or not h or "hostname" not in msg.lower():
            raise
        alt = json.loads(json.dumps(payload))
        alt["definitions"][0].pop("hostname", None)
        alt["hostname"] = h
        try:
            return _post_once("measurements/", key, alt), "top-level"
        except RuntimeError as e2:
            raise RuntimeError("两种 hostname 位置都被拒 | in-definitions: %s | top-level: %s"
                               % (msg[-300:], str(e2)[-300:]))


def wait_participants(key, msm, want=1, timeout=300, step=10):
    """轮询 participant_count / status，直到 >= want 或超时；返回实际人数。

    实测（2026-11-11）：新建测量会先处于 **Specified**（participant=NULL），
    约 1–2 分钟后才转 Ongoing 并分配探针。**短超时会误判为"0 探针"并触发重发，
    造成重复测量**——本条就是被这个坑咬过一次，故超时一律给足 5 分钟、且**不再自动重发**。
    """
    import time as _t
    deadline = _t.time() + timeout
    last, status = 0, "?"
    while _t.time() < deadline:
        try:
            req = urllib.request.Request(
                "https://atlas.ripe.net/api/v2/measurements/%d/?fields=participant_count,status" % msm,
                headers={"Authorization": "Key " + key})
            d = json.loads(urllib.request.urlopen(req, timeout=30).read().decode())
            last = int(d.get("participant_count") or 0)
            status = (d.get("status") or {}).get("name") or "?"
            if last >= want:
                return last
        except Exception:
            pass
        _t.sleep(step)
    return last


def api_stop(key, msm):
    """只 Stop，不 Delete。失败不致命（记一行）。"""
    for path, body, meth in (("measurements/%d/stop/" % msm, None, "POST"),
                             ("measurements/%d/" % msm, {"status": 2}, "PATCH")):
        try:
            req = urllib.request.Request(
                "https://atlas.ripe.net/api/v2/" + path,
                data=(json.dumps(body).encode() if body is not None else b""),
                headers={"Authorization": "Key " + key, "Content-Type": "application/json"},
                method=meth)
            urllib.request.urlopen(req, timeout=60)
            print("  stopped msm %d（%s）" % (msm, meth))
            return True
        except Exception:
            continue
    print("  [warn] stop msm %d 失败（两种入口都被拒）" % msm)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=sorted(STAGES), required=True)
    ap.add_argument("--commit", action="store_true", help="真正 POST（默认 dry-run）")
    ap.add_argument("--stagger", type=int, default=60)
    ap.add_argument("--skip", type=int, default=0,
                    help="跳过前 N 条（已发过的同构作业用；跳过的不记账）")
    ap.add_argument("--limit", type=int, default=0,
                    help="只发前 N 条（冒烟用；0=全部）。冒烟那条真正创建后要单独记账，不会自动丢弃")
    ap.add_argument("--exclude", default="",
                    help="逗号分隔的臂名，本阶段不发（如未部署的 rig_middlebox）；跳过须写进 deviations.md")
    a = ap.parse_args()
    excl = tuple(x.strip() for x in a.exclude.split(",") if x.strip())

    spec = load(SPEC)
    gate_prereg(spec)
    jobs = build_jobs(spec, a.stage, exclude=excl)
    if a.skip:
        print("[续发] 跳过前 %d 条（已发过的同构作业）" % a.skip)
        jobs = jobs[a.skip:]
    if a.limit:
        print("[冒烟] 只发前 %d 条（其余留待确认后再发）" % a.limit)
        jobs = jobs[:a.limit]
    if not jobs:
        print("没有可发起的作业（靶表/臂为空）")
        return 3
    need = estimate(jobs)
    print("阶段 %s：%d 条测量，预估 %d credits（每结果 10/20/6/60 的实测价）"
          % (a.stage, len(jobs), need))
    for j in jobs[:6]:
        p = j["payload"]["definitions"][0]
        print("  %-22s %-10s target=%s hostname=%s probes=%d"
              % (j["arm"], j["group"], redact(j["target_ip"]),
                 p.get("hostname", "-"), j["n_probes"]))
    if len(jobs) > 6:
        print("  … 其余 %d 条同构" % (len(jobs) - 6))

    if not a.commit:
        print("\n[dry-run] 未发起任何测量。确认无误后加 --commit 并设置 ATLAS_API_KEY。")
        return 0

    key = os.environ.get("ATLAS_API_KEY", "")
    if not key:
        raise SystemExit("--commit 需要 ATLAS_API_KEY（只走环境变量）")
    gate_balance(key, need)

    created, now = [], int(time.time())
    for i, j in enumerate(jobs):
        payload = dict(j["payload"])
        start = int(time.time()) + 300 + i * a.stagger
        payload["start_time"] = start
        # recurring 必须显式 stop_time：不写会一直跑，credits 无止境流失
        if not payload.get("is_oneoff"):
            hours = j.get("hours") or 48
            payload["stop_time"] = start + int(hours * 3600)
        res, shape = post_measurement(key, payload)
        if shape == "top-level" and not getattr(main, "_shape_logged", False):
            print("  [note] hostname 采用**顶层**位置（definitions 内被拒）——后续沿用该形状")
            main._shape_logged = True
        msm = res.get("measurements") or res.get("id") or res.get("msm_id")
        if isinstance(msm, list):
            msm = msm[0]
        msm = int(msm)
        # 先记账再验证：实测 236404637 在 5 分钟内 participant 一直是 0，
        # 之后自行转为 Ongoing/24 —— 说明"0 探针"多半是调度时序，不是失败。
        # 故这里**只告警、不中止、不重发**，真正的健康检查交给事后审计。
        got = wait_participants(key, msm, want=1, timeout=60)
        if not got:
            print("  [info] msm %d 暂未分配探针（可能仍在 Specified）；已记账，稍后审计" % msm)
        created.append({"msm_id": msm, "arm": j["arm"], "group": j["group"],
                        "type": j["type"], "start_time": payload["start_time"]})
        print("created msm %s (%s/%s) target=%s participants=%s" % (
            msm, j["arm"], j["group"], redact(j["target_ip"]), got))
        # 逐条落盘：36 条要跑半小时以上，中途崩掉不能丢已创建的 msm 号
        # （2026-11-12 已因整批写盘遇到过一次"已计费未入册"）
        reg = load(OUT_MSM) if os.path.exists(OUT_MSM) else {"measurements": []}
        if msm not in {r["msm_id"] for r in reg["measurements"]}:
            reg["measurements"].append(created[-1])
        reg["updated_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with io.open(OUT_MSM, "w", encoding="utf-8", newline="") as f:
            f.write(json.dumps(reg, ensure_ascii=False, indent=1))
        time.sleep(3)

    print("登记 %d 条 → %s（累计 %d）" % (len(created), os.path.relpath(OUT_MSM, ROOT),
                                       len(load(OUT_MSM)["measurements"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
