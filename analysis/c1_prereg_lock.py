#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""c1_prereg_lock.py —— 预注册锁定：确认栏全勾后才允许取哈希并写进 campaign_spec。

为什么要有这一步（而不是手算 sha256）：
  1. 哈希必须**排除 `sha256` 那一行自身**，否则永远对不上；
  2. 只要有任一确认栏没勾，就不该锁定——本脚本会直接拒并列出未勾项；
  3. 锁定后 spec 里的 `meta.prereg.sha256` 必须与文件字节一致，**补跑校验**是开测前的最后一道闸。

用法：
  python tools/c1_prereg_lock.py                 # 只打印：未勾项 / 当前哈希 / spec 里写的值
  python tools/c1_prereg_lock.py --commit        # 写 spec 的 sha256（仅在全部勾选时）
  python tools/c1_prereg_lock.py --verify        # 校验 spec 里的哈希 == 现文件哈希
"""
import argparse
import hashlib
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PREREG = os.path.join(ROOT, "paper", "round2", "prereg_round2.md")
SPEC = os.path.join(ROOT, "paper", "round2", "campaign_spec.template.json")
SHA_LINE = re.compile(r"(?m)^sha256\s*:.*$")


def read(p):
    with io.open(p, encoding="utf-8", newline="") as f:
        return f.read()


def digest(text):
    """对"除 sha256 行外"的全部字节取哈希（换行按文件原样，不做归一化）。"""
    body = SHA_LINE.sub("sha256         : <EXCLUDED-FROM-HASH>", text, count=1)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def unticked(text):
    return [ln.strip() for ln in text.splitlines() if ln.strip().startswith("- [ ]")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--commit", action="store_true", help="把哈希写进 spec")
    ap.add_argument("--verify", action="store_true", help="校验 spec 里的哈希")
    a = ap.parse_args()

    text = read(PREREG)
    boxes = unticked(text)
    h = digest(text)
    spec = json.loads(read(SPEC))
    cur = (spec.get("meta", {}).get("prereg") or {}).get("sha256")

    print("预注册：%s" % os.path.relpath(PREREG, ROOT))
    print("  当前哈希 = %s" % h)
    print("  spec 里  = %s" % cur)
    print("  未勾确认栏 = %d 项%s" % (len(boxes), "" if not boxes else "："))
    for b in boxes:
        print("    %s" % b[:96])

    if a.verify:
        ok = (cur == h)
        print("\n校验：%s" % ("PASS（spec 与实际文件一致）" if ok else "FAIL（不一致，须重新锁定）"))
        return 0 if ok else 2

    if a.commit:
        if boxes:
            print("\n[拒绝] 还有 %d 项未勾，不能锁定。勾完再跑 --commit。" % len(boxes))
            return 2
        spec["meta"]["prereg"]["sha256"] = h
        spec["meta"]["prereg"]["status"] = "locked"
        spec["meta"]["status"] = "locked"
        with io.open(SPEC, "w", encoding="utf-8", newline="") as f:
            f.write(json.dumps(spec, ensure_ascii=False, indent=2) + "\n")
        print("\n[已锁定] 哈希写入 %s" % os.path.relpath(SPEC, ROOT))
        return 0

    print("\n（只读检查；要锁定加 --commit，要校验加 --verify）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
