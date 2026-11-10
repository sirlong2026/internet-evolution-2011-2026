#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Release copy (built by tools/build_repo_c1.py): paths rewritten for the
# artifact layout; prose annotations are historical working notes — the
# authoritative calibers live in README.md and are enforced by
# analysis/verify_paper_tables.py.
"""routeviews_rib.py —— MRT TABLE_DUMP_V2 RIB 零依赖解析器（C0 档案层，2026-11-08）。
只依赖标准库（bz2/struct/socket/json）。解析 RouteViews/RIS 的 rib.*.bz2 / bview.*.gz：
  MRT 公共头 12B（ts u32 / type u16 / subtype u16 / len u32）
  type=13 TABLE_DUMP_V2：subtype 1=PEER_INDEX_TABLE，2=RIB_IPV4_UNICAST，4=RIB_IPV6_UNICAST
  RIB 记录：seq u32 / prefix_len u8 / prefix ceil(len/8)B / entry_count u16 / 逐 entry 跳过
C0 只统计前缀级（不拆 BGP 属性）；entry 内属性原样跳过并计数。
截断容忍：文件尾不完整记录 → truncated=True 保留已解析统计（供下载中试跑）；
正式跑必须 truncated=False。交叉验证：云上 bgpdump 1.6.2 独立解析对照前缀数。
用法：python routeviews_rib.py <rib.bz2|rib.gz|-> [--json out.json]
"""
import bz2
import gzip
import json
import socket
import struct
import sys
from collections import Counter

HDR = struct.Struct(">IHHI")  # ts, type, subtype, length


def open_stream(path):
    if path == "-":
        return sys.stdin.buffer
    if path.endswith(".bz2"):
        return bz2.open(path, "rb")
    if path.endswith(".gz"):
        return gzip.open(path, "rb")
    return open(path, "rb")


class Truncated(Exception):
    pass


def read_exact(f, n):
    try:
        b = f.read(n)
    except EOFError:  # bz2/gzip 截断流：解压到不完整处抛 EOFError
        raise Truncated("compressed stream ends early (need %d)" % n)
    if len(b) != n:
        raise Truncated("need %d got %d" % (n, len(b)))
    return b


def parse(path, dump_prefixes=None):
    stats = {
        "source_file": path,
        "record_types": Counter(),
        "peer_count": 0,
        "collector_bgp_id": None,
        "view_name": None,
        "rib_ipv4": {"prefixes": 0, "entries": 0, "plen_hist": Counter()},
        "rib_ipv6": {"prefixes": 0, "entries": 0, "plen_hist": Counter()},
        "skipped_other": Counter(),
        "truncated": False,
        "bytes_consumed": 0,
    }
    intervals4 = []
    intervals6 = []
    dumpf = open(dump_prefixes, "w", encoding="utf-8") if dump_prefixes else None
    f = open_stream(path)
    try:
        while True:
            try:
                h = read_exact(f, HDR.size)
            except Truncated:
                break  # 干净 EOF 或尾部残头
            ts, typ, sub, length = HDR.unpack(h)
            stats["record_types"]["%d/%d" % (typ, sub)] += 1
            try:
                body = read_exact(f, length)
            except Truncated:
                stats["truncated"] = True
                break
            stats["bytes_consumed"] += HDR.size + length
            if typ != 13:
                stats["skipped_other"]["type%d" % typ] += 1
                continue
            if sub == 1:  # PEER_INDEX_TABLE
                bgp_id = socket.inet_ntoa(body[0:4])
                vlen = struct.unpack_from(">H", body, 4)[0]
                view = body[6:6 + vlen].decode("utf-8", "replace")
                off = 6 + vlen
                npeer = struct.unpack_from(">H", body, off)[0]
                stats["collector_bgp_id"] = bgp_id
                stats["view_name"] = view
                stats["peer_count"] = npeer
                continue
            if sub not in (2, 3, 4, 5):
                stats["skipped_other"]["13/%d" % sub] += 1
                continue
            # RIB_*：seq(4) plen(1) prefix(ceil/8) entry_count(2) entries...
            plen = body[4]
            pbytes = (plen + 7) // 8
            prefix_raw = body[5:5 + pbytes]
            off = 5 + pbytes
            nentry = struct.unpack_from(">H", body, off)[0]
            off += 2
            for _ in range(nentry):
                # peer_index(2) orig_time(4) attr_len(2) attr(attr_len)
                alen = struct.unpack_from(">H", body, off + 6)[0]
                off += 8 + alen
            if off != len(body):
                raise ValueError("RIB record size mismatch: off=%d len=%d sub=%d" % (off, len(body), sub))
            af = "rib_ipv4" if sub in (2, 3) else "rib_ipv6"
            bucket = stats[af]
            bucket["prefixes"] += 1
            bucket["entries"] += nentry
            bucket["plen_hist"][plen] += 1
            if sub == 2:  # 只收 unicast 做覆盖并集（multicast 另计不并入）
                p = prefix_raw + b"\x00" * (4 - pbytes)
                start = struct.unpack(">I", p)[0]
                size = 1 << (32 - plen) if plen else 1 << 32
                intervals4.append((start, start + size - 1))
                if dumpf:
                    dumpf.write("%d %d\n" % (start, plen))
            elif sub == 4:
                p = prefix_raw + b"\x00" * (16 - pbytes)
                start = int.from_bytes(p, "big")
                size = 1 << (128 - plen) if plen else 1 << 128
                intervals6.append((start, start + size - 1))
    finally:
        f.close()
        if dumpf:
            dumpf.close()
    stats["ipv4_union_addresses"] = union_size(intervals4)
    stats["ipv6_union_addresses"] = union_size(intervals6)
    stats["ipv4_slash8_covered"] = len({s >> 24 for s, _ in intervals4})
    stats["record_types"] = dict(stats["record_types"])
    stats["skipped_other"] = dict(stats["skipped_other"])
    for af in ("rib_ipv4", "rib_ipv6"):
        stats[af]["plen_hist"] = dict(sorted(stats[af]["plen_hist"].items()))
    return stats


def union_size(intervals):
    """排序区间并集大小（前缀重叠去重）。"""
    if not intervals:
        return 0
    intervals.sort()
    total = 0
    cs, ce = intervals[0]
    for s, e in intervals[1:]:
        if s <= ce + 1:
            ce = max(ce, e)
        else:
            total += ce - cs + 1
            cs, ce = s, e
    total += ce - cs + 1
    return total


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    out = None
    if "--json" in sys.argv:
        out = sys.argv[sys.argv.index("--json") + 1]
        args = [a for a in args if a != out]
    dump = None
    if "--dump-prefixes" in sys.argv:
        dump = sys.argv[sys.argv.index("--dump-prefixes") + 1]
        args = [a for a in args if a != dump]
    if not args:
        print(__doc__)
        sys.exit(2)
    st = parse(args[0], dump_prefixes=dump)
    v4, v6 = st["rib_ipv4"], st["rib_ipv6"]
    print("peers=%d view=%s truncated=%s" % (st["peer_count"], st["view_name"], st["truncated"]))
    print("IPv4 unicast+multicast prefixes=%d entries=%d union=%d /8covered=%d" % (
        v4["prefixes"], v4["entries"], st["ipv4_union_addresses"], st["ipv4_slash8_covered"]))
    print("IPv6 prefixes=%d entries=%d union=%d" % (v6["prefixes"], v6["entries"], st["ipv6_union_addresses"]))
    print("records:", st["record_types"], "skipped:", st["skipped_other"])
    if out:
        with open(out, "w", encoding="utf-8") as fo:
            json.dump(st, fo, ensure_ascii=False, indent=1)
        print("json ->", out)


if __name__ == "__main__":
    main()