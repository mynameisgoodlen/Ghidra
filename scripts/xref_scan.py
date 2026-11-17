#!/usr/bin/env python3
"""
xref_scan v2 - find code that references known strings in a 32-bit ARM .so
without whole-program analysis.

PC-relative address computation (the usual PIC string access) is matched by
working BACKWARDS from the literal: for a pool word W (or a movw/movt constant C)
and a target string S, the exact address of the `add rX, pc` that would produce S
is  A = S - W - 4  (Thumb) / S - W - 8 (ARM).  We then check that an `add rX, pc`
really sits at A.  This has no instruction-distance limit.  A hit needs an exact
address match plus a real add-pc instruction, so false positives are negligible.

Pass 1: string address S.
Pass 2: "pointer cells" - 32-bit words in the file that equal S (relocated pointers in
        data, or absolute literals).  Code is searched for PC-relative refs to the cell
        (GOT-style) and for direct `ldr rX,[pc,#..]` of the cell.

Usage: xref_scan.py <lib.so> <targets.tsv> <outdir> [seg_len_hex]
targets.tsv: "<vaddr hex>\t<name>" per line (vaddr == file offset in the first LOAD).
"""
import os
import struct
import sys

import numpy as np

CH = 1 << 22          # elements per chunk
OV = 64               # chunk overlap (elements)
MASK = 0xFFFFFFFF
WIN = 8192            # max |pool word - add| distance
WINM = 512            # max movt -> add distance
MAX_CELLS_PER_TARGET = 16


# ----------------------------------------------------------------------------- ELF
def read_loads(path):
    """Return [(p_offset, p_vaddr, p_filesz)] for PT_LOAD, or None if not ELF."""
    with open(path, "rb") as f:
        eh = f.read(52)
        if eh[:4] != b"\x7fELF":
            return None
        phoff, = struct.unpack_from("<I", eh, 28)
        phentsize, phnum = struct.unpack_from("<HH", eh, 42)
        f.seek(phoff)
        loads = []
        for _ in range(phnum):
            ph = f.read(phentsize)
            p_type, p_off, p_va, _pa, p_fsz, _msz, _fl, _al = struct.unpack_from("<8I", ph, 0)
            if p_type == 1:
                loads.append((p_off, p_va, p_fsz))
        return loads


def first_load_len(path, loads):
    if loads:
        for off, va, fsz in loads:
            if off == 0 and va == 0:
                return fsz
    return os.path.getsize(path)


def load_targets(path):
    t = {}
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        t[int(parts[0], 16)] = parts[1] if len(parts) > 1 else parts[0]
    return t


# ----------------------------------------------------------------------------- windows
def build_windows(S_list, lo_off, hi_off):
    """Merged intervals [S+lo_off, S+hi_off] taken modulo 2**32."""
    iv = []
    for s in S_list:
        lo, hi = int(s) + lo_off, int(s) + hi_off
        if lo < 0:
            iv.append((lo + (1 << 32), hi + (1 << 32)))
        iv.append((lo, hi))
    iv.sort()
    merged = []
    for a, b in iv:
        if merged and a <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return (np.array([m[0] for m in merged], dtype=np.int64),
            np.array([m[1] for m in merged], dtype=np.int64))


def in_windows(v, lo, hi):
    j = np.searchsorted(lo, v, side="right") - 1
    ok = j >= 0
    jj = np.where(ok, j, 0)
    return ok & (v <= hi[jj])


def swrap(x):
    return ((x + (1 << 31)) & MASK) - (1 << 31)


def add_hw_thumb(rd):
    return 0x4478 | ((rd >> 3) << 7) | (rd & 7)


# ----------------------------------------------------------------------------- stage 2 checks
LDR_ADD_MAX = 512     # max bytes between the ldr and the add that uses its register


def ldr_feeds_add(mode, P, A, regs, hm, words):
    """True if an ldr-literal that loads the pool word at P sits 0..LDR_ADD_MAX bytes
    BEFORE the add at A and loads into a register the add really uses (register match)."""
    lo = max(0, A - LDR_ADD_MAX)
    if mode == "T":
        base = lo // 2
        h = np.asarray(hm[base: A // 2 + 1]).astype(np.int64)
        i16 = np.flatnonzero((h[:-1] & 0xF800) == 0x4800)
        if len(i16):
            addr = 2 * (base + i16)
            lit = ((addr + 4) & ~3) + (h[i16] & 0xFF) * 4
            rt = (h[i16] >> 8) & 7
            if ((lit == P) & (addr < A) & np.isin(rt, regs)).any():
                return True
        i32 = np.flatnonzero((h[:-1] & 0xFF7F) == 0xF85F)
        if len(i32):
            addr = 2 * (base + i32)
            imm = h[i32 + 1] & 0xFFF
            up = (h[i32] >> 7) & 1
            lit = ((addr + 4) & ~3) + np.where(up == 1, imm, -imm)
            rt = (h[i32 + 1] >> 12) & 0xF
            if ((lit == P) & (addr < A) & np.isin(rt, regs)).any():
                return True
        return False
    base = lo // 4
    w = np.asarray(words[base: A // 4 + 1]).astype(np.int64)
    ii = np.flatnonzero((w & 0x0F7F0000) == 0x051F0000)
    if len(ii):
        x = w[ii]
        addr = 4 * (base + ii)
        lit = addr + 8 + np.where(((x >> 23) & 1) == 1, x & 0xFFF, -(x & 0xFFF))
        rt = (x >> 12) & 0xF
        return bool(((lit == P) & (addr < A) & np.isin(rt, regs)).any())
    return False


def check_literal(P, W, S_arr, hm, words, seg_len, out, label):
    """P: byte address of pool word, W: its value. Exact check against every target."""
    if len(P) == 0:
        return
    blk = max(64, 3000000 // max(1, len(S_arr)))
    for b in range(0, len(P), blk):
        p, w = P[b:b + blk], W[b:b + blk]
        # Thumb: S = W + A + 4
        A = (S_arr[None, :] - w[:, None] - 4) & MASK
        d = swrap(p[:, None] - A)
        ok = (np.abs(d) <= WIN) & ((A & 1) == 0) & (A + 2 <= seg_len)
        ri, ci = np.nonzero(ok)
        if len(ri):
            a = A[ri, ci]
            hw = np.asarray(hm[a >> 1]).astype(np.int64)
            m = (hw & 0xFF78) == 0x4478
            pp = p[ri[m]]
            for a_, s_, p_, hw_ in zip(a[m], S_arr[ci[m]], pp, hw[m]):
                rdn = int(((hw_ >> 7) & 1) << 3 | (hw_ & 7))
                if ldr_feeds_add("T", int(p_), int(a_), [rdn], hm, words):
                    out.append(("T", int(a_), int(s_), label + "literal+add"))
        # ARM: S = W + A + 8
        A = (S_arr[None, :] - w[:, None] - 8) & MASK
        d = swrap(p[:, None] - A)
        ok = (np.abs(d) <= WIN) & ((A & 3) == 0) & (A + 4 <= seg_len)
        ri, ci = np.nonzero(ok)
        if len(ri):
            a = A[ri, ci]
            x = np.asarray(words[a >> 2]).astype(np.int64)
            m = ((x & 0x0FFF0FF0) == 0x008F0000) | ((x & 0x0FF00FFF) == 0x0080000F)
            pp = p[ri[m]]
            for a_, s_, p_, x_ in zip(a[m], S_arr[ci[m]], pp, x[m]):
                x_ = int(x_)
                regs = [x_ & 0xF] if (x_ & 0x0FFF0FF0) == 0x008F0000 else [(x_ >> 16) & 0xF]
                if ldr_feeds_add("A", int(p_), int(a_), regs, hm, words):
                    out.append(("A", int(a_), int(s_), label + "literal+add"))


def check_movwt(mode, cand, S_arr, hm, words, seg_len, out, label):
    """cand: arrays (c, end, rd). Add must sit 0..WINM bytes after the movt."""
    c, end, rd = cand
    if len(c) == 0:
        return
    k = 4 if mode == "T" else 8
    blk = max(64, 3000000 // max(1, len(S_arr)))
    for b in range(0, len(c), blk):
        cc, ee, rr = c[b:b + blk], end[b:b + blk], rd[b:b + blk]
        A = (S_arr[None, :] - cc[:, None] - k) & MASK
        e = A - ee[:, None]
        step = 1 if mode == "T" else 3
        ok = (e >= 0) & (e <= WINM) & ((A & step) == 0) & (A + 4 <= seg_len)
        ri, ci = np.nonzero(ok)
        if not len(ri):
            continue
        a = A[ri, ci]
        if mode == "T":
            hw = np.asarray(hm[a >> 1]).astype(np.int64)
            m = hw == add_hw_thumb(rr[ri])
        else:
            x = np.asarray(words[a >> 2]).astype(np.int64)
            r_ = rr[ri]
            m = ((x & 0x0FFFFFFF) == (0x008F0000 | (r_ << 12) | r_)) | \
                ((x & 0x0FFFFFFF) == (0x00800000 | (r_ << 16) | (r_ << 12) | 0xF))
        for a_, s_ in zip(a[m], S_arr[ci[m]]):
            out.append((mode, int(a_), int(s_), label + "movw/movt+add"))


# ----------------------------------------------------------------------------- scanning
def scan_pcrel(hm, words, S_arr, seg_len, label):
    """PC-relative references to any address in S_arr. Returns list of hits."""
    out = []
    S_list = [int(s) for s in S_arr]
    lo_l, hi_l = build_windows(S_list, -8 - WIN, -4 + WIN)       # literal pools
    lo_m, hi_m = build_windows(S_list, -8 - WINM, -4)            # movw/movt

    # ---- literal pool words (all 4-aligned words)
    nw = len(words)
    for start in range(0, nw, CH):
        w = np.asarray(words[start:start + CH]).astype(np.int64)
        P = (start + np.arange(len(w), dtype=np.int64)) * 4
        V = (w + P) & MASK
        sel = in_windows(V, lo_l, hi_l)
        if sel.any():
            check_literal(P[sel], w[sel], S_arr, hm, words, seg_len, out, label)

    # ---- Thumb-2 movw / movt
    nh = len(hm)
    for start in range(0, nh, CH):
        h = np.asarray(hm[start:start + CH + OV]).astype(np.int64)
        n = len(h)
        if n < 40:
            continue
        lim = min(CH, n)
        h0, h1 = h[:-1], h[1:]
        ok2 = (h1 & 0x8000) == 0
        isw = np.zeros(n, bool)
        ist = np.zeros(n, bool)
        isw[:-1] = ((h0 & 0xFBF0) == 0xF240) & ok2
        ist[:-1] = ((h0 & 0xFBF0) == 0xF2C0) & ok2

        def imm_rd(idx):
            a, b = h[idx], h[idx + 1]
            return (((a & 0xF) << 12) | (((a >> 10) & 1) << 11) | (((b >> 12) & 7) << 8) | (b & 0xFF),
                    (b >> 8) & 0xF)

        iw = np.flatnonzero(isw[:lim])
        iw = iw[iw + 30 < n]
        if not len(iw):
            continue
        wimm, wrd = imm_rd(iw)
        cs, es, rs = [], [], []
        for g in range(0, 13):
            j = iw + 2 + g
            m = ist[j]
            if not m.any():
                continue
            jj = j[m]
            timm, trd = imm_rd(jj)
            same = trd == wrd[m]
            if not same.any():
                continue
            jj = jj[same]
            cs.append((timm[same] << 16) | wimm[m][same])
            es.append(2 * (start + jj) + 4)          # byte address right after the movt
            rs.append(wrd[m][same])
        if cs:
            c, e, r = np.concatenate(cs), np.concatenate(es), np.concatenate(rs)
            sel = in_windows((c + e) & MASK, lo_m, hi_m)
            check_movwt("T", (c[sel], e[sel], r[sel]), S_arr, hm, words, seg_len, out, label)

    # ---- ARM movw / movt
    for start in range(0, nw, CH):
        w = np.asarray(words[start:start + CH + OV]).astype(np.int64)
        n = len(w)
        if n < 40:
            continue
        lim = min(CH, n)
        isw = (w & 0x0FF00000) == 0x03000000
        ist = (w & 0x0FF00000) == 0x03400000

        def imm_rd(idx):
            x = w[idx]
            return ((x >> 4) & 0xF000) | (x & 0xFFF), (x >> 12) & 0xF

        iw = np.flatnonzero(isw[:lim])
        iw = iw[iw + 30 < n]
        if not len(iw):
            continue
        wimm, wrd = imm_rd(iw)
        cs, es, rs = [], [], []
        for g in range(0, 7):
            j = iw + 1 + g
            m = ist[j]
            if not m.any():
                continue
            jj = j[m]
            timm, trd = imm_rd(jj)
            same = trd == wrd[m]
            if not same.any():
                continue
            jj = jj[same]
            cs.append((timm[same] << 16) | wimm[m][same])
            es.append(4 * (start + jj) + 4)
            rs.append(wrd[m][same])
        if cs:
            c, e, r = np.concatenate(cs), np.concatenate(es), np.concatenate(rs)
            sel = in_windows((c + e) & MASK, lo_m, hi_m)
            check_movwt("A", (c[sel], e[sel], r[sel]), S_arr, hm, words, seg_len, out, label)
    return out


def scan_direct_ldr(hm, words, cells_arr, seg_len, label):
    """Direct `ldr rX,[pc,#..]` whose literal address is one of the cells."""
    out = []
    cset = np.asarray(cells_arr, dtype=np.int64)
    nh = len(hm)
    for start in range(0, nh, CH):
        h = np.asarray(hm[start:start + CH + OV]).astype(np.int64)
        n = len(h)
        if n < 40:
            continue
        lim = min(CH, n)
        il = np.flatnonzero(((h & 0xF800) == 0x4800)[:lim])
        if len(il):
            lit = ((2 * (start + il) + 4) & ~3) + (h[il] & 0xFF) * 4
            m = np.isin(lit, cset)
            for i_, l_ in zip(il[m], lit[m]):
                out.append(("T", 2 * (start + int(i_)), int(l_), label + "ldr-direct"))
        il = np.flatnonzero((((h[:-1] & 0xFF7F) == 0xF85F))[:lim])
        if len(il):
            imm12 = h[il + 1] & 0xFFF
            up = (h[il] >> 7) & 1
            lit = ((2 * (start + il) + 4) & ~3) + np.where(up == 1, imm12, -imm12)
            m = np.isin(lit, cset)
            for i_, l_ in zip(il[m], lit[m]):
                out.append(("T", 2 * (start + int(i_)), int(l_), label + "ldr.w-direct"))
    nw = len(words)
    for start in range(0, nw, CH):
        w = np.asarray(words[start:start + CH]).astype(np.int64)
        il = np.flatnonzero((w & 0x0F7F0000) == 0x051F0000)
        if len(il):
            x = w[il]
            lit = 4 * (start + il) + 8 + np.where(((x >> 23) & 1) == 1, x & 0xFFF, -(x & 0xFFF))
            m = np.isin(lit, cset)
            for i_, l_ in zip(il[m], lit[m]):
                out.append(("A", 4 * (start + int(i_)), int(l_), label + "ldr-direct"))
    return out


def find_cells(path, loads, S_arr):
    """File words equal to a target address -> {cell_vaddr: S}."""
    size = os.path.getsize(path) // 4
    mm = np.memmap(path, dtype="<u4", mode="r", shape=(size,))
    cells = {}
    sset = np.asarray(S_arr, dtype=np.int64)
    for start in range(0, size, 1 << 23):
        w = np.asarray(mm[start:start + (1 << 23)]).astype(np.int64)
        m = np.isin(w, sset)
        for k in np.flatnonzero(m):
            off = 4 * (start + int(k))
            va = None
            if loads is None:
                va = off
            else:
                for p_off, p_va, p_fsz in loads:
                    if p_off <= off < p_off + p_fsz:
                        va = p_va + (off - p_off)
                        break
            if va is not None:
                cells.setdefault(int(w[k]), []).append(va)
    return cells


# ----------------------------------------------------------------------------- function starts
def thumb_starts(hm, site, back=0x6000, limit=2):
    lo = max(0, (site - back) // 2)
    hi = site // 2
    h = np.asarray(hm[lo:hi + 2]).astype(np.int64)
    c16 = (h[:-1] & 0xFF00) == 0xB500
    c32 = (h[:-1] == 0xE92D) & ((h[1:] & 0x4000) != 0)
    idx = np.flatnonzero((c16 | c32)[: hi - lo])
    return [2 * (lo + int(i)) for i in idx[::-1][:limit]]


def arm_starts(words, site, back=0x6000, limit=2):
    lo = max(0, (site - back) // 4)
    hi = site // 4
    w = np.asarray(words[lo:hi + 1]).astype(np.int64)
    c = ((w & 0xFFFFC000) == 0xE92D4000) | (w == 0xE52DE004)
    idx = np.flatnonzero(c[: hi - lo])
    return [4 * (lo + int(i)) for i in idx[::-1][:limit]]


# ----------------------------------------------------------------------------- main
STRUCT_BACK = 128      # references to (cell - k), k = 0..STRUCT_BACK step 4  (name pointer inside a static struct)


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(2)
    lib, tfile, outdir = sys.argv[1:4]
    os.makedirs(outdir, exist_ok=True)
    loads = read_loads(lib)
    seg_len = (int(sys.argv[4], 16) if len(sys.argv) > 4 else first_load_len(lib, loads)) & ~3
    targets = load_targets(tfile)
    S_arr = np.array(sorted(targets), dtype=np.int64)
    print("segment length: 0x%x, targets: %d" % (seg_len, len(targets)))

    hm = np.memmap(lib, dtype="<u2", mode="r", shape=(seg_len // 2,))
    words = np.memmap(lib, dtype="<u4", mode="r", shape=(seg_len // 4,))

    hits = []   # dicts: mode, site, s (string), kind, target (address the code computes), cell, k
    print("pass 1: direct pc-relative references to the strings ...")
    for mode, site, s_, kind in scan_pcrel(hm, words, S_arr, seg_len, ""):
        hits.append(dict(mode=mode, site=site, s=s_, kind=kind, target=s_, cell=0, k=0))

    print("pass 2: pointer cells and the structs that contain them ...")
    cells = find_cells(lib, loads, S_arr)
    cell_lines = []
    tmap = {}                   # computed address -> (string, cell, k)
    for s_, cl in sorted(cells.items()):
        cell_lines.append("%08x %-55s cells(%d): %s" % (
            s_, targets.get(s_, "?"), len(cl), " ".join("%x" % c for c in cl[:MAX_CELLS_PER_TARGET])))
        for c in cl[:MAX_CELLS_PER_TARGET]:
            for k in range(0, STRUCT_BACK + 4, 4):
                t = c - k
                if t > 0 and t not in tmap:
                    tmap[t] = (s_, c, k)
    if tmap:
        tarr = np.array(sorted(tmap), dtype=np.int64)
        for mode, site, t, kind in scan_pcrel(hm, words, tarr, seg_len, "via-cell:"):
            s_, c, k = tmap[t]
            hits.append(dict(mode=mode, site=site, s=s_, kind=kind, target=t, cell=c, k=k))
        carr = np.array(sorted({c for (_, c, _k) in tmap.values()}), dtype=np.int64)
        c2s = {c: s_ for (s_, c, _k) in tmap.values()}
        for mode, site, c, kind in scan_direct_ldr(hm, words, carr, seg_len, "via-cell:"):
            hits.append(dict(mode=mode, site=site, s=c2s[c], kind=kind, target=c, cell=c, k=0))

    seen, uniq, cell_count = set(), [], {}
    for h in sorted(hits, key=lambda r: (r["cell"] != 0, r["s"], r["k"], r["site"])):
        key = (h["mode"], h["site"], h["s"])
        if key in seen:
            continue
        if h["cell"]:
            cell_count[h["s"]] = cell_count.get(h["s"], 0) + 1
            if cell_count[h["s"]] > 6:
                continue
        seen.add(key)
        uniq.append(h)

    per = {}
    starts_by_name = {}
    with open(os.path.join(outdir, "hits.tsv"), "w") as fh, \
         open(os.path.join(outdir, "candidates.tsv"), "w") as fc:
        fh.write("mode\tsite\tstring\tname\tkind\ttarget\tcell\tk\n")
        fc.write("name\tmode\tsite\tstart\tstring\ttarget\n")
        for h in uniq:
            name = targets[h["s"]]
            per.setdefault(name, [0, 0])[1 if h["cell"] else 0] += 1
            fh.write("%s\t0x%08x\t0x%08x\t%s\t%s\t0x%08x\t0x%x\t%d\n" % (
                h["mode"], h["site"], h["s"], name, h["kind"], h["target"], h["cell"], h["k"]))
            st = thumb_starts(hm, h["site"]) if h["mode"] == "T" else arm_starts(words, h["site"])
            for i, a in enumerate(st):
                fc.write("%s\t%s\t0x%08x\t0x%08x\t0x%08x\t0x%08x\n" % (
                    name, h["mode"], h["site"], a, h["s"], h["target"]))
            if st:
                key = (st[0], h["mode"], "cell+%d" % h["k"] if h["cell"] else "direct")
                starts_by_name.setdefault(name, {}).setdefault(key, 0)
                starts_by_name[name][key] += 1

    with open(os.path.join(outdir, "cells.txt"), "w") as f:
        f.write("\n".join(cell_lines) + "\n")
    with open(os.path.join(outdir, "summary.txt"), "w") as fs:
        fs.write("hits: %d   targets with direct hits: %d   with via-cell hits: %d   (of %d targets)\n" % (
            len(uniq), sum(1 for v in per.values() if v[0]), sum(1 for v in per.values() if v[1]), len(targets)))
        for v in sorted(targets):
            n = targets[v]
            d, c = per.get(n, [0, 0])
            fs.write("%-8s %-58s direct=%d cell=%d cells=%d\n" % ("%x" % v, n, d, c, len(cells.get(v, []))))
    # compact table: most likely function start per target (most sites first)
    with open(os.path.join(outdir, "strong.tsv"), "w") as fs:
        fs.write("name\tfunc_start\tmode\tvia\tsites\n")
        for name in sorted(starts_by_name):
            items = sorted(starts_by_name[name].items(), key=lambda kv: -kv[1])[:4]
            for (st, mode, via), n in items:
                fs.write("%s\t0x%08x\t%s\t%s\t%d\n" % (name, st, mode, via, n))
    print(open(os.path.join(outdir, "summary.txt")).read())


if __name__ == "__main__":
    main()
