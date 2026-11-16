#!/usr/bin/env python3
"""
Find code that references known strings in a 32-bit ARM shared library, without
whole-program analysis (which needs far more RAM than a free CI runner has).

Looks for the usual position-independent ways compilers load a string address:
  Thumb-2 : movw/movt + "add rX, pc"      ldr(.w) literal + "add rX, pc"
  ARM     : movw/movt + "add rX, pc, rX"  ldr literal    + "add rX, pc, rX"
A hit is only reported when the computed address equals a target string exactly,
so false positives are essentially impossible.

For every hit it also guesses up to 3 function-start candidates by scanning
backwards for a push {..., lr} prologue.

Usage: xref_scan.py <lib.so> <targets.tsv> <outdir> [seg_len_hex]
targets.tsv: "<vaddr hex>\t<name>" per line (vaddr == file offset in the first LOAD).
seg_len defaults to the size of the first (R E) LOAD segment read from the ELF header.
"""
import os
import struct
import sys

import numpy as np

CH = 1 << 22      # elements per chunk
OV = 64           # overlap, in elements
MASK = 0xFFFFFFFF


def first_load_len(path):
    with open(path, "rb") as f:
        eh = f.read(52)
        phoff, = struct.unpack_from("<I", eh, 28)
        phentsize, phnum = struct.unpack_from("<HH", eh, 42)
        f.seek(phoff)
        for _ in range(phnum):
            ph = f.read(phentsize)
            p_type, p_off, p_va, p_pa, p_fsz, p_msz, p_fl, p_al = struct.unpack_from("<8I", ph, 0)
            if p_type == 1 and p_off == 0 and p_va == 0:
                return p_fsz
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


def add_hw_thumb(rd):
    """Thumb16 'add rd, pc'  (ADD Rdn, Rm with Rm = PC)."""
    return 0x4478 | ((rd >> 3) << 7) | (rd & 7)


def report(out, mode, site, s, kind):
    out.append((mode, int(site), int(s), kind))


def scan_thumb(hm, words, tarr, out):
    n_total = len(hm)
    seg_len = len(words) * 4
    for start in range(0, n_total, CH):
        end = min(n_total, start + CH + OV)
        h = np.asarray(hm[start:end]).astype(np.int64)
        n = len(h)
        lim = min(CH, n)
        if n < 40:
            continue
        h0, h1 = h[:-1], h[1:]
        ok2 = (h1 & 0x8000) == 0
        isw = np.zeros(n, bool)
        ist = np.zeros(n, bool)
        isw[:-1] = ((h0 & 0xFBF0) == 0xF240) & ok2
        ist[:-1] = ((h0 & 0xFBF0) == 0xF2C0) & ok2

        def imm_rd(idx):
            a, b = h[idx], h[idx + 1]
            imm = ((a & 0xF) << 12) | (((a >> 10) & 1) << 11) | (((b >> 12) & 7) << 8) | (b & 0xFF)
            return imm, (b >> 8) & 0xF

        # --- movw / movt / add rX, pc
        iw = np.flatnonzero(isw[:lim])
        iw = iw[iw + 30 < n]
        if len(iw):
            wimm, wrd = imm_rd(iw)
            for g in range(0, 7):
                j = iw + 2 + g
                m = ist[j]
                if not m.any():
                    continue
                jj, sel = j[m], iw[m]
                timm, trd = imm_rd(jj)
                same = trd == wrd[m]
                if not same.any():
                    continue
                jj, sel = jj[same], sel[same]
                c = (timm[same] << 16) | wimm[m][same]
                rd = wrd[m][same]
                want = add_hw_thumb(rd)
                for g2 in range(0, 7):
                    a = jj + 2 + g2
                    okadd = h[a] == want
                    if not okadd.any():
                        continue
                    s = (c[okadd] + 2 * (start + a[okadd]) + 4) & MASK
                    hit = np.isin(s, tarr)
                    for s_, site in zip(s[hit], sel[okadd][hit]):
                        report(out, "T", 2 * (start + int(site)), s_, "movw/movt+add")

        # --- ldr (16-bit) literal / add rX, pc
        il = np.flatnonzero(((h & 0xF800) == 0x4800)[:lim])
        il = il[il + 30 < n]
        if len(il):
            rt = (h[il] >> 8) & 7
            imm8 = h[il] & 0xFF
            addr = 2 * (start + il)
            lit = ((addr + 4) & ~3) + imm8 * 4
            valid = lit + 4 <= seg_len
            il, rt, lit = il[valid], rt[valid], lit[valid]
            if len(il):
                w = np.asarray(words[lit >> 2]).astype(np.int64)
                want = add_hw_thumb(rt)
                for g in range(0, 8):
                    a = il + 1 + g
                    okadd = h[a] == want
                    if not okadd.any():
                        continue
                    s = (w[okadd] + 2 * (start + a[okadd]) + 4) & MASK
                    hit = np.isin(s, tarr)
                    for s_, site in zip(s[hit], il[okadd][hit]):
                        report(out, "T", 2 * (start + int(site)), s_, "ldr+add")

        # --- ldr.w literal / add rX, pc
        il = np.flatnonzero((((h0 & 0xFF7F) == 0xF85F))[:lim])
        il = il[il + 30 < n]
        if len(il):
            b = h[il + 1]
            rt = (b >> 12) & 0xF
            imm12 = b & 0xFFF
            up = (h[il] >> 7) & 1
            addr = 2 * (start + il)
            lit = ((addr + 4) & ~3) + np.where(up == 1, imm12, -imm12)
            valid = (lit >= 0) & (lit + 4 <= seg_len) & (rt != 15)
            il, rt, lit = il[valid], rt[valid], lit[valid]
            if len(il):
                w = np.asarray(words[lit >> 2]).astype(np.int64)
                want = add_hw_thumb(rt)
                for g in range(0, 8):
                    a = il + 2 + g
                    okadd = h[a] == want
                    if not okadd.any():
                        continue
                    s = (w[okadd] + 2 * (start + a[okadd]) + 4) & MASK
                    hit = np.isin(s, tarr)
                    for s_, site in zip(s[hit], il[okadd][hit]):
                        report(out, "T", 2 * (start + int(site)), s_, "ldr.w+add")


def scan_arm(words, tarr, out):
    n_total = len(words)
    seg_len = n_total * 4
    for start in range(0, n_total, CH):
        end = min(n_total, start + CH + OV)
        w = np.asarray(words[start:end]).astype(np.int64)
        n = len(w)
        lim = min(CH, n)
        if n < 40:
            continue

        def imm_rd(idx):
            x = w[idx]
            return ((x >> 4) & 0xF000) | (x & 0xFFF), (x >> 12) & 0xF

        isw = (w & 0x0FF00000) == 0x03000000
        ist = (w & 0x0FF00000) == 0x03400000

        def add_ok(word_arr, rd):
            # add rd, pc, rd   |   add rd, rd, pc   (cond ignored)
            a1 = (word_arr & 0x0FFFFFFF) == (0x008F0000 | (rd << 12) | rd)
            a2 = (word_arr & 0x0FFFFFFF) == (0x00800000 | (rd << 16) | (rd << 12) | 0xF)
            return a1 | a2

        iw = np.flatnonzero(isw[:lim])
        iw = iw[iw + 20 < n]
        if len(iw):
            wimm, wrd = imm_rd(iw)
            for g in range(0, 7):
                j = iw + 1 + g
                m = ist[j]
                if not m.any():
                    continue
                jj, sel = j[m], iw[m]
                timm, trd = imm_rd(jj)
                same = trd == wrd[m]
                if not same.any():
                    continue
                jj, sel = jj[same], sel[same]
                c = (timm[same] << 16) | wimm[m][same]
                rd = wrd[m][same]
                for g2 in range(0, 7):
                    a = jj + 1 + g2
                    okadd = add_ok(w[a], rd)
                    if not okadd.any():
                        continue
                    s = (c[okadd] + 4 * (start + a[okadd]) + 8) & MASK
                    hit = np.isin(s, tarr)
                    for s_, site in zip(s[hit], sel[okadd][hit]):
                        report(out, "A", 4 * (start + int(site)), s_, "movw/movt+add")

        il = np.flatnonzero(((w & 0x0F7F0000) == 0x051F0000)[:lim])
        il = il[il + 20 < n]
        if len(il):
            x = w[il]
            rt = (x >> 12) & 0xF
            imm12 = x & 0xFFF
            up = (x >> 23) & 1
            addr = 4 * (start + il)
            lit = addr + 8 + np.where(up == 1, imm12, -imm12)
            valid = (lit >= 0) & (lit + 4 <= seg_len) & ((lit & 3) == 0)
            il, rt, lit = il[valid], rt[valid], lit[valid]
            if len(il):
                lw = np.asarray(words[lit >> 2]).astype(np.int64)
                for g in range(0, 8):
                    a = il + 1 + g
                    okadd = add_ok(w[a], rt)
                    if not okadd.any():
                        continue
                    s = (lw[okadd] + 4 * (start + a[okadd]) + 8) & MASK
                    hit = np.isin(s, tarr)
                    for s_, site in zip(s[hit], il[okadd][hit]):
                        report(out, "A", 4 * (start + int(site)), s_, "ldr+add")


def thumb_starts(hm, site, back=0x6000, limit=3):
    lo = max(0, (site - back) // 2)
    hi = site // 2
    h = np.asarray(hm[lo:hi + 2]).astype(np.int64)
    cand16 = (h[:-1] & 0xFF00) == 0xB500                       # push {.., lr}
    cand32 = (h[:-1] == 0xE92D) & ((h[1:] & 0x4000) != 0)      # push.w / stmdb sp!, {.., lr}
    idx = np.flatnonzero((cand16 | cand32)[: hi - lo])
    idx = idx[::-1][:limit]
    return [2 * (lo + int(i)) for i in idx]


def arm_starts(words, site, back=0x6000, limit=3):
    lo = max(0, (site - back) // 4)
    hi = site // 4
    w = np.asarray(words[lo:hi + 1]).astype(np.int64)
    c = ((w & 0xFFFFC000) == 0xE92D4000) | (w == 0xE52DE004)   # push {.., lr} / str lr,[sp,#-4]!
    idx = np.flatnonzero(c[: hi - lo])
    idx = idx[::-1][:limit]
    return [4 * (lo + int(i)) for i in idx]


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(2)
    lib, tfile, outdir = sys.argv[1:4]
    seg_len = int(sys.argv[4], 16) if len(sys.argv) > 4 else first_load_len(lib)
    seg_len &= ~3
    os.makedirs(outdir, exist_ok=True)
    targets = load_targets(tfile)
    tarr = np.array(sorted(targets), dtype=np.int64)
    print("segment length: 0x%x, targets: %d" % (seg_len, len(targets)))

    hm = np.memmap(lib, dtype="<u2", mode="r", shape=(seg_len // 2,))
    words = np.memmap(lib, dtype="<u4", mode="r", shape=(seg_len // 4,))

    out = []
    print("scanning Thumb ...")
    scan_thumb(hm, words, tarr, out)
    print("scanning ARM ...")
    scan_arm(words, tarr, out)

    seen = set()
    hits = []
    for mode, site, s, kind in sorted(out, key=lambda r: (r[2], r[1])):
        if (mode, site, s) in seen:
            continue
        seen.add((mode, site, s))
        hits.append((mode, site, s, kind))

    per = {}
    with open(os.path.join(outdir, "hits.tsv"), "w") as fh, \
         open(os.path.join(outdir, "candidates.tsv"), "w") as fc:
        fh.write("mode\tsite\tstring\tname\tkind\n")
        fc.write("name\tmode\tsite\tstart\tstring\n")
        for mode, site, s, kind in hits:
            name = targets[s]
            per[name] = per.get(name, 0) + 1
            fh.write("%s\t0x%08x\t0x%08x\t%s\t%s\n" % (mode, site, s, name, kind))
            starts = thumb_starts(hm, site) if mode == "T" else arm_starts(words, site)
            for st in starts:
                fc.write("%s\t%s\t0x%08x\t0x%08x\t0x%08x\n" % (name, mode, site, st, s))

    with open(os.path.join(outdir, "summary.txt"), "w") as fs:
        fs.write("hits: %d   targets with hits: %d / %d\n" % (len(hits), len(per), len(targets)))
        for v in sorted(targets):
            fs.write("%-8s %-60s %d\n" % ("%x" % v, targets[v], per.get(targets[v], 0)))
    print(open(os.path.join(outdir, "summary.txt")).read())


if __name__ == "__main__":
    main()
