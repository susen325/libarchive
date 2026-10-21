#!/usr/bin/env python3
"""
build_seeds.py - turn libarchive's own test archives into fuzzing seed corpora.

libarchive/test/ ships hundreds of real, valid archives as uuencoded .uu files.
Decoding the ones for a format gives a far better starting corpus than random
bytes, so the fuzzer reaches deep parser/decompressor code immediately.

For each FMT, decodes libarchive/test/test_read_format_<FMT>_*.uu (and a few
known aliases) into corpus/<FMT>_fuzz/  -- the exact dir the adaptive loops read.

Usage:
  python3 pipeline/build_seeds.py 7zip zip rar5 xar iso9660 cab lha tar
Then (optional) minimize to a diverse set with libFuzzer:
  <any built fuzzer for that fmt> -merge=1 corpus/<fmt>_min corpus/<fmt>_fuzz
"""
import os, sys, glob, binascii

# our loop's format name -> filename tokens used in libarchive/test
ALIASES = {
    "iso9660": ["iso9660", "iso"],
    "7zip": ["7zip"], "zip": ["zip"], "rar5": ["rar5"], "rar": ["rar"],
    "xar": ["xar"], "cab": ["cab"], "lha": ["lha"], "tar": ["tar"],
    "cpio": ["cpio"], "warc": ["warc"], "mtree": ["mtree"],
}

def uudecode(path, outdir):
    """Decode one uuencoded file into outdir using the embedded 'begin' name."""
    name = os.path.basename(path)
    if name.endswith(".uu"):
        name = name[:-3]
    out = bytearray()
    started = False
    with open(path, "rb") as fh:
        for line in fh:
            line = line.rstrip(b"\n")
            if not started:
                if line.startswith(b"begin "):
                    started = True
                    parts = line.split(b" ", 2)
                    if len(parts) == 3 and parts[2].strip():
                        name = os.path.basename(parts[2].strip().decode("latin1"))
                continue
            if line.strip() in (b"end", b"`", b""):
                if line.strip() == b"end":
                    break
                continue
            try:
                out += binascii.a2b_uu(line)
            except binascii.Error:
                # tolerate a malformed length byte on the final data line
                try:
                    n = (line[0] - 32) & 0x3f
                    out += binascii.a2b_uu(bytes([n + 32]) + line[1:])[:n]
                except Exception:
                    pass
    if out:
        safe = name or (os.path.basename(path)[:-3])
        open(os.path.join(outdir, safe), "wb").write(out)
        return True
    return False

def main():
    if len(sys.argv) < 2:
        sys.exit("usage: python3 pipeline/build_seeds.py FMT [FMT ...]")
    for fmt in sys.argv[1:]:
        outdir = "corpus/%s_fuzz" % fmt
        os.makedirs(outdir, exist_ok=True)
        files = []
        for tok in ALIASES.get(fmt, [fmt]):
            files += glob.glob("libarchive/test/test_read_format_%s_*.uu" % tok)
            files += glob.glob("libarchive/test/test_read_format_%s.*.uu" % tok)
        files = sorted(set(files))
        n = 0
        for f in files:
            try:
                if uudecode(f, outdir):
                    n += 1
            except Exception:
                pass
        print("%-10s %3d/%-3d test files decoded -> %s" % (fmt, n, len(files), outdir))

if __name__ == "__main__":
    main()
