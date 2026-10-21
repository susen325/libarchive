import subprocess, os, glob

LIB = "build-fuzz/libarchive/libarchive.a"
LIBS = ["-lz", "-llzma", "-lbz2", "-lcrypto", "-lxml2", "-lzstd"]

# Fallback smoke seeds, used only when no corpus/<fmt>_fuzz dir exists.
SMOKE = {
    "rar5": "corpus/seeds/test_read_format_rar5_stored.rar",
    "7zip": "corpus/seeds/test_read_format_7zip_copy.7z",
    "xar":  "corpus/seeds/test_read_format_xar_empty_xattr.xar",
}
MAX_SMOKE = int(os.environ.get("SMOKE_SEEDS", "5"))

def _smoke_seeds(fmt):
    """Prefer real seeds from corpus/<fmt>_fuzz; fall back to the SMOKE map."""
    d = "corpus/%s_fuzz" % fmt
    if os.path.isdir(d):
        fs = sorted(f for f in glob.glob(d + "/*") if os.path.isfile(f))
        if fs:
            return fs[:MAX_SMOKE]
    s = SMOKE.get(fmt)
    return [s] if s and os.path.exists(s) else []

def validate(harness_path, fmt, binpath):
    """Compile the harness (ASan+UBSan+fuzzer) and smoke-run it on known-good
    seeds. Returns (ok, reason, detail). Stronger than v1: rejects degenerate
    harnesses and smoke-tests several real seeds instead of one."""
    # 1) reject harnesses that don't actually drive the reader
    try:
        srctext = open(harness_path).read()
    except OSError:
        return False, "no_harness", ""
    if "archive_read_next_header" not in srctext:
        return False, "degenerate_harness", "harness never calls archive_read_next_header"

    # 2) compile
    cmd = ["clang", "-fsanitize=address,undefined,fuzzer", "-g", "-O1",
           "-I", "libarchive", harness_path, LIB] + LIBS + ["-o", binpath]
    cp = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if cp.returncode != 0:
        return False, "compile_fail", cp.stderr

    # 3) smoke-run on several known-good seeds; any sanitizer abort on a
    #    valid archive means the harness misuses the API -> reject
    env = dict(os.environ,
               ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",
               UBSAN_OPTIONS="halt_on_error=1")
    seeds = _smoke_seeds(fmt)
    for seed in seeds:
        try:
            sp = subprocess.run([binpath, seed], capture_output=True,
                                text=True, timeout=30, env=env)
        except subprocess.TimeoutExpired:
            return False, "smoke_timeout", seed
        if sp.returncode != 0:
            return False, "smoke_crash", seed + "\n" + sp.stderr[-800:]
    return True, "valid", "smoke_seeds=%d" % len(seeds)

if __name__ == "__main__":
    import sys
    hp, fmt, bp = sys.argv[1], sys.argv[2], sys.argv[3]
    ok, reason, detail = validate(hp, fmt, bp)
    print(("VALID" if ok else "INVALID") + ": " + reason)
    if detail:
        print("--- detail ---")
        print(detail)
