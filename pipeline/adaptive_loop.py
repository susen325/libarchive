#!/usr/bin/env python3
"""
adaptive_loop.py - coverage-steered fuzzing loop with LLM feedback.

For one (format, target_func): build a harness, fuzz in short bursts, measure
coverage after each burst; when coverage plateaus, ask the LLM to revise the
harness toward the still-uncovered functions, re-validate + rebuild, and keep
going. A best-state is kept and revisions that don't help are rolled back.
Stops on first crash, overall time budget, or max revisions.

This solves the "ran for hours, no crash" problem: instead of waiting, the loop
detects the coverage plateau and changes the harness/strategy.

Run from the libarchive repo root:
  GEMINI_API_KEY=... python3 pipeline/adaptive_loop.py FORMAT FUNC [BUDGET_S]

Reuses pipeline/generate.py (Gemini client) and pipeline/validate.py (oracle).
"""
import os, re, sys, json, time, shutil, subprocess, glob, random
def _burst_len(default):
    lo = int(os.environ.get('BURST_MIN','0')); hi = int(os.environ.get('BURST_MAX','0'))
    return random.randint(lo, hi) if hi >= lo > 0 else default
sys.path.insert(0, "pipeline")
import generate                         # Gemini client + helpers
from validate import validate, LIBS    # oracle (compile + smoke) + link libs

# ----------------------------- config (overridable via env) -----------------
LIB_COV        = os.environ.get("LIB_COV", "build-cov/libarchive/libarchive.a")
LLVM_PROFDATA  = os.environ.get("LLVM_PROFDATA", "llvm-profdata")
LLVM_COV       = os.environ.get("LLVM_COV", "llvm-cov")
BURST_SECONDS  = int(os.environ.get("BURST_SECONDS", "300"))    # fuzz time per burst
PLATEAU_EPS    = float(os.environ.get("PLATEAU_EPS", "0.5"))    # %line-cov gain that counts as progress
PLATEAU_PATIENCE = int(os.environ.get("PLATEAU_PATIENCE", "2")) # stalled bursts before revising
MAX_REVISIONS  = int(os.environ.get("MAX_REVISIONS", "4"))
DEFAULT_BUDGET = int(os.environ.get("BUDGET_S", "3600"))        # overall per target
WORKROOT       = "pipeline/adaptive"
# ----------------------------------------------------------------------------

def sh(cmd, timeout=None, env=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, env=env or os.environ)
    except subprocess.TimeoutExpired as e:
        class R: pass
        r = R(); r.returncode = 124
        dec = lambda x: x.decode("utf-8","ignore") if isinstance(x, bytes) else (x or "")
        r.stdout, r.stderr = dec(e.stdout), dec(e.stderr)
        return r

def src_file(fmt):
    return "libarchive/archive_read_support_format_%s.c" % fmt

def source_context(fmt, func):
    lines = open(src_file(fmt)).read().split("\n")
    idx = next((i for i, l in enumerate(lines) if func in l and "(" in l), 0)
    return "\n".join(lines[max(0, idx-5):idx+55])

def compile_cov(harness_path, covbin):
    cmd = ["clang", "-fsanitize=address,undefined,fuzzer", "-fprofile-instr-generate",
           "-fcoverage-mapping", "-g", "-O1", "-I", "libarchive",
           harness_path, LIB_COV] + LIBS + ["-o", covbin]
    cp = sh(cmd, timeout=180)
    return cp.returncode == 0, cp.stderr

def measure_coverage(covbin, corpus_dir, fmt, workdir):
    """Replay the corpus through the coverage build; return (line%, [uncovered funcs])."""
    profdir = os.path.join(workdir, "prof")
    shutil.rmtree(profdir, ignore_errors=True); os.makedirs(profdir)
    env = dict(os.environ, LLVM_PROFILE_FILE=os.path.join(profdir, "%p-%m.profraw"))
    sh([covbin, "-runs=0", corpus_dir], timeout=900, env=env)   # -runs=0 = execute seeds, no mutation
    raws = glob.glob(os.path.join(profdir, "*.profraw"))
    if not raws:
        return None, []
    pdata = os.path.join(workdir, "cov.profdata")
    if sh([LLVM_PROFDATA, "merge", "-sparse", *raws, "-o", pdata], timeout=300).returncode != 0:
        return None, []
    ex = sh([LLVM_COV, "export", covbin, "-instr-profile=" + pdata, src_file(fmt)], timeout=300)
    if ex.returncode != 0 or not ex.stdout.strip():
        return None, []
    try:
        d = json.loads(ex.stdout)["data"][0]
        pct = d["totals"]["lines"]["percent"]
        uncovered = [f.get("name", "") for f in d.get("functions", [])
                     if f.get("count", 0) == 0
                     and any((fmt in fn or src_file(fmt) in fn) for fn in f.get("filenames", []))]
        return pct, uncovered
    except Exception:
        return None, []

def run_burst(fuzzbin, corpus_dir, seconds, artifact_prefix):
    cp = sh([fuzzbin, corpus_dir, "-max_total_time=%d" % seconds,
             "-artifact_prefix=" + artifact_prefix], timeout=seconds + 120)
    out = (cp.stdout or "") + (cp.stderr or "")
    crashed = (cp.returncode not in (0, 124)) and bool(re.search(
        r"ERROR: (libFuzzer|AddressSanitizer)|runtime error:|LeakSanitizer: detected|SUMMARY:", out))
    m = re.findall(r"^#(\d+)", out, re.M)
    execs = int(m[-1]) if m else 0
    cfile = None
    if crashed:
        arts = sorted(glob.glob(artifact_prefix + "*"), key=os.path.getmtime)
        cfile = arts[-1] if arts else None
    return crashed, cfile, execs, out[-2500:]

FEEDBACK_PROMPT = """You are improving a libFuzzer test driver (a QA harness) for
the open-source C library libarchive, to raise code coverage of the {fmt} reader.

Current harness:
--- BEGIN HARNESS ---
{harness}
--- END HARNESS ---

After fuzzing, these functions in the {fmt} reader are still NOT reached (0 coverage):
{uncovered}

Source context around `{func}`:
--- BEGIN SOURCE ---
{src}
--- END SOURCE ---

Revise the harness so the library is more likely to execute those uncovered
functions. You may change which archive_entry_* accessors you call, read entry
data with archive_read_data_block, set options via archive_read_set_options, or
open the input differently - but keep the EXACT entry point signature
`int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` and keep it one
self-contained C file. Respond with ONLY the C code, no explanation, no markdown."""

def revise(fmt, func, harness, uncovered, src):
    unc = "\n".join("  - " + u for u in uncovered[:20]) or "  (none reported)"
    prompt = FEEDBACK_PROMPT.format(fmt=fmt, func=func, harness=harness, uncovered=unc, src=src)
    for attempt in range(5):
        try:
            r = generate.client.models.generate_content(model=generate.MODEL, contents=prompt)
            t = getattr(r, "text", None)
            if t:
                return generate.strip_code(t)
            return None
        except Exception as e:
            msg = str(e)
            if any(k in msg for k in ("503", "UNAVAILABLE", "429", "RESOURCE_EXHAUSTED")):
                time.sleep([10, 30, 60, 90, 120][attempt]); continue
            print("  revise API error:", msg[:160]); return None
    return None

def main():
    fmt, func = sys.argv[1], sys.argv[2]
    budget = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_BUDGET

    if not os.path.exists(LIB_COV):
        sys.exit("ERROR: coverage lib %s missing. Build a coverage libarchive, e.g.:\n"
                 "  cmake -S . -B build-cov -DENABLE_TEST=OFF "
                 "-DCMAKE_C_FLAGS='-fprofile-instr-generate -fcoverage-mapping -g -O1'\n"
                 "  cmake --build build-cov\n"
                 "(or set LIB_COV=/path/to/coverage/libarchive.a)" % LIB_COV)
    for tool in (LLVM_PROFDATA, LLVM_COV):
        if shutil.which(tool) is None:
            sys.exit("ERROR: %s not on PATH" % tool)

    work = os.path.join(WORKROOT, "%s__%s" % (fmt, func))
    shutil.rmtree(work, ignore_errors=True); os.makedirs(work)
    corpus = os.path.join(work, "corpus"); os.makedirs(corpus)
    seed = "corpus/%s_fuzz" % fmt
    if os.path.isdir(seed):
        for f in glob.glob(seed + "/*"):
            if os.path.isfile(f):
                shutil.copy(f, corpus)

    logf = open(os.path.join(work, "loop.log"), "w")
    def say(*a):
        s = " ".join(str(x) for x in a); print(s, flush=True); logf.write(s + "\n"); logf.flush()

    src = source_context(fmt, func)
    vpath = "pipeline/valid/%s__%s.c" % (fmt, func)
    if os.path.exists(vpath):
        harness = open(vpath).read(); say("[init] reusing valid harness", vpath)
    else:
        say("[init] generating initial harness ...")
        harness = generate.generate_harness(fmt, func, src)
        if not harness:
            sys.exit("ERROR: initial generation failed")

    hpath   = os.path.join(work, "harness.c"); open(hpath, "w").write(harness)
    fuzzbin = os.path.join(work, "fuzz.bin")
    covbin  = os.path.join(work, "cov.bin")

    def build_both(hp):
        ok, reason, detail = validate(hp, fmt, fuzzbin)   # compile(fuzz+asan) + smoke
        if not ok:
            return False, "fuzz_" + reason, detail
        ok2, err = compile_cov(hp, covbin)
        return (True, "ok", "") if ok2 else (False, "cov_build_fail", err)

    ok, reason, detail = build_both(hpath)
    if not ok:
        sys.exit("ERROR: initial build failed (%s)\n%s" % (reason, (detail or "")[:600]))

    def snapshot():
        snap = os.path.join(work, "best_corpus")
        shutil.rmtree(snap, ignore_errors=True); shutil.copytree(corpus, snap); return snap
    def restore(snap):
        if snap and os.path.isdir(snap):
            shutil.rmtree(corpus, ignore_errors=True); shutil.copytree(snap, corpus)

    best = {"harness": harness, "cov": -1.0, "snap": None}
    t0 = time.time(); stall = 0; revisions = 0; burst = 0

    prev, _ = measure_coverage(covbin, corpus, fmt, work)
    prev = prev or 0.0
    best.update(cov=prev, snap=snapshot())
    say("[cov] start = %.2f%%" % prev)

    def finish(status, extra=None):
        rec = {"fmt": fmt, "func": func, "status": status, "cov": round(best["cov"], 2),
               "revisions": revisions, "bursts": burst, "seconds": round(time.time() - t0)}
        if extra: rec.update(extra)
        json.dump(rec, open(os.path.join(work, "result.json"), "w"), indent=2)
        open(os.path.join(work, "best_harness.c"), "w").write(best["harness"])
        say("[result]", json.dumps(rec))

    while time.time() - t0 < budget:
        burst += 1
        burst_s = _burst_len(BURST_SECONDS)
        say("[burst %d] fuzzing %ds ..." % (burst, burst_s))
        crashed, cfile, execs, tail = run_burst(fuzzbin, corpus, burst_s,
                                                os.path.join(work, "crash_%d_" % burst))
        say("         execs=%d crashed=%s" % (execs, crashed))
        if crashed:
            say("=== CRASH FOUND ===", cfile); say(tail)
            finish("crash", {"crash": cfile}); return

        cov, uncovered = measure_coverage(covbin, corpus, fmt, work)
        cov = cov if cov is not None else prev
        gain = cov - prev
        say("[cov] %.2f%% (gain %+.2f, uncovered funcs=%d)" % (cov, gain, len(uncovered)))
        if cov > best["cov"]:
            best.update(harness=open(hpath).read(), cov=cov, snap=snapshot())
        if gain >= PLATEAU_EPS:
            stall = 0; prev = cov; continue
        stall += 1
        say("[plateau] stalled %d/%d" % (stall, PLATEAU_PATIENCE))
        if stall < PLATEAU_PATIENCE:
            prev = cov; continue

        # ---------- plateau: ask the model to steer ----------
        if revisions >= MAX_REVISIONS:
            say("[stop] max revisions reached"); break
        revisions += 1; stall = 0
        say("[revise %d] targeting %d uncovered funcs ..." % (revisions, len(uncovered)))
        new = revise(fmt, func, best["harness"], uncovered, src)
        if not new:
            say("  revise failed; keep current"); prev = cov; continue
        open(hpath, "w").write(new)
        ok, reason, detail = build_both(hpath)
        if not ok:
            say("  revision rejected by oracle (%s); rolling back" % reason)
            open(hpath, "w").write(best["harness"]); build_both(hpath)
            restore(best["snap"]); prev = best["cov"]; continue
        rev_burst_s = _burst_len(BURST_SECONDS)
        crashed, cfile, execs, tail = run_burst(fuzzbin, corpus, rev_burst_s,
                                                os.path.join(work, "revcrash_%d_" % revisions))
        if crashed:
            say("=== CRASH FOUND (after revision) ===", cfile); say(tail)
            best["harness"] = new; finish("crash", {"crash": cfile}); return
        cov2, _ = measure_coverage(covbin, corpus, fmt, work); cov2 = cov2 or cov
        say("[cov] after revision = %.2f%% (best %.2f%%)" % (cov2, best["cov"]))
        if cov2 > best["cov"] + PLATEAU_EPS:
            say("  accepted"); best.update(harness=new, cov=cov2, snap=snapshot()); prev = cov2
        else:
            say("  did not help; rolling back to best")
            open(hpath, "w").write(best["harness"]); build_both(hpath)
            restore(best["snap"]); prev = best["cov"]

    finish("no_crash")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: python3 pipeline/adaptive_loop.py FORMAT FUNC [BUDGET_S]")
    main()
