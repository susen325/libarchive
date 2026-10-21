#!/usr/bin/env python3
"""
adaptive_loop_v2.py - coverage-steered fuzzing loop with an LLM action-policy.

Over v1 this adds, for one (format, target_func):
  * BRANCH-level coverage as the reward (falls back to region/line), and the
    loop reports the specific uncovered BRANCH source lines to the model, not
    just uncovered function names.
  * libFuzzer -use_value_profile=1 (gets past magic-byte / length compares).
  * An action POLICY on plateau instead of "always rewrite the harness":
        dict  -> ask the LLM for a libFuzzer dictionary built from the source
        seeds -> ask the LLM to synthesize structured seed inputs (base64)
        harness -> revise the harness toward the uncovered branches
    The order is configurable (ACTIONS env). dict/seeds are additive and kept
    only if they help; harness changes are validated + rolled back if not.
  * CROSS-RUN LEARNING: accepted harnesses and useful dictionaries are saved
    under pipeline/adaptive_memory/ and reused as the warm start / few-shot
    for the next run, so the system improves across runs instead of cold-start.
  * CRASH TRIAGE: on a crash it minimizes the input, classifies the sanitizer
    report, computes a stack hash for dedup, and writes a crash_report.md.
  * Optional differential check against bsdtar (bonus, only if bsdtar present).

Reuses pipeline/generate.py (Gemini client) and pipeline/validate.py (oracle).

Run from the libarchive repo root:
  GEMINI_API_KEY=... python3 pipeline/adaptive_loop_v2.py FORMAT FUNC [BUDGET_S]
"""
import os, re, sys, json, time, shutil, subprocess, glob, random, base64, hashlib
sys.path.insert(0, "pipeline")
import generate                       # Gemini client + helpers
from validate import validate, LIBS   # oracle (compile+smoke) + link libs

# ----------------------------- config (env-overridable) ----------------------
LIB_COV        = os.environ.get("LIB_COV", "build-cov/libarchive/libarchive.a")
LLVM_PROFDATA  = os.environ.get("LLVM_PROFDATA", "llvm-profdata")
LLVM_COV       = os.environ.get("LLVM_COV", "llvm-cov")
BURST_SECONDS  = int(os.environ.get("BURST_SECONDS", "300"))
BURST_MIN      = int(os.environ.get("BURST_MIN", "0"))      # >0 with BURST_MAX => random burst len
BURST_MAX      = int(os.environ.get("BURST_MAX", "0"))
PLATEAU_EPS    = float(os.environ.get("PLATEAU_EPS", "0.5"))   # %-coverage gain that counts
PLATEAU_PATIENCE = int(os.environ.get("PLATEAU_PATIENCE", "3"))
MAX_REVISIONS  = int(os.environ.get("MAX_REVISIONS", "4"))
DEFAULT_BUDGET = int(os.environ.get("BUDGET_S", "3600"))
USE_VALUE_PROFILE = os.environ.get("USE_VALUE_PROFILE", "1") == "1"
ACTIONS        = os.environ.get("ACTIONS", "dict,seeds,harness").split(",")
EPSILON        = float(os.environ.get("EPSILON", "0.3"))        # bandit exploration rate
RSS_LIMIT_MB   = int(os.environ.get("RSS_LIMIT_MB", "1024"))    # OOM sensitivity (unbounded-alloc bugs)
FUZZ_TIMEOUT   = int(os.environ.get("FUZZ_TIMEOUT", "25"))      # per-input timeout (slow-unit / DoS)
FORK           = int(os.environ.get("FORK", "0"))               # >0 => libFuzzer -fork=N parallel workers
NO_LLM         = os.environ.get("NO_LLM", "0") == "1"            # skip all LLM actions, pure fuzzing
WORKROOT       = os.environ.get("WORKROOT", "pipeline/adaptive_v2")
MEMROOT        = os.environ.get("MEMROOT", "pipeline/adaptive_memory")
# -----------------------------------------------------------------------------

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

def burst_len():
    return random.randint(BURST_MIN, BURST_MAX) if BURST_MAX >= BURST_MIN > 0 else BURST_SECONDS

def src_file(fmt):
    return "libarchive/archive_read_support_format_%s.c" % fmt

def source_context(fmt, func):
    try:
        lines = open(src_file(fmt)).read().split("\n")
    except OSError:
        return ""
    idx = next((i for i, l in enumerate(lines) if func in l and "(" in l), 0)
    return "\n".join(lines[max(0, idx-5):idx+55])

# ----------------------------- coverage build + measure ----------------------
def compile_cov(harness_path, covbin):
    cmd = ["clang", "-fsanitize=address,undefined,fuzzer",
           "-fprofile-instr-generate", "-fcoverage-mapping", "-g", "-O1",
           "-I", "libarchive", harness_path, LIB_COV] + LIBS + ["-o", covbin]
    cp = sh(cmd, timeout=180)
    return cp.returncode == 0, cp.stderr

def _first_pct(totals, keys):
    for k in keys:
        v = totals.get(k, {})
        if isinstance(v, dict) and v.get("percent") is not None:
            return float(v["percent"])
    return None

def measure_coverage(covbin, corpus_dir, fmt, workdir, target=None):
    """Replay corpus; return (reward_pct, uncov_funcs, uncov_branch_lines, target_reached)."""
    profdir = os.path.join(workdir, "prof")
    shutil.rmtree(profdir, ignore_errors=True); os.makedirs(profdir)
    env = dict(os.environ, LLVM_PROFILE_FILE=os.path.join(profdir, "%p-%m.profraw"))
    sh([covbin, "-runs=0", corpus_dir], timeout=900, env=env)
    raws = glob.glob(os.path.join(profdir, "*.profraw"))
    if not raws:
        return None, [], [], False
    pdata = os.path.join(workdir, "cov.profdata")
    if sh([LLVM_PROFDATA, "merge", "-sparse", *raws, "-o", pdata], timeout=300).returncode != 0:
        return None, [], [], False
    ex = sh([LLVM_COV, "export", covbin, "-instr-profile=" + pdata, src_file(fmt)], timeout=300)
    if ex.returncode != 0 or not ex.stdout.strip():
        return None, [], [], False
    try:
        d = json.loads(ex.stdout)["data"][0]
    except Exception:
        return None, [], [], False
    reward = _first_pct(d.get("totals", {}), ["branches", "regions", "lines"]) or 0.0
    uncov_funcs, uncov_branch, reached = [], [], False
    src_base = os.path.basename(src_file(fmt))
    for f in d.get("functions", []):
        fnames = f.get("filenames", [])
        if not any(src_base in fn for fn in fnames):
            continue
        nm = f.get("name", "")
        if f.get("count", 0) == 0:
            if nm:
                uncov_funcs.append(nm)
        elif target and target in nm:
            reached = True
        # uncovered branches: prefer the per-function 'branches' array,
        # [lineStart,colStart,lineEnd,colEnd,trueCount,falseCount,fileID,expandedID]
        for b in f.get("branches", []):
            try:
                if len(b) >= 6 and (b[4] == 0 or b[5] == 0):
                    uncov_branch.append("%s:%d" % (src_base, b[0]))
            except Exception:
                pass
        for reg in f.get("regions", []):  # fallback: branch regions (kind 4)
            try:
                if len(reg) >= 8 and reg[7] == 4 and reg[4] == 0:
                    uncov_branch.append("%s:%d" % (src_base, reg[0]))
            except Exception:
                pass
    uncov_branch = sorted(set(uncov_branch), key=lambda s: int(s.rsplit(":", 1)[1]))[:25]
    return reward, uncov_funcs[:25], uncov_branch, reached

# ----------------------------- fuzzing burst ---------------------------------
CRASH_RE = re.compile(r"ERROR: (libFuzzer|AddressSanitizer)|runtime error:|LeakSanitizer: detected|SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer)")

def run_burst(fuzzbin, corpus_dir, seconds, artifact_prefix, dict_path=None):
    cmd = [fuzzbin, corpus_dir, "-max_total_time=%d" % seconds,
           "-artifact_prefix=" + artifact_prefix,
           "-rss_limit_mb=%d" % RSS_LIMIT_MB, "-timeout=%d" % FUZZ_TIMEOUT]
    if FORK > 0:
        cmd.append("-fork=%d" % FORK)
    if USE_VALUE_PROFILE:
        cmd.append("-use_value_profile=1")
    if dict_path and os.path.exists(dict_path):
        cmd.append("-dict=" + dict_path)
    cp = sh(cmd, timeout=seconds + 120)
    out = (cp.stdout or "") + (cp.stderr or "")
    crashed = (cp.returncode not in (0, 124)) and bool(CRASH_RE.search(out))
    m = re.findall(r"^#(\d+)", out, re.M)
    execs = int(m[-1]) if m else 0
    cfile = None
    if crashed:
        arts = sorted(glob.glob(artifact_prefix + "*"), key=os.path.getmtime)
        cfile = arts[-1] if arts else None
    return crashed, cfile, execs, out[-3000:]

# ----------------------------- LLM actions -----------------------------------
def ask(prompt):
    # 3 bounded attempts; _gen enforces a hard per-call timeout so a dead API
    # fails fast instead of hanging the whole run.
    for attempt in range(3):
        try:
            r = generate._gen(generate.MODEL, prompt)
            return getattr(r, "text", None)
        except Exception as e:
            msg = str(e) or type(e).__name__
            if any(k in msg for k in ("503", "UNAVAILABLE", "429", "RESOURCE_EXHAUSTED")):
                time.sleep([5, 15, 30][attempt]); continue
            print("  LLM error:", msg[:160]); return None
    return None

HARNESS_PROMPT = """You are improving a libFuzzer test driver (a QA harness) for the
open-source C library libarchive, to raise coverage of the {fmt} reader.

Current harness:
--- BEGIN HARNESS ---
{harness}
--- END HARNESS ---

After fuzzing, these functions are still NOT reached (0 coverage):
{uncov_funcs}
And these specific BRANCHES were never taken (file:line):
{uncov_branch}
{memory}
Source context around `{func}`:
--- BEGIN SOURCE ---
{src}
--- END SOURCE ---

Revise the harness so the library is more likely to execute those uncovered
branches. You may change which archive_entry_* accessors you call, read entry
data with archive_read_data_block, set archive_read_set_options, or open the
input differently - but keep the EXACT entry point signature
`int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` and keep it one
self-contained C file. Respond with ONLY the C code, no markdown, no prose."""

DICT_PROMPT = """You are writing a libFuzzer dictionary to help fuzz the {fmt} reader
of libarchive. From the source below, extract the concrete byte tokens that the
parser compares against: magic numbers / file signatures, fixed header tags,
format keywords, and important constant strings. Output ONLY libFuzzer dictionary
lines, one per line, in the form:
  name="\\xNN\\xNN..."   (for binary) or  name="literal"   (for ASCII)
No comments beyond optional '#' lines, no markdown. Aim for 15-40 high-value
entries.

Source:
--- BEGIN SOURCE ---
{src}
--- END SOURCE ---"""

SEED_PROMPT = """You are synthesizing SEED INPUTS for a libFuzzer harness that feeds raw
bytes to libarchive's {fmt} reader. The goal is to reach these branches that
fuzzing has not covered (file:line):
{uncov_branch}

Using the parser source below, construct a few minimal byte inputs that satisfy
the header/magic checks guarding those branches (correct signature, plausible
header fields, small body). Return ONLY a JSON array of base64-encoded byte
strings, e.g. ["UEsDBA==","..."]. 3 to 6 seeds. No prose, no markdown.

Source:
--- BEGIN SOURCE ---
{src}
--- END SOURCE ---"""

def gen_dict(fmt, src):
    t = ask(DICT_PROMPT.format(fmt=fmt, src=src))
    if not t:
        return []
    t = generate.strip_code(t)
    lines = []
    for ln in t.split("\n"):
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if '"' in ln:                       # keep only plausible dict entries
            lines.append(ln)
    return lines

def synth_seeds(fmt, uncov_branch, src):
    t = ask(SEED_PROMPT.format(fmt=fmt, uncov_branch="\n".join("  " + b for b in uncov_branch) or "  (none)", src=src))
    if not t:
        return []
    t = generate.strip_code(t)
    blobs = []
    try:
        arr = json.loads(t)
        if isinstance(arr, list):
            for s in arr:
                try:
                    b = base64.b64decode(s)
                    if 0 < len(b) <= 1_000_000:
                        blobs.append(b)
                except Exception:
                    pass
    except Exception:
        for tok in re.findall(r"[A-Za-z0-9+/=]{8,}", t):
            try:
                b = base64.b64decode(tok)
                if 0 < len(b) <= 1_000_000:
                    blobs.append(b)
            except Exception:
                pass
    return blobs[:6]

def revise_harness(fmt, func, harness, uncov_funcs, uncov_branch, src, mem_example):
    mem = ""
    if mem_example:
        mem = ("\nA harness that previously worked well for this reader (for reference, "
               "do not copy blindly):\n--- BEGIN REFERENCE ---\n%s\n--- END REFERENCE ---\n" % mem_example)
    p = HARNESS_PROMPT.format(
        fmt=fmt, func=func, harness=harness,
        uncov_funcs="\n".join("  - " + u for u in uncov_funcs) or "  (none)",
        uncov_branch="\n".join("  - " + b for b in uncov_branch) or "  (none)",
        memory=mem, src=src)
    t = ask(p)
    return generate.strip_code(t) if t else None

# ----------------------------- crash triage ----------------------------------
ASAN_TYPE_RE = re.compile(r"(AddressSanitizer|UndefinedBehaviorSanitizer): ([a-zA-Z0-9_\-]+)")
UBSAN_RE     = re.compile(r"runtime error: (.+)")
FRAME_RE     = re.compile(r"#\d+ 0x[0-9a-f]+ in ([^\s]+) ([^\s]+)")

def triage_crash(fuzzbin, crash_file, workdir, fmt):
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1", UBSAN_OPTIONS="print_stacktrace=1")
    rep = sh([fuzzbin, crash_file], timeout=60, env=env)
    out = (rep.stdout or "") + (rep.stderr or "")
    m = ASAN_TYPE_RE.search(out)
    if m:
        bug_type = "%s:%s" % (m.group(1), m.group(2))
    elif UBSAN_RE.search(out):
        bug_type = "UBSan:" + UBSAN_RE.search(out).group(1)[:60]
    else:
        bug_type = "unknown"
    frames = FRAME_RE.findall(out)[:4]
    stack_sig = "|".join(fn for fn, _loc in frames)
    stack_hash = hashlib.sha1(stack_sig.encode()).hexdigest()[:12] if stack_sig else "nostack"
    # minimize
    minimized = os.path.join(workdir, "min_" + os.path.basename(crash_file))
    sh([fuzzbin, "-minimize_crash=1", "-runs=20000",
        "-exact_artifact_path=" + minimized, crash_file], timeout=300)
    if not os.path.exists(minimized):
        minimized = crash_file
    report = os.path.join(workdir, "crash_report_%s.md" % stack_hash)
    with open(report, "w") as fh:
        fh.write("# Crash report (%s)\n\n" % fmt)
        fh.write("- **Type:** %s\n- **Stack hash:** %s\n- **Input:** %s (%d bytes)\n"
                 "- **Minimized:** %s (%d bytes)\n\n"
                 % (bug_type, stack_hash, crash_file, os.path.getsize(crash_file),
                    minimized, os.path.getsize(minimized)))
        fh.write("## Top frames\n")
        for fn, loc in frames:
            fh.write("- `%s`  %s\n" % (fn, loc))
        fh.write("\n## Reproduce\n```\n%s %s\n```\n\n## Sanitizer output (tail)\n```\n%s\n```\n"
                 % (fuzzbin, minimized, out[-2500:]))
    return {"type": bug_type, "stack_hash": stack_hash, "minimized": minimized, "report": report}

# ----------------------------- differential (optional) -----------------------
def differential_check(crash_file):
    """Bonus: if bsdtar exists, note whether it also chokes on the input."""
    if not shutil.which("bsdtar"):
        return None
    r = sh(["bsdtar", "-tf", crash_file], timeout=20)
    return {"bsdtar_rc": r.returncode, "bsdtar_err": (r.stderr or "")[-200:]}

# ----------------------------- action bandit (#5, cross-run) ------------------
def bandit_load(path, actions):
    stats = {a: {"n": 0, "gain": 0.0} for a in actions}
    if os.path.exists(path):
        try:
            saved = json.load(open(path))
            for a in actions:
                if a in saved and isinstance(saved[a], dict):
                    stats[a] = {"n": int(saved[a].get("n", 0)), "gain": float(saved[a].get("gain", 0.0))}
        except Exception:
            pass
    return stats

def bandit_pick(stats, actions):
    untried = [a for a in actions if stats[a]["n"] == 0]
    if untried:
        return untried[0]                       # try each action once first
    if random.random() < EPSILON:
        return random.choice(actions)           # explore
    return max(actions, key=lambda a: stats[a]["gain"] / stats[a]["n"])  # exploit best avg gain

def bandit_update(stats, action, delta, path):
    s = stats.setdefault(action, {"n": 0, "gain": 0.0})
    s["n"] += 1; s["gain"] += max(0.0, delta)
    try:
        json.dump(stats, open(path, "w"), indent=2)
    except OSError:
        pass

def bandit_avgs(stats, actions):
    return {a: round(stats[a]["gain"] / stats[a]["n"], 2) if stats[a]["n"] else 0.0 for a in actions}

# ----------------------------- main loop -------------------------------------
def main():
    fmt, func = sys.argv[1], sys.argv[2]
    budget = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_BUDGET

    if not os.path.exists(LIB_COV):
        sys.exit("ERROR: coverage lib %s missing. Build one, e.g.:\n"
                 "  cmake -S . -B build-cov -DCMAKE_C_FLAGS='-fprofile-instr-generate "
                 "-fcoverage-mapping -g -O1' && cmake --build build-cov\n"
                 "(or set LIB_COV=/path/to/coverage/libarchive.a)" % LIB_COV)
    for tool in (LLVM_PROFDATA, LLVM_COV):
        if shutil.which(tool) is None:
            sys.exit("ERROR: %s not on PATH" % tool)

    work = os.path.join(WORKROOT, "%s__%s" % (fmt, func))
    shutil.rmtree(work, ignore_errors=True); os.makedirs(work)
    corpus = os.path.join(work, "corpus"); os.makedirs(corpus)
    os.makedirs(MEMROOT, exist_ok=True)
    mem_harness_path = os.path.join(MEMROOT, "%s__%s.harness.c" % (fmt, func))
    mem_dict_path    = os.path.join(MEMROOT, "%s.dict" % fmt)

    seed = "corpus/%s_fuzz" % fmt
    if os.path.isdir(seed):
        for f in glob.glob(seed + "/*"):
            if os.path.isfile(f):
                shutil.copy(f, corpus)

    logf = open(os.path.join(work, "loop.log"), "w")
    def say(*a):
        s = " ".join(str(x) for x in a); print(s, flush=True); logf.write(s + "\n"); logf.flush()

    src = source_context(fmt, func)
    mem_example = open(mem_harness_path).read() if os.path.exists(mem_harness_path) else ""

    # ----- initial harness: learned memory > prior valid > fresh generate -----
    vpath = "pipeline/valid/%s__%s.c" % (fmt, func)
    if mem_example:
        harness = mem_example; say("[init] warm-starting from learned harness", mem_harness_path)
    elif os.path.exists(vpath):
        harness = open(vpath).read(); say("[init] reusing valid harness", vpath)
    else:
        say("[init] generating initial harness ..."); harness = generate.generate_harness(fmt, func, src)
        if not harness:
            sys.exit("ERROR: initial generation failed")

    hpath   = os.path.join(work, "harness.c"); open(hpath, "w").write(harness)
    fuzzbin = os.path.join(work, "fuzz.bin")
    covbin  = os.path.join(work, "cov.bin")

    def build_both(hp):
        ok, reason, detail = validate(hp, fmt, fuzzbin)      # ASan+UBSan+fuzzer + smoke
        if not ok:
            return False, "fuzz_" + reason, detail
        ok2, err = compile_cov(hp, covbin)
        return (True, "ok", "") if ok2 else (False, "cov_build_fail", err)

    ok, reason, detail = build_both(hpath)
    if not ok:
        sys.exit("ERROR: initial build failed (%s)\n%s" % (reason, (detail or "")[:600]))

    # ----- active dictionary: start from learned memory dict if present -------
    active_dict = os.path.join(work, "fuzz.dict"); dict_entries = []
    if os.path.exists(mem_dict_path):
        dict_entries = [l.rstrip("\n") for l in open(mem_dict_path) if l.strip()]
    def write_dict():
        if dict_entries:
            open(active_dict, "w").write("\n".join(sorted(set(dict_entries))) + "\n")
    write_dict()
    use_dict = active_dict if dict_entries else None

    def snapshot():
        snap = os.path.join(work, "best_corpus")
        shutil.rmtree(snap, ignore_errors=True); shutil.copytree(corpus, snap); return snap
    def restore(snap):
        if snap and os.path.isdir(snap):
            shutil.rmtree(corpus, ignore_errors=True); shutil.copytree(snap, corpus)

    best = {"harness": harness, "cov": -1.0, "snap": None, "reached": False}
    ACTION_SET = list(dict.fromkeys([a.strip() for a in ACTIONS if a.strip()]))
    bandit_path = os.path.join(MEMROOT, "bandit_%s.json" % fmt)
    stats = bandit_load(bandit_path, ACTION_SET)
    t0 = time.time(); stall = 0; revisions = 0; burst = 0
    llm_dead = False; noop_streak = 0
    history = []

    prev, uf, ub, reached0 = measure_coverage(covbin, corpus, fmt, work, func)
    prev = prev or 0.0
    best.update(cov=prev, snap=snapshot(), reached=reached0)
    say("[cov] start (branch) = %.2f%%  uncovered_funcs=%d uncovered_branches=%d target_reached=%s"
        % (prev, len(uf), len(ub), reached0))

    def finish(status, extra=None):
        rec = {"fmt": fmt, "func": func, "status": status, "cov": round(best["cov"], 2),
               "target_reached": best.get("reached", False),
               "revisions": revisions, "bursts": burst, "dict_entries": len(dict_entries),
               "bandit": bandit_avgs(stats, ACTION_SET),
               "seconds": round(time.time() - t0), "history": history}
        if extra: rec.update(extra)
        json.dump(rec, open(os.path.join(work, "result.json"), "w"), indent=2)
        open(os.path.join(work, "best_harness.c"), "w").write(best["harness"])
        # cross-run learning: persist what worked
        try:
            open(mem_harness_path, "w").write(best["harness"])
            if dict_entries:
                open(mem_dict_path, "w").write("\n".join(sorted(set(dict_entries))) + "\n")
        except OSError:
            pass
        say("[result]", json.dumps(rec))

    def do_burst(tag, prefix):
        nonlocal burst
        burst += 1; secs = burst_len()
        say("[%s %d] fuzzing %ds ... (dict=%s valueprofile=%s)"
            % (tag, burst, secs, "yes" if use_dict else "no", "yes" if USE_VALUE_PROFILE else "no"))
        return run_burst(fuzzbin, corpus, secs, prefix, use_dict)

    while time.time() - t0 < budget:
        crashed, cfile, execs, tail = do_burst("burst", os.path.join(work, "crash_%d_" % burst))
        say("         execs=%d crashed=%s" % (execs, crashed))
        if crashed:
            say("=== CRASH FOUND ===", cfile)
            tri = triage_crash(fuzzbin, cfile, work, fmt) if cfile else {}
            diff = differential_check(cfile) if cfile else None
            say("  triage:", json.dumps(tri));
            if diff: say("  differential(bsdtar):", json.dumps(diff))
            finish("crash", {"crash": cfile, "triage": tri, "differential": diff}); return

        cov, uf, ub, reached = measure_coverage(covbin, corpus, fmt, work, func)
        cov = cov if cov is not None else prev
        gain = cov - prev
        say("[cov] %.2f%% (gain %+.2f, uncovered_funcs=%d uncovered_branches=%d target_reached=%s)"
            % (cov, gain, len(uf), len(ub), reached))
        if cov > best["cov"]:
            best.update(harness=open(hpath).read(), cov=cov, snap=snapshot())
        if reached:
            best["reached"] = True
        if gain >= PLATEAU_EPS:
            stall = 0; prev = cov; continue
        stall += 1
        say("[plateau] stalled %d/%d" % (stall, PLATEAU_PATIENCE))
        if stall < PLATEAU_PATIENCE:
            prev = cov; continue

        # ---------------- plateau: decide what to do --------------------------
        if NO_LLM or llm_dead:
            say("[plateau] fuzzing-only (%s); using the rest of the budget"
                % ("NO_LLM" if NO_LLM else "LLM disabled after repeated failures"))
            prev = cov; stall = 0; continue
        if revisions >= MAX_REVISIONS:
            say("[stop] max LLM actions reached; fuzzing-only for the rest"); llm_dead = True
            prev = cov; stall = 0; continue
        action = bandit_pick(stats, ACTION_SET); stall = 0
        say("[action %d] %s  (bandit avg gains %s; targeting %d funcs / %d branches)"
            % (revisions + 1, action, bandit_avgs(stats, ACTION_SET), len(uf), len(ub)))

        if action == "dict":
            added = [e for e in gen_dict(fmt, src) if e not in dict_entries]
            if not added:
                say("  no new dict entries"); history.append({"action": "dict", "result": "noop"})
                bandit_update(stats, action, 0.0, bandit_path)
                noop_streak += 1
                if noop_streak >= 2:
                    llm_dead = True; say("  [llm] repeated no-ops; disabling LLM, fuzzing-only")
                prev = cov; continue
            dict_entries += added; write_dict(); use_dict = active_dict
            say("  +%d dict entries (total %d); re-fuzzing" % (len(added), len(dict_entries)))
            crashed, cfile, execs, tail = run_burst(fuzzbin, corpus, burst_len(),
                                                    os.path.join(work, "dictcrash_%d_" % revisions), use_dict)
            if crashed:
                say("=== CRASH FOUND (after dict) ===", cfile)
                tri = triage_crash(fuzzbin, cfile, work, fmt) if cfile else {}
                finish("crash", {"crash": cfile, "triage": tri}); return
            cov2, uf, ub, reached = measure_coverage(covbin, corpus, fmt, work, func); cov2 = cov2 or cov
            delta = cov2 - cov
            say("  dict -> %.2f%% (was %.2f%%, target_reached=%s)" % (cov2, cov, reached))
            if cov2 > best["cov"]:
                best.update(cov=cov2, snap=snapshot())
            if reached:
                best["reached"] = True
            prev = max(prev, cov2)
            history.append({"action": "dict", "added": len(added), "delta": round(delta, 2)})
            bandit_update(stats, action, delta, bandit_path)
            revisions += 1; noop_streak = 0; continue

        if action == "seeds":
            blobs = synth_seeds(fmt, ub, src)
            if not blobs:
                say("  no seeds synthesized"); history.append({"action": "seeds", "result": "noop"})
                bandit_update(stats, action, 0.0, bandit_path)
                noop_streak += 1
                if noop_streak >= 2:
                    llm_dead = True; say("  [llm] repeated no-ops; disabling LLM, fuzzing-only")
                prev = cov; continue
            added_files = []
            for i, b in enumerate(blobs):
                fp = os.path.join(corpus, "synth_%d_%d" % (revisions, i)); open(fp, "wb").write(b); added_files.append(fp)
            say("  added %d synthesized seeds; re-fuzzing" % len(added_files))
            crashed, cfile, execs, tail = run_burst(fuzzbin, corpus, burst_len(),
                                                    os.path.join(work, "seedcrash_%d_" % revisions), use_dict)
            if crashed:
                say("=== CRASH FOUND (after seeds) ===", cfile)
                tri = triage_crash(fuzzbin, cfile, work, fmt) if cfile else {}
                finish("crash", {"crash": cfile, "triage": tri}); return
            cov2, uf, ub, reached = measure_coverage(covbin, corpus, fmt, work, func); cov2 = cov2 or cov
            delta = cov2 - cov
            say("  seeds -> %.2f%% (was %.2f%%, target_reached=%s)" % (cov2, cov, reached))
            if cov2 > best["cov"] + PLATEAU_EPS or (reached and not best["reached"]):
                say("  kept"); best.update(cov=max(cov2, best["cov"]), snap=snapshot(),
                                           reached=best["reached"] or reached); prev = cov2
                history.append({"action": "seeds", "delta": round(delta, 2), "kept": True})
            else:
                for fp in added_files:
                    try: os.remove(fp)
                    except OSError: pass
                restore(best["snap"]); prev = best["cov"]
                history.append({"action": "seeds", "delta": round(delta, 2), "kept": False})
            bandit_update(stats, action, delta, bandit_path)
            revisions += 1; noop_streak = 0; continue

        if action == "harness":
            new = revise_harness(fmt, func, best["harness"], uf, ub, src, mem_example)
            if not new:
                say("  revise failed; keeping current"); history.append({"action": "harness", "result": "noop"})
                bandit_update(stats, action, 0.0, bandit_path)
                noop_streak += 1
                if noop_streak >= 2:
                    llm_dead = True; say("  [llm] repeated no-ops; disabling LLM, fuzzing-only")
                prev = cov; continue
            open(hpath, "w").write(new)
            ok, reason, detail = build_both(hpath)
            if not ok:
                say("  revision rejected by oracle (%s); rolling back" % reason)
                open(hpath, "w").write(best["harness"]); build_both(hpath); restore(best["snap"])
                prev = best["cov"]; history.append({"action": "harness", "result": "rejected:" + reason})
                bandit_update(stats, action, 0.0, bandit_path)
                revisions += 1; noop_streak = 0; continue   # LLM produced output; counts as a used action
            crashed, cfile, execs, tail = run_burst(fuzzbin, corpus, burst_len(),
                                                    os.path.join(work, "revcrash_%d_" % revisions), use_dict)
            if crashed:
                say("=== CRASH FOUND (after revision) ===", cfile)
                best["harness"] = new
                tri = triage_crash(fuzzbin, cfile, work, fmt) if cfile else {}
                finish("crash", {"crash": cfile, "triage": tri}); return
            cov2, uf, ub, reached = measure_coverage(covbin, corpus, fmt, work, func); cov2 = cov2 or cov
            delta = cov2 - cov
            say("  harness -> %.2f%% (best %.2f%%, target_reached=%s)" % (cov2, best["cov"], reached))
            if cov2 > best["cov"] + PLATEAU_EPS or (reached and not best["reached"]):
                say("  accepted"); best.update(harness=new, cov=max(cov2, best["cov"]), snap=snapshot(),
                                               reached=best["reached"] or reached); prev = cov2
                history.append({"action": "harness", "delta": round(delta, 2), "kept": True})
            else:
                open(hpath, "w").write(best["harness"]); build_both(hpath); restore(best["snap"])
                prev = best["cov"]; history.append({"action": "harness", "delta": round(delta, 2), "kept": False})
            bandit_update(stats, action, delta, bandit_path)
            revisions += 1; noop_streak = 0; continue

        say("  unknown action '%s', skipping" % action); prev = cov

    finish("no_crash")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: python3 pipeline/adaptive_loop_v2.py FORMAT FUNC [BUDGET_S]")
    main()
