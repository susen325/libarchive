import json, os, sys, time
sys.path.insert(0, "pipeline")
from generate import generate_harness
from validate import validate

TARGETS_FILE = sys.argv[1] if len(sys.argv) > 1 else "pipeline/targets.json"
targets = json.load(open(TARGETS_FILE))
os.makedirs("pipeline/harnesses", exist_ok=True)
os.makedirs("pipeline/valid", exist_ok=True)

results = []
for fmt, funcs in targets.items():
    src = open("libarchive/archive_read_support_format_" + fmt + ".c").read().split("\n")
    for func in funcs:
        print("[" + fmt + "] " + func + " ...", flush=True)
        idx = next((i for i, l in enumerate(src) if func in l and "(" in l), 0)
        context = "\n".join(src[max(0, idx - 5):idx + 55])
        harness = generate_harness(fmt, func, context)
        rec = {"format": fmt, "func": func}
        if not harness:
            rec["status"] = "gen_fail"
            results.append(rec)
            print("   gen_fail")
            continue
        hp = "pipeline/harnesses/" + fmt + "__" + func + ".c"
        open(hp, "w").write(harness)
        bp = "/tmp/h_" + fmt + "_" + func
        ok, reason, _ = validate(hp, fmt, bp)
        rec["status"] = reason
        if ok:
            open("pipeline/valid/" + fmt + "__" + func + ".c", "w").write(harness)
        results.append(rec)
        print("   " + reason)
        time.sleep(6)

json.dump(results, open("pipeline/results.json", "w"), indent=2)

from collections import Counter
n = len(results)
compiled = sum(1 for r in results if r["status"] in ("valid", "smoke_crash", "smoke_timeout"))
valid = sum(1 for r in results if r["status"] == "valid")
print("")
print("==================== SUMMARY ====================")
print("Targets attempted : " + str(n))
print("Compiled          : " + str(compiled) + "  (" + str(100 * compiled // max(n, 1)) + "%)")
print("VALID             : " + str(valid) + "  (" + str(100 * valid // max(n, 1)) + "%)   <- validity rate")
print("Breakdown         : " + str(dict(Counter(r["status"] for r in results))))
print("libErator baseline: ~25%")
