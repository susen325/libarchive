#!/usr/bin/env python3
"""
rank_targets.py - rank functions in a libarchive format reader by bug-proneness,
so the adaptive loop chases the risky code instead of the lowest-coverage code.

Scores each function by static signals that correlate with the memory-safety
bugs this project already found (untrusted-size -> allocation / arithmetic):

  +4  allocation (malloc/calloc/realloc/alloca) whose size is an expression
      (contains '*', '+', '<<', or a variable) -> classic overflow-before-alloc
  +3  memcpy/memmove/memset with a non-constant length
  +3  reads a width field from the input (archive_le16/32/64dec, get_uint*, be/le)
  +2  pointer arithmetic on a buffer with a file-derived index
  +2  loop bound driven by a parsed count
  +1  each additional risky line in the function body

Usage:
  python3 pipeline/rank_targets.py libarchive/archive_read_support_format_7zip.c
  python3 pipeline/rank_targets.py 7zip            # shorthand for the path
Outputs a ranked table and a JSON list of the top function names (feed to the loop).
"""
import os, re, sys, json, subprocess

ALLOC_RE   = re.compile(r"\b(malloc|calloc|realloc|alloca)\s*\(([^;]*)")
MEMOP_RE   = re.compile(r"\b(memcpy|memmove|memset)\s*\(([^;]*)")
WIDTH_RE   = re.compile(r"\b(archive_le\d+dec|archive_be\d+dec|get_uint\d+|le\d+|be\d+|read_u?int\d+)\b")
MULTI_RE   = re.compile(r"[*+]|<<")
NAME_BEFORE_PAREN = re.compile(r"([A-Za-z_]\w*)\s*\(")
KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "do", "else"}

def resolve(arg):
    if os.path.exists(arg):
        return arg
    p = "libarchive/archive_read_support_format_%s.c" % arg
    if os.path.exists(p):
        return p
    sys.exit("source not found: %s" % arg)

def split_functions(src):
    """Light brace-matching splitter: returns [(name, start_line, body_lines)].
    Handles libarchive style where the signature line (name + args) sits on its
    own line, followed by a line starting with '{'."""
    lines = src.split("\n")
    funcs = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        nextline = lines[i + 1].lstrip() if i + 1 < len(lines) else ""
        if (stripped.endswith(")") and "(" in stripped and ";" not in stripped
                and nextline.startswith("{")):
            m = NAME_BEFORE_PAREN.search(stripped)
            if m and m.group(1) not in KEYWORDS:
                name = m.group(1)
                depth = 0; body = []; j = i + 1; started = False
                while j < len(lines):
                    body.append(lines[j])
                    depth += lines[j].count("{") - lines[j].count("}")
                    started = started or "{" in lines[j]
                    if started and depth <= 0:
                        break
                    j += 1
                funcs.append((name, i + 1, body))
                i = j + 1
                continue
        i += 1
    return funcs

def score_function(body):
    score, reasons = 0, []
    text = "\n".join(body)
    for m in ALLOC_RE.finditer(text):
        args = m.group(2)
        if MULTI_RE.search(args) or re.search(r"[A-Za-z_]\w*", args.replace("sizeof", "")):
            score += 4; reasons.append("alloc(expr:%s)" % m.group(1))
    for m in MEMOP_RE.finditer(text):
        # crude: non-constant 3rd arg
        parts = m.group(2).split(",")
        if len(parts) >= 3 and not parts[-1].strip().rstrip(")").isdigit():
            score += 3; reasons.append(m.group(1) + "(var-len)")
    w = len(WIDTH_RE.findall(text))
    if w:
        score += min(3, w); reasons.append("width-reads:%d" % w)
    if re.search(r"\bfor\s*\([^;]*;[^;]*\b(count|num|n|entries|size)\b", text):
        score += 2; reasons.append("count-driven-loop")
    if re.search(r"\[\s*[A-Za-z_]\w*\s*\]", text) and w:
        score += 2; reasons.append("file-driven-index")
    return score, reasons

def churn_bonus(path, name, since="18 months ago"):
    """+bonus if this function's code changed recently (git -S pickaxe).
    Recently-churned parser code is where regressions cluster."""
    try:
        r = subprocess.run(["git", "log", "-S", name, "--since=" + since,
                            "--oneline", "--", path],
                           capture_output=True, text=True, timeout=30)
        n = len([l for l in r.stdout.splitlines() if l.strip()])
        return min(3, n), n
    except Exception:
        return 0, 0

def main():
    if len(sys.argv) < 2:
        sys.exit("usage: python3 pipeline/rank_targets.py <source.c | format>  [--churn]")
    use_churn = "--churn" in sys.argv[1:] or os.environ.get("CHURN") == "1"
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    path = resolve(args[0])
    src = open(path).read()
    ranked = []
    for name, ln, body in split_functions(src):
        s, reasons = score_function(body)
        if s > 0:
            if use_churn:
                b, n = churn_bonus(path, name)
                if b:
                    s += b; reasons.append("churn:%d" % n)
            ranked.append((s, name, ln, len(body), reasons))
    ranked.sort(reverse=True)
    print("rank  score  function (line, loc)                 signals")
    print("-" * 78)
    for i, (s, name, ln, loc, reasons) in enumerate(ranked[:25], 1):
        print("%-5d %-6d %-36s %s" % (i, s, "%s (L%d, %d loc)" % (name, ln, loc), ", ".join(reasons[:4])))
    top = [name for _s, name, _l, _loc, _r in ranked[:12]]
    print("\nTOP_TARGETS_JSON=" + json.dumps(top))

if __name__ == "__main__":
    main()
