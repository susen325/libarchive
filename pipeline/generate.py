import os, re, time
from google import genai

MODEL = "gemini-3.8-flash"
client = None
def _get_client():
    global client
    if client is None:
        client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    return client

import concurrent.futures as _cf
_EXEC = _cf.ThreadPoolExecutor(max_workers=4)
def _gen(model, contents):
    """Gemini call with a hard timeout. On timeout we abandon the background
    thread and return control immediately. NOTE: do not wrap _EXEC in a `with`
    block -- its __exit__ calls shutdown(wait=True), which would block on the
    hung call and defeat the timeout. A leaked thread ends when the socket
    finally errors; the loop keeps going meanwhile."""
    t = int(os.environ.get("GEMINI_TIMEOUT_S", "60"))
    c = _get_client()
    fut = _EXEC.submit(lambda: c.models.generate_content(model=model, contents=contents))
    return fut.result(timeout=t)

SKELETON = """#include <archive.h>
#include <archive_entry.h>
#include <stdint.h>
#include <stddef.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct archive *a = archive_read_new();
    if (a == NULL) return 0;
    archive_read_support_format_FORMAT(a);
    archive_read_support_filter_all(a);
    if (archive_read_open_memory(a, data, size) == ARCHIVE_OK) {
        struct archive_entry *e;
        int n = 0;
        while (n++ < 4096 && archive_read_next_header(a, &e) == ARCHIVE_OK) {
            /* touch metadata accessors (cheap, exercises header parsing) */
            archive_entry_pathname(e);
            archive_entry_size(e);
            archive_entry_filetype(e);
            archive_entry_symlink(e);
            archive_entry_mode(e);
            archive_entry_mtime(e);
            /* decompress the entry body: this is what reaches the codec /
               decompressor code (read_Folder, extract_pack_stream, inflate,
               lzma, bzip2, ppmd, ...) where the deep bugs live */
            const void *buf; size_t len; int64_t off;
            while (archive_read_data_block(a, &buf, &len, &off) == ARCHIVE_OK) { }
        }
    }
    archive_read_free(a);
    return 0;
}"""

def build_prompt(format_name, target_func, source_context):
    return f"""You are helping with automated software testing (QA) of the
open-source C library libarchive. The goal is to improve test coverage of
the {format_name} reader by writing a small libFuzzer test driver that
exercises the function `{target_func}` through the public API.

Here is a known-good driver skeleton for this library. Note it already reads
entry bodies with archive_read_data_block, which is required to reach the
decompressor/codec code - keep that behavior:

{SKELETON.replace("FORMAT", format_name)}

Here is source context around the target function `{target_func}`:
--- BEGIN SOURCE ---
{source_context}
--- END SOURCE ---

Write a single complete C test driver, based on the skeleton, that is most
likely to make the library execute `{target_func}`. Keep reading entry data
with archive_read_data_block. You may add the right archive_entry_* accessor
calls (pathname, symlink, xattr, acl, etc.), set archive_read_set_options, or
add archive_read_support_* calls if that helps reach the target. Keep the exact
entry point signature `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`.
Respond with ONLY the C code, no explanation, no markdown fences."""

def strip_code(text):
    # remove ```c ... ``` fences if present
    m = re.search(r"```(?:c|cpp)?\s*(.*?)```", text, re.DOTALL)
    code = m.group(1) if m else text
    return code.strip()

def generate_harness(format_name, target_func, source_context):
    prompt = build_prompt(format_name, target_func, source_context)
    r = None
    waits = [5, 15, 30]
    for attempt in range(len(waits)):
        try:
            r = _gen(MODEL, prompt)
            break
        except Exception as e:
            msg = str(e) or type(e).__name__
            if "503" in msg or "UNAVAILABLE" in msg or "429" in msg or "RESOURCE_EXHAUSTED" in msg:
                wait = waits[attempt]
                print(f"  transient error, retry in {wait}s ({attempt+1}/{len(waits)})")
                time.sleep(wait)
                continue
            print("  API error:", msg[:200])
            return None
    if r is None:
        print("  gave up after retries")
        return None
    # robust text extraction across client versions
    text = None
    try:
        text = r.text
    except Exception:
        text = None
    if not text:
        try:
            for c in (r.candidates or []):
                cont = getattr(c, "content", None)
                for part in (getattr(cont, "parts", None) or []):
                    t = getattr(part, "text", None)
                    if t:
                        text = (text or "") + t
        except Exception as e:
            print("  parse error:", str(e)[:150])
    if not text:
        fr = "?"
        try:
            fr = r.candidates[0].finish_reason
        except Exception:
            pass
        print("  no text, finish_reason:", fr)
        print("  raw repr:", repr(r)[:400])
        return None
    return strip_code(text)

if __name__ == "__main__":
    import sys
    fmt, func, srcfile = sys.argv[1], sys.argv[2], sys.argv[3]
    src = open(srcfile).read()
    # grab ~60 lines around the function definition as context
    lines = src.split("\n")
    idx = next((i for i,l in enumerate(lines) if func in l and "(" in l), 0)
    context = "\n".join(lines[max(0,idx-5):idx+55])
    harness = generate_harness(fmt, func, context)
    if harness:
        print(harness)
    else:
        print("GENERATION FAILED")
