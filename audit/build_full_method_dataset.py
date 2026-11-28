"""Build a leak-free, full-method contrastive dataset on Colab/Linux.

Combines:
1. Real Semgrep findings (`p/default`, `p/java`, `p/security-audit`, `p/owasp-top-ten`)
   on pre-fix (`sha^`) non-test Java files + their patched post-fix (`sha`) counterparts.
2. Enclosing methods touched by real security fixes whose sink matches `RULE_PATTERNS`
   in `sink_finder.py` (pre-fix = TP, post-fix = FP), using full enclosing methods
   (`imports + class_decl + body`) instead of short diff hunks.
"""
import argparse
import json
import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import javalang

try:
    from sink_finder import RULE_PATTERNS
except ImportError:
    from d1_triage.sink_finder import RULE_PATTERNS

MODIFIERS = "public|private|protected|static|final|synchronized|abstract|native|strictfp|default"
SIG_RE = re.compile(
    r"^[ \t]*(?:(?:" + MODIFIERS + r")\s+)*[\w.$<>\[\],? ]+?\s+(\w+)\s*"
    r"\([^;{}]*\)\s*(?:throws [\w., ]+)?\s*\{",
    re.MULTILINE,
)
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
TEST_SOURCE = ("/src/test/", "/src/testFixtures/", "/src/it/", "/test/java/")

CWE_TO_RULE = {
    "CWE-22": ("java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal", "path-traversal"),
    "CWE-74": ("java.lang.security.audit.el-injection.el-injection", "el-injection"),
    "CWE-77": ("java.lang.security.audit.script-engine-injection.script-engine-injection", "script-engine-injection"),
    "CWE-78": ("java.lang.security.audit.script-engine-injection.script-engine-injection", "script-engine-injection"),
    "CWE-89": ("java.lang.security.audit.formatted-sql-string.formatted-sql-string", "formatted-sql-string"),
    "CWE-94": ("java.lang.security.audit.script-engine-injection.script-engine-injection", "script-engine-injection"),
    "CWE-502": ("java.lang.security.audit.object-deserialization.object-deserialization", "object-deserialization"),
    "CWE-611": ("java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing", "documentbuilderfactory"),
    "CWE-1336": ("java.lang.security.audit.el-injection.el-injection", "el-injection"),
}


def is_test_path(path: str) -> bool:
    p = "/" + path.replace("\\", "/")
    if any(part in p for part in TEST_SOURCE):
        return True
    parts = Path(path).parts[:-1]
    if any(x in ("test", "tests", "it") or x.endswith(("-test", "-tests")) for x in parts):
        return True
    return Path(path).name.lower().endswith("test.java")


def line_offsets(src: str):
    offs = [0]
    for line in src.splitlines(keepends=True):
        offs.append(offs[-1] + len(line))
    return offs


def scan_to(src: str, pos: int, target: str) -> int:
    i, n = pos, len(src)
    while i < n:
        c = src[i]
        if c == '"':
            i += 1
            while i < n and src[i] != '"':
                i += 2 if src[i] == "\\" else 1
            i += 1
        elif c == "'":
            i += 1
            while i < n and src[i] != "'":
                i += 2 if src[i] == "\\" else 1
            i += 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif c == target:
            return i
        else:
            i += 1
    return -1


def match_brace(src: str, open_idx: int) -> int:
    depth, i, n = 0, open_idx, len(src)
    while i < n:
        c = src[i]
        if c == '"':
            i += 1
            while i < n and src[i] != '"':
                i += 2 if src[i] == "\\" else 1
            i += 1
        elif c == "'":
            i += 1
            while i < n and src[i] != "'":
                i += 2 if src[i] == "\\" else 1
            i += 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif c == "{":
            depth += 1
            i += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
            i += 1
        else:
            i += 1
    return -1


def method_ranges(src: str):
    out = []
    try:
        tree = javalang.parse.parse(src)
        for _, node in tree.filter(javalang.tree.MethodDeclaration):
            if node.position:
                out.append((node.name, node.position.line, node.position.column))
    except Exception:
        out = []
    if not out:
        for m in SIG_RE.finditer(src):
            out.append((m.group(1), src.count("\n", 0, m.start()) + 1, 1))
    offs = line_offsets(src)
    ranges = []
    for name, line, col in out:
        if line - 1 >= len(offs):
            continue
        start = offs[line - 1] + max(0, col - 1)
        brace = scan_to(src, start, "{")
        if brace < 0:
            continue
        end = match_brace(src, brace)
        if end < 0:
            continue
        ranges.append((name, line, src.count("\n", 0, end) + 1))
    return ranges


def enclosing_method(ranges, line: int):
    hits = [r for r in ranges if r[1] <= line <= r[2]]
    return min(hits, key=lambda r: r[2] - r[1]) if hits else None


def class_decl(src: str) -> str:
    m = re.search(r"^[ \t]*(?:public\s+)?(?:final\s+|abstract\s+)?class\s+\w+[^{]*\{", src, re.MULTILINE)
    return m.group(0).strip() if m else ""


def format_method_window(src: str, start_line: int, end_line: int) -> str:
    lines = src.splitlines()
    body = "\n".join(lines[start_line - 1:end_line])
    imports = "\n".join(l for l in lines if l.strip().startswith(("package ", "import ")))
    return "\n\n".join(x for x in (imports, class_decl(src), body) if x)


def find_method_by_name(src: str, name: str, approx_line: int):
    ranges = [r for r in method_ranges(src) if r[0] == name]
    if not ranges:
        return None
    hit = min(ranges, key=lambda r: abs(r[1] - approx_line))
    _, start_line, end_line = hit
    return format_method_window(src, start_line, end_line), start_line


def git(cwd: Path, *args, timeout=60):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout)


def diff_hunks(repo: Path, sha: str, paths):
    res = git(repo, "-c", "core.quotepath=false", "diff", "--unified=0", f"{sha}^", sha, "--", *paths)
    if res.returncode != 0:
        return {}
    old_touched = {}
    current = None
    for line in res.stdout.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
            if current.endswith(".java"):
                old_touched.setdefault(current, set())
            else:
                current = None
        elif current and line.startswith("@@"):
            m = HUNK_RE.match(line)
            if not m:
                continue
            s_old, c_old = int(m.group(1)), int(m.group(2) or 1)
            old_lines = {s_old, s_old + 1} if c_old == 0 else set(range(s_old, s_old + c_old))
            for n in old_lines:
                old_touched[current].update(range(n - 2, n + 3))
    return old_touched


def rule_cwes(meta: dict):
    raw = meta.get("cwe") or []
    if isinstance(raw, str):
        raw = [raw]
    out = []
    for item in raw:
        m = re.search(r"CWE-(\d+)", item)
        if m:
            out.append(f"CWE-{m.group(1)}")
    return sorted(set(out))


def checkout_one(entry, pre_root: Path, post_root: Path):
    vid = entry["vul_id"]
    sha = entry["patch_commit"]
    tmp = Path("/tmp/git_tmp") / vid
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True, exist_ok=True)
    try:
        git(tmp, "init", "-q")
        git(tmp, "remote", "add", "origin", f"https://github.com/{entry['repo']}.git")
        if git(tmp, "fetch", "-q", "--depth", "2", "--filter=blob:none", "origin", sha, timeout=45).returncode != 0:
            return None, "fetch_fail"
        res = git(tmp, "-c", "core.quotepath=false", "diff", "--name-only", f"{sha}^", sha, "--", "*.java", timeout=20)
        if res.returncode != 0:
            return None, "diff_fail"
        java_files = [p for p in res.stdout.splitlines() if p.strip() and not is_test_path(p.strip())]
        if not java_files or len(java_files) > 12:
            return None, "no_or_wide_java"

        ls = git(tmp, "-c", "core.quotepath=false", "ls-tree", "-r", "--name-only", "-z", f"{sha}^", "--", *java_files)
        existing_pre = [p for p in java_files if p in set(ls.stdout.split("\0"))]
        if not existing_pre:
            return None, "no_pre"
        if git(tmp, "checkout", "-q", f"{sha}^", "--", *existing_pre, timeout=45).returncode != 0:
            return None, "checkout_pre_fail"

        old_touched = diff_hunks(tmp, sha, existing_pre)
        for p in existing_pre:
            src_f = tmp / p
            if src_f.exists():
                dst = pre_root / vid / p
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_f, dst)

        if git(tmp, "checkout", "-q", sha, "--", *existing_pre, timeout=45).returncode == 0:
            for p in existing_pre:
                src_f = tmp / p
                if src_f.exists():
                    dst = post_root / vid / p
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_f, dst)

        return {"entry": entry, "old_touched": old_touched}, "ok"
    except Exception as e:
        return None, f"exc:{type(e).__name__}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def match_pattern_in_body(body_lines, cwe_id: str):
    """Find a rule+line in a touched method body using RULE_PATTERNS."""
    candidates = []
    if cwe_id in CWE_TO_RULE:
        rule_id, pat_key = CWE_TO_RULE[cwe_id]
        candidates.append((rule_id, RULE_PATTERNS.get(pat_key, [])))
    for pat_key, pats in RULE_PATTERNS.items():
        if pat_key not in ("unrestricted-request-mapping",):
            candidates.append((f"java.lang.security.audit.{pat_key}.{pat_key}", pats))
    for rule_id, pats in candidates:
        for pat in pats:
            for idx, line in enumerate(body_lines):
                if re.search(pat, line, re.IGNORECASE):
                    return rule_id, idx
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default="heldout_pool.jsonl")
    ap.add_argument("--out", default="full_method_train.jsonl")
    ap.add_argument("--limit", type=int, default=600)
    ap.add_argument("--workers", type=int, default=12)
    args, _ = ap.parse_known_args()

    pool = [json.loads(l) for l in open(args.pool, encoding="utf-8") if l.strip()][:args.limit]
    pre_root = Path("/tmp/harvest_pre")
    post_root = Path("/tmp/harvest_post")
    shutil.rmtree(pre_root, ignore_errors=True)
    shutil.rmtree(post_root, ignore_errors=True)
    pre_root.mkdir(parents=True, exist_ok=True)
    post_root.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    meta_by_vid = {}
    stats = {}
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for i, (res, status) in enumerate(ex.map(lambda e: checkout_one(e, pre_root, post_root), pool), 1):
            stats[status] = stats.get(status, 0) + 1
            if res is not None:
                meta_by_vid[res["entry"]["vul_id"]] = res
            if i % 100 == 0 or i == len(pool):
                print(f"  Checkout [{i}/{len(pool)}] {stats} ({time.time()-t0:.0f}s)", flush=True)

    scan_out = Path("/tmp/batch_semgrep_pre.json")
    print(f"Running batch Semgrep over {len(meta_by_vid)} repos...", flush=True)
    t1 = time.time()
    cmd = [
        "semgrep", "--config", "p/default", "--config", "p/java",
        "--config", "p/security-audit", "--config", "p/owasp-top-ten",
        "--json", "--quiet", "--jobs", "2", "--timeout", "15",
        "--max-target-bytes", "1000000", "--metrics", "off",
        "-o", str(scan_out), str(pre_root),
    ]
    sr = subprocess.run(cmd, capture_output=True, text=True, timeout=400)
    print(f"Semgrep done in {time.time()-t1:.0f}s (rc={sr.returncode})", flush=True)

    results = json.loads(scan_out.read_text(encoding="utf-8")).get("results", []) if scan_out.exists() else []
    print(f"Raw Semgrep findings: {len(results)}", flush=True)

    rows = []
    seen_keys = set()

    for f in results:
        p = Path(f["path"]).resolve()
        try:
            rel_full = p.relative_to(pre_root.resolve()).as_posix()
        except ValueError:
            continue
        vid, _, rel = rel_full.partition("/")
        info = meta_by_vid.get(vid)
        if not info or not rel:
            continue
        entry = info["entry"]
        pre_src = p.read_text(encoding="utf-8", errors="replace")
        line = f["start"]["line"]
        ranges = method_ranges(pre_src)
        mr = enclosing_method(ranges, line)
        if not mr:
            continue
        method_name, start_line, end_line = mr
        window = format_method_window(pre_src, start_line, end_line)
        if len(window) > 7000 or len(window.splitlines()) < 5:
            continue

        touched = info["old_touched"].get(rel, set())
        hit = line in touched or (bool(touched) and any(start_line <= n <= end_line for n in touched))

        extra = f.get("extra", {})
        cwes = rule_cwes(extra.get("metadata", {}))
        cwe = cwes[0] if cwes else entry["cwe_id"]
        rule = f["check_id"]
        msg = extra.get("message", "")
        sev = extra.get("severity", "WARNING")

        k_pre = (vid, rel, method_name, "TP" if hit else "FP")
        if k_pre not in seen_keys:
            seen_keys.add(k_pre)
            rows.append({
                "id": f"{vid}:sg:{rule}:{rel}:{line}",
                "vul_id": vid,
                "label": "TP" if hit else "FP",
                "rule": rule,
                "cwe": cwe,
                "severity": sev,
                "file": rel,
                "line": line,
                "method": method_name,
                "message": msg,
                "code_window": window,
                "source": "semgrep_pre",
            })

        post_file = post_root / vid / rel
        if hit and post_file.exists():
            k_post = (vid, rel, method_name, "FP_post")
            if k_post not in seen_keys:
                seen_keys.add(k_post)
                post_src = post_file.read_text(encoding="utf-8", errors="replace")
                post_got = find_method_by_name(post_src, method_name, line)
                if post_got:
                    post_window, post_line = post_got
                    if post_window != window and len(post_window) <= 7000:
                        rows.append({
                            "id": f"{vid}:sg_post:{rule}:{rel}:{post_line}",
                            "vul_id": vid,
                            "label": "FP",
                            "rule": rule,
                            "cwe": cwe,
                            "severity": sev,
                            "file": rel,
                            "line": line,
                            "method": method_name,
                            "message": msg,
                            "code_window": post_window,
                            "source": "semgrep_post",
                        })

    added_pairs = 0
    for vid, info in meta_by_vid.items():
        entry = info["entry"]
        cwe = entry["cwe_id"]
        msg = entry.get("summary", "")
        for rel, touched in info["old_touched"].items():
            if not touched:
                continue
            pre_file = pre_root / vid / rel
            post_file = post_root / vid / rel
            if not pre_file.exists() or not post_file.exists():
                continue
            pre_src = pre_file.read_text(encoding="utf-8", errors="replace")
            post_src = post_file.read_text(encoding="utf-8", errors="replace")
            src_lines = pre_src.splitlines()
            for method_name, start_line, end_line in method_ranges(pre_src):
                if not any(start_line <= n <= end_line for n in touched):
                    continue
                if (vid, rel, method_name, "TP") in seen_keys:
                    continue
                body_lines = src_lines[start_line - 1:end_line]
                if len(body_lines) < 4 or len(body_lines) > 120:
                    continue
                matched = match_pattern_in_body(body_lines, cwe)
                if not matched:
                    continue
                rule_id, rel_idx = matched
                pre_window = format_method_window(pre_src, start_line, end_line)
                post_got = find_method_by_name(post_src, method_name, start_line)
                if not post_got:
                    continue
                post_window, _ = post_got
                if pre_window == post_window or len(pre_window) > 7000 or len(post_window) > 7000:
                    continue
                seen_keys.add((vid, rel, method_name, "TP"))
                seen_keys.add((vid, rel, method_name, "FP_post"))
                line_no = start_line + rel_idx
                rows.append({
                    "id": f"{vid}:meth_pre:{rel}:{line_no}",
                    "vul_id": vid,
                    "label": "TP",
                    "rule": rule_id,
                    "cwe": cwe,
                    "severity": "ERROR",
                    "file": rel,
                    "line": line_no,
                    "method": method_name,
                    "message": msg,
                    "code_window": pre_window,
                    "source": "method_pre",
                })
                rows.append({
                    "id": f"{vid}:meth_post:{rel}:{line_no}",
                    "vul_id": vid,
                    "label": "FP",
                    "rule": rule_id,
                    "cwe": cwe,
                    "severity": "ERROR",
                    "file": rel,
                    "line": line_no,
                    "method": method_name,
                    "message": msg,
                    "code_window": post_window,
                    "source": "method_post",
                })
                added_pairs += 1

    with open(args.out, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    tp = sum(r["label"] == "TP" for r in rows)
    print(f"Wrote {len(rows)} rows (TP={tp}, FP={len(rows)-tp}, method_pairs={added_pairs}) to {args.out}", flush=True)


if __name__ == "__main__":
    main()
