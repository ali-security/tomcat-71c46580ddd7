#!/usr/bin/env python3
# Summarises Ant plain-formatter JUnit logs (output/build/logs/TEST-*.txt):
# prints every skipped test with its reason (falling back to the Assume/@Ignore
# line in the test source when the runtime message is empty or a bare hamcrest
# assumption), every failed/errored test, grouped skip reasons and a TOTAL line.
import collections
import glob
import os
import re
import sys

logdir = sys.argv[1] if len(sys.argv) > 1 else "output/build/logs"
srcroot = sys.argv[2] if len(sys.argv) > 2 else "test"

HEADER = re.compile(r"Tests run: (\d+), Failures: (\d+), Errors: (\d+), Skipped: (\d+)")
CASE = re.compile(r"^Testcase: (.+?) took ")
BARE = re.compile(r"^(|null|.*got: <(true|false)>, expected: is <(true|false)>.*)$")


def source_reason(suite, case):
    path = os.path.join(srcroot, suite.replace(".", "/") + ".java")
    if not os.path.exists(path):
        return "no source found"
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    method = re.sub(r"\[.*$", "", case)
    hits = []
    m = re.search(r"void\s+" + re.escape(method) + r"\s*\(", text)
    if m:
        pre = text[max(0, m.start() - 300):m.start()]
        ig = re.findall(r"@Ignore[^\n]*", pre)
        if ig:
            hits.append(ig[-1].strip())
        body = text[m.end():m.end() + 4000]
        end = re.search(r"\n    }\n", body)
        body = body[:end.start()] if end else body
        hits += [l.strip() for l in body.splitlines() if re.search(r"Assume\.|assume[A-Z]|@Ignore", l)]
    if not hits:
        # class-level @Ignore or assumptions in @Before/@BeforeClass/parameters
        hits = [l.strip() for l in text.splitlines()
                if re.search(r"^@Ignore|Assume\.|assume[A-Z]", l.strip())][:3]
    return " ; ".join(hits) if hits else "no reason given in source"


totals = collections.Counter()
skips, fails = [], []
for log in sorted(glob.glob(os.path.join(logdir, "TEST-*.txt"))):
    base = os.path.basename(log)[len("TEST-"):-len(".txt")]
    suite = re.sub(r"\.(NIO2?|APR)$", "", base)
    with open(log, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    totals["suites"] += 1
    hdr = next((HEADER.search(l) for l in lines if HEADER.search(l)), None)
    ncase = 0
    cur = None
    for l in lines:
        m = CASE.match(l)
        if m:
            cur = m.group(1)
            ncase += 1
            continue
        s = l.strip()
        if cur and s.startswith("SKIPPED"):
            msg = s[len("SKIPPED"):].lstrip(": ").strip()
            if BARE.match(msg):
                msg = (msg + " -- " if msg else "") + "source: " + source_reason(suite, cur)
            skips.append((base, cur, msg))
        elif cur and (s.startswith("FAILED") or s.startswith("Caused an ERROR")):
            fails.append((base, cur, s))
    if hdr:
        run, f_, e, sk = map(int, hdr.groups())
    else:
        print(f"NOTE {base}: no 'Tests run' header, counted {ncase} Testcase lines")
        run, f_, e, sk = ncase, 0, 0, sum(1 for x in skips if x[0] == base)
    totals["tests"] += run
    totals["failures"] += f_
    totals["errors"] += e
    totals["skipped"] += sk

for base, case, msg in skips:
    print(f"SKIPPED {base}#{case}: {msg}")
for base, case, s in fails:
    print(f"FAILED {base}#{case}: {s}")
groups = collections.Counter((b, m) for b, _, m in skips)
for (b, m), n in sorted(groups.items()):
    print(f"SKIP-GROUP {n} x {b} -- {m}")
passed = totals["tests"] - totals["failures"] - totals["errors"] - totals["skipped"]
print(f"TOTAL: suites={totals['suites']} tests={totals['tests']} passed={passed} "
      f"failures={totals['failures']} errors={totals['errors']} skipped={totals['skipped']}")
