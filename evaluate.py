#!/usr/bin/env python3
"""Run guardrails over every folder in cases/ and compare with expected.json.
Prints a markdown table. The last line is `cases: N/N match`. Exit 0 only when all match."""
import datetime
import json
import os
import sys
from typing import List, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "cases")
sys.path.insert(0, HERE)
import guardrails  # noqa: E402


def compact(exit_code: int, keys: List[str]) -> str:
    codes = sorted(k.split(" ")[0] + ("w" if k.endswith(" WAIVED") else "") for k in keys)
    return "exit=%d %s" % (exit_code, " ".join(codes) if codes else "-")


def run_case(name: str) -> Tuple[str, str]:
    """Return (expected_text, got_text). A crash is a got_text that cannot match."""
    folder = os.path.join(CASES, name)
    try:
        with open(os.path.join(folder, "expected.json"), encoding="utf-8") as fh:
            exp = json.load(fh)
        want_keys = sorted(exp["findings"])
        want = compact(exp["exit"], want_keys)
        today = datetime.date.fromisoformat(exp["today"])
    except (OSError, ValueError, KeyError) as exc:
        return "unreadable expected.json", "ERROR " + type(exc).__name__
    plan = os.path.join(CASES, exp.get("plan_from", name), "plan.json")
    waivers = os.path.join(folder, "waivers.json")
    try:
        try:
            findings, _ = guardrails.check_files(plan, waivers if os.path.isfile(waivers) else None, today)
            got_keys = sorted("%s %s %s" % (f.rule, f.resource, f.status) for f in findings)
            code = 1 if any(f.status == "FAIL" for f in findings) else 0
        except guardrails.BadInput:
            got_keys, code = [], 2
        got = compact(code, got_keys)
        if got == want and got_keys != want_keys:
            got += " (resources differ)"
    except Exception as exc:  # a crash is a mismatch, never a pass
        return want, "ERROR " + type(exc).__name__
    return want, got


def main() -> int:
    names = sorted(n for n in os.listdir(CASES) if os.path.isdir(os.path.join(CASES, n)))
    rows, matched = [], 0
    print("| case | expected | got | match |")
    print("|---|---|---|---|")
    for n in names:
        want, got = run_case(n)
        ok = want == got
        matched += ok
        rows.append({"case": n, "expected": want, "got": got, "match": ok})
        print("| %s | %s | %s | %s |" % (n, want, got, "yes" if ok else "NO"))
    with open(os.path.join(HERE, "PROOF.json"), "w", encoding="utf-8") as fh:
        json.dump({"matched": matched, "total": len(names), "cases": rows}, fh, indent=2)
        fh.write("\n")
    print()
    print("cases: %d/%d match" % (matched, len(names)))
    return 0 if names and matched == len(names) else 1


if __name__ == "__main__":
    sys.exit(main())
