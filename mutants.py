#!/usr/bin/env python3
"""Mutation check: break guardrails.py in one spot at a time, run the test suite, require a failure.

Each mutant is a hand-written (old, new) replacement. The repo is copied to .mutants/, the
replacement is applied to the copy (it must match exactly once), and pytest runs there.
A mutant is killed when pytest exits non-zero. A baseline run of the unmutated copy must pass first.
Last line: `mutants: K/K killed`. Exit 0 only if every mutant is killed.
"""
import os
import shutil
import subprocess
import sys
from typing import List, Tuple

ROOT = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(ROOT, ".mutants")

# (name, exact text in guardrails.py, replacement)
MUTANTS = [
    ("bool check never compares", "if val is not want:", "if False:"),
    ("bedrock:* no longer flagged", 'if low == "bedrock:*" or low == "*":', 'if low == "*":'),
    ("wildcard actions not matched", "elif fnmatch.fnmatchcase(INVOKE_ACTION, low) and",
     "elif low == INVOKE_ACTION and"),
    ("waiver valid on expiry day fails", "if expires < today:", "if expires <= today:"),
    ("exit code always 0", "return 1 if failing else 0", "return 0"),
    ("scope and waiver findings waivable", 'NOT_WAIVABLE = ("GR000", "GR900")', "NOT_WAIVABLE = ()"),
    ("unknown values ignored", "if isinstance(res.unknown, dict) and is_unknown(res.unknown.get(name)):",
     "if False:"),
    ("kind match is case sensitive", 'elif kind.lower() == "openai":', 'elif kind == "OpenAI":'),
    ("gateway endpoint accepted", 'None if (state == "ok" and typ == "Interface") else',
     'None if state == "ok" else'),
    ("hex key check disabled", "if HEX32.match(value):", "if False:"),
    ("trail with logging off counts", 'trail_ok = any(bool_is(t, "enable_logging", True) is None for t in trails)',
     "trail_ok = bool(trails)"),
    ("kms rotation not checked", 'run.check("GR004", key.address, bool_is(key, "enable_key_rotation", True))',
     'run.check("GR004", key.address, None)'),
    ("waived status never set", 'status="WAIVED"', 'status="FAIL"'),
    ("NotAction not recognised", 'if "NotAction" in st or "NotResource" in st:', "if False:"),
    ("Deny statements flagged", 'if effect == "Deny":', "if False:"),
    ("blank tag counts as present", "not nonblank(val.get(k))", "k not in val"),
    ("policy text alone gives no AWS scope", 'if state == "ok" and isinstance(raw, str) and "bedrock" in raw.lower():',
     "if False:"),
    ("diagnostic needs destination or log", "if has_dest and has_log:", "if has_dest or has_log:"),
    ("duplicate JSON keys accepted", 'raise ValueError("duplicate key " + key)', "pass"),
    ("sarif drops suppressions", 'if f.status == "WAIVED":', "if False:"),
]  # type: List[Tuple[str, str, str]]


def copy_repo(dest: str) -> None:
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns(".mutants", ".git", "__pycache__", ".pytest_cache"))


def run_tests(cwd: str) -> int:
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try:
        p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider"],
                           cwd=cwd, env=env, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return 124
    return p.returncode


def main() -> int:
    total = len(MUTANTS)
    base = os.path.join(WORK, "baseline")
    copy_repo(base)
    if run_tests(base) != 0:
        print("baseline: the unmutated copy fails its own tests; mutation results would mean nothing")
        shutil.rmtree(WORK, ignore_errors=True)
        print("mutants: 0/%d killed" % total)
        return 1
    killed = 0
    print("| # | mutant | result |")
    print("|---|---|---|")
    for i, (name, old, new) in enumerate(MUTANTS, 1):
        dest = os.path.join(WORK, "m%02d" % i)
        copy_repo(dest)
        path = os.path.join(dest, "guardrails.py")
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        if text.count(old) != 1:
            result = "SPOT NOT FOUND (%d matches)" % text.count(old)
        else:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text.replace(old, new))
            if run_tests(dest) != 0:
                killed += 1
                result = "killed"
            else:
                result = "SURVIVED"
        print("| %d | %s | %s |" % (i, name, result))
        shutil.rmtree(dest, ignore_errors=True)
    shutil.rmtree(WORK, ignore_errors=True)
    print("mutants: %d/%d killed" % (killed, total))
    return 0 if killed == total else 1


if __name__ == "__main__":
    sys.exit(main())
