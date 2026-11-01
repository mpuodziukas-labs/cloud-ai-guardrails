"""Shared test helpers. Paths resolve from this file, so a copy of the repo tests itself."""
import copy
import datetime
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import guardrails  # noqa: E402

CASES = os.path.join(ROOT, "cases")
TODAY = datetime.date(2026, 11, 1)

AZ = "azurerm_cognitive_account.main"
PE = "azurerm_private_endpoint.openai"
DIAG = "azurerm_monitor_diagnostic_setting.openai"
KMS = "aws_kms_key.ai"
EP = "aws_vpc_endpoint.bedrock_runtime"
LOGC = "aws_bedrock_model_invocation_logging_configuration.main"
TRAIL = "aws_cloudtrail.main"
POL = "aws_iam_policy.invoke"
ACCT_ID = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-synthetic/"
           "providers/Microsoft.CognitiveServices/accounts/")


def load(case: str) -> Dict[str, Any]:
    with open(os.path.join(CASES, case, "plan.json"), encoding="utf-8") as fh:
        return json.load(fh)


def aws() -> Dict[str, Any]:
    return copy.deepcopy(load("aws_all_good"))


def azure() -> Dict[str, Any]:
    return copy.deepcopy(load("azure_all_good"))


def resource(plan: Dict[str, Any], address: str) -> Dict[str, Any]:
    for r in plan["planned_values"]["root_module"]["resources"]:
        if r["address"] == address:
            return r
    raise KeyError(address)


def values(plan: Dict[str, Any], address: str) -> Dict[str, Any]:
    return resource(plan, address)["values"]


def drop(plan: Dict[str, Any], address: str) -> None:
    res = plan["planned_values"]["root_module"]["resources"]
    res[:] = [r for r in res if r["address"] != address]


def mark_unknown(plan: Dict[str, Any], address: str, attr: str, node: Any = True) -> None:
    plan.setdefault("resource_changes", []).append(
        {"address": address, "change": {"actions": ["create"], "after_unknown": {attr: node}}})


def set_policy(plan: Dict[str, Any], statements: Any) -> None:
    values(plan, POL)["policy"] = json.dumps({"Version": "2012-10-17", "Statement": statements})


def check(plan: Any, waivers: Any = None, today: datetime.date = TODAY) -> List[guardrails.Finding]:
    findings, _ = guardrails.evaluate(plan)
    if waivers is not None:
        findings = guardrails.apply_waivers(findings, waivers, today)
    return guardrails.sort_findings(findings)


def keys(findings: List[guardrails.Finding]) -> List[Tuple[str, str, str]]:
    return [(f.rule, f.resource, f.status) for f in findings]


def reason(findings: List[guardrails.Finding], rule: str, res: Optional[str] = None) -> str:
    for f in findings:
        if f.rule == rule and (res is None or f.resource == res):
            return f.reason
    raise AssertionError("no %s finding for %s in %r" % (rule, res, keys(findings)))


def only(findings: List[guardrails.Finding], rule: str, res: str) -> None:
    assert keys(findings) == [(rule, res, "FAIL")], keys(findings)


def write(tmp_path: Any, name: str, obj: Any) -> str:
    path = os.path.join(str(tmp_path), name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(obj if isinstance(obj, str) else json.dumps(obj))
    return path


def cli(*args: str) -> Tuple[int, str, str]:
    p = subprocess.run([sys.executable, os.path.join(ROOT, "guardrails.py")] + list(args),
                       cwd=ROOT, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr
