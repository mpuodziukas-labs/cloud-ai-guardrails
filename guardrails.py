#!/usr/bin/env python3
"""cloud-ai-guardrails: offline checker for Terraform plan JSON (`terraform show -json`)
covering AI workloads on AWS (Bedrock) and Azure (Azure OpenAI).

Usage: python3 guardrails.py <plan.json> [--waivers w.json] [--sarif out.sarif] [--today YYYY-MM-DD]
Exit codes: 0 no unwaived findings, 1 findings, 2 bad input.

Fail closed: an unreadable plan is exit 2, never a pass. An unknown or missing value on a checked
attribute is a finding with a reason. A waiver without owner, reason and a live expiry is a finding.
Standard library only. No network. The only clock read is the default for --today.
"""
import argparse
import datetime
import fnmatch
import json
import re
import sys
from typing import Any, Dict, Iterator, List, NamedTuple, Optional, Sequence, Tuple

VERSION = "1.0.0"
REQUIRED_TAGS = ("data_classification", "owner")
PLAN_AWS = "plan:aws-bedrock"
INVOKE_ACTION = "bedrock:invokemodel"

RULES = {
    "GR000": {
        "name": "SCOPE_UNDETERMINED", "severity": "high",
        "rationale": "A check that cannot tell what it is looking at would pass by default.",
        "remediation": "Set kind or service_name to a literal value, or include a resource this checker covers.",
        "nist_800_53": ["CM-6"], "ai_rmf": ["GOVERN 1.4"], "owasp_llm": [],
    },
    "GR001": {
        "name": "PRIVATE_ENDPOINT", "severity": "high",
        "rationale": "Model traffic that stays on the cloud private network is not reachable from the public internet.",
        "remediation": "Add an azurerm_private_endpoint connected to the OpenAI account, or an Interface aws_vpc_endpoint for the bedrock-runtime service.",
        "nist_800_53": ["SC-7"], "ai_rmf": ["MEASURE 2.7"], "owasp_llm": ["LLM02"],
    },
    "GR002": {
        "name": "PUBLIC_ACCESS_DISABLED", "severity": "critical",
        "rationale": "A public endpoint on a model account lets anyone with a key, or a leaked key, call the model from anywhere.",
        "remediation": "Set public_network_access_enabled = false on the azurerm_cognitive_account.",
        "nist_800_53": ["SC-7", "CM-6"], "ai_rmf": ["MEASURE 2.7"], "owasp_llm": ["LLM02"],
    },
    "GR003": {
        "name": "LOCAL_AUTH_DISABLED", "severity": "high",
        "rationale": "Static API keys skip identity controls and cannot be scoped or traced to a person.",
        "remediation": "Set local_auth_enabled = false and use Entra ID role assignments.",
        "nist_800_53": ["IA-5", "AC-6"], "ai_rmf": ["MEASURE 2.7"], "owasp_llm": ["LLM02"],
    },
    "GR004": {
        "name": "CMK_ENCRYPTION", "severity": "high",
        "rationale": "A customer-managed key lets the owner rotate, disable and audit the key that protects model data at rest.",
        "remediation": "Add a customer_managed_key block with key_vault_key_id (Azure), or an aws_kms_key with enable_key_rotation = true (AWS).",
        "nist_800_53": ["SC-28", "SC-12"], "ai_rmf": ["MEASURE 2.10"], "owasp_llm": ["LLM02"],
    },
    "GR005": {
        "name": "INVOCATION_LOGGING", "severity": "high",
        "rationale": "Without a record of who called the model and when, misuse cannot be detected or investigated.",
        "remediation": "Add Bedrock invocation logging with a CloudWatch or S3 destination, or an aws_cloudtrail with enable_logging = true; on Azure add a diagnostic setting with a destination and an enabled log.",
        "nist_800_53": ["AU-2", "AU-12"], "ai_rmf": ["MANAGE 4.1"], "owasp_llm": [],
    },
    "GR006": {
        "name": "LEAST_PRIVILEGE_IAM", "severity": "critical",
        "rationale": "Broad Bedrock permissions let one stolen role invoke any model or change any Bedrock setting.",
        "remediation": "List the specific bedrock actions needed and the ARNs of the specific models; remove bedrock:* and Resource \"*\" on bedrock:InvokeModel.",
        "nist_800_53": ["AC-6"], "ai_rmf": ["GOVERN 1.4"], "owasp_llm": ["LLM06"],
    },
    "GR007": {
        "name": "NO_HARDCODED_KEYS", "severity": "critical",
        "rationale": "A key stored in a variable lands in plan files, state and logs.",
        "remediation": "Remove the value, rotate the key, and read it from a secret manager at run time.",
        "nist_800_53": ["IA-5", "SC-12"], "ai_rmf": ["MEASURE 2.7"], "owasp_llm": ["LLM02"],
    },
    "GR008": {
        "name": "REQUIRED_TAGS", "severity": "medium",
        "rationale": "Without a data classification and an owner, nobody can say how sensitive the data is or who answers for the resource.",
        "remediation": "Set non-empty data_classification and owner tags.",
        "nist_800_53": ["CM-6"], "ai_rmf": ["GOVERN 1.4"], "owasp_llm": [],
    },
    "GR900": {
        "name": "WAIVER_INVALID", "severity": "high",
        "rationale": "A waiver with no owner, no reason or no live expiry is a permanent silent exception.",
        "remediation": "Give every waiver a rule, resource, owner, reason and a future YYYY-MM-DD expiry, or remove it.",
        "nist_800_53": ["CM-6"], "ai_rmf": ["GOVERN 1.4"], "owasp_llm": [],
    },
}
NOT_WAIVABLE = ("GR000", "GR900")
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


class BadInput(Exception):
    """Input that cannot be checked. Maps to exit code 2, never to a pass."""


class Finding(NamedTuple):
    rule: str
    resource: str
    reason: str
    status: str = "FAIL"
    waiver: str = ""


class Res(NamedTuple):
    address: str
    type: str
    values: Dict[str, Any]
    unknown: Any


# ---------------------------------------------------------------- input

def _no_dups(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    out = {}  # type: Dict[str, Any]
    for key, val in pairs:
        if key in out:
            raise ValueError("duplicate key " + key)
        out[key] = val
    return out


def _bad_const(name: str) -> Any:
    raise ValueError("non-finite number " + name)


def parse_json(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_no_dups, parse_constant=_bad_const)


def load_json(path: str, label: str) -> Any:
    try:
        with open(path, "rb") as fh:
            text = fh.read().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise BadInput("%s unreadable: %s" % (label, type(exc).__name__))
    try:
        return parse_json(text)
    except (ValueError, RecursionError) as exc:
        raise BadInput("%s is not valid JSON: %s" % (label, exc))


def _walk(module: Any, out: List[Res], unknown: Dict[str, Any], depth: int) -> None:
    if not isinstance(module, dict) or depth > 40:
        raise BadInput("planned_values module is malformed")
    resources = module.get("resources", []) or []
    children = module.get("child_modules", []) or []
    if not isinstance(resources, list) or not isinstance(children, list):
        raise BadInput("planned_values module is malformed")
    for item in resources:
        if not isinstance(item, dict) or not isinstance(item.get("address"), str) \
                or not isinstance(item.get("type"), str):
            raise BadInput("planned_values resource needs string address and type")
        values = item.get("values", {})
        if values is None:
            values = {}
        if not isinstance(values, dict):
            raise BadInput("resource %s has non-object values" % item["address"])
        out.append(Res(item["address"], item["type"], values, unknown.get(item["address"])))
    for child in children:
        _walk(child, out, unknown, depth + 1)


def collect_resources(plan: Any) -> List[Res]:
    if not isinstance(plan, dict):
        raise BadInput("plan is not a JSON object")
    pv = plan.get("planned_values")
    if not isinstance(pv, dict) or not isinstance(pv.get("root_module"), dict):
        raise BadInput("no planned_values.root_module: not terraform show -json output")
    unknown = {}  # type: Dict[str, Any]
    changes = plan.get("resource_changes", [])
    if not isinstance(changes, list):
        raise BadInput("resource_changes is not a list")
    for ch in changes:
        if isinstance(ch, dict) and isinstance(ch.get("address"), str) and isinstance(ch.get("change"), dict):
            unknown[ch["address"]] = ch["change"].get("after_unknown")
    out = []  # type: List[Res]
    _walk(pv["root_module"], out, unknown, 0)
    return sorted(out, key=lambda r: r.address)


# ---------------------------------------------------------------- attribute access

def is_unknown(node: Any) -> bool:
    if node is True:
        return True
    if isinstance(node, dict):
        return any(is_unknown(v) for v in node.values())
    if isinstance(node, list):
        return any(is_unknown(v) for v in node)
    return False


def get(res: Res, name: str) -> Tuple[str, Any]:
    """Return (state, value). state is ok, missing or unknown. Unknown wins over a value."""
    if isinstance(res.unknown, dict) and is_unknown(res.unknown.get(name)):
        return "unknown", None
    val = res.values.get(name)
    if val is None:
        return "missing", None
    return "ok", val


def bool_is(res: Res, name: str, want: bool) -> Optional[str]:
    state, val = get(res, name)
    if state == "unknown":
        return "%s is unknown at plan time" % name
    if state == "missing":
        return "%s is missing from the plan" % name
    if not isinstance(val, bool):
        return "%s is not a boolean" % name
    if val is not want:
        return "%s is %s, expected %s" % (name, json.dumps(val), json.dumps(want))
    return None


def nonblank(val: Any) -> bool:
    return isinstance(val, str) and val.strip() != ""


def first_dicts(res: Res, name: str) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    """A nested block as a list of dicts, or (reason, [])."""
    state, val = get(res, name)
    if state == "unknown":
        return "%s is unknown at plan time" % name, []
    if state == "missing":
        return "%s is missing from the plan" % name, []
    if not isinstance(val, list) or not val or not all(isinstance(v, dict) for v in val):
        return "%s is empty or malformed" % name, []
    return None, val


def target_matches(target: Any, acct: Res) -> bool:
    if not isinstance(target, str):
        return False
    state, rid = get(acct, "id")
    if state == "ok" and isinstance(rid, str) and target.lower() == rid.lower():
        return True
    state, name = get(acct, "name")
    return state == "ok" and isinstance(name, str) and name != "" \
        and target.lower().endswith("/accounts/" + name.lower())


# ---------------------------------------------------------------- the checker

class Run:
    def __init__(self) -> None:
        self.findings = []  # type: List[Finding]
        self.checks = 0

    def check(self, rule: str, resource: str, reason: Optional[str]) -> None:
        self.checks += 1
        if reason:
            self.findings.append(Finding(rule, resource, reason))


def _policy_reasons(res: Res) -> List[str]:
    state, raw = get(res, "policy")
    if state == "unknown":
        return ["policy is unknown at plan time"]
    if state == "missing":
        return ["policy is missing from the plan"]
    if not isinstance(raw, str):
        return ["policy is not a JSON string"]
    try:
        doc = parse_json(raw)
    except (ValueError, RecursionError):
        return ["policy is not valid JSON"]
    if not isinstance(doc, dict) or "Statement" not in doc:
        return ["policy has no Statement"]
    statements = doc["Statement"]
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements or not all(isinstance(s, dict) for s in statements):
        return ["policy Statement is malformed"]
    reasons = set()
    for st in statements:
        effect = st.get("Effect")
        if effect == "Deny":
            continue
        if effect != "Allow":
            reasons.add("statement Effect is missing or not Allow or Deny")
            continue
        if "NotAction" in st or "NotResource" in st:
            reasons.add("Allow statement uses NotAction or NotResource")
            continue
        actions = st.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        resources = st.get("Resource")
        resources = [resources] if isinstance(resources, str) else resources
        if not isinstance(actions, list) or not actions or not all(isinstance(a, str) for a in actions):
            reasons.add("statement Action is missing or malformed")
            continue
        if not isinstance(resources, list) or not resources or not all(isinstance(r, str) for r in resources):
            reasons.add("statement Resource is missing or malformed")
            continue
        for act in actions:
            low = act.lower()
            if low == "bedrock:*" or low == "*":
                reasons.add("grants %s" % act)
            elif fnmatch.fnmatchcase(INVOKE_ACTION, low) and "*" in resources:
                reasons.add("%s applies to Resource \"*\"" % act)
    return sorted(reasons)


def _tag_reason(res: Res) -> Optional[str]:
    first = None  # type: Optional[str]
    for name in ("tags", "tags_all"):
        state, val = get(res, name)
        if state == "ok" and isinstance(val, dict):
            bad = [k for k in REQUIRED_TAGS if not nonblank(val.get(k))]
            return ("tags missing or blank: " + ", ".join(bad)) if bad else None
        if first is None:
            first = "%s is %s" % (name, "unknown at plan time" if state == "unknown" else "missing or not a map")
    return first


SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("sk- style API key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]
NAME_HINT = re.compile(r"(key|secret|token|passw|credential)", re.I)
HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
OPAQUE = re.compile(r"^[A-Za-z0-9+=_\-]{24,}$")


def _strings(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k in sorted(node):
            for s in _strings(node[k]):
                yield s
    elif isinstance(node, list):
        for v in node:
            for s in _strings(v):
                yield s


def _secret_kind(name: str, value: str) -> Optional[str]:
    for label, rx in SECRET_PATTERNS:
        if rx.search(value):
            return label
    if NAME_HINT.search(name):
        if HEX32.match(value):
            return "32 hex character key"
        if OPAQUE.match(value) and re.search(r"[A-Z]", value) and re.search(r"[a-z]", value) \
                and re.search(r"[0-9]", value):
            return "opaque token"
    return None


def evaluate(plan: Any) -> Tuple[List[Finding], int]:
    """Run every rule. Returns (findings, number of checks made)."""
    resources = collect_resources(plan)
    run = Run()
    by_type = {}  # type: Dict[str, List[Res]]
    for r in resources:
        by_type.setdefault(r.type, []).append(r)

    # scope
    accounts = []  # type: List[Res]
    for r in by_type.get("azurerm_cognitive_account", []):
        state, kind = get(r, "kind")
        if state != "ok" or not isinstance(kind, str):
            run.check("GR000", r.address, "kind is %s, so the account cannot be classed as Azure OpenAI" % state)
        elif kind.lower() == "openai":
            accounts.append(r)
    endpoints = []  # type: List[Res]
    for r in by_type.get("aws_vpc_endpoint", []):
        state, svc = get(r, "service_name")
        if state != "ok" or not isinstance(svc, str):
            run.check("GR000", r.address, "service_name is %s, so the endpoint cannot be classed" % state)
        elif re.search(r"\.bedrock-runtime(-fips)?$", svc):
            endpoints.append(r)
    policies = by_type.get("aws_iam_policy", [])
    aws_in_scope = bool(endpoints) or any(t.startswith("aws_bedrock") for t in by_type)
    if not aws_in_scope:
        for p in policies:
            state, raw = get(p, "policy")
            if state == "ok" and isinstance(raw, str) and "bedrock" in raw.lower():
                aws_in_scope = True
    run.check("GR000", "plan", None if (accounts or aws_in_scope) else
              "no Azure OpenAI account and no Bedrock resource in the plan, so nothing was checked")

    # GR001 .. GR005 Azure
    pe_targets = []  # type: List[Tuple[Res, List[Any]]]
    unknown_pe = 0
    for pe in by_type.get("azurerm_private_endpoint", []):
        why, conns = first_dicts(pe, "private_service_connection")
        if why:
            unknown_pe += 1
            continue
        pe_targets.append((pe, [c.get("private_connection_resource_id") for c in conns]))
    tag_scope = []  # type: List[Res]
    for acct in accounts:
        tag_scope.append(acct)
        matched = [pe for pe, targets in pe_targets if any(target_matches(t, acct) for t in targets)]
        tag_scope.extend(m for m in matched if m not in tag_scope)
        run.check("GR001", acct.address, None if matched else
                  "no private endpoint with a known connection to this account (%d endpoint(s) unreadable)" % unknown_pe)
        run.check("GR002", acct.address, bool_is(acct, "public_network_access_enabled", False))
        run.check("GR003", acct.address, bool_is(acct, "local_auth_enabled", False))
        why, blocks = first_dicts(acct, "customer_managed_key")
        if not why and not any(nonblank(b.get("key_vault_key_id")) for b in blocks):
            why = "customer_managed_key has no key_vault_key_id"
        run.check("GR004", acct.address, why)
        diag_why = "no diagnostic setting targets this account"
        good = False
        for ds in by_type.get("azurerm_monitor_diagnostic_setting", []):
            state, tgt = get(ds, "target_resource_id")
            if state != "ok" or not target_matches(tgt, acct):
                continue
            has_dest = any(nonblank(get(ds, k)[1]) for k in
                           ("log_analytics_workspace_id", "storage_account_id", "eventhub_authorization_rule_id"))
            logs = get(ds, "enabled_log")[1]
            old = get(ds, "log")[1]
            has_log = (isinstance(logs, list) and any(isinstance(x, dict) for x in logs)) or \
                (isinstance(old, list) and any(isinstance(x, dict) and x.get("enabled") is True for x in old))
            if has_dest and has_log:
                good = True
                break
            diag_why = "diagnostic setting %s has %s" % (
                ds.address, "no enabled log category" if has_dest else "no known destination")
        run.check("GR005", acct.address, None if good else diag_why)

    # GR001 .. GR005 AWS
    if aws_in_scope:
        run.check("GR001", PLAN_AWS, None if endpoints else "no aws_vpc_endpoint for the bedrock-runtime service")
        for ep in endpoints:
            tag_scope.append(ep)
            state, typ = get(ep, "vpc_endpoint_type")
            run.check("GR001", ep.address, None if (state == "ok" and typ == "Interface") else
                      "vpc_endpoint_type is %s, expected Interface" % (typ if state == "ok" else state))
        keys = by_type.get("aws_kms_key", [])
        run.check("GR004", PLAN_AWS, None if keys else "no aws_kms_key in the plan")
        for key in keys:
            tag_scope.append(key)
            run.check("GR004", key.address, bool_is(key, "enable_key_rotation", True))
        trails = by_type.get("aws_cloudtrail", [])
        tag_scope.extend(trails)
        trail_ok = any(bool_is(t, "enable_logging", True) is None for t in trails)
        log_ok = False
        for cfg in by_type.get("aws_bedrock_model_invocation_logging_configuration", []):
            why, blocks = first_dicts(cfg, "logging_config")
            for blk in blocks:
                for sub, field in (("cloudwatch_config", "log_group_name"), ("s3_config", "bucket_name")):
                    dests = blk.get(sub)
                    if isinstance(dests, list) and any(isinstance(d, dict) and nonblank(d.get(field)) for d in dests):
                        log_ok = True
        run.check("GR005", PLAN_AWS, None if (log_ok or trail_ok) else
                  "no Bedrock invocation logging destination and no aws_cloudtrail with enable_logging true")

    # GR006 and GR008 for IAM policies
    for pol in policies:
        reasons = _policy_reasons(pol)
        run.check("GR006", pol.address, "; ".join(reasons) if reasons else None)
        tag_scope.append(pol)
    seen = set()
    for res in tag_scope:
        if res.address not in seen:
            seen.add(res.address)
            run.check("GR008", res.address, _tag_reason(res))

    # GR007 variables
    variables = plan.get("variables", {})
    if variables is None:
        variables = {}
    if not isinstance(variables, dict):
        raise BadInput("variables is not an object")
    for name in sorted(variables):
        entry = variables[name]
        kind = None  # type: Optional[str]
        if isinstance(entry, dict):
            for text in _strings(entry.get("value")):
                kind = kind or _secret_kind(name, text)
        run.check("GR007", "var." + name, ("value looks like a %s (value not shown)" % kind) if kind else None)
    return run.findings, run.checks


# ---------------------------------------------------------------- waivers

def apply_waivers(findings: List[Finding], raw: Any, today: datetime.date) -> List[Finding]:
    if not isinstance(raw, dict) or not isinstance(raw.get("waivers"), list):
        raise BadInput('waivers file needs an object with a "waivers" list')
    valid = []  # type: List[Dict[str, str]]
    extra = []  # type: List[Finding]
    for i, w in enumerate(raw["waivers"]):
        where = "waivers[%d]" % i
        if not isinstance(w, dict):
            extra.append(Finding("GR900", where, "waiver is not an object"))
            continue
        missing = [k for k in ("rule", "resource", "owner", "reason", "expires") if not nonblank(w.get(k))]
        if missing:
            extra.append(Finding("GR900", where, "waiver incomplete, missing: " + ", ".join(missing)))
            continue
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", w["expires"]):
            extra.append(Finding("GR900", where, "expires is not a YYYY-MM-DD date"))
            continue
        try:
            expires = datetime.date.fromisoformat(w["expires"])
        except ValueError:
            extra.append(Finding("GR900", where, "expires is not a real date"))
            continue
        if w["rule"] not in RULES or w["rule"] in NOT_WAIVABLE:
            extra.append(Finding("GR900", where, "rule %s cannot be waived" % w["rule"]))
            continue
        if expires < today:
            extra.append(Finding("GR900", where, "waiver for %s on %s expired %s" % (
                w["rule"], w["resource"], w["expires"])))
            continue
        valid.append(w)
    out = []  # type: List[Finding]
    for f in findings:
        hit = next((w for w in valid if w["rule"] == f.rule and w["resource"] == f.resource), None)
        if hit and f.rule not in NOT_WAIVABLE:
            out.append(f._replace(status="WAIVED", waiver="owner %s; reason %s; expires %s" % (
                hit["owner"], hit["reason"], hit["expires"])))
        else:
            out.append(f)
    return out + extra


# ---------------------------------------------------------------- output

def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (f.rule, f.resource, f.reason, f.status))


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def findings_table(findings: List[Finding]) -> str:
    lines = ["| rule | severity | status | resource | reason |", "|---|---|---|---|---|"]
    for f in findings:
        lines.append("| %s | %s | %s | %s | %s |" % (
            f.rule, RULES[f.rule]["severity"], f.status, _cell(f.resource), _cell(f.reason)))
    return "\n".join(lines)


def mapping_table(rule_ids: Sequence[str]) -> str:
    lines = ["| rule | name | NIST SP 800-53 Rev. 5 | NIST AI RMF | OWASP LLM Top 10 2025 |", "|---|---|---|---|---|"]
    for rid in rule_ids:
        r = RULES[rid]
        lines.append("| %s | %s | %s | %s | %s |" % (
            rid, r["name"], ", ".join(r["nist_800_53"]) or "-", ", ".join(r["ai_rmf"]) or "-",
            ", ".join(r["owasp_llm"]) or "-"))
    return "\n".join(lines)


def to_sarif(findings: List[Finding], plan_name: str) -> Dict[str, Any]:
    ids = sorted(RULES)
    rules = []
    for rid in ids:
        r = RULES[rid]
        rules.append({
            "id": rid, "name": r["name"],
            "shortDescription": {"text": r["name"]},
            "fullDescription": {"text": r["rationale"]},
            "help": {"text": r["remediation"]},
            "defaultConfiguration": {"level": LEVEL[r["severity"]]},
            "properties": {"tags": ["NIST-800-53:" + x for x in r["nist_800_53"]] +
                           ["AI-RMF:" + x for x in r["ai_rmf"]] + ["OWASP-LLM:" + x for x in r["owasp_llm"]],
                           "severity": r["severity"]},
        })
    results = []
    for f in findings:
        res = {
            "ruleId": f.rule, "ruleIndex": ids.index(f.rule),
            "level": LEVEL[RULES[f.rule]["severity"]],
            "message": {"text": "%s: %s" % (f.resource, f.reason)},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": plan_name}},
                "logicalLocations": [{"fullyQualifiedName": f.resource, "kind": "resource"}],
            }],
        }  # type: Dict[str, Any]
        if f.status == "WAIVED":
            res["suppressions"] = [{"kind": "external", "justification": f.waiver}]
        results.append(res)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "cloud-ai-guardrails", "version": VERSION, "rules": rules}},
                  "results": results}],
    }


def check_files(plan_path: str, waivers_path: Optional[str], today: datetime.date) -> Tuple[List[Finding], int]:
    plan = load_json(plan_path, "plan")
    findings, checks = evaluate(plan)
    if waivers_path is not None:
        findings = apply_waivers(findings, load_json(waivers_path, "waivers"), today)
    return sort_findings(findings), checks


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="guardrails.py", description="Check a terraform show -json plan for AI workload guardrails.")
    ap.add_argument("plan", nargs="?", help="plan JSON from terraform show -json")
    ap.add_argument("--waivers", help="waivers JSON: owner, reason and expiry required")
    ap.add_argument("--sarif", help="write SARIF 2.1.0 to this path")
    ap.add_argument("--today", help="date for waiver expiry, YYYY-MM-DD (default: system date)")
    ap.add_argument("--mapping", action="store_true", help="print the control mapping for every rule and exit")
    args = ap.parse_args(argv)
    if args.mapping:
        print(mapping_table(sorted(RULES)))
        return 0
    if not args.plan:
        ap.error("plan is required")
    try:
        today = datetime.date.fromisoformat(args.today) if args.today else datetime.date.today()
    except ValueError:
        ap.error("--today must be YYYY-MM-DD")
    try:
        findings, checks = check_files(args.plan, args.waivers, today)
        if args.sarif:
            try:
                with open(args.sarif, "w", encoding="utf-8") as fh:
                    json.dump(to_sarif(findings, args.plan.replace("\\", "/").split("/")[-1]),
                              fh, indent=2, sort_keys=True)
                    fh.write("\n")
            except OSError as exc:
                raise BadInput("cannot write SARIF: %s" % type(exc).__name__)
    except BadInput as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    failing = [f for f in findings if f.status == "FAIL"]
    waived = len(findings) - len(failing)
    if findings:
        print(findings_table(findings))
        print()
        print(mapping_table(sorted(set(f.rule for f in findings))))
        print()
    print("checks: %d, findings: %d, waived: %d" % (checks, len(failing), waived))
    print("result: %s" % ("FAIL" if failing else "PASS"))
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
