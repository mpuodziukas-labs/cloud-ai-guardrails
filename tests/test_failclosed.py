"""Fail-closed behaviour: bad input, secrets in variables, and waivers."""
import datetime
import json

import pytest

import guardrails
from helpers import AZ, TODAY, azure, aws, check, keys, load, only, reason, write

AKIA = "AKIA" + "IOSFODNN7EXAMPLE"


# ---- bad input is exit 2 material, never a pass

@pytest.mark.parametrize("plan", [[], "text", 7, None, {}, {"planned_values": {}},
                                  {"planned_values": {"root_module": []}}])
def test_non_plan_shapes_raise_bad_input(plan):
    with pytest.raises(guardrails.BadInput):
        guardrails.evaluate(plan)


@pytest.mark.parametrize("key", ["resources", "child_modules"])
@pytest.mark.parametrize("bad", [5, True, -1.5])
def test_non_list_resources_or_children_raise_bad_input(key, bad):
    plan = azure()
    plan["planned_values"]["root_module"][key] = bad
    with pytest.raises(guardrails.BadInput):
        guardrails.evaluate(plan)


def test_evaluate_rejects_arguments_with_exit_two():
    import os
    import subprocess
    import sys
    from helpers import ROOT
    r = subprocess.run([sys.executable, os.path.join(ROOT, "evaluate.py"), "--bogus"],
                       capture_output=True, text=True)
    assert r.returncode == 2
    assert "usage" in r.stderr


def test_resource_without_address_raises_bad_input():
    plan = {"planned_values": {"root_module": {"resources": [{"type": "x", "values": {}}]}}}
    with pytest.raises(guardrails.BadInput):
        guardrails.evaluate(plan)


def test_variables_that_are_not_an_object_raise_bad_input():
    plan = azure()
    plan["variables"] = ["a"]
    with pytest.raises(guardrails.BadInput):
        guardrails.evaluate(plan)


@pytest.mark.parametrize("text", ['{"a": 1, "a": 2}', '{"a": NaN}', '{"a": Infinity}', "{", ""])
def test_strict_json_rejects_duplicates_nan_and_truncation(text):
    with pytest.raises(ValueError):
        guardrails.parse_json(text)


def test_load_json_names_the_failure_without_a_traceback(tmp_path):
    with pytest.raises(guardrails.BadInput) as exc:
        guardrails.load_json(str(tmp_path / "absent.json"), "plan")
    assert "unreadable" in str(exc.value)
    with pytest.raises(guardrails.BadInput) as exc:
        guardrails.load_json(write(tmp_path, "bad.json", "{oops"), "plan")
    assert "not valid JSON" in str(exc.value)


def test_empty_plan_is_a_finding_not_a_pass():
    only(check({"planned_values": {"root_module": {}}}), "GR000", "plan")


def test_resources_in_child_modules_are_checked():
    plan = azure()
    res = plan["planned_values"]["root_module"]["resources"]
    plan["planned_values"]["root_module"] = {"resources": [], "child_modules": [{"resources": res}]}
    assert check(plan) == []
    for r in res:
        if r["address"] == AZ:
            r["values"]["local_auth_enabled"] = True
    only(check(plan), "GR003", AZ)


# ---- GR007 hard-coded keys

def _vars(name, value):
    plan = azure()
    plan["variables"] = {name: {"value": value}}
    return check(plan)


def test_gr007_flags_aws_key_id_and_never_prints_it():
    found = _vars("deploy_id", AKIA)
    only(found, "GR007", "var.deploy_id")
    assert AKIA not in reason(found, "GR007") and "value not shown" in reason(found, "GR007")


def test_gr007_flags_sk_key_and_private_key_block():
    only(_vars("anything", "sk-" + "a" * 24), "GR007", "var.anything")
    only(_vars("pem", "-----BEGIN EXAMPLE RSA PRIVATE KEY-----"), "GR007", "var.pem")


def test_gr007_finds_a_key_nested_inside_a_value():
    only(_vars("settings", {"inner": [AKIA]}), "GR007", "var.settings")


def test_gr007_hex_and_opaque_tokens_need_a_name_hint():
    only(_vars("api_key", "0123456789abcdef0123456789abcdef"), "GR007", "var.api_key")
    assert _vars("build_id", "0123456789abcdef0123456789abcdef") == []
    only(_vars("auth_token", "Abcdefghijklmnop1234567890XY"), "GR007", "var.auth_token")
    assert _vars("auth_token", "all-lowercase-words-and-dashes") == []


def test_gr007_ordinary_values_pass():
    assert _vars("region", "eastus") == []
    assert _vars("count", 3) == []


# ---- waivers

def _plan_with_public_access():
    plan = azure()
    plan["planned_values"]["root_module"]["resources"][0]["values"]["public_network_access_enabled"] = True
    return plan


def _waiver(**over):
    w = {"rule": "GR002", "resource": AZ, "owner": "synthetic-owner", "reason": "synthetic reason",
         "expires": "2026-12-31"}
    w.update(over)
    return {"waivers": [w]}


def test_valid_waiver_marks_the_finding_waived():
    found = check(_plan_with_public_access(), _waiver())
    assert keys(found) == [("GR002", AZ, "WAIVED")]
    assert "synthetic-owner" in found[0].waiver


def test_waiver_expiring_today_is_still_valid():
    assert keys(check(_plan_with_public_access(), _waiver(expires="2026-11-01"))) == [("GR002", AZ, "WAIVED")]


def test_expired_waiver_keeps_the_fail_and_adds_gr900():
    found = check(_plan_with_public_access(), _waiver(expires="2026-10-31"))
    assert keys(found) == [("GR002", AZ, "FAIL"), ("GR900", "waivers[0]", "FAIL")]
    assert "expired" in reason(found, "GR900")


@pytest.mark.parametrize("field", ["owner", "reason", "expires", "rule", "resource"])
def test_incomplete_waiver_is_rejected(field):
    found = check(_plan_with_public_access(), _waiver(**{field: "  "}))
    assert ("GR900", "waivers[0]", "FAIL") in keys(found)
    assert ("GR002", AZ, "FAIL") in keys(found)
    assert field in reason(found, "GR900")


@pytest.mark.parametrize("expires", ["tomorrow", "2026-13-40", "2026-1-1", "20261231"])
def test_bad_expiry_is_rejected(expires):
    found = check(_plan_with_public_access(), _waiver(expires=expires))
    assert ("GR900", "waivers[0]", "FAIL") in keys(found)
    assert ("GR002", AZ, "FAIL") in keys(found)


def test_waiver_for_another_resource_does_not_apply():
    found = check(_plan_with_public_access(), _waiver(resource="azurerm_cognitive_account.other"))
    assert keys(found) == [("GR002", AZ, "FAIL")]


def test_scope_and_waiver_findings_cannot_be_waived():
    plan = azure()
    del plan["planned_values"]["root_module"]["resources"][0]["values"]["kind"]
    found = check(plan, _waiver(rule="GR000", resource=AZ))
    assert ("GR000", AZ, "FAIL") in keys(found)
    assert "cannot be waived" in reason(found, "GR900")


def test_waiver_entry_that_is_not_an_object_is_a_finding():
    found = check(_plan_with_public_access(), {"waivers": ["x"]})
    assert ("GR900", "waivers[0]", "FAIL") in keys(found)


@pytest.mark.parametrize("raw", [[], {}, {"waivers": {}}, "x"])
def test_waivers_file_shape_is_bad_input(raw):
    with pytest.raises(guardrails.BadInput):
        guardrails.apply_waivers([], raw, TODAY)


def test_waiver_clock_is_a_parameter():
    plan = _plan_with_public_access()
    late = datetime.date(2027, 1, 1)
    findings, _ = guardrails.evaluate(plan)
    got = guardrails.apply_waivers(findings, _waiver(), late)
    assert ("GR900", "waivers[0]", "FAIL") in keys(got)


def test_fixture_cases_exist_for_both_clouds():
    assert load("aws_all_good") and load("azure_all_good") and aws() and json.dumps(azure())
