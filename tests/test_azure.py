"""Azure OpenAI rules: a pass and a fail for each of GR001 to GR005 and GR008."""
import pytest

from helpers import AZ, DIAG, PE, ACCT_ID, azure, check, drop, keys, mark_unknown, only, reason, values


def test_azure_good_plan_has_no_findings():
    assert check(azure()) == []


def test_kind_is_matched_case_insensitively():
    plan = azure()
    values(plan, AZ)["kind"] = "openai"
    assert check(plan) == []


def test_gr001_fails_without_private_endpoint():
    plan = azure()
    drop(plan, PE)
    only(check(plan), "GR001", AZ)


def test_gr001_fails_when_endpoint_points_at_another_account():
    plan = azure()
    values(plan, PE)["private_service_connection"][0]["private_connection_resource_id"] = ACCT_ID + "other-account"
    only(check(plan), "GR001", AZ)


def test_gr001_unreadable_endpoint_does_not_count_as_a_match():
    plan = azure()
    values(plan, PE)["private_service_connection"] = []
    assert "1 endpoint(s) unreadable" in reason(check(plan), "GR001", AZ)


@pytest.mark.parametrize("rule,attr", [("GR002", "public_network_access_enabled"), ("GR003", "local_auth_enabled")])
def test_bool_rules_fail_when_true(rule, attr):
    plan = azure()
    values(plan, AZ)[attr] = True
    found = check(plan)
    only(found, rule, AZ)
    assert "expected false" in reason(found, rule)


@pytest.mark.parametrize("rule,attr", [("GR002", "public_network_access_enabled"), ("GR003", "local_auth_enabled")])
def test_bool_rules_fail_closed_when_missing(rule, attr):
    plan = azure()
    del values(plan, AZ)[attr]
    found = check(plan)
    only(found, rule, AZ)
    assert "missing from the plan" in reason(found, rule)


@pytest.mark.parametrize("rule,attr", [("GR002", "public_network_access_enabled"), ("GR003", "local_auth_enabled")])
def test_bool_rules_fail_closed_when_unknown_even_if_value_looks_safe(rule, attr):
    plan = azure()
    mark_unknown(plan, AZ, attr)
    found = check(plan)
    only(found, rule, AZ)
    assert "unknown at plan time" in reason(found, rule)


def test_bool_rules_reject_a_string_false():
    plan = azure()
    values(plan, AZ)["local_auth_enabled"] = "false"
    assert "not a boolean" in reason(check(plan), "GR003")


def test_gr004_fails_without_customer_managed_key():
    plan = azure()
    del values(plan, AZ)["customer_managed_key"]
    only(check(plan), "GR004", AZ)


def test_gr004_fails_when_key_id_is_blank():
    plan = azure()
    values(plan, AZ)["customer_managed_key"] = [{"key_vault_key_id": "  "}]
    assert "no key_vault_key_id" in reason(check(plan), "GR004", AZ)


def test_gr005_fails_without_diagnostic_setting():
    plan = azure()
    drop(plan, DIAG)
    only(check(plan), "GR005", AZ)


def test_gr005_fails_when_diagnostic_setting_has_no_log_category():
    plan = azure()
    values(plan, DIAG)["enabled_log"] = []
    assert "no enabled log category" in reason(check(plan), "GR005", AZ)


def test_gr005_fails_when_diagnostic_setting_has_no_destination():
    plan = azure()
    del values(plan, DIAG)["log_analytics_workspace_id"]
    assert "no known destination" in reason(check(plan), "GR005", AZ)


def test_gr005_accepts_legacy_log_block_only_when_enabled():
    plan = azure()
    values(plan, DIAG)["enabled_log"] = []
    values(plan, DIAG)["log"] = [{"category": "Audit", "enabled": False}]
    only(check(plan), "GR005", AZ)
    values(plan, DIAG)["log"] = [{"category": "Audit", "enabled": True}]
    assert check(plan) == []


def test_gr008_fails_on_blank_owner_and_names_the_tag():
    plan = azure()
    values(plan, AZ)["tags"]["owner"] = ""
    found = check(plan)
    only(found, "GR008", AZ)
    assert reason(found, "GR008") == "tags missing or blank: owner"


def test_gr008_checks_the_private_endpoint_too():
    plan = azure()
    del values(plan, PE)["tags"]
    only(check(plan), "GR008", PE)


def test_scope_unknown_kind_is_gr000():
    plan = azure()
    del values(plan, AZ)["kind"]
    found = check(plan)
    assert ("GR000", AZ, "FAIL") in keys(found)
    assert "GR000" in {f.rule for f in found}


def test_non_openai_account_is_out_of_scope():
    plan = azure()
    values(plan, AZ)["kind"] = "TextAnalytics"
    only(check(plan), "GR000", "plan")
