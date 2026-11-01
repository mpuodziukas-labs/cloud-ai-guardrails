"""CLI exit codes, SARIF 2.1.0, the mapping table and determinism."""
import json
import os

import guardrails
from helpers import CASES, ROOT, cli, write

GOOD = os.path.join(CASES, "azure_all_good", "plan.json")
BAD = os.path.join(CASES, "azure_public_access_on", "plan.json")


def test_cli_exit_0_on_a_passing_plan():
    code, out, _ = cli(GOOD)
    assert code == 0 and out.rstrip().endswith("result: PASS")


def test_cli_exit_1_on_findings_with_table_and_mapping():
    code, out, _ = cli(BAD)
    assert code == 1
    assert "| GR002 | critical | FAIL |" in out
    assert "| rule | name | NIST SP 800-53 Rev. 5 |" in out
    assert out.rstrip().endswith("result: FAIL")


def test_cli_exit_2_on_unreadable_and_invalid_input(tmp_path):
    code, _, err = cli(str(tmp_path / "absent.json"))
    assert code == 2 and err.startswith("error:")
    code, _, err = cli(write(tmp_path, "bad.json", "{oops"))
    assert code == 2 and "not valid JSON" in err
    code, _, _ = cli(write(tmp_path, "shape.json", "[]"))
    assert code == 2
    code, _, _ = cli()
    assert code == 2
    code, _, _ = cli(GOOD, "--today", "not-a-date")
    assert code == 2


def test_cli_waiver_flow_and_exit_codes(tmp_path):
    w = write(tmp_path, "w.json", {"waivers": [{"rule": "GR002", "resource": "azurerm_cognitive_account.main",
                                                "owner": "synthetic-owner", "reason": "synthetic",
                                                "expires": "2026-11-01"}]})
    assert cli(BAD, "--waivers", w, "--today", "2026-11-01")[0] == 0
    assert cli(BAD, "--waivers", w, "--today", "2026-11-02")[0] == 1
    assert cli(BAD, "--waivers", write(tmp_path, "bw.json", "[]"))[0] == 2


def test_sarif_structure(tmp_path):
    out = str(tmp_path / "out.sarif")
    code, _, _ = cli(BAD, "--sarif", out)
    assert code == 1
    with open(out, encoding="utf-8") as fh:
        doc = json.load(fh)
    assert doc["version"] == "2.1.0" and "sarif" in doc["$schema"]
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == sorted(guardrails.RULES)
    for r in rules:
        assert r["fullDescription"]["text"] and r["help"]["text"]
    res = run["results"]
    assert [x["ruleId"] for x in res] == ["GR002"]
    assert rules[res[0]["ruleIndex"]]["id"] == "GR002" and res[0]["level"] == "error"
    assert res[0]["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] == "azurerm_cognitive_account.main"
    assert "suppressions" not in res[0]


def test_sarif_marks_waived_findings_suppressed(tmp_path):
    w = write(tmp_path, "w.json", {"waivers": [{"rule": "GR002", "resource": "azurerm_cognitive_account.main",
                                                "owner": "synthetic-owner", "reason": "synthetic",
                                                "expires": "2026-12-31"}]})
    out = str(tmp_path / "out.sarif")
    assert cli(BAD, "--waivers", w, "--today", "2026-11-01", "--sarif", out)[0] == 0
    with open(out, encoding="utf-8") as fh:
        res = json.load(fh)["runs"][0]["results"]
    assert res[0]["suppressions"][0]["kind"] == "external"
    assert "synthetic-owner" in res[0]["suppressions"][0]["justification"]


def test_sarif_to_unwritable_path_is_exit_2(tmp_path):
    code, _, err = cli(BAD, "--sarif", str(tmp_path / "no_dir" / "out.sarif"))
    assert code == 2 and "cannot write SARIF" in err


def test_mapping_flag_lists_every_rule_with_framework_ids():
    code, out, _ = cli("--mapping")
    assert code == 0
    for rid, rule in guardrails.RULES.items():
        row = [ln for ln in out.splitlines() if ln.startswith("| %s |" % rid)]
        assert len(row) == 1
        for cid in rule["nist_800_53"] + rule["ai_rmf"] + rule["owasp_llm"]:
            assert cid in row[0]


def test_every_rule_carries_severity_rationale_and_remediation():
    for rule in guardrails.RULES.values():
        assert rule["severity"] in guardrails.LEVEL
        assert rule["rationale"] and rule["remediation"] and rule["nist_800_53"]


def test_output_is_deterministic():
    assert cli(BAD) == cli(BAD)


def test_secret_value_never_reaches_the_output(tmp_path):
    secret = "AKIA" + "IOSFODNN7EXAMPLE"
    with open(GOOD, encoding="utf-8") as fh:
        plan = json.load(fh)
    plan["variables"] = {"deploy_id": {"value": secret}}
    out = str(tmp_path / "o.sarif")
    code, stdout, stderr = cli(write(tmp_path, "p.json", plan), "--sarif", out)
    with open(out, encoding="utf-8") as fh:
        sarif = fh.read()
    assert code == 1 and secret not in stdout + stderr + sarif


def test_repo_ships_no_dash_characters_in_the_checker():
    with open(os.path.join(ROOT, "guardrails.py"), encoding="utf-8") as fh:
        text = fh.read()
    assert chr(0x2013) not in text and chr(0x2014) not in text
