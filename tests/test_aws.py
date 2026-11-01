"""AWS Bedrock rules: a pass and a fail for each of GR001, GR004, GR005, GR006, GR008."""
import pytest

from helpers import EP, KMS, LOGC, POL, TRAIL, aws, check, drop, keys, mark_unknown, only, reason, set_policy, values

PLAN = "plan:aws-bedrock"
ARN = "arn:aws:bedrock:us-east-1::foundation-model/synthetic.model-v1"


def test_aws_good_plan_has_no_findings():
    assert check(aws()) == []


def test_gr001_fails_without_bedrock_runtime_endpoint():
    plan = aws()
    drop(plan, EP)
    only(check(plan), "GR001", PLAN)


def test_gr001_fails_for_gateway_endpoint_type():
    plan = aws()
    values(plan, EP)["vpc_endpoint_type"] = "Gateway"
    only(check(plan), "GR001", EP)


def test_gr001_fips_service_name_is_in_scope():
    plan = aws()
    values(plan, EP)["service_name"] = "com.amazonaws.us-east-1.bedrock-runtime-fips"
    assert check(plan) == []


def test_unrelated_endpoint_with_unknown_service_is_gr000():
    plan = aws()
    values(plan, EP)["service_name"] = "com.amazonaws.us-east-1.s3"
    assert ("GR001", PLAN, "FAIL") in keys(check(plan))
    plan = aws()
    mark_unknown(plan, EP, "service_name")
    assert ("GR000", EP, "FAIL") in keys(check(plan))


def test_gr004_fails_when_rotation_is_off():
    plan = aws()
    values(plan, KMS)["enable_key_rotation"] = False
    only(check(plan), "GR004", KMS)


def test_gr004_fails_closed_when_rotation_unknown():
    plan = aws()
    mark_unknown(plan, KMS, "enable_key_rotation")
    assert "unknown at plan time" in reason(check(plan), "GR004", KMS)


def test_gr004_fails_with_no_kms_key():
    plan = aws()
    drop(plan, KMS)
    only(check(plan), "GR004", PLAN)


def test_gr005_fails_with_no_logging_and_no_trail():
    plan = aws()
    drop(plan, LOGC)
    drop(plan, TRAIL)
    only(check(plan), "GR005", PLAN)


def test_gr005_trail_alone_passes_and_logging_config_alone_passes():
    plan = aws()
    drop(plan, LOGC)
    assert check(plan) == []
    plan = aws()
    drop(plan, TRAIL)
    assert check(plan) == []


def test_gr005_trail_with_logging_off_does_not_count():
    plan = aws()
    drop(plan, LOGC)
    values(plan, TRAIL)["enable_logging"] = False
    only(check(plan), "GR005", PLAN)


def test_gr005_blank_destination_does_not_count():
    plan = aws()
    drop(plan, TRAIL)
    values(plan, LOGC)["logging_config"][0]["cloudwatch_config"][0]["log_group_name"] = " "
    only(check(plan), "GR005", PLAN)


@pytest.mark.parametrize("action", ["bedrock:*", "*", "BEDROCK:*"])
def test_gr006_fails_on_wildcard_action(action):
    plan = aws()
    set_policy(plan, [{"Effect": "Allow", "Action": action, "Resource": [ARN]}])
    only(check(plan), "GR006", POL)


@pytest.mark.parametrize("action", ["bedrock:InvokeModel", "bedrock:Invoke*", "bedrock:*Model"])
def test_gr006_fails_on_invoke_with_star_resource(action):
    plan = aws()
    set_policy(plan, [{"Effect": "Allow", "Action": [action], "Resource": "*"}])
    only(check(plan), "GR006", POL)


def test_gr006_passes_other_actions_on_star_and_ignores_deny():
    plan = aws()
    set_policy(plan, [{"Effect": "Allow", "Action": ["bedrock:ListFoundationModels"], "Resource": "*"},
                      {"Effect": "Deny", "Action": "bedrock:*", "Resource": "*"}])
    assert check(plan) == []


def test_gr006_fails_on_notaction_and_missing_effect():
    plan = aws()
    set_policy(plan, [{"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}])
    assert "NotAction" in reason(check(plan), "GR006", POL)
    set_policy(plan, [{"Action": "bedrock:InvokeModel", "Resource": [ARN]}])
    assert "Effect" in reason(check(plan), "GR006", POL)


def test_gr006_fails_closed_on_bad_policy_text():
    plan = aws()
    values(plan, POL)["policy"] = "{not json"
    assert reason(check(plan), "GR006", POL) == "policy is not valid JSON"
    values(plan, POL)["policy"] = '{"Statement": [], "Statement": []}'
    assert reason(check(plan), "GR006", POL) == "policy is not valid JSON"
    values(plan, POL)["policy"] = "{}"
    assert reason(check(plan), "GR006", POL) == "policy has no Statement"
    del values(plan, POL)["policy"]
    assert "missing" in reason(check(plan), "GR006", POL)


def test_gr006_fails_closed_on_unknown_policy():
    plan = aws()
    mark_unknown(plan, POL, "policy")
    assert "unknown at plan time" in reason(check(plan), "GR006", POL)


def test_gr008_fails_for_missing_classification_on_kms():
    plan = aws()
    del values(plan, KMS)["tags"]["data_classification"]
    found = check(plan)
    only(found, "GR008", KMS)
    assert reason(found, "GR008") == "tags missing or blank: data_classification"


def test_gr008_falls_back_to_tags_all():
    plan = aws()
    tags = values(plan, KMS).pop("tags")
    values(plan, KMS)["tags_all"] = tags
    assert check(plan) == []


def test_policy_mentioning_bedrock_puts_a_bare_plan_in_scope():
    plan = aws()
    for addr in (EP, KMS, LOGC, TRAIL):
        drop(plan, addr)
    got = keys(check(plan))
    assert ("GR001", PLAN, "FAIL") in got and ("GR000", "plan", "FAIL") not in got
