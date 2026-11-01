# cloud-ai-guardrails

Proves: an offline checker of Terraform plan JSON enforces eight guardrails on AWS Bedrock and Azure OpenAI workloads and fails closed on unreadable, unknown or missing values and on expired or incomplete waivers. Verify in 60s: `python3 evaluate.py`

All plan files in this repo are hand-written and synthetic. No real account, tenant, key or person appears in them.

## The problem

AI workloads reach the cloud through a few settings that are easy to get wrong in code review: is the model endpoint public, are static keys still on, is the data key customer-managed, is anyone logging calls, does the IAM policy allow every model. A reviewer reading a pull request misses these. A checker that reads the Terraform plan can catch them before apply, with no cloud credentials.

The harder failure is the quiet pass. A plan value that is unknown until apply, a missing attribute, or a malformed policy can make a naive checker report nothing wrong. This checker treats each of those as a finding with a reason.

## Run it

```
python3 evaluate.py                                   # table of cases, last line: cases: N/N match
python3 guardrails.py plan.json                       # exit 0 pass, 1 findings, 2 bad input
python3 guardrails.py plan.json --waivers w.json      # waivers need owner, reason, expiry
python3 guardrails.py plan.json --sarif out.sarif     # SARIF 2.1.0 for code scanning
python3 guardrails.py --mapping                       # rule to framework id table
bash run.sh                                           # table, pytest, mutants (CI entry point)
```

Input is the output of `terraform show -json <planfile>`. Standard library only, Python 3.9 or newer, no network, no install step for the checker. The tests need pytest.

A waiver file looks like this:

```
{"waivers": [{"rule": "GR002", "resource": "azurerm_cognitive_account.main",
              "owner": "team name", "reason": "why", "expires": "2026-12-31"}]}
```

A waiver that is incomplete, expired, has a bad date, or names GR000 or GR900 produces a GR900 finding and the original finding stays FAIL. A waiver is valid through its expiry date. `--today YYYY-MM-DD` sets the clock; the default is the system date.

## What it checks

| id | name | what must be true |
|---|---|---|
| GR001 | PRIVATE_ENDPOINT | Azure: a private endpoint connects to the OpenAI account. AWS: an Interface VPC endpoint exists for bedrock-runtime. |
| GR002 | PUBLIC_ACCESS_DISABLED | Azure OpenAI `public_network_access_enabled` is false. |
| GR003 | LOCAL_AUTH_DISABLED | Azure OpenAI `local_auth_enabled` is false. |
| GR004 | CMK_ENCRYPTION | Azure: `customer_managed_key` with a key id. AWS: a KMS key with rotation enabled. |
| GR005 | INVOCATION_LOGGING | AWS: Bedrock invocation logging with a destination, or a CloudTrail with logging on. Azure: a diagnostic setting with a destination and an enabled log. |
| GR006 | LEAST_PRIVILEGE_IAM | No `bedrock:*`, no `*`, and no `bedrock:InvokeModel` (or a wildcard that covers it) on Resource `*`. |
| GR007 | NO_HARDCODED_KEYS | No key-shaped value in plan variables. The value is never printed. |
| GR008 | REQUIRED_TAGS | Non-empty `data_classification` and `owner` tags on in-scope resources. |
| GR000 | SCOPE_UNDETERMINED | The checker can tell what it is looking at. An unknown `kind` or `service_name`, or a plan with no AI resource, fails. |
| GR900 | WAIVER_INVALID | Every waiver has rule, resource, owner, reason and a live expiry. |

Fail-closed behaviour:

- A plan that is not valid JSON, has duplicate keys, has NaN, or is not `terraform show -json` shaped is exit 2.
- An attribute that is unknown at plan time (`after_unknown`) fails its rule, even when a value is also shown.
- A missing attribute on an in-scope resource fails its rule.
- An IAM policy that cannot be parsed, or that uses `NotAction` or `NotResource` on an Allow, fails GR006.

Each rule carries a severity, rationale and remediation. They appear in the SARIF rule metadata and in `guardrails.py`.

## Mapping

Output of `python3 guardrails.py --mapping`:

| rule | name | NIST SP 800-53 Rev. 5 | NIST AI RMF | OWASP LLM Top 10 2025 |
|---|---|---|---|---|
| GR000 | SCOPE_UNDETERMINED | CM-6 | GOVERN 1.4 | - |
| GR001 | PRIVATE_ENDPOINT | SC-7 | MEASURE 2.7 | LLM02 |
| GR002 | PUBLIC_ACCESS_DISABLED | SC-7, CM-6 | MEASURE 2.7 | LLM02 |
| GR003 | LOCAL_AUTH_DISABLED | IA-5, AC-6 | MEASURE 2.7 | LLM02 |
| GR004 | CMK_ENCRYPTION | SC-28, SC-12 | MEASURE 2.10 | LLM02 |
| GR005 | INVOCATION_LOGGING | AU-2, AU-12 | MANAGE 4.1 | - |
| GR006 | LEAST_PRIVILEGE_IAM | AC-6 | GOVERN 1.4 | LLM06 |
| GR007 | NO_HARDCODED_KEYS | IA-5, SC-12 | MEASURE 2.7 | LLM02 |
| GR008 | REQUIRED_TAGS | CM-6 | GOVERN 1.4 | - |
| GR900 | WAIVER_INVALID | CM-6 | GOVERN 1.4 | - |

The mapping is the author's reading. NIST 800-53 entries are control ids only; text not verified from primary source in this repo. The AI RMF and OWASP wording that was fetched is quoted in SOURCES.md with its URL and fetch date. A passing run does not show that a control is met.

## Honesty

The plan files are synthetic, hand-written for this repo. No language model runs in the loop: the checker and the evaluator import only the Python standard library and open no network connection. The expected results sit beside the cases the checks are scored against, so the match count is a consistency check and not a claim that the checks generalize. The key-shaped string in the hardcoded key case is a test fixture, not a secret. Nothing here was run against production data.

## Limitations

- Engineering evidence, not legal advice. No certification, audit result or compliance status is claimed.
- Fixtures are synthetic. Passing them shows the rules behave as written, not that a real deployment is safe.
- It reads a plan, not live cloud state. Console changes after apply are invisible to it.
- Secret detection is heuristic: a few known key shapes, plus hex and opaque strings when the variable name hints at a secret. It will miss some keys and may flag some non-keys.
- CloudTrail records API calls, not prompt or response content. Only Bedrock invocation logging captures content.
- A value unknown until apply fails the rule. The way through is a dated waiver or a plan where the value is known.
- A plan with no Azure OpenAI account and no Bedrock resource fails GR000 rather than passing.
- Covered resource types are the ones named above. Other ways to reach a model (other providers, other resource types) are out of scope.
- Waivers are matched on rule and resource address only.

Proof files: `evaluate.py` writes `PROOF.json`; `mutants.py` breaks the checker one spot at a time and requires the tests to notice. See AGENTS.md, SOURCES.md and INSPO.md.
