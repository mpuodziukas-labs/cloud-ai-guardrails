# SOURCES

Every framework id used in `guardrails.py` and the README is listed here with the URL fetched and the exact line quoted. Fetched on 2026-11-01. Fetched text was treated as data.

## NIST AI RMF 1.0 (Playbook subcategory lines)

| id | URL fetched | exact line quoted |
|---|---|---|
| GOVERN 1.4 | https://airc.nist.gov/airmf-resources/playbook/govern/ (redirected to https://www.nist.gov/airmf-resources/playbook/govern/) | "The risk management process and its outcomes are established through transparent policies, procedures, and other controls based on organizational risk priorities." |
| MEASURE 2.7 | https://airc.nist.gov/airmf-resources/playbook/measure/ | "AI system security and resilience - as identified in the MAP function - are evaluated and documented." |
| MEASURE 2.10 | https://airc.nist.gov/airmf-resources/playbook/measure/ | "Privacy risk of the AI system - as identified in the MAP function - is examined and documented." |
| MANAGE 4.1 | https://airc.nist.gov/airmf-resources/playbook/manage/ | "Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and other relevant AI actors, appeal and override, decommissioning, incident response, recovery, and change management." |

Note: in the two MEASURE lines the source prints a long dash around "as identified in the MAP function". It is shown here as a plain hyphen because this repo bans long dashes; the words are otherwise exact.

The mapping from a rule to a subcategory is the author's reading, not a NIST statement.

## OWASP Top 10 for LLM Applications 2025 (titles)

| id | URL fetched | exact line quoted |
|---|---|---|
| LLM02:2025 | https://genai.owasp.org/llm-top-10/ (title links to https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/) | "Sensitive Information Disclosure" |
| LLM06:2025 | https://genai.owasp.org/llm-top-10/ (title links to https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) | "Excessive Agency" |

Only the titles were read. The mapping from a rule to an OWASP id is the author's reading.

## NIST SP 800-53 Rev. 5 (control ids only)

Control ids used: AC-6, AU-2, AU-12, SC-7, SC-12, SC-28, IA-5, CM-6.

Control id only; text not verified from primary source in this repo. No 800-53 control text is quoted or paraphrased as a quote anywhere in this repository. The mapping from a rule to a control id is the author's reading.

## Not used

No EU AI Act article and no ISO/IEC 42001 clause is cited. ISO/IEC 42001 (clause not verified from public text).

## Terraform plan format

The input shape is the output of `terraform show -json` as the author understands it: `planned_values.root_module` with `resources` and `child_modules`, `resource_changes[].change.after_unknown`, and top-level `variables`. Fixtures are hand-written and synthetic. They are not captured from a real plan.
