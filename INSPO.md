# INSPO: tools and samples this repo learns from

Star counts below were returned by the GitHub API on 2026-11-01. Each description is the general, well-known purpose of the project. Nothing here claims knowledge of a project's internals; this author did not read their source for this repo.

## What this repo adds on top of all of them

1. AI-service-specific rules: Bedrock invocation logging, bedrock-runtime endpoints, Azure OpenAI `local_auth_enabled`, and `bedrock:InvokeModel` on `Resource "*"`.
2. Fail closed on unknown or missing values: a checked attribute that is unknown at plan time, or absent on an in-scope resource, is a finding with a reason.
3. Waiver expiry: a waiver needs owner, reason and a live expiry date. An expired or incomplete waiver is itself a finding.
4. AI RMF mapping: every rule carries NIST AI RMF, NIST SP 800-53 Rev. 5 and OWASP LLM Top 10 (2025) ids.
5. Mutation-tested: `mutants.py` changes the checker one spot at a time and the tests must catch every change.

## Scanners and policy engines

| project | stars | known for | what this repo adds |
|---|---|---|---|
| aquasecurity/trivy | 38886 | An all-in-one scanner for container images, file systems, infrastructure as code and dependencies. | AI-service rules only; fail closed on unknown values; waiver expiry; AI RMF ids; mutation-tested. |
| prowler-cloud/prowler | 15149 | A cloud security assessment tool for AWS, Azure and other clouds, with compliance framework reports. | Works on a plan before anything is deployed, not on a live account; AI-service rules with AI RMF ids; mutation-tested. |
| open-policy-agent/opa | 12421 | A general-purpose policy engine with the Rego policy language. | Ships finished AI-service rules instead of a language to write them in; fail closed by default; waiver expiry. |
| bridgecrewio/checkov | 9125 | A static analysis tool for infrastructure as code with a large built-in policy library. | A small AI-only rule set with AI RMF mapping; unknown values fail instead of being skipped; waiver expiry; mutation-tested. |
| turbot/steampipe | 7992 | Queries cloud APIs with SQL. | Offline plan checking with no credentials; AI-service rules; waiver expiry. |
| nccgroup/ScoutSuite | 7869 | A multi-cloud security auditing tool that reads a live account's configuration. | Plan-time checks instead of live-account audit; AI-service rules; fail closed on missing values. |
| aquasecurity/tfsec | 7058 | A Terraform static analysis scanner (its checks now live in Trivy). | AI-service rules; fail closed on unknown values; waiver expiry; AI RMF ids. |
| cloud-custodian/cloud-custodian | 6099 | A rules engine for managing cloud resources, often used to enforce policy on live accounts. | Pre-deploy plan checks instead of live enforcement; AI-service rules; mutation-tested. |
| terraform-linters/tflint | 5847 | A Terraform linter with provider-specific rule plugins. | Security and governance rules for AI services with AI RMF ids; waiver expiry. |
| tenable/terrascan | 5215 | An infrastructure as code scanner for policy and compliance (archived). | A maintained small scope: AI-service rules, fail closed on unknown values, waiver expiry. |
| open-policy-agent/conftest | 3293 | Runs OPA policies against structured files such as Terraform plan JSON. | Ready-made AI-service rules; fail closed when the plan is unreadable; waiver expiry; mutation-tested. |
| Checkmarx/kics | 2728 | An infrastructure as code scanner with many queries across formats. | AI-only rules with AI RMF ids; unknown values fail; waiver expiry; mutation-tested. |
| terraform-compliance/cli | 1463 | A behaviour-driven test tool that checks Terraform plans against feature files. | Fixed rules with ids, severity and remediation; fail closed on unknown values; waiver expiry; AI RMF ids. |

## Reference architectures and samples for AI on the cloud

These show how to build AI workloads. They are not checkers. This repo turns the controls such designs usually include (private networking, customer-managed keys, logging, least-privilege roles) into rules that can fail a plan.

| project | stars | known for | what this repo adds |
|---|---|---|---|
| aws-samples/amazon-bedrock-workshop | 2220 | Hands-on workshop material for building with Amazon Bedrock. | A pre-deploy check of the guardrails around a Bedrock workload; the samples teach, this repo verifies. |
| aws-samples/amazon-bedrock-samples | 1529 | Code samples for Amazon Bedrock. | The same: rules for logging, private endpoints, KMS and IAM, with mutation-tested checks. |
| Azure/agent-landing-zone | 1204 | A landing zone reference for agent workloads on Azure. | Plan checks for Azure OpenAI settings (public access, local auth, CMK, diagnostics) with fail-closed behaviour. |
| awslabs/generative-ai-cdk-constructs | 543 | CDK constructs for generative AI patterns on AWS. | Checks Terraform plans, not CDK; verifies the result rather than generating it. |
| Azure/azure-openai-landing-zone | 118 | A landing zone reference for Azure OpenAI. | Rule-level verification of the same controls, with waiver expiry and AI RMF mapping. |
| aws-ia/terraform-aws-bedrock | 88 | A Terraform module for Amazon Bedrock. | An independent plan check that can be run on any module's output, with fail-closed behaviour. |
