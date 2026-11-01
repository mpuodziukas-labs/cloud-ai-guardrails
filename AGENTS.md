# Verifying this repository

Purpose: Show that an offline checker of Terraform plan JSON enforces eight guardrails on AI workloads (AWS Bedrock, Azure OpenAI), fails closed on unreadable, unknown or missing values, and rejects expired or incomplete waivers.

Verify: `bash run.sh`

Pass condition: exit code 0 and these exact output lines: `cases: N/N match` from evaluate.py and, as the last line, `mutants: K/K killed`.

Scope: synthetic hand-written plan fixtures, offline, standard library only.

Limitations: engineering evidence, not legal advice, no certification claimed. Framework mappings are the author's reading.

Anything else = not verified.
