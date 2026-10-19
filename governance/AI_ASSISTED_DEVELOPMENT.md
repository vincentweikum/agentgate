# AI-assisted development policy (STD-AI-06)

AI coding assistants are allowed, with the same guardrails as any other contributor.

1. **Disclose it.** The pull request template asks whether AI tools helped write the change, and which one.
2. **Own it.** The author reviews every AI-generated line and can explain it.
3. **Same gates.** AI-assisted changes go through the full pipeline: unit tests, contract tests,
   standards lint, breaking-change check, security scans, and agent guardrail scenarios.
4. **Human review.** Branch protection requires a CODEOWNER's approval. Changes to governance rules,
   scripts, CI workflows, client scopes, token checks, or the agent gateway need the governance owner.
5. **No secrets or customer data in prompts.** Use the seed data in `app/data.py`.

This repository was built with an AI coding assistant (Claude) under this policy.
