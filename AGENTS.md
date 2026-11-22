# Maintain the source security gate

This public repository contains trusted scanner workflows, scripts, rules and documentation. It must contain no private source, credentials, customer data, copied scan targets or raw scanner output. `main` is the canonical workflow ref.

For a security-check request, follow the [external-source skill](.agents/skills/external-github-source-security-gate/SKILL.md). When asked for a prompt, use [PROMPT.md](PROMPT.md) and fill it in from the known public targets.

Read [the README](README.md), [the decision policy](policy/gate.json) and the [external-source skill](.agents/skills/external-github-source-security-gate/SKILL.md) before changing the gate. Preserve manual dispatch, standard public runners, pinned actions and images, read-only source, offline scanner execution, redacted public reports and fail-closed outcomes. Verify material changes against real external source using the hosted workflow, including evidence that Semgrep analysed the external snapshot.
