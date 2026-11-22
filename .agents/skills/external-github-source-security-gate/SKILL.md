---
name: external-github-source-security-gate
description: Use when Jack asks to check or scan a GitHub repository for security threats, malware, suspicious scripts, secrets, vulnerabilities or safety, and before downloading, cloning, installing, testing or integrating third-party public GitHub source for ProfitFlowing. Run the trusted gate and review the exact-commit report.
---

# External GitHub Source Security Gate

Examples that invoke this process include “check this GitHub repo for security threats”, “scan these repos for malware”, and “is this GitHub template safe to use?” Use it for a security-only assessment as well as before adopting external code. Scan and report only when Jack asks for a check.

1. Resolve the exact `owner/repository` for each target from the request and current chat. Resolve any requested branch or tag to a full commit SHA using GitHub metadata. With no requested revision, use the target's default branch. Ask only for information that cannot be resolved without guessing. If Jack asks for a prompt, fill in [the copyable prompt](https://github.com/jprofitflowing/profitflowing-template-security/blob/main/PROMPT.md) and stop there.
2. Confirm the target is public before dispatch. Keep private repository identifiers, source and findings out of public Actions inputs, logs and summaries. For an authorised existing private ProfitFlowing checkout, use the local security review process and report its actual coverage. For other private targets, identify the access or private scan route required.
3. Dispatch one run per public target using [the Actions workflow on main](https://github.com/jprofitflowing/profitflowing-template-security/actions/workflows/source-security.yml). In local Codex, use the authorised GitHub CLI if available.

   ```shell
   gh workflow run source-security.yml --repo jprofitflowing/profitflowing-template-security --ref main -f repository=OWNER/REPOSITORY
   ```

   Add `-f commit=FULL_SHA` for a specified revision. Save the returned run URL, wait for the run, and use its report even if GitHub marks the job as failed. Check whether the dispatch was accepted before retrying a transient failure.
4. If you can read GitHub but cannot dispatch, give Jack the workflow link and the exact **Run workflow** inputs for each public target. Ask him to return the run URL or paste its **Summary**. Treat the scan as pending until there is evidence. If you can dispatch but cannot read the report, give him the run link and ask for the Summary.
5. Verify the Summary matches the target and exact SHA. Use `gh run view RUN_ID --repo jprofitflowing/profitflowing-template-security --log` if needed. The sanitised report appears between `SOURCE GATE REPORT BEGIN` and `SOURCE GATE REPORT END`. Return the run link, full source SHA, verdict, any incomplete checks, key findings and next action for each repository. Treat missing, stale, skipped or mismatched evidence and scanner failures as incomplete. Use the verdict in the report.
6. Hold download into the development workspace, installation and integration for **BLOCKED**, **NEEDS REVIEW**, incomplete or unavailable reports. **READY FOR ISOLATED TESTING** allows authorised isolated testing of that SHA. Before any production integration, use fictional data for runtime tests, monitor outbound traffic, review asset and dependency licences, remove unapproved scripts, rescan changed source and obtain production approval from the owning project.

The gate runs on GitHub and requires only the authorised public workflow. Keep third-party code inactive during review. A static scan cannot guarantee absence of malware.
