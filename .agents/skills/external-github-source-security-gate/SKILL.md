---
name: external-github-source-security-gate
description: Use before downloading, cloning, installing, testing or integrating a third-party public GitHub repository for ProfitFlowing. Run the external source scan, inspect its exact-commit report and hold any blocked, incomplete or unresolved source. Use for templates and open-source packages obtained from GitHub.
---

# External GitHub Source Security Gate

1. Resolve the exact public GitHub `owner/repository` and intended commit, if known. Metadata lookup is permitted before scanning. Keep private repositories and private data out of this public gate.
2. Dispatch [the trusted workflow on main](https://github.com/jprofitflowing/profitflowing-template-security/actions/workflows/source-security.yml) in the connected ProfitFlowing GitHub account. Use the Actions tab, or run `gh workflow run source-security.yml --repo jprofitflowing/profitflowing-template-security --ref main -f repository=OWNER/REPOSITORY`. Add `-f commit=FULL_SHA` when the intended revision is already known. Match the resulting run to the request and wait for its report.
3. Read the summary and record the run link, exact external source SHA, verdict, each check's completeness and any unresolved findings in the owning task. The sanitised report is also in the scan step log between `SOURCE GATE REPORT BEGIN` and `SOURCE GATE REPORT END`. Treat missing, skipped, stale or mismatched reports and any scanner failure as incomplete.
4. Hold download into the development workspace, installation and integration for **BLOCKED**, **NEEDS REVIEW**, incomplete or unavailable reports. Report the exact hold and the next verification required. Tell Jack how to dispatch the gate if the current environment lacks Actions access. Never treat a GitHub status icon as the verdict.
5. **READY FOR ISOLATED TESTING** allows the authorised isolated test of that exact SHA. Use fictional data, no production credentials, and observe outbound traffic. Review asset and dependency licences. Remove unapproved scripts and rescan changed source. Require affirmative production approval through the owning ProfitFlowing project after those checks.

Never auto-merge, install or publish into ProfitFlowing. Never say a scan guarantees absence of malware. For non-public source, hold and obtain a separately authorised private scanning route.
