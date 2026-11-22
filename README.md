# External GitHub Source Security Gate

Run a static security scan before bringing public GitHub source into ProfitFlowing. The gate scans the tracked files at one commit on a disposable standard GitHub-hosted Ubuntu runner. It uses free public-repository compute and retains the Actions summary and redacted job log. It uploads no artifacts or scanner caches. [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions)

## Run a scan

1. Open [Actions → External GitHub Source Security Gate](https://github.com/jprofitflowing/profitflowing-template-security/actions/workflows/source-security.yml).
2. Select **Run workflow** on the default branch. Enter a public repository such as `owner/repository`. Leave **commit** blank to scan the default branch HEAD, or enter a full lowercase SHA to repeat the same source snapshot. GitHub requires write access to dispatch.
3. Open the run and read its **Summary**. Confirm the repository, source SHA, gate SHA, check statuses and finding counts. Use the recorded SHA for any later review. A repeat scan can have different results because malware signatures and vulnerability advisories change.

The optional commit pins the external source. The Actions branch selects the trusted gate workflow. Keep it on the default branch. If the job is skipped, cancelled, times out or produces no verdict, treat the report as **INCOMPLETE** and the source as **NEEDS REVIEW**.

## Read the outcome

| Outcome | Meaning |
| --- | --- |
| **BLOCKED** | ClamAV detected malware or the policy flagged a serious vulnerability, misconfiguration, exposed secret or disallowed repository licence. Review findings and false positives before any further approval. |
| **NEEDS REVIEW** | A check was incomplete, coverage was missing, the licence was unclear or an indicator needs investigation. A completed check can still have findings. |
| **READY FOR ISOLATED TESTING** | Required checks completed for their declared scope, and the report contains no blocking or review findings. This permits isolated testing only. |

For automation, both held verdicts return a failing job status. The report has precedence over the GitHub check icon. A blocked result stays blocked if another scanner is incomplete. Tool crashes, missing data, internal limits and scanner timeouts never yield a ready verdict.

Review findings at the recorded source commit. Public reports show selected paths, detector IDs and literal hostnames. The gate omits secret matches, source snippets, URL paths and raw scanner output. Keep follow-up investigation out of the public log. Even a ready verdict cannot guarantee that the source is free of malware.

## Coverage and boundaries

- **Source:** anonymous HTTPS fetch into a bare Git directory. The gate reads tracked blobs directly, ignores checkout filters and hooks, and skips submodules, Git LFS payloads and symlinks. Source beyond the 40 MiB per-file, 500 MiB tree or 50,000-entry limits causes a coverage hold.
- **ClamAV:** FreshClam updates or confirms official signatures before the offline scan. Malware hits, scan limits and tool failures are reported separately.
- **Trivy:** scans source files for known dependency vulnerabilities, secrets and infrastructure misconfigurations using a fresh vulnerability database and the scanner image's bundled configuration checks. This covers supported file formats and recognised dependency inventories. Downloaded dependencies, container images and infrastructure outside the snapshot are outside this scan.
- **Static and Semgrep CE:** looks for executable files, suspicious JavaScript, obfuscation, install hooks, embedded scripts and outbound-network indicators. The checked-in Semgrep rules analyse supported JavaScript, TypeScript, Python, Go and PHP files in the **external** source tree. Unsupported languages and missing expected targets require review. Rules are deliberately narrow and cannot establish full code coverage or intent.
- **Licence:** GitHub's SPDX result must match a licence blob at the scanned commit. The allow and block lists in [gate.json](policy/gate.json) are preliminary company screening policy. Review all shipped assets and dependencies separately, including fonts, photos, icons, bundles and individual template folders.

The workflow never invokes the external repository's workflows, scripts, build, package manager or install commands. Scanner containers receive source read-only with no network access. The job's temporary read-only GitHub token is used for trusted workflow checkout and GitHub metadata requests. The external Git fetch is anonymous, and the scanners receive no token. No production secrets, self-hosted or paid runners, release steps, uploads or integration permissions are used.

Before production integration, run the approved commit in a fresh isolated environment with fictional data and no production credentials. Monitor external network requests, review the licences of code, dependencies and assets, and remove unapproved scripts. Rescan a changed commit and obtain approval through the owning ProfitFlowing project before integration.

## Maintain the gate

- Keep this repository public and the workflow on the standard `ubuntu-24.04` GitHub runner. Keep write access limited to trusted maintainers.
- Review scanner security advisories and upstream release notes before changing versions. Pin reviewed scanner images by digest in [gate.json](policy/gate.json). Pin any GitHub Action to a reviewed full commit SHA. The scanner data updates independently of the pinned engines.
- Review [the Semgrep rules](policy/semgrep.yml) and the licence lists when supported stacks or company policy change. Confirm rule execution against known-safe fixtures and benign synthetic detections. Check that a scanner failure or omitted file holds the verdict.
- Re-run the [three initial public source scans](https://github.com/jprofitflowing/profitflowing-template-security/actions/workflows/source-security.yml) after material scanner or policy changes. Use the run summaries to verify coverage and investigate any failure before treating a candidate as ready.
- Install the [AI skill](.agents/skills/external-github-source-security-gate/SKILL.md) in each coding environment and add the invocation rule to the environment's top-level instructions. Automatic discovery depends on those instructions and the skill being present.
