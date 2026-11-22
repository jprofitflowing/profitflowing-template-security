# Copyable GitHub security-check prompt

Use this in any chat that can read the ProfitFlowing security gate repository. Add the public GitHub links or `owner/repository` names you want checked. You can list several. Include a branch, tag or commit when it matters.

```text
Check these GitHub repositories for security threats before I use them in ProfitFlowing.

Targets:
- [Public GitHub link or owner/repository]
- [Add any other public repositories, with a branch, tag or commit if relevant]

Read and follow the External GitHub Source Security Gate instructions:
https://github.com/jprofitflowing/profitflowing-template-security/blob/main/.agents/skills/external-github-source-security-gate/SKILL.md

Use any exact targets already established in this chat. Ask for the missing repository only if the intended target is unclear. The gate repository above provides the instructions.

Run the gate if you can dispatch GitHub Actions. Otherwise give me the exact run instructions and ask me to return each run URL or its Summary. Keep private targets out of the public workflow. Report one result per repository with the exact commit, verdict, run link and any findings or incomplete checks. Hold any blocked, incomplete or unresolved source. Stop at the scan and review.
```

If the target repositories were discussed in another chat, open this file there and ask it to **fill in the prompt with the public repositories from that chat and return it without running scans**. Include only targets you can identify exactly and omit unused placeholder lines.
