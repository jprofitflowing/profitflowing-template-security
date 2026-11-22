"""Verify an exact, reviewed source before a person or importer fetches it."""

import json
import re
import sys
from pathlib import Path

import source

MANIFEST = Path(__file__).resolve().parents[1] / "policy/approved-sources.json"
RUN = re.compile(r"https://github\.com/jprofitflowing/profitflowing-template-security/actions/runs/[0-9]+")


def verify(repository, commit, scope):
    if (not source.REPOSITORY.fullmatch(repository) or repository.split("/")[1] in {".", ".."}
            or not source.SHA.fullmatch(commit)):
        return "Expected a GitHub owner/repository and a full lowercase commit SHA."
    records = json.loads(MANIFEST.read_text())
    matches = [entry for entry in records["approved_sources"]
               if entry["repository"].casefold() == repository.casefold() and entry.get("source_path", "") == scope]
    if len(matches) != 1:
        return "No unique approval for this repository and directory. Complete security and reuse review first."
    approved = matches[0]
    if (records["schema_version"] != 1 or not source.SHA.fullmatch(approved["commit"])
            or not RUN.fullmatch(approved["security_run"]) or approved["licence_decision"] != "approved"):
        return "Approval record is invalid or lacks security and reuse evidence."
    if commit != approved["commit"]:
        return "The requested commit differs from the approved snapshot. Reassess it before import."
    metadata = source.api(repository)
    if metadata.get("visibility") != "public" or metadata.get("full_name", "").casefold() != repository.casefold():
        return "Could not confirm the exact repository is public."
    if source.api(repository, "/commits/HEAD").get("sha") != approved["commit"]:
        return "Upstream HEAD changed. Reassess the new source before import."
    return None


def main():
    if len(sys.argv) != 4:
        print("Usage: verify_import.py OWNER/REPOSITORY FULL_SHA SOURCE_DIRECTORY")
        return 1
    try:
        failure = verify(*sys.argv[1:])
    except Exception:
        failure = "Approval evidence or upstream metadata could not be read. Import is held."
    print(failure or "Approved snapshot matches the requested commit and current upstream HEAD.")
    return int(failure is not None)


if __name__ == "__main__":
    raise SystemExit(main())
