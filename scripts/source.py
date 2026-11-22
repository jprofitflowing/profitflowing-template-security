"""Acquire an exact public Git tree without checking it out."""

import json
import os
import re
import subprocess
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

REPOSITORY = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?/[a-zA-Z0-9_.-]{1,100}")
SHA = re.compile(r"[a-f0-9]{40}")
LFS = b"version https://git-lfs.github.com/spec/v1"
MIB = 1024 * 1024
MAX_FILE = 40 * MIB
MAX_TREE = 500 * MIB
MAX_ENTRIES = 50_000


class SourceError(Exception):
    """An acquisition failure with a message safe for a public report."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def api(repository, path=""):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "ProfitFlowing-source-gate"}
    if token := os.environ.get("GATE_METADATA_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    request = Request(
        f"https://api.github.com/repos/{repository}{path}",
        headers=headers,
    )
    with build_opener(NoRedirect()).open(request, timeout=25) as response:
        return json.load(response)


def acquire(repository, requested_sha, work, target, report):
    if not REPOSITORY.fullmatch(repository) or repository.split("/")[1] in (".", ".."):
        raise SourceError("Expected a GitHub repository in owner/repository format.")
    report["repository"] = repository
    if requested_sha and not SHA.fullmatch(requested_sha):
        raise SourceError("An optional commit must be a full lowercase Git SHA.")
    try:
        meta = api(repository)
    except HTTPError as error:
        raise SourceError(f"GitHub repository metadata returned HTTP {error.code}.") from None
    if (meta.get("visibility") != "public" or meta.get("private") is not False
            or meta.get("full_name", "").lower() != repository.lower()):
        raise SourceError("GitHub did not confirm the exact repository is public.")
    report["repository"] = meta["full_name"]

    empty = work / "git-settings"
    empty.mkdir()
    git_dir = work / "objects"
    git_env = {
        "PATH": os.environ["PATH"], "HOME": str(empty), "XDG_CONFIG_HOME": str(empty),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_ALLOW_PROTOCOL": "https", "LC_ALL": "C",
    }
    git = ["git", "-c", "http.followRedirects=false", "-c", "fetch.fsckObjects=true"]

    def run_git(*args, cwd=git_dir, capture=False, seconds=180):
        return subprocess.run(
            [*git, *args], cwd=cwd, env=git_env, check=True, timeout=seconds,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).stdout

    run_git("init", "--bare", f"--template={empty}", str(git_dir), cwd=work)
    run_git(
        "fetch", "--depth=1", "--no-tags", "--no-recurse-submodules", "--",
        f"https://github.com/{repository}.git", requested_sha or "HEAD",
    )
    commit = run_git("rev-parse", "--verify", "FETCH_HEAD^{commit}", capture=True).decode().strip()
    if not SHA.fullmatch(commit) or (requested_sha and commit != requested_sha):
        raise SourceError("The fetched commit did not match the requested commit.")
    report["commit"] = commit
    tree = run_git("ls-tree", "-r", "-z", "-l", "--full-tree", commit, capture=True)
    entries = tree.split(b"\0")[:-1]
    if len(entries) > MAX_ENTRIES:
        raise SourceError(f"Tree exceeds the {MAX_ENTRIES:,}-entry scan limit.")

    target.mkdir()
    total = 0
    files = {}
    with subprocess.Popen(
        [*git, "cat-file", "--batch"], cwd=git_dir, env=git_env, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    ) as reader:
        try:
            for entry in entries:
                description, raw_name = entry.split(b"\t", 1)
                mode, kind, blob, size = description.split()
                try:
                    name = raw_name.decode("utf-8")
                except UnicodeDecodeError:
                    report["add"]("Source", "Unsupported filename encoding")
                    continue
                parts = name.split("/")
                if any(part.lower() in ("", ".", "..", ".git") or "\\" in part
                       or any(ord(char) < 32 or ord(char) == 127 for char in part) for part in parts):
                    report["add"]("Source", "Unsafe path omitted")
                    continue
                if kind != b"blob" or mode not in (b"100644", b"100755"):
                    reason = "Submodule content omitted" if mode == b"160000" else "Non-regular file omitted"
                    report["add"]("Source", reason, name)
                    continue
                size = int(size)
                if size > MAX_FILE:
                    report["add"]("Source", "File exceeded the scan size limit", name)
                    continue
                total += size
                if total > MAX_TREE:
                    raise SourceError("Tree exceeds the 500 MiB materialisation limit.")
                reader.stdin.write(blob + b"\n")
                reader.stdin.flush()
                if reader.stdout.readline().split() != [blob, b"blob", str(size).encode()]:
                    raise SourceError("Git returned an unexpected blob header.")
                content = reader.stdout.read(size)
                if len(content) != size or reader.stdout.read(1) != b"\n":
                    raise SourceError("Git returned an incomplete blob.")
                destination = target.joinpath(*parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("xb") as output:
                    output.write(content)
                files[name] = (mode == b"100755", blob.decode())
                if content.startswith(LFS + b"\n") or content.startswith(LFS + b"\r\n"):
                    report["add"]("Source", "Git LFS content omitted", name)
        finally:
            reader.stdin.close()
            reader.wait(timeout=10)
    if not files or reader.returncode:
        raise SourceError("Git did not produce a scannable source tree.")
    return files


def licence(report, files, policy):
    try:
        info = api(report["repository"], "/license?" + urlencode({"ref": report["commit"]}))
    except HTTPError as error:
        return f"Unclassified (GitHub licence metadata HTTP {error.code})", "review"
    if files.get(info.get("path"), (False, ""))[1] != info.get("sha"):
        return "Unclassified (licence could not be matched to the scanned Git blob)", "review"
    spdx = (info.get("license") or {}).get("spdx_id")
    if spdx in policy["licences"]["allowed"]:
        return spdx, "ok"
    if spdx in policy["licences"]["blocked"]:
        return spdx, "block"
    return "Unclassified by policy" if not spdx else spdx, "review"
