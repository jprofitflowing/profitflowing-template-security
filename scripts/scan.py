"""Run trusted scanners and publish a fail-closed, redacted verdict."""

import html
import json
import os
import re
import subprocess
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import extra_checks
import heuristics
import source

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "policy/gate.json").read_text())
CHECKS = ("Source", "ClamAV", "Trivy", "OSV", "Static", "Semgrep", "CodeQL JS/TS", "CodeQL Actions", "Licence")
MAX_EXAMPLES = 3
TRIVY_LOG_LEVEL = re.compile(r"^\S+\s+(WARN|ERROR|FATAL)\s+(.*)$")


class Incomplete(Exception):
    """A failed check with a fixed, publishable explanation."""


def safe(value):
    value = str(value)[:240]
    value = re.sub(r"[^a-zA-Z0-9_ ./@+():,=\[\]-]", "?", value)
    return html.escape(value).replace("@", "&#64;").replace(".", "&#46;").replace("[", "&#91;")


def identifier(value):
    # Never publish arbitrary descriptions, dependency versions or matched text.
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._:/-]{1,90}", value) else "Unclassified ID"


class Report:
    def __init__(self):
        self.data = {"repository": "Unvalidated input", "commit": "Unknown", "add": self.add}
        self.status = {name: ("INCOMPLETE", "Check did not run.") for name in CHECKS}
        self.counts = Counter()
        self.examples = defaultdict(list)
        self.domains = set()

    def add(self, checker, reason, path=None, level="review"):
        key = (checker, level, reason)
        self.counts[key] += 1
        if path and len(self.examples[key]) < MAX_EXAMPLES:
            self.examples[key].append(path.removeprefix("/source/"))

    def run(self, name, function):
        try:
            detail = function()
            self.status[name] = ("COMPLETED", detail)
        except (source.SourceError, Incomplete) as error:
            self.status[name] = ("INCOMPLETE", str(error))
        except Exception as error:
            # Exceptions from parsers can contain source fragments.
            self.status[name] = ("INCOMPLETE", f"Unexpected failure ({type(error).__name__}).")
        return self.status[name][0] == "COMPLETED"

    def publish(self):
        groups = Counter()
        for (_, level, _), count in self.counts.items():
            groups[level] += count
        if groups["block"]:
            verdict = "BLOCKED"
        elif groups["review"] or any(state == "INCOMPLETE" for state, _ in self.status.values()):
            verdict = "NEEDS REVIEW"
        else:
            verdict = "READY FOR ISOLATED TESTING"
        lines = [
            f"## {verdict}", "",
            f"- Repository: {safe(self.data['repository'])}",
            f"- Source directory: {safe(self.data.get('scope', '.'))}",
            f"- Source commit: {safe(self.data['commit'])}",
            f"- Gate commit: {safe(os.environ.get('GITHUB_SHA', 'Unknown'))}",
            f"- Findings: {groups['block']} blocking, {groups['review']} requiring review, "
            f"{groups['info']} informational", "",
            "| Check | Status | Evidence or limitation |", "| --- | --- | --- |",
        ]
        for name, (state, detail) in self.status.items():
            lines.append(f"| {name} | **{state}** | {safe(detail)} |")
        order = {"block": 0, "review": 1, "info": 2}
        findings = sorted(self.counts.items(), key=lambda item: (order[item[0][1]], -item[1], item[0]))
        if findings:
            lines.extend(["", "### Findings"])
            # Keep coverage and other dimensions visible when a lockfile has many CVEs.
            check_rows = Counter()
            shown = 0
            for key, count in findings:
                checker, level, reason = key
                grouping = (checker, level)
                if check_rows[grouping] >= 18:
                    continue
                check_rows[grouping] += 1
                shown += 1
                paths = ", ".join(safe(path) for path in self.examples[key])
                suffix = f" ({paths})" if paths else ""
                lines.append(f"- **{level.upper()}** · {checker} · {safe(reason)} × {count}{suffix}")
            if len(findings) > shown:
                lines.append(f"- {len(findings) - shown} more finding types omitted from the public summary.")
        if self.domains:
            lines.extend(["", f"### Literal network destinations in code and markup ({len(self.domains)} observed)",
                          ", ".join(safe(host) for host in sorted(self.domains)[:25]),
                          "These strings may include examples. Resolved and dynamic destinations need runtime review."])
        lines.extend(["", "Before production, complete isolated runtime testing, monitor outbound traffic, "
                      "review asset and dependency licences, and remove unapproved scripts. "
                      "This report covers a Git snapshot and cannot guarantee absence of malware."])
        summary = "\n".join(lines) + "\n"
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
            output.write(summary)
        print("SOURCE GATE REPORT BEGIN\n" + summary + "SOURCE GATE REPORT END", flush=True)
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write("report_written=true\n")
        return 0 if verdict == "READY FOR ISOLATED TESTING" else 1


def command(args, work, label, seconds):
    stdout, stderr = work / f"{label}.out", work / f"{label}.err"
    env = {key: os.environ[key] for key in ("PATH", "HOME") if key in os.environ}
    env["LC_ALL"] = "C.UTF-8"
    try:
        with stdout.open("wb") as out, stderr.open("wb") as err:
            result = subprocess.run(args, cwd=work, env=env, stdout=out, stderr=err, timeout=seconds)
    except subprocess.TimeoutExpired:
        raise Incomplete(f"{label} timed out after {seconds} seconds.") from None
    return result.returncode, stdout, stderr


def docker(tool, work, label, args, *, mounts=(), entry=None, network=False, seconds=420, root=False):
    image = POLICY["images"][tool]
    name = f"gate-{work.name}-{label}".lower()
    options = [
        "docker", "run", "--rm", "--name", name, "--pull=never", "--workdir=/",
        "--security-opt=no-new-privileges", "--pids-limit=256", "--memory=4g", "--cpus=2",
        "--read-only", "--tmpfs=/tmp:rw,nosuid,nodev,size=1g", "--env=HOME=/tmp",
    ]
    if not network:
        options.extend(("--network=none", "--cap-drop=ALL"))
    if not root:
        options.extend(("--user", f"{os.getuid()}:{os.getgid()}"))
    if entry:
        options.extend(("--entrypoint", entry))
    for mount in mounts:
        options.extend(("--mount", mount))
    try:
        return command([*options, image, *args], work, label, seconds)
    except Incomplete:
        command(["docker", "rm", "-f", name], work, "container-cleanup", 20)
        raise


def pull(tool, work):
    code, _, _ = command(["docker", "pull", POLICY["images"][tool]], work, f"{tool}-pull", 240)
    if code:
        raise Incomplete(f"{tool} pinned image could not be downloaded (exit {code}).")


def scan_clam(work, target_mount, report, expected):
    pull("ClamAV", work)
    volume = f"clam-db-{work.name}"
    db = f"type=volume,src={volume},dst=/var/lib/clamav"
    config = work / "freshclam.conf"
    config.write_text("DatabaseOwner clamav\nDatabaseMirror database.clamav.net\n")
    config_mount = f"type=bind,src={config},dst=/freshclam.conf,readonly"
    try:
        code, _, _ = docker("ClamAV", work, "freshclam", ["--stdout", "--config-file=/freshclam.conf"],
                            mounts=(db, config_mount),
                            entry="freshclam", network=True, root=True, seconds=360)
        if code:
            raise Incomplete(f"FreshClam could not confirm updated signatures (exit {code}).")
        code, version, _ = docker("ClamAV", work, "clam-version", ["--version"],
                                  mounts=(db + ",readonly",), entry="clamscan", seconds=30)
        identity = version.read_text(errors="replace").strip()
        if code or not re.fullmatch(r"ClamAV [0-9.]+/[0-9]+/[A-Za-z0-9 :]+", identity):
            raise Incomplete("ClamAV signature version could not be verified.")
        code, output, errors = docker(
            "ClamAV", work, "clamscan", [
                "--recursive", "--infected", "--follow-dir-symlinks=0", "--follow-file-symlinks=0",
                "--alert-exceeds-max=yes", "--max-filesize=40M", "--max-scansize=150M", "/source",
            ], mounts=(target_mount, db + ",readonly"), entry="clamscan",
        )
        scanned = 0
        limit_alerts = 0
        malware_alerts = 0
        with output.open(errors="replace") as lines:
            for line in lines:
                match = re.fullmatch(r"Scanned files:\s+(\d+)\s*", line)
                if match:
                    scanned = int(match[1])
                if not line.rstrip().endswith(" FOUND"):
                    continue
                path, _, signature = line.rstrip()[:-len(" FOUND")].rpartition(": ")
                if signature.startswith("Heuristics.Limits.Exceeded"):
                    limit_alerts += 1
                    report.add("ClamAV", "Scan limit exceeded inside a file", path)
                else:
                    malware_alerts += 1
                    report.add("ClamAV", "Detection " + identifier(signature), path, "block")
        if (code not in (0, 1) or scanned < expected or not scanned or (code == 1 and not (limit_alerts or malware_alerts))
                or limit_alerts or re.search(r"(?im)\b(error|failed):", errors.read_text(errors="replace"))):
            raise Incomplete(f"ClamAV reported a scan error, internal limit or incomplete result (exit {code}).")
        return f"{identity}. {scanned} files scanned, {malware_alerts} detections. {expected} nonempty tracked files."
    finally:
        command(["docker", "volume", "rm", volume], work, "clam-volume-cleanup", 30)


def scan_trivy(work, target_mount, report, files):
    pull("Trivy", work)
    cache = work / "trivy-cache"
    cache.mkdir()
    mount = f"type=bind,src={cache},dst=/cache"
    base = ["filesystem", "--cache-dir", "/cache", "--skip-version-check", "--disable-telemetry"]
    code, _, _ = docker("Trivy", work, "trivy-db", [*base, "--download-db-only"], mounts=(mount,), network=True)
    if code:
        raise Incomplete(f"Trivy vulnerability database could not be updated (exit {code}).")
    stamp = json.loads((cache / "db/metadata.json").read_text())["UpdatedAt"]
    updated = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    if not timedelta(hours=-1) <= datetime.now(timezone.utc) - updated <= timedelta(days=2):
        raise Incomplete("Trivy database update timestamp is outside the 48-hour freshness window.")
    if any(Path(name).suffix.lower() in {".jar", ".war", ".ear", ".par"} for name in files):
        code, _, _ = docker("Trivy", work, "trivy-java-db", [*base, "--download-java-db-only"],
                            mounts=(mount,), network=True)
        if code:
            raise Incomplete(f"Trivy Java index could not be downloaded (exit {code}).")
    code, output, errors = docker(
        "Trivy", work, "trivy-fs", [
            *base, "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--offline-scan",
            "--scanners", "vuln,secret,misconfig,license", "--license-full", "--ignorefile=", "--secret-config=", "--include-dev-deps",
            "--include-non-failures",
            "--parallel", "2", "--timeout", "6m", "--format", "json", "/source",
        ], mounts=(target_mount, mount),
    )
    if code:
        raise Incomplete(f"Trivy did not complete its filesystem scan (exit {code}).")
    data = json.loads(output.read_text())
    if not data.get("SchemaVersion") or data.get("ArtifactType") != "filesystem":
        raise Incomplete("Trivy did not return a filesystem report.")
    results = data.get("Results") or []
    for result in results:
        target = result.get("Target", "")
        for group, field in (("Vulnerabilities", "VulnerabilityID"), ("Misconfigurations", "ID"), ("Secrets", "RuleID")):
            for finding in result.get(group) or []:
                if group == "Misconfigurations" and finding.get("Status") not in (None, "FAIL"):
                    continue
                severity = identifier(finding.get("Severity"))
                if group == "Secrets" or severity in POLICY["block_trivy_severities"]:
                    level = "block"
                elif severity in POLICY["review_trivy_severities"] or severity == "Unclassified ID":
                    level = "review"
                else:
                    level = "info"
                category = {"Vulnerabilities": "Dependency", "Misconfigurations": "Config", "Secrets": "Secret"}[group]
                label = f"{category} {severity} {identifier(finding.get(field))}"
                if group == "Vulnerabilities":
                    package = extra_checks.package_label(finding.get("PkgName"), finding.get("InstalledVersion"),
                                                         finding.get("FixedVersion"))
                    label += f" {package}"
                report.add("Trivy", label, target if group != "Secrets" else None, level)
        for finding in result.get("Licenses") or []:
            category = identifier(finding.get("Category")).lower()
            level = "review" if category in ("forbidden", "restricted", "reciprocal", "unknown", "unclassified id") else "info"
            report.add("Trivy", f"Licence {identifier(finding.get('Name'))} ({category})",
                       finding.get("FilePath") or target, level)
    for line in errors.read_text(errors="replace").splitlines():
        logged = TRIVY_LOG_LEVEL.fullmatch(line)
        if not logged:
            continue
        severity, message = logged.groups()
        # The policy uses the checks compiled into this pinned image. No OCI policy cache is populated.
        if (severity == "ERROR" and message.startswith("[misconfig] Falling back to embedded checks")
                and 'failed to check cache: cache does not exist at' in message
                and "/cache/policy/content" in message):
            continue
        if severity in ("ERROR", "FATAL") or re.search(
                r"skip|fail|unable|unsupported|could not|too (?:large|big)", message, re.IGNORECASE):
            raise Incomplete("Trivy reported a scan error or coverage warning beyond the expected embedded checks.")
    inventories = sum(result.get("Class") == "lang-pkgs" for result in results)
    if not inventories and any(Path(name).name in heuristics.LOCKS for name in files):
        raise Incomplete("Lockfiles were present but Trivy returned no language package inventory.")
    version = POLICY["images"]["Trivy"].split(":", 1)[1].split("@", 1)[0]
    return f"Trivy {version}: vulnerabilities, secrets, configuration and licences. DB {updated:%Y-%m-%d %H:%M} UTC. {inventories} dependency inventories."


def scan_semgrep(work, target_mount, report, expected):
    if not expected:
        return "Not applicable to this snapshot. No files match the configured JS/TS, Python, Go or PHP rules."
    pull("Semgrep", work)
    rules = f"type=bind,src={ROOT / 'policy'},dst=/policy,readonly"
    code, output, _ = docker(
        "Semgrep", work, "semgrep", [
            "scan", "--config=/policy/semgrep.yml", "--metrics=off", "--disable-version-check", "--no-git-ignore",
            "--x-ignore-semgrepignore-files", "--disable-nosem", "--no-rewrite-rule-ids",
            "--strict", "--max-target-bytes=8388608", "--timeout=10", "--jobs=2", "--json", "/source",
        ], mounts=(target_mount, rules), entry="semgrep",
    )
    data = json.loads(output.read_text()) if output.stat().st_size else {}
    for match in data.get("results") or []:
        path, line = match.get("path"), (match.get("start") or {}).get("line")
        location = f"{path}:{line}" if path and isinstance(line, int) else path
        report.add("Semgrep", identifier(match.get("check_id")), location)
    scanned = {
        path.removeprefix("/source/").removeprefix("source/")
        for path in (data.get("paths") or {}).get("scanned", [])
    }
    missing = expected - scanned
    for path in sorted(missing):
        report.add("Semgrep", "Expected source file absent from the scan", path)
    if code or data.get("errors") or missing:
        raise Incomplete(f"Semgrep exit {code}. Analysed {len(expected & scanned)} of {len(expected)} expected files. "
                         f"{len(data.get('errors') or [])} analysis errors.")
    unit = "file" if len(expected) == 1 else "files"
    return f"Semgrep {POLICY['images']['Semgrep'].split(':', 1)[1].split('@', 1)[0]} local rules analysed {len(expected)} external source {unit}."


def main():
    report = Report()
    with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP"), prefix="source-gate-") as scratch:
        work = Path(scratch)
        target = work / "tree"
        target_mount = f"type=bind,src={target},dst=/source,readonly"

        def acquire():
            nonlocal files
            files = source.acquire(os.environ["SOURCE_REPOSITORY"], os.environ.get("SOURCE_COMMIT", ""),
                                   work, target, report.data, os.environ.get("SOURCE_PATH", ""))
            if any(check == "Source" and level == "review" for check, level, _ in report.counts):
                raise Incomplete(f"Materialised {len(files)} tracked files. Some content was omitted.")
            return f"Materialised {len(files)} tracked files from Git blobs. No checkout filters or hooks ran."

        def inspect():
            nonlocal expected
            expected, report.domains = heuristics.inspect(target, files, report)
            return f"Inspected {len(files)} files for active content, executable files, hooks and network markers."

        def licence():
            description, level = source.licence(report.data, files, POLICY)
            if level != "ok":
                report.add("Licence", description, level=level)
            return f"Repository licence {description}. Assets and dependencies require separate review."

        files, expected = {}, set()
        report.run("Source", acquire)
        if files:
            inspected = report.run("Static", inspect)
            nonempty = sum((target / name).stat().st_size > 0 for name in files)
            report.run("ClamAV", lambda: scan_clam(work, target_mount, report, nonempty))
            report.run("Trivy", lambda: scan_trivy(work, target_mount, report, files))
            if inspected:
                report.run("Semgrep", lambda: scan_semgrep(work, target_mount, report, expected))
            report.run("Licence", licence)
            tools = extra_checks.StaticTools(work, target, target_mount, files, report, POLICY, command, docker, pull, Incomplete)
            report.run("OSV", tools.osv)
            opensource = report.status["Licence"][1].startswith(tuple(
                f"Repository licence {spdx}. " for spdx in POLICY["licences"]["allowed"]
            ))
            for language, name in (("javascript", "CodeQL JS/TS"), ("actions", "CodeQL Actions")):
                report.run(name, lambda: tools.codeql(language, name, opensource))
    return report.publish()


if __name__ == "__main__":
    raise SystemExit(main())
