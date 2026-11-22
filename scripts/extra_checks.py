"""Run checksum-pinned static tools with read-only source and no network."""

import json
import re
from datetime import datetime, timezone
from hashlib import file_digest
from pathlib import PurePosixPath

JS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".es6"}
INLINE_SCRIPT = re.compile(rb"<script\b[^>]*>\s*[^<\s]", re.IGNORECASE)
NPM_LOCKS = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"}


def package_label(name, version, fixed=None):
    name = str(name)
    version = str(version)
    label = name if re.fullmatch(r"[@a-zA-Z0-9._/+:-]{1,100}", name) else "unclassified package"
    if re.fullmatch(r"[v0-9][a-zA-Z0-9.+:~_-]{0,44}", version):
        label += f" {version}"
    if fixed and re.fullmatch(r"[v0-9][a-zA-Z0-9.,+ :~_-]{0,65}", str(fixed)):
        label += f" (fix {fixed})"
    return label


def bind(path, destination, readonly=True):
    return f"type=bind,src={path},dst={destination}" + (",readonly" if readonly else "")


class StaticTools:
    def __init__(self, work, target, source_mount, files, report, policy, command, docker, pull, incomplete):
        self.work, self.target, self.source_mount, self.files = work, target, source_mount, files
        self.report, self.policy = report, policy
        self.command, self.docker, self.pull, self.incomplete = command, docker, pull, incomplete

    def download(self, name, url, destination, checksum=None):
        code, _, _ = self.command([
            "curl", "--fail", "--silent", "--show-error", "--location", "--retry", "2",
            "--proto", "=https", "--proto-redir", "=https", "--remote-time",
            "--max-time", "120", "--output", str(destination), url,
        ], self.work, name, 260)
        if code or not destination.is_file() or not destination.stat().st_size:
            raise self.incomplete(f"{name} download failed (exit {code}).")
        if checksum:
            with destination.open("rb") as asset:
                if file_digest(asset, "sha256").hexdigest() != checksum:
                    raise self.incomplete(f"{name} did not match the pinned SHA256.")

    def osv(self):
        self.pull("OSV", self.work)
        spec = self.policy["tools"]["OSV"]
        database = self.work / "osv/npm/all.zip"
        database.parent.mkdir(parents=True)
        self.download("OSV npm advisory database", "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip", database)
        config = self.work / "osv-config.toml"
        config.write_text("\n")
        mounts = (bind(database.parent.parent, "/data", False), bind(config, "/trusted-config.toml"))
        common = ["scan", "source", "--offline", "--local-db-path=/data",
                  "--config=/trusted-config.toml", "--all-packages", "--format=json"]
        fixture = self.work / "osv-fixture"
        fixture.mkdir()
        package_lock = {
            "name": "gate-smoke", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
            "packages": {
                "": {"name": "gate-smoke", "version": "1.0.0", "dependencies": {"is-number": "7.0.0"}},
                "node_modules/is-number": {"version": "7.0.0"},
            },
        }
        (fixture / "package-lock.json").write_text(json.dumps(package_lock))
        code, output, errors = self.docker("OSV", self.work, "osv-fixture", [
            *common, "-L", "/fixture/package-lock.json",
        ], mounts=(*mounts, bind(fixture, "/fixture")), entry="/osv-scanner")
        if code not in (0, 1) or not output.stat().st_size:
            # This invocation can see only the trusted fixture and public advisory DB.
            diagnostic = " ".join(errors.read_text(errors="replace").split())[-158:]
            raise self.incomplete(f"OSV fixture failed (exit {code}). {diagnostic}")
        if not any(item.get("package", {}).get("name") == "is-number"
                   for result in json.loads(output.read_text()).get("results", [])
                   for item in result.get("packages", [])):
            raise self.incomplete("OSV did not analyse the fixture's expected package.")
        code, output, errors = self.docker("OSV", self.work, "osv", [
            *common, "--recursive", "--no-ignore", "--allow-no-lockfiles", "/source",
        ], mounts=(*mounts, self.source_mount), entry="/osv-scanner")
        if code not in (0, 1) or not output.stat().st_size:
            raise self.incomplete(f"OSV-Scanner {spec['version']} did not return results (exit {code}).")
        data = json.loads(output.read_text())
        results = data.get("results")
        if not isinstance(results, list):
            raise self.incomplete("OSV-Scanner did not return a source inventory.")
        packages = 0
        vulnerabilities = 0
        inventoried = set()
        for result in results:
            path = (result.get("source") or {}).get("path", "").removeprefix("/source/")
            inventoried.add(path)
            for item in result.get("packages") or []:
                packages += 1
                package = item.get("package") or {}
                name, version = package.get("name"), package.get("version")
                for advisory in item.get("vulnerabilities") or []:
                    identifier = advisory.get("id", "")
                    if not re.fullmatch(r"[A-Za-z0-9-]{1,80}", identifier):
                        raise self.incomplete("OSV-Scanner returned an invalid advisory identifier.")
                    vulnerabilities += 1
                    fixed = next((event["fixed"] for affected in advisory.get("affected", [])
                                  if affected.get("package", {}).get("name") == name
                                  for interval in affected.get("ranges", []) for event in interval.get("events", [])
                                  if "fixed" in event), None)
                    self.report.add("OSV", f"{identifier} {package_label(name, version, fixed)}", path)
        missing = {path for path in self.files if PurePosixPath(path).name in NPM_LOCKS} - inventoried
        for path in sorted(missing):
            self.report.add("OSV", "Lockfile yielded no reported package inventory", path)
        diagnostics = errors.read_text(errors="replace")
        if missing or (code == 1 and not vulnerabilities) or re.search(r"(?im)\b(error|failed|unable)\b", diagnostics):
            raise self.incomplete(f"OSV-Scanner {spec['version']} reported an error or incomplete inventory.")
        stamp = datetime.fromtimestamp(database.stat().st_mtime, timezone.utc)
        return (f"OSV-Scanner {spec['version']}. {packages} package entries, {vulnerabilities} advisory matches. "
                f"Offline npm database fetched; file timestamp {stamp:%Y-%m-%d %H:%M} UTC. "
                "Known lockfile fixture passed. Unpinned packages are outside advisory coverage.")

    def codeql(self, language, check, opensource):
        if language == "actions":
            candidates = [name for name in self.files if name.startswith(".github/workflows/")
                          and PurePosixPath(name).suffix.lower() in {".yaml", ".yml"}]
        else:
            candidates = [name for name in self.files if PurePosixPath(name).suffix.lower() in JS
                          or (PurePosixPath(name).suffix.lower() in {".html", ".htm"}
                              and INLINE_SCRIPT.search((self.target / name).read_bytes()))]
        if not candidates:
            return "Not applicable. No relevant source files in this snapshot."
        if not opensource:
            raise self.incomplete("Free CodeQL terms require a verified open-source licence. See Semgrep for fallback coverage.")
        self.pull("Analysis base", self.work)
        spec = self.policy["tools"]["CodeQL"][language]
        archive = self.work / f"bundle-{language}.tar.zst"
        self.download(f"CodeQL-{language}", spec["url"], archive, spec["sha256"])
        bundle = self.work / f"bundle-{language}"
        bundle.mkdir()
        code, _, _ = self.command(["tar", "--extract", "--file", str(archive), "--directory", str(bundle)],
                                  self.work, f"unpack-{language}", 90)
        if code or not (bundle / "codeql/codeql").is_file():
            raise self.incomplete(f"CodeQL {language} bundle could not be extracted.")
        data = self.work / f"codeql-{language}-data"
        data.mkdir()
        mounts = (self.source_mount, bind(bundle / "codeql", "/engine"), bind(data, "/data", False))
        run = lambda action, args: self.docker(
            "Analysis base", self.work, f"codeql-{language}-{action}", args,
            mounts=mounts, entry="/engine/codeql", seconds=540,
        )
        code, _, errors = run("create", [
            "database", "create", "/data/db", f"--language={language}",
            "--build-mode=none", "--source-root=/source", "--threads=2", "--ram=3000",
        ])
        if code:
            diagnostics = errors.read_text(errors="replace")
            if re.search(r"(?i)no source code|no code seen|no files to process", diagnostics):
                detail = "Extractor reported no analysable source."
            elif re.search(r"(?i)not found|no such file|error while loading shared libraries", diagnostics):
                detail = "Extractor reported a missing file or runtime dependency."
            else:
                detail = "No public diagnostic matched."
            raise self.incomplete(f"CodeQL {language} database creation failed (exit {code}). {detail}")
        code, _, _ = run("analyze", [
            "database", "analyze", "/data/db", f"{language}-code-scanning.qls",
            "--format=sarifv2.1.0", "--output=/data/results.sarif", "--threads=2", "--ram=3000",
        ])
        if code:
            raise self.incomplete(f"CodeQL {language} analysis failed (exit {code}).")
        sarif = json.loads((data / "results.sarif").read_text())
        if not sarif.get("runs"):
            raise self.incomplete("CodeQL returned no SARIF analysis runs.")
        findings = 0
        version = self.policy["tools"]["CodeQL"]["version"]
        for analysis in sarif["runs"]:
            driver = analysis["tool"]["driver"]
            if driver.get("semanticVersion", driver.get("version")) != version:
                raise self.incomplete("CodeQL report version did not match the pinned bundle.")
            rules = {rule["id"]: rule for rule in driver.get("rules", [])}
            for result in analysis.get("results", []):
                key = result["ruleId"]
                if not re.fullmatch(r"[A-Za-z0-9/_.-]{1,90}", key):
                    raise self.incomplete("CodeQL returned an invalid rule identifier.")
                rule = rules.get(key, {})
                severity = rule.get("properties", {}).get("security-severity", result.get("level", "unrated"))
                title = rule.get("shortDescription", {}).get("text", "")
                location = next(iter(result.get("locations", [])), {}).get("physicalLocation", {})
                path = location.get("artifactLocation", {}).get("uri", "")
                line = location.get("region", {}).get("startLine")
                self.report.add(check, f"{key} ({severity}) {title}", f"{path}:{line}" if line else path)
                findings += 1
        return f"CodeQL {version}, {language} standard suite. {len(candidates)} candidate files, {findings} findings."
