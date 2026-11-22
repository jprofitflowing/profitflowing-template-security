"""Bounded, passive checks for source, markup, and packages."""

import json
import re
from pathlib import PurePosixPath
from urllib.parse import urlsplit

SAST = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".py", ".go", ".php"}
OTHER_CODE = {
    ".c", ".cc", ".cpp", ".cs", ".dart", ".ex", ".exs", ".fs", ".groovy", ".h", ".hpp",
    ".java", ".kt", ".kts", ".lua", ".pl", ".ps1", ".rb", ".rs", ".scala", ".sh", ".swift",
    ".vue", ".svelte", ".vb", ".zig",
}
MARKUP = {".html", ".htm", ".xhtml", ".svg"}
URL = re.compile(r"""(?i)\b(?:https?|wss?)://[^\s"'<>\\`]{1,500}""")
REMOTE_SCRIPT = re.compile(r"""(?is)<script\b[^>]{0,2000}\bsrc\s*=\s*['"]?\s*(?:https?://|//)""")
INLINE = re.compile(r"(?is)<script\b|<iframe\b|<object\b|<embed\b|\bon[a-z]{3,20}\s*=|\bjavascript\s*:")
SCRIPT_CODE = re.compile(r"\b(?:eval|Function|atob|unescape|setTimeout|setInterval)\s*\(\s*(?:['\"]|[A-Za-z_$])")
OBFUSCATION = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}|(?:\\u[0-9a-fA-F]{4}){8,}|\b_0x[0-9a-fA-F]{4,}\b")
RUNTIME_NETWORK = re.compile(r"\b(?:fetch|importScripts|WebSocket|EventSource|sendBeacon|XMLHttpRequest)\s*\(")
INLINE_SCRIPT_BODY = re.compile(r"(?is)<script\b[^>]*>(.*?)</script\s*>")
ACTIVE_NETWORK = re.compile(r"(?i)\b(?:import\s*\(|importScripts\s*\(|createElement\s*\(\s*['\"]script['\"]|"
                            r"serviceWorker\.register\s*\(|window\.open\s*\(|location\.(?:assign|replace)\s*\()")
REDIRECT_META = re.compile(r"(?is)<meta\b[^>]*http-equiv\s*=\s*['\"]?refresh\b")
MINER = re.compile(r"(?i)\b(?:coinhive|cryptoloot|coinimp|webminepool|cryptonight)\b")
EXE_EXTENSIONS = {".exe", ".dll", ".msi", ".app", ".scr", ".bat", ".cmd", ".com", ".wasm", ".so", ".dylib", ".jar"}
ARCHIVES = {".zip", ".gz", ".xz", ".7z", ".rar", ".tar", ".tgz", ".bz2"}
LOCKS = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"}
INSTALL_HOOKS = {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepack"}
LFS_POINTER = "version https://git-lfs.github.com/spec/v1"
MAX_TEXT = 8 * 1024 * 1024


def inspect(target, files, report):
    sast = set()
    domains = set()
    locks = {str(PurePosixPath(name).parent) for name in files if PurePosixPath(name).name in LOCKS}
    for name, (executable, _) in files.items():
        path = PurePosixPath(name)
        suffix = path.suffix.lower()
        file = target / name
        content = file.read_bytes()
        is_code = suffix in SAST or suffix in OTHER_CODE or suffix in MARKUP
        if suffix in SAST:
            sast.add(name)
        if suffix in OTHER_CODE:
            report.add("Static", "Language outside configured Semgrep rules", name)
        if executable or content.startswith(b"#!"):
            report.add("Static", "Executable mode or interpreter marker", name)
        if (suffix in EXE_EXTENSIONS or content.startswith((b"MZ", b"\x7fELF", b"\0asm",
                b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"))):
            report.add("Static", "Executable binary or bytecode", name)
        if suffix in ARCHIVES:
            report.add("Static", "Archive requires contents and licence review", name)
        if len(content) > MAX_TEXT:
            if is_code or b"\0" not in content[:8192]:
                report.add("Static", "Text exceeded the heuristic scan limit", name)
            continue
        if b"\0" in content:
            if is_code:
                report.add("Static", "Binary or encoded content in a source file", name)
            continue
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            if is_code:
                report.add("Static", "Source encoding outside heuristic coverage", name)
            continue
        if text.startswith(LFS_POINTER):
            continue
        if path.name in ("package.json", "composer.json"):
            try:
                package = json.loads(text)
                if not isinstance(package, dict):
                    raise ValueError
                scripts = package.get("scripts") or {}
                if not isinstance(scripts, dict):
                    raise ValueError
                active = INSTALL_HOOKS.intersection(scripts)
                if path.name == "composer.json":
                    active = {key for key in scripts if "install" in key or "update" in key}
                if active:
                    report.add("Static", "Package install or lifecycle hook", name)
                if (path.name == "package.json"
                        and any(package.get(field) for field in ("dependencies", "devDependencies", "optionalDependencies"))
                        and all(str(parent) not in locks for parent in path.parents)):
                    report.add("Static", "JavaScript package without a matching lockfile", name)
            except ValueError:
                report.add("Static", "Package manifest could not be parsed", name)
        if suffix in MARKUP and INLINE.search(text):
            report.add("Static", "Embedded script, active markup or event handler", name)
        if suffix in MARKUP and REMOTE_SCRIPT.search(text):
            report.add("Static", "Remote script loaded by markup", name)
        inline = "\n".join(INLINE_SCRIPT_BODY.findall(text)) if suffix in MARKUP else ""
        active_code = text if suffix in SAST else inline
        if active_code and ACTIVE_NETWORK.search(active_code):
            report.add("Static", "Dynamic load, navigation, or background worker API", name)
        if active_code and MINER.search(active_code):
            report.add("Static", "Possible browser mining indicator", name)
        if suffix in MARKUP and REDIRECT_META.search(text):
            report.add("Static", "Automatic HTML redirect", name)
        if inline and (OBFUSCATION.search(inline) or SCRIPT_CODE.search(inline)):
            report.add("Static", "Dynamic or potentially obfuscated inline code", name)
        if suffix in SAST and (OBFUSCATION.search(text) or
                (suffix in {".js", ".mjs", ".cjs"} and SCRIPT_CODE.search(text))):
            report.add("Static", "Dynamic or potentially obfuscated code", name)
        if suffix in {".js", ".mjs", ".cjs"} and (
                path.name.endswith(".min.js") or any(len(line) > 2000 for line in text.splitlines())):
            report.add("Static", "Minified or unusually long JavaScript lines", name)
        urls = URL.finditer(text)
        file_has_host = False
        for url in urls:
            try:
                host = urlsplit(url.group()).hostname
            except ValueError:
                continue
            if host and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host):
                file_has_host = True
                if is_code and len(domains) < 500:
                    domains.add(host)
        if is_code and RUNTIME_NETWORK.search(text):
            report.add("Static", "Runtime network API usage", name)
        elif suffix in MARKUP and file_has_host:
            report.add("Static", "External destination in active markup", name, level="info")
    return sast, domains
