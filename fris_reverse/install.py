"""Curated official downloads. No sudo or remote shell installer."""
from __future__ import annotations
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import tempfile
import urllib.parse
import urllib.request
from .safety import Failure, confined, extract_archive, run_process, sha256

CATALOG = {
    "jadx": {"version": "1.5.6", "url": "https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip", "sha256": "545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974"},
    "apktool": {"version": "3.0.3", "url": "https://github.com/iBotPeaches/Apktool/releases/download/v3.0.3/apktool_3.0.3.jar", "sha256": "dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423"},
}

def trusted_url(url):
    try:
        p = urllib.parse.urlparse(url)
        host = p.hostname or ""
        allowed = host in {"github.com", "api.github.com", "api.adoptium.net"} or host.endswith(".githubusercontent.com")
        valid = p.scheme == "https" and allowed and not p.username and not p.password and p.port in (None, 443)
    except ValueError:
        valid = False
    if not valid:
        raise Failure("UNTRUSTED_SOURCE", "Not an allowed official HTTPS endpoint")
    return url

class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        trusted_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def request(url):
    trusted_url(url)
    opener = urllib.request.build_opener(SafeRedirect())
    return opener.open(urllib.request.Request(url, headers={"User-Agent": "fris-reverse-mcp/0.2.0"}), timeout=60)

def download(url, expected, destination):
    if not re.fullmatch(r"[0-9a-f]{64}", expected or ""):
        raise Failure("MISSING_CHECKSUM", "SHA-256 is mandatory")
    destination = Path(destination)
    created = False
    try:
        with request(url) as response, destination.open("xb") as output:
            created = True
            total = 0
            while True:
                chunk = response.read(1048576)
                if not chunk:
                    break
                total += len(chunk)
                if total > 268435456:
                    raise Failure("DOWNLOAD_LIMIT", "Download exceeds 256 MiB")
                output.write(chunk)
        if sha256(destination) != expected:
            raise Failure("CHECKSUM_MISMATCH", "SHA-256 verification failed")
    except Exception:
        if created:
            destination.unlink(missing_ok=True)
        raise

def verify_files(root, record):
    if not isinstance(record.get("files"), dict) or not record["files"]:
        raise Failure("TOOL_INTEGRITY", "Installation file inventory missing")
    for relative, expected in record["files"].items():
        path = confined(root, relative)
        if not path.is_file() or sha256(path) != expected:
            raise Failure("TOOL_INTEGRITY", "Installed file was modified")

class Installer:
    def __init__(self, home):
        self.home = Path(home).resolve()
        self.home.mkdir(parents=True, exist_ok=True)
        self.tools = self.home / "tools"
        self.tools.mkdir(exist_ok=True)

    def java(self):
        suffix = "java.exe" if os.name == "nt" else "java"
        candidates = []
        if os.environ.get("JAVA_HOME"):
            candidates.append(Path(os.environ["JAVA_HOME"]) / "bin" / suffix)
        found = shutil.which("java")
        if found:
            candidates.append(Path(found))
        portable = self.tools / "java"
        if (portable / "install.json").is_file():
            try:
                verify_files(portable, json.loads((portable / "install.json").read_text(encoding="utf-8")))
                candidates.extend(portable.glob("**/bin/" + suffix))
            except (Failure, ValueError, OSError):
                pass
        for candidate in candidates:
            if not candidate.is_file():
                continue
            try:
                result = run_process([str(candidate), "-version"], self.home, 15)
                match = re.search(r"version [\"](\d+)", result["stderr"] + result["stdout"])
                if result["exit_code"] == 0 and match and int(match.group(1)) >= 21:
                    return str(candidate)
            except Failure:
                continue
        return None

    def command(self, name):
        if name not in CATALOG:
            raise Failure("TOOL_MISSING", "Unknown curated tool")
        java = self.java()
        if not java:
            raise Failure("JAVA_MISSING", "Java 21 or newer is required", "Run setup --yes")
        root = self.tools / name
        marker = root / "install.json"
        if not marker.is_file():
            raise Failure("TOOL_MISSING", "Curated tool is not installed", "Run setup --yes")
        record = json.loads(marker.read_text(encoding="utf-8"))
        if record.get("sha256") != CATALOG[name]["sha256"]:
            raise Failure("TOOL_INTEGRITY", "Installation differs from pinned catalog")
        verify_files(root, record)
        if name == "apktool":
            return [java, "-Xmx512m", "-jar", str(root / "apktool.jar")]
        jars = sorted(root.glob("**/lib/*.jar"))
        if not jars:
            raise Failure("TOOL_INTEGRITY", "JADX classpath missing")
        return [java, "-Xmx512m", "-cp", os.pathsep.join(str(x) for x in jars), "jadx.cli.JadxCLI"]

    def doctor(self):
        tools = {}
        for name in CATALOG:
            try:
                result = run_process(self.command(name) + ["--version"], self.home, 30)
                text = (result["stdout"] + result["stderr"]).strip()[:500]
                tools[name] = {"ready": result["exit_code"] == 0 and CATALOG[name]["version"] in text, "expected_version": CATALOG[name]["version"], "output": text}
            except (Failure, ValueError, OSError) as exc:
                error = exc.as_dict() if isinstance(exc, Failure) else {"code": "INSTALL_STATE", "message": "Invalid installation state"}
                tools[name] = {"ready": False, "error": error}
        return {"java": self.java(), "tools": tools, "ready": all(x["ready"] for x in tools.values()), "platform": platform.system(), "machine": platform.machine()}

    def java_asset(self):
        if hasattr(sys, "getandroidapilevel") or os.environ.get("TERMUX_VERSION"):
            raise Failure("UNSUPPORTED_HOST", "Java bootstrap unavailable on Android", "Provide compatible Java 21; Android is experimental")
        system = {"Linux": "linux", "Darwin": "mac", "Windows": "windows"}.get(platform.system())
        arch = {"x86_64": "x64", "AMD64": "x64", "arm64": "aarch64", "aarch64": "aarch64"}.get(platform.machine())
        if not system or not arch:
            raise Failure("UNSUPPORTED_HOST", "No curated runtime for this host")
        url = "https://api.adoptium.net/v3/assets/latest/21/hotspot?" + urllib.parse.urlencode({"architecture": arch, "image_type": "jre", "os": system, "vendor": "eclipse"})
        with request(url) as response:
            raw = response.read(2097153)
        if len(raw) > 2097152:
            raise Failure("METADATA_LIMIT", "Metadata too large")
        assets = json.loads(raw)
        if not isinstance(assets, list) or not assets:
            raise Failure("UNSUPPORTED_HOST", "No Java 21 archive published")
        package = assets[0]["binary"]["package"]
        return {"url": package["link"], "sha256": package["checksum"], "version": assets[0]["release_name"]}

    def setup(self):
        lock = self.home / "install.lock"
        try:
            lock.mkdir()
        except FileExistsError as exc:
            raise Failure("INSTALL_BUSY", "Installer lock exists", "Remove stale lock only after checking no install is running") from exc
        try:
            if not self.java():
                self._install("java", self.java_asset())
            for name, asset in CATALOG.items():
                try:
                    self.command(name)
                except (Failure, ValueError, OSError):
                    self._install(name, asset)
            return self.doctor()
        finally:
            lock.rmdir()

    def _install(self, name, asset):
        with tempfile.TemporaryDirectory(prefix="fris-install-", dir=self.home) as temp:
            temp = Path(temp)
            package = temp / "download"
            download(asset["url"], asset["sha256"], package)
            payload = temp / "payload"
            payload.mkdir()
            if name == "apktool":
                shutil.copy2(package, payload / "apktool.jar")
            else:
                extract_archive(package, payload)
            record = dict(asset)
            record["files"] = {p.relative_to(payload).as_posix(): sha256(p) for p in payload.rglob("*") if p.is_file()}
            (payload / "install.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
            target = self.tools / name
            if target.exists():
                shutil.rmtree(target)
            payload.rename(target)
