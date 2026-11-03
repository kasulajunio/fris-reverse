import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from fris_reverse.app import App
from fris_reverse.inspection import manifest_review, dex_header, elf_header
from fris_reverse.install import download, trusted_url
from fris_reverse.safety import Failure, checked_zip, confined, extract_archive, member_path, run_process, sha256
from fris_reverse.server import Server, TOOLS

MANIFEST = b"<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"studio.fris.fixture\"><uses-sdk android:minSdkVersion=\"21\" android:targetSdkVersion=\"35\"/><uses-permission android:name=\"android.permission.CAMERA\"/><application android:debuggable=\"true\"><activity android:name=\".Main\" android:exported=\"true\"/></application></manifest>"

class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = App(self.root / "workspace", self.root / "state")
        self.workspace = self.app.root

    def apk(self, entries=None, name="fixture.apk"):
        target = self.workspace / name
        with zipfile.ZipFile(target, "w") as archive:
            for path, data in (entries or {"AndroidManifest.xml": MANIFEST, "classes.dex": b"dex\n035\x00"}).items():
                archive.writestr(path, data)
        return target

    def job(self):
        ident = "a" * 32
        target = self.app.results / ident
        target.mkdir(exist_ok=True)
        return ident, target

    def request(self, server, method, params=None):
        return server.handle({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})

    def server(self, version="2025-11-25"):
        server = Server(self.app)
        self.request(server, "initialize", {"protocolVersion": version})
        return server

    def test_inventory_identity(self):
        target = self.apk()
        self.assertEqual(self.app.inspect_apk(target.name)["sha256"], sha256(target))

    def test_inventory_dex(self):
        self.apk()
        self.assertEqual(self.app.inspect_apk("fixture.apk")["dex_files"], ["classes.dex"])

    def test_native_abi(self):
        self.apk({"AndroidManifest.xml": MANIFEST, "lib/arm64-v8a/libflutter.so": b"x"})
        info = self.app.inspect_apk("fixture.apk")
        self.assertEqual(info["abis"], ["arm64-v8a"])
        self.assertTrue(info["flutter_markers"])

    def test_unity_marker(self):
        self.apk({"AndroidManifest.xml": MANIFEST, "assets/bin/Data/info": b"x"})
        self.assertTrue(self.app.inspect_apk("fixture.apk")["unity_markers"])

    def test_manifest_required(self):
        with self.assertRaises(Failure):
            self.app.inspect_apk(self.apk({"x": b"x"}).name)

    def test_bad_zip(self):
        target = self.workspace / "bad.apk"
        target.write_bytes(b"not zip")
        with self.assertRaises(Failure):
            checked_zip(target)

    def test_workspace_escape(self):
        with self.assertRaises(Failure):
            confined(self.workspace, "../outside", False)

    def test_zip_traversal(self):
        with self.assertRaises(Failure):
            checked_zip(self.apk({"../escape": b"x"}))

    def test_raw_zip_backslash_and_null(self):
        for raw in (b"a\\b", b"a\x00b"):
            target = self.apk({"a_b": b"x"})
            target.write_bytes(target.read_bytes().replace(b"a_b", raw))
            with self.assertRaises(Failure):
                checked_zip(target)

    def test_absolute_member(self):
        for name in ("/escape", "C:/escape"):
            with self.assertRaises(Failure):
                member_path(self.root, name)

    def test_windows_reserved_names(self):
        for name in ("CON.txt", "x/NUL", "x/trailing.", "x/trailing "):
            with self.assertRaises(Failure):
                member_path(self.root, name)

    def test_case_collision(self):
        with self.assertRaises(Failure):
            checked_zip(self.apk({"a": b"x", "A": b"y"}))

    def test_zip_symlink(self):
        target = self.workspace / "link.zip"
        with zipfile.ZipFile(target, "w") as archive:
            item = zipfile.ZipInfo("link")
            item.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(item, "outside")
        with self.assertRaises(Failure):
            checked_zip(target)

    def test_expansion_budget(self):
        with self.assertRaises(Failure):
            checked_zip(self.apk(), max_bytes=1)

    def test_zip_extract(self):
        extract_archive(self.apk(), self.root / "extracted")
        self.assertTrue((self.root / "extracted/classes.dex").is_file())

    def test_tar_fifo_refused(self):
        target = self.root / "bad.tar"
        with tarfile.open(target, "w") as archive:
            item = tarfile.TarInfo("pipe")
            item.type = tarfile.FIFOTYPE
            archive.addfile(item)
        with self.assertRaises(Failure):
            extract_archive(target, self.root / "extracted")

    def test_tar_escape_link(self):
        target = self.root / "bad.tar"
        with tarfile.open(target, "w") as archive:
            item = tarfile.TarInfo("link")
            item.type, item.linkname = tarfile.SYMTYPE, "../../outside"
            archive.addfile(item)
        with self.assertRaises(Failure):
            extract_archive(target, self.root / "extracted")

    def test_url_policy(self):
        for url in ("http://github.com/x", "https://github.com.evil.test/x", "https://u:p@github.com/x", "file:///x", "https://github.com:bad/x"):
            with self.assertRaises(Failure):
                trusted_url(url)
        self.assertEqual(trusted_url("https://github.com/x"), "https://github.com/x")

    def test_download_checksum(self):
        target = self.root / "download"
        with patch("fris_reverse.install.request", return_value=io.BytesIO(b"tampered")):
            with self.assertRaises(Failure):
                download("https://github.com/x", "0" * 64, target)
        self.assertFalse(target.exists())

    def test_download_preserves_existing_file(self):
        target = self.root / "existing"
        target.write_bytes(b"preserve")
        with patch("fris_reverse.install.request", return_value=io.BytesIO(b"x")):
            with self.assertRaises(FileExistsError):
                download("https://github.com/x", "0" * 64, target)
        self.assertEqual(target.read_bytes(), b"preserve")

    def test_dual_consent(self):
        for policy, confirmation in (("0", True), ("1", False)):
            with patch.dict(os.environ, {"FRIS_ALLOW_DOWNLOADS": policy}):
                with self.assertRaises(Failure):
                    self.app.install_tools(confirmation)

    def test_capabilities_no_download(self):
        with patch.object(self.app.installer, "setup") as setup:
            self.app.capabilities()
            setup.assert_not_called()

    def test_process_timeout(self):
        with self.assertRaises(Failure) as error:
            run_process([sys.executable, "-c", "import time; time.sleep(3)"], self.root, 0.1)
        self.assertEqual(error.exception.code, "TIMEOUT")

    def test_process_environment(self):
        with patch.dict(os.environ, {"FRIS_TEST_SECRET": "must-not-leak"}):
            result = run_process([sys.executable, "-c", "import os; print(os.environ.get(chr(70)+chr(82)+chr(73)+chr(83)+chr(95)+chr(84)+chr(69)+chr(83)+chr(84)+chr(95)+chr(83)+chr(69)+chr(67)+chr(82)+chr(69)+chr(84), chr(79)+chr(75)))"], self.root)
        self.assertEqual(result["stdout"].strip(), "OK")

    def test_initialize_required(self):
        self.assertEqual(self.request(Server(self.app), "tools/list")["error"]["code"], -32002)

    def test_discovery(self):
        self.assertEqual(len(self.request(self.server(), "tools/list")["result"]["tools"]), 12)

    def test_all_tool_methods_exist(self):
        for tool in TOOLS:
            self.assertTrue(callable(getattr(self.app, tool["name"])))

    def test_structured_result(self):
        reply = self.request(self.server(), "tools/call", {"name": "capabilities"})
        self.assertFalse(reply["result"]["isError"])
        self.assertIn("structuredContent", reply["result"])

    def test_older_protocol(self):
        reply = self.request(self.server("2024-11-05"), "tools/call", {"name": "capabilities"})
        self.assertNotIn("structuredContent", reply["result"])

    def test_bad_argument_type(self):
        for args in ({"path": 5}, {}, {"path": "x", "shell": "x"}):
            reply = self.request(self.server(), "tools/call", {"name": "inspect_apk", "arguments": args})
            self.assertTrue(reply["result"]["isError"])

    def test_boolean_not_integer(self):
        reply = self.request(self.server(), "tools/call", {"name": "list_artifacts", "arguments": {"job_id": "a" * 32, "offset": True}})
        self.assertTrue(reply["result"]["isError"])

    def test_notification(self):
        self.assertIsNone(self.server().handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_parse_error(self):
        output = io.StringIO()
        self.server().serve(io.StringIO("not-json\n"), output)
        self.assertEqual(json.loads(output.getvalue())["error"]["code"], -32700)

    def test_invalid_request(self):
        self.assertEqual(self.server().handle([])["error"]["code"], -32600)

    def test_job_traversal(self):
        with self.assertRaises(Failure):
            self.app.list_artifacts("../../x")

    def test_bounded_read(self):
        ident, target = self.job()
        (target / "a.java").write_text("x" * 50000)
        result = self.app.read_artifact(ident, "a.java", limit=100)
        self.assertEqual(len(result["text"]), 100)
        self.assertEqual(result["next_offset"], 100)

    def test_binary_read_refused(self):
        ident, target = self.job()
        (target / "a.txt").write_bytes(bytes([0]))
        with self.assertRaises(Failure):
            self.app.read_artifact(ident, "a.txt")

    def test_manifest_package(self):
        self.assertEqual(manifest_review(MANIFEST)["package"], "studio.fris.fixture")

    def test_manifest_permissions(self):
        self.assertIn("android.permission.CAMERA", manifest_review(MANIFEST)["sensitive_permissions"])

    def test_manifest_findings(self):
        rules = {x["rule"] for x in manifest_review(MANIFEST)["findings"]}
        self.assertIn("debuggable-enabled", rules)
        self.assertIn("exported-without-component-permission", rules)

    def test_manifest_dtd_refused(self):
        with self.assertRaises(Failure):
            manifest_review(b"<!DOCTYPE manifest><manifest/>")

    def test_manifest_binary_refused(self):
        with self.assertRaises(Failure):
            manifest_review(bytes([3, 0, 8, 0]))

    def test_manifest_modern_exported_unknown(self):
        raw = MANIFEST.replace(b" android:exported=\"true\"", b"").replace(b"/></application>", b"><intent-filter/></activity></application>")
        self.assertIsNone(manifest_review(raw)["components"][0]["exported"])

    def test_manifest_job(self):
        ident, target = self.job()
        (target / "apktool").mkdir()
        (target / "apktool/AndroidManifest.xml").write_bytes(MANIFEST)
        self.assertEqual(self.app.review_manifest(ident)["target_sdk"], 35)

    def test_dex_header(self):
        raw = bytearray(112)
        raw[:8] = b"dex\n035\x00"
        struct.pack_into("<III", raw, 32, 112, 112, 0x12345678)
        struct.pack_into("<I", raw, 96, 7)
        result = dex_header(raw, 112)
        self.assertEqual(result["class_defs"], 7)
        self.assertTrue(result["size_matches"])

    def test_dex_invalid(self):
        with self.assertRaises(Failure):
            dex_header(b"bad", 3)

    def test_elf_header(self):
        raw = bytearray(64)
        raw[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HH", raw, 16, 3, 183)
        self.assertEqual(elf_header(raw)["architecture"], "AArch64")

    def test_elf_invalid(self):
        with self.assertRaises(Failure):
            elf_header(b"bad")

    def test_header_error_partial(self):
        self.apk()
        result = self.app.inspect_headers("fixture.apk")
        self.assertIn("error", result["headers"][0])

    def test_apk_comparison(self):
        self.apk({"AndroidManifest.xml": MANIFEST, "a": b"old"}, "before.apk")
        self.apk({"AndroidManifest.xml": MANIFEST, "a": b"new", "b": b"x"}, "after.apk")
        result = self.app.compare_apks("before.apk", "after.apk")
        self.assertEqual(result["changed"], ["a"])
        self.assertEqual(result["added"], ["b"])

    def test_identical_apks(self):
        self.apk()
        self.assertTrue(self.app.compare_apks("fixture.apk", "fixture.apk")["identical_apk_bytes"])

    def test_literal_search(self):
        ident, target = self.job()
        (target / "a.java").write_text("HELLO [a-z]+\n")
        result = self.app.search_artifacts(ident, "[a-z]+")
        self.assertEqual(len(result["matches"]), 1)

    def test_search_limit(self):
        ident, target = self.job()
        (target / "a.txt").write_text("hello\n" * 10)
        self.assertTrue(self.app.search_artifacts(ident, "hello", 2)["truncated"])

    def test_summary(self):
        ident, target = self.job()
        (target / "report.json").write_text(json.dumps({"status": "partial", "runs": {"jadx": {"status": "failed"}}}))
        result = self.app.summarize_job(ident)
        self.assertIn("partial", result["markdown"])
        self.assertTrue((target / "summary.md").is_file())

    def test_failed_engine_report(self):
        self.apk()
        with patch.object(self.app.installer, "command", side_effect=Failure("TOOL_MISSING", "missing")):
            report = self.app.analyze_apk("fixture.apk")
        self.assertEqual(report["status"], "failed")
        self.assertTrue((self.app.job(report["job_id"]) / "report.json").is_file())

    def test_real_stdio(self):
        request = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}}
        proc = subprocess.run([sys.executable, "-m", "fris_reverse", "--workspace", str(self.workspace), "--home", str(self.root / "state"), "serve"], input=json.dumps(request) + "\n", text=True, capture_output=True, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["result"]["protocolVersion"], "2025-11-25")

if __name__ == "__main__":
    unittest.main()
