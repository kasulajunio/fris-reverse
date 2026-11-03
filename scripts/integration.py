"""Build an original unsigned fixture; execute analyzers, never the APK."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fris_reverse.app import App
from fris_reverse.safety import run_process

def execute(argv):
    subprocess.run([str(x) for x in argv], check=True, timeout=120)

def main():
    evidence = {}
    try:
        with tempfile.TemporaryDirectory(prefix="fris-real-") as temp:
            root = Path(temp)
            app = App(root / "workspace", root / "state")
            asset = app.installer.java_asset()
            app.installer._install("java", asset)
            portable = list((app.installer.tools / "java").glob("**/bin/java"))
            assert portable, "Portable Java missing"
            probe = run_process([str(portable[0]), "-version"], root, 30)
            assert probe["exit_code"] == 0, probe
            evidence["portable_java"] = {"version": asset["version"], "sha256": asset["sha256"], "probe": probe}
            doctor = app.installer.setup()
            evidence["doctor"] = doctor
            assert doctor["ready"], doctor
            sdk = Path(os.environ.get("ANDROID_HOME", os.environ.get("ANDROID_SDK_ROOT", "/usr/local/lib/android/sdk")))
            buildtools = sorted(p for p in (sdk / "build-tools").glob("*") if (p / "aapt2").is_file() and (p / "d8").is_file())
            platforms = sorted((sdk / "platforms").glob("*/android.jar"))
            assert buildtools and platforms, "Android SDK unavailable"
            tools = buildtools[-1]
            source = root / "Probe.java"
            source.write_text("package studio.fris.fixture; public final class Probe { public static String hello() { return \"FRIS_PROBE_42\"; } }", encoding="utf-8")
            classes, dex = root / "classes", root / "dex"
            classes.mkdir()
            dex.mkdir()
            execute(["javac", "--release", "8", "-d", classes, source])
            jar = root / "fixture.jar"
            execute(["jar", "cf", jar, "-C", classes, "."])
            execute([tools / "d8", "--min-api", "21", "--output", dex, jar])
            manifest = root / "AndroidManifest.xml"
            manifest.write_text("<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"studio.fris.fixture\"><uses-sdk android:minSdkVersion=\"21\" android:targetSdkVersion=\"35\"/><application android:label=\"Fris Fixture\"/></manifest>", encoding="utf-8")
            apk = app.root / "fixture.apk"
            execute([tools / "aapt2", "link", "-o", apk, "--manifest", manifest, "-I", platforms[-1]])
            with zipfile.ZipFile(apk, "a") as archive:
                archive.write(dex / "classes.dex", "classes.dex")
            evidence["headers"] = app.inspect_headers("fixture.apk")
            report = app.analyze_apk("fixture.apk", "both")
            evidence["analysis"] = report
            assert report["status"] == "complete", report
            job = app.job(report["job_id"])
            generated = list((job / "jadx").rglob("*.java"))
            assert any("FRIS_PROBE_42" in p.read_text(encoding="utf-8") for p in generated), "Decompiled fixture marker missing"
            review = app.review_manifest(report["job_id"])
            evidence["manifest_review"] = review
            assert review["package"] == "studio.fris.fixture", review
            assert app.search_artifacts(report["job_id"], "FRIS_PROBE_42")["matches"]
            evidence["summary"] = app.summarize_job(report["job_id"])
            evidence["result"] = "passed"
    finally:
        Path("integration-evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")

if __name__ == "__main__":
    main()
