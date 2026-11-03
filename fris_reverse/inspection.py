"""Bounded static observations. Findings are review hints, not verdicts."""
from __future__ import annotations
import struct
import xml.etree.ElementTree as ET
from .safety import Failure

ANDROID = "{http://schemas.android.com/apk/res/android}"
SENSITIVE = {
    "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.READ_CALL_LOG", "android.permission.READ_PHONE_STATE",
    "android.permission.MANAGE_EXTERNAL_STORAGE", "android.permission.REQUEST_INSTALL_PACKAGES",
}

def attribute(element, name, default=None):
    return element.get(ANDROID + name, default)

def number(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

def manifest_review(raw):
    if len(raw) > 2097152:
        raise Failure("MANIFEST_LIMIT", "Manifest exceeds 2 MiB")
    # Android decoded manifests should be UTF-8 text, not UTF-16 or AXML.
    if chr(0).encode() in raw:
        raise Failure("BINARY_MANIFEST", "Decode binary XML with analyze_apk resources first")
    upper = raw.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise Failure("XML_POLICY", "DTD and entity declarations are refused")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise Failure("XML_PARSE", "Expected decoded Android XML") from exc
    if root.tag != "manifest":
        raise Failure("BAD_MANIFEST", "Root element must be manifest")
    sdk = root.find("uses-sdk")
    target = number(attribute(sdk, "targetSdkVersion")) if sdk is not None else None
    minimum = number(attribute(sdk, "minSdkVersion")) if sdk is not None else None
    permissions = sorted({attribute(e, "name") for e in root if e.tag in {"uses-permission", "uses-permission-sdk-23"} and attribute(e, "name")})
    application = root.find("application")
    findings, components = [], []
    if application is not None:
        if attribute(application, "debuggable") == "true":
            findings.append({"rule": "debuggable-enabled", "severity": "review", "evidence": "application android:debuggable=true"})
        if attribute(application, "usesCleartextTraffic") == "true":
            findings.append({"rule": "cleartext-declared", "severity": "review", "evidence": "application android:usesCleartextTraffic=true"})
        if attribute(application, "allowBackup", "true") == "true":
            findings.append({"rule": "backup-not-explicitly-disabled", "severity": "info", "evidence": "allowBackup=true or absent; actual backup depends on platform and backup rules"})
        for element in application:
            if element.tag not in {"activity", "activity-alias", "service", "receiver", "provider"}:
                continue
            explicit = attribute(element, "exported")
            intent = element.find("intent-filter") is not None
            if explicit is not None:
                exported, basis = explicit == "true", "explicit XML attribute"
            elif element.tag == "provider":
                exported = target <= 16 if target is not None else None
                basis = "provider default inferred from target SDK"
            elif target is not None and target >= 31 and intent:
                exported, basis = None, "missing required exported declaration for target 31+ with intent filter"
            else:
                exported, basis = intent, "legacy intent-filter default; target SDK may be unresolved"
            item = {"type": element.tag, "name": attribute(element, "name"), "exported": exported, "basis": basis, "permission": attribute(element, "permission", attribute(application, "permission"))}
            components.append(item)
            if exported and not item["permission"]:
                findings.append({"rule": "exported-without-component-permission", "severity": "review", "component": item["name"], "evidence": basis, "caveat": "Public entry points can be intentional; code-level controls and provider read/write permissions are not evaluated"})
    return {"package": root.get("package"), "min_sdk": minimum, "target_sdk": target, "permissions": permissions, "sensitive_permissions": [p for p in permissions if p in SENSITIVE], "components": components, "findings": findings, "limitations": ["No runtime behavior, exploitability or malware verdict", "Manifest placeholders, permission protections and network security config require manual review", "Sensitive permission list is illustrative, not exhaustive"]}

def dex_header(raw, actual_size):
    if len(raw) < 112 or raw[:4] != b"dex\n" or raw[7] != 0:
        raise Failure("BAD_DEX", "Not a conventional DEX header")
    version = raw[4:7].decode("ascii", "replace")
    if version not in {"035", "036", "037", "038", "039", "040"}:
        raise Failure("DEX_VERSION", "DEX version not supported by this header reader")
    order = "<" if raw[40:44] == bytes.fromhex("78563412") else ">" if raw[40:44] == bytes.fromhex("12345678") else None
    if order is None:
        raise Failure("BAD_DEX", "Invalid DEX endian tag")
    value = lambda offset: struct.unpack_from(order + "I", raw, offset)[0]
    return {"version": version, "declared_file_size": value(32), "actual_file_size": actual_size, "size_matches": value(32) == actual_size, "header_size": value(36), "string_ids": value(56), "type_ids": value(64), "proto_ids": value(72), "field_ids": value(80), "method_ids": value(88), "class_defs": value(96), "limitations": ["Header fields are untrusted observations; bytecode, checksum and DEX signature not verified"]}

def elf_header(raw):
    if len(raw) < 24 or raw[:4] != b"\x7fELF" or raw[4] not in {1, 2} or raw[5] not in {1, 2}:
        raise Failure("BAD_ELF", "Unsupported ELF header")
    order = "<" if raw[5] == 1 else ">"
    kind, machine = struct.unpack_from(order + "HH", raw, 16)
    architecture = {3: "x86", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}.get(machine, "unknown")
    return {"bits": 32 if raw[4] == 1 else 64, "byte_order": "little" if raw[5] == 1 else "big", "object_type": kind, "machine": machine, "architecture": architecture, "limitations": ["Header only; no disassembly, symbols or native code recovery"]}
