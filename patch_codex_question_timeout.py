#!/usr/bin/env python3
"""Disable Codex desktop's automatic request_user_input timer."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import mmap
import os
import plistlib
import shlex
import shutil
import stat
import struct
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Sequence


DEFAULT_APP = Path("/Applications/ChatGPT.app")
DEFAULT_BACKUP_ROOT = (
    Path.home()
    / "Library"
    / "Application Support"
    / "Codex"
    / "Patch Backups"
    / "question-timeout"
)
EXPECTED_BUNDLE_ID = "com.openai.codex"
OPENAI_TEAM_ID = "2DC432GLL2"
OPENAI_REQUIREMENT = (
    f'identifier "{EXPECTED_BUNDLE_ID}" and anchor apple generic and '
    f'certificate leaf[subject.OU] = "{OPENAI_TEAM_ID}"'
)
MANIFEST_SCHEMA_VERSION = 3
CHUNK_SIZE = 8 * 1024 * 1024
ASAR_RELATIVE_PATH = "Contents/Resources/app.asar"
INFO_RELATIVE_PATH = "Contents/Info.plist"

ENTITLEMENTS_HELPER = "helper"
ENTITLEMENTS_NONE = "none"
ENTITLEMENTS_MAIN = "main"
ENTITLEMENTS_OPTIONAL_SHARED = "optional-shared"
EXPECTED_SIGNING_FLAGS = "0x10000(runtime)"
EXPECTED_AD_HOC_SIGNING_FLAGS = "0x10002(adhoc,runtime)"

SANITIZED_ENTITLEMENTS = {
    "com.apple.security.app-sandbox": False,
    "com.apple.security.automation.apple-events": True,
    "com.apple.security.cs.allow-jit": True,
    "com.apple.security.cs.allow-unsigned-executable-memory": True,
    "com.apple.security.cs.disable-library-validation": True,
    "com.apple.security.device.audio-input": True,
    "com.apple.security.device.camera": True,
    "com.apple.security.files.user-selected.read-write": True,
    "com.apple.security.network.client": True,
}

EXPECTED_ORIGINAL_SHARED_ENTITLEMENTS = {
    key: value
    for key, value in SANITIZED_ENTITLEMENTS.items()
    if key != "com.apple.security.cs.disable-library-validation"
}
EXPECTED_ORIGINAL_SHARED_ENTITLEMENTS["com.apple.security.application-groups"] = [
    f"{OPENAI_TEAM_ID}.com.openai.codex.notifications",
    f"{OPENAI_TEAM_ID}.com.openai.sky.CUAService",
]
EXPECTED_ORIGINAL_MAIN_ENTITLEMENTS = {
    **EXPECTED_ORIGINAL_SHARED_ENTITLEMENTS,
    "com.apple.application-identifier": f"{OPENAI_TEAM_ID}.{EXPECTED_BUNDLE_ID}",
    "com.apple.developer.team-identifier": OPENAI_TEAM_ID,
    "keychain-access-groups": [
        f"{OPENAI_TEAM_ID}.*",
        f"{OPENAI_TEAM_ID}.com.openai.shared",
    ],
}

ORIGINAL = b"if(e.method===`item/tool/requestUserInput`){this.trackRequest("
PATCHED = b"if(e.method===`item/tool/xequestUserInput`){this.trackRequest("
PRE_CONTEXT = b"observeServerRequest("
EMPTY_ANSWER_CONTEXT = b"`empty-user-input`);return}"
MCP_CONTEXT = b"`mcpServer/elicitation/request`"

STATUS_READY = "ready"
STATUS_PATCHED = "patched"
STATUS_PATCHED_UNRESTORABLE = "patched-unrestorable"
STATUS_RECOVERY_REQUIRED = "recovery-required"
STATUS_UNSUPPORTED = "unsupported"
STATUS_UNTRUSTED = "untrusted"


class PatchError(RuntimeError):
    """A safe, expected refusal or validation failure."""


class UnsupportedError(PatchError):
    """The installed application does not match the semantic patch contract."""


class PairMismatchError(PatchError):
    """Info.plist and the ASAR raw header do not match."""


@dataclass(frozen=True)
class Bundle:
    app: Path
    info: Path
    asar: Path
    executable: Path
    version: str
    build: str


@dataclass(frozen=True)
class SigningTarget:
    path: Path
    relative_path: str
    identifier: str
    entitlement_policy: str
    flags: str
    runtime_version: str


@dataclass(frozen=True)
class SigningPlan:
    targets: tuple[SigningTarget, ...]
    backup_files: tuple[str, ...]


@dataclass
class AsarInspection:
    header: dict[str, Any]
    raw_header: bytes
    json_start: int
    json_end: int
    content_start: int
    target_path: str
    target_entry: dict[str, Any]
    target_start: int
    target_end: int
    target_content: bytes
    marker_offset: int
    marker_state: str


@dataclass
class PairInspection:
    asar: AsarInspection
    info_blob: bytes
    info_header_hash: str


@dataclass
class PatchPlan:
    target_path: str
    target_start: int
    target_end: int
    json_start: int
    json_end: int
    changed_target: bytes
    changed_header: bytes
    changed_info: bytes
    original_asar_hash: str
    original_info_hash: str
    original_header_hash: str
    patched_asar_hash: str
    patched_info_hash: str
    patched_header_hash: str


@dataclass(frozen=True)
class BackupFile:
    relative_path: str
    backup_path: Path
    sha256: str
    size: int
    mode: str
    role: str


@dataclass
class ManifestRecord:
    directory: Path
    asar: Path
    info: Path
    data: dict[str, Any]
    plan: PatchPlan
    files: tuple[BackupFile, ...]
    signing: SigningPlan
    entitlements: Path


@dataclass
class StateReport:
    bundle: Bundle
    backup_directory: Path
    status: str
    asar_hash: str
    info_hash: str
    signature_valid: bool
    target_path: str | None = None
    plan: PatchPlan | None = None
    detail: str | None = None


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            hasher.update(chunk)
    return hasher.hexdigest()


def digest_file_with_replacements(
    path: Path,
    replacements: Sequence[tuple[int, int, bytes]],
) -> str:
    ordered = sorted(replacements, key=lambda item: item[0])
    cursor = 0
    hasher = hashlib.sha256()
    size = path.stat().st_size
    with path.open("rb") as handle:
        for start, end, changed in ordered:
            if start < cursor or end < start or end > size:
                raise PatchError("invalid or overlapping digest replacement")
            if len(changed) != end - start:
                raise PatchError("digest replacement changed file length")
            hash_range(handle, hasher, cursor, start)
            hasher.update(changed)
            cursor = end
        hash_range(handle, hasher, cursor, size)
    return hasher.hexdigest()


def hash_range(
    handle: Any,
    hasher: Any,
    start: int,
    end: int,
) -> None:
    handle.seek(start)
    remaining = end - start
    while remaining:
        chunk = handle.read(min(CHUNK_SIZE, remaining))
        if not chunk:
            raise PatchError("unexpected end of file while hashing")
        hasher.update(chunk)
        remaining -= len(chunk)


def is_within(path: Path, parent: Path) -> bool:
    try:
        return os.path.commonpath((str(path), str(parent))) == str(parent)
    except ValueError:
        return False


def require_regular_file(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise PatchError(f"{label} is not a regular file: {path}")


def parse_info_blob(info_blob: bytes, source: Path) -> dict[str, Any]:
    try:
        info = plistlib.loads(info_blob)
    except (plistlib.InvalidFileException, ValueError) as exc:
        raise PatchError(f"invalid Info.plist at {source}: {exc}") from exc
    if not isinstance(info, dict):
        raise PatchError(f"Info.plist is not a dictionary: {source}")
    return info


def bundle_from_app(app_arg: Path) -> Bundle:
    app = app_arg.expanduser().resolve(strict=True)
    if not app.is_dir():
        raise PatchError(f"application bundle is not a directory: {app}")
    info_path = app / "Contents" / "Info.plist"
    asar_path = app / "Contents" / "Resources" / "app.asar"
    require_regular_file(info_path, "Info.plist")
    require_regular_file(asar_path, "app.asar")
    info = parse_info_blob(info_path.read_bytes(), info_path)
    if info.get("CFBundleIdentifier") != EXPECTED_BUNDLE_ID:
        raise PatchError(f"unexpected bundle identifier in {info_path}")
    executable_name = info.get("CFBundleExecutable")
    if not isinstance(executable_name, str) or not executable_name:
        raise PatchError(f"CFBundleExecutable is missing from {info_path}")
    executable = app / "Contents" / "MacOS" / executable_name
    require_regular_file(executable, "application executable")
    version = str(info.get("CFBundleShortVersionString", "unknown"))
    build = str(info.get("CFBundleVersion", "unknown"))
    return Bundle(app, info_path, asar_path, executable, version, build)


def normalized_backup_root(root_arg: Path, bundle: Bundle) -> Path:
    root = root_arg.expanduser().resolve(strict=False)
    if is_within(root, bundle.app):
        raise PatchError("backup root must be outside the application bundle")
    return root


def sanitize_identity(value: str) -> str:
    return "".join(
        character if character.isalnum() or character in ".-_" else "_"
        for character in value
    )


def backup_directory(root: Path, bundle: Bundle) -> Path:
    identity = sanitize_identity(f"{bundle.version}-{bundle.build}")
    return root / identity


def validate_backup_directory(root: Path, directory: Path) -> None:
    if directory.is_symlink():
        raise PatchError(f"backup directory must not be a symlink: {directory}")
    if not directory.exists():
        return
    if not directory.is_dir():
        raise PatchError(f"backup directory is not a directory: {directory}")
    resolved = directory.resolve(strict=True)
    if resolved.parent != root or not is_within(resolved, root):
        raise PatchError(f"backup directory escapes backup root: {directory}")


def walk_asar_files(
    node: dict[str, Any],
    content_start: int,
    archive_size: int,
    prefix: str = "",
) -> Iterator[tuple[str, dict[str, Any], int, int]]:
    files = node.get("files")
    if not isinstance(files, dict):
        raise UnsupportedError("invalid files node in ASAR header")
    for name, entry in files.items():
        if not isinstance(name, str) or not isinstance(entry, dict):
            raise UnsupportedError("invalid ASAR header entry")
        path = f"{prefix}/{name}" if prefix else name
        if "files" in entry:
            yield from walk_asar_files(
                entry,
                content_start,
                archive_size,
                path,
            )
            continue
        if entry.get("unpacked"):
            continue
        if "offset" not in entry or "size" not in entry:
            continue
        try:
            offset = int(entry["offset"])
            size = int(entry["size"])
        except (TypeError, ValueError) as exc:
            raise UnsupportedError(f"invalid ASAR bounds for {path}") from exc
        start = content_start + offset
        end = start + size
        if offset < 0 or size < 0 or start < content_start or end > archive_size:
            raise UnsupportedError(f"out-of-range ASAR entry: {path}")
        yield path, entry, start, end


def find_all(
    archive: mmap.mmap,
    marker: bytes,
    start: int,
    end: int,
) -> list[int]:
    positions: list[int] = []
    cursor = start
    while True:
        position = archive.find(marker, cursor, end)
        if position < 0:
            return positions
        positions.append(position)
        cursor = position + 1


def validate_non_overlapping_entries(
    entries: Sequence[tuple[str, dict[str, Any], int, int]],
) -> None:
    previous_end = -1
    previous_path = ""
    for path, _, start, end in sorted(entries, key=lambda item: item[2]):
        if start < previous_end and end > start:
            raise UnsupportedError(
                f"overlapping ASAR entries: {previous_path} and {path}"
            )
        if end > previous_end:
            previous_end = end
            previous_path = path


def validate_semantic_context(content: bytes, marker_offset: int) -> None:
    before = content[max(0, marker_offset - 256) : marker_offset]
    after_start = marker_offset + len(ORIGINAL)
    after = content[after_start : after_start + 512]
    if PRE_CONTEXT not in before:
        raise UnsupportedError("target is not inside observeServerRequest")
    if EMPTY_ANSWER_CONTEXT not in after:
        raise UnsupportedError("target no longer registers empty-user-input")
    if MCP_CONTEXT not in after:
        raise UnsupportedError("MCP request branch is missing after target")


def validate_entry_integrity(
    path: str,
    entry: dict[str, Any],
    content: bytes,
) -> None:
    integrity = entry.get("integrity")
    if not isinstance(integrity, dict):
        raise UnsupportedError(f"target has no integrity metadata: {path}")
    if integrity.get("algorithm") != "SHA256":
        raise UnsupportedError(f"unsupported target integrity algorithm: {path}")
    block_size = integrity.get("blockSize")
    if not isinstance(block_size, int) or block_size <= 0:
        raise UnsupportedError(f"invalid target block size: {path}")
    blocks = [
        digest_bytes(content[index : index + block_size])
        for index in range(0, len(content), block_size)
    ]
    if integrity.get("hash") != digest_bytes(content):
        raise UnsupportedError(f"target content hash mismatch: {path}")
    if integrity.get("blocks") != blocks:
        raise UnsupportedError(f"target block hash mismatch: {path}")


def inspect_asar(path: Path) -> AsarInspection:
    require_regular_file(path, "ASAR archive")
    archive_size = path.stat().st_size
    if archive_size < 16:
        raise UnsupportedError("ASAR archive is too short")
    with path.open("rb") as handle:
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as archive:
            header_pickle_size = struct.unpack_from("<I", archive, 4)[0]
            json_size = struct.unpack_from("<I", archive, 12)[0]
            json_start = 16
            json_end = json_start + json_size
            content_start = 8 + header_pickle_size
            if json_end > content_start or content_start > archive_size:
                raise UnsupportedError("invalid ASAR header bounds")
            raw_header = bytes(archive[json_start:json_end])
            try:
                header = json.loads(raw_header)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise UnsupportedError(f"invalid ASAR JSON header: {exc}") from exc
            if not isinstance(header, dict):
                raise UnsupportedError("ASAR header is not a dictionary")
            entries = list(
                walk_asar_files(header, content_start, archive_size)
            )
            validate_non_overlapping_entries(entries)
            original_positions = find_all(
                archive,
                ORIGINAL,
                content_start,
                archive_size,
            )
            patched_positions = find_all(
                archive,
                PATCHED,
                content_start,
                archive_size,
            )
            counts = len(original_positions), len(patched_positions)
            if counts == (1, 0):
                marker_state = STATUS_READY
                marker_position = original_positions[0]
                marker = ORIGINAL
            elif counts == (0, 1):
                marker_state = STATUS_PATCHED
                marker_position = patched_positions[0]
                marker = PATCHED
            else:
                raise UnsupportedError(
                    f"expected one timer marker, found original={counts[0]} "
                    f"patched={counts[1]}"
                )
            containing = [
                item
                for item in entries
                if item[2] <= marker_position
                and marker_position + len(marker) <= item[3]
            ]
            if len(containing) != 1:
                raise UnsupportedError("timer marker is not in exactly one ASAR entry")
            target_path, target_entry, target_start, target_end = containing[0]
            target_content = bytes(archive[target_start:target_end])
            marker_offset = marker_position - target_start
            validate_semantic_context(target_content, marker_offset)
            validate_entry_integrity(
                target_path,
                target_entry,
                target_content,
            )
            return AsarInspection(
                header=header,
                raw_header=raw_header,
                json_start=json_start,
                json_end=json_end,
                content_start=content_start,
                target_path=target_path,
                target_entry=target_entry,
                target_start=target_start,
                target_end=target_end,
                target_content=target_content,
                marker_offset=marker_offset,
                marker_state=marker_state,
            )


def info_header_hash(info_blob: bytes, source: Path) -> str:
    info = parse_info_blob(info_blob, source)
    integrity_root = info.get("ElectronAsarIntegrity")
    if not isinstance(integrity_root, dict):
        raise UnsupportedError("Info.plist has no ElectronAsarIntegrity dictionary")
    integrity = integrity_root.get("Resources/app.asar")
    if not isinstance(integrity, dict) or integrity.get("algorithm") != "SHA256":
        raise UnsupportedError("Info.plist has no supported ASAR integrity entry")
    value = integrity.get("hash")
    if not isinstance(value, str) or len(value) != 64:
        raise UnsupportedError("Info.plist has an invalid ASAR header hash")
    return value


def inspect_pair(asar_path: Path, info_path: Path) -> PairInspection:
    asar = inspect_asar(asar_path)
    info_blob = info_path.read_bytes()
    expected_hash = info_header_hash(info_blob, info_path)
    actual_hash = digest_bytes(asar.raw_header)
    if expected_hash != actual_hash:
        raise PairMismatchError(
            "Info.plist ASAR hash does not match the raw ASAR header"
        )
    return PairInspection(asar, info_blob, expected_hash)


def changed_byte_positions(original: bytes, changed: bytes) -> list[int]:
    if len(original) != len(changed):
        raise PatchError("patch changed target content length")
    return [
        index
        for index, pair in enumerate(zip(original, changed))
        if pair[0] != pair[1]
    ]


def build_patch_plan(asar_path: Path, info_path: Path) -> PatchPlan:
    pair = inspect_pair(asar_path, info_path)
    asar = pair.asar
    if asar.marker_state != STATUS_READY:
        raise PatchError("cannot build a patch plan from an already patched archive")
    if len(ORIGINAL) != len(PATCHED):
        raise PatchError("patch markers do not have equal length")
    changed_target = asar.target_content.replace(ORIGINAL, PATCHED, 1)
    differences = changed_byte_positions(asar.target_content, changed_target)
    expected_difference = asar.marker_offset + ORIGINAL.index(b"requestUserInput")
    if differences != [expected_difference]:
        raise PatchError(
            f"target patch changed unexpected bytes: {differences}"
        )
    canonical_header = json.dumps(
        asar.header,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    if canonical_header != asar.raw_header:
        raise PatchError("ASAR header serialization is not byte-stable")
    integrity = asar.target_entry["integrity"]
    block_size = integrity["blockSize"]
    integrity["hash"] = digest_bytes(changed_target)
    integrity["blocks"] = [
        digest_bytes(changed_target[index : index + block_size])
        for index in range(0, len(changed_target), block_size)
    ]
    changed_header = json.dumps(
        asar.header,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    if len(changed_header) != len(asar.raw_header):
        raise PatchError("patched ASAR header changed length")
    old_header_hash = digest_bytes(asar.raw_header).encode()
    new_header_hash = digest_bytes(changed_header).encode()
    if pair.info_blob.count(old_header_hash) != 1:
        raise PatchError("could not locate exactly one ASAR hash in Info.plist")
    changed_info = pair.info_blob.replace(old_header_hash, new_header_hash, 1)
    if len(changed_info) != len(pair.info_blob):
        raise PatchError("patched Info.plist changed length")
    replacements = (
        (asar.json_start, asar.json_end, changed_header),
        (asar.target_start, asar.target_end, changed_target),
    )
    return PatchPlan(
        target_path=asar.target_path,
        target_start=asar.target_start,
        target_end=asar.target_end,
        json_start=asar.json_start,
        json_end=asar.json_end,
        changed_target=changed_target,
        changed_header=changed_header,
        changed_info=changed_info,
        original_asar_hash=digest_file(asar_path),
        original_info_hash=digest_bytes(pair.info_blob),
        original_header_hash=digest_bytes(asar.raw_header),
        patched_asar_hash=digest_file_with_replacements(
            asar_path,
            replacements,
        ),
        patched_info_hash=digest_bytes(changed_info),
        patched_header_hash=digest_bytes(changed_header),
    )


def signature_result(app: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "/usr/bin/codesign",
            "--verify",
            "--deep",
            "--strict",
            f"-R={OPENAI_REQUIREMENT}",
            str(app),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def openai_signature_valid(app: Path) -> bool:
    return signature_result(app).returncode == 0


def generic_signature_result(app: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "/usr/bin/codesign",
            "--verify",
            "--deep",
            "--strict",
            str(app),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def generic_signature_valid(app: Path) -> bool:
    return generic_signature_result(app).returncode == 0


def codesign_display(
    target: Path,
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/usr/bin/codesign", "--display", *arguments, str(target)],
        capture_output=True,
        text=True,
        check=False,
    )


def codesign_identifier(target: Path) -> str:
    result = codesign_display(target, "--verbose=4")
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        raise UnsupportedError(f"cannot inspect signing target {target}: {message}")
    for line in (result.stdout + result.stderr).splitlines():
        if line.startswith("Identifier="):
            return line.removeprefix("Identifier=")
    raise UnsupportedError(f"signing target has no identifier: {target}")


def codesign_contract_metadata(target: Path) -> tuple[str, str]:
    result = codesign_display(target, "--verbose=4")
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        raise UnsupportedError(f"cannot inspect signing metadata {target}: {message}")
    flags: str | None = None
    runtime_version: str | None = None
    for line in (result.stdout + result.stderr).splitlines():
        if line.startswith("CodeDirectory ") and " flags=" in line:
            flags = line.split(" flags=", 1)[1].split(" hashes=", 1)[0]
        elif line.startswith("Runtime Version="):
            runtime_version = line.removeprefix("Runtime Version=")
    if flags is None or runtime_version is None:
        raise UnsupportedError(f"signing metadata is incomplete for {target}")
    return flags, runtime_version


def codesign_possible_files(bundle: Bundle, target: Path) -> set[str]:
    result = codesign_display(target, "--file-list", "-")
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        raise UnsupportedError(f"cannot inspect signing file list {target}: {message}")
    files: set[str] = set()
    for line in result.stdout.splitlines():
        if not line.startswith("/"):
            continue
        path = Path(line).resolve(strict=True)
        if not is_within(path, bundle.app):
            raise UnsupportedError(f"signing file escapes application bundle: {path}")
        require_regular_file(path, "signing backup file")
        files.add(path.relative_to(bundle.app).as_posix())
    if not files:
        raise UnsupportedError(f"signing target reported no possible files: {target}")
    return files


def resolved_target(bundle: Bundle, relative_path: str) -> Path:
    candidate = bundle.app / relative_path
    try:
        path = candidate.resolve(strict=True)
    except OSError as exc:
        raise UnsupportedError(
            f"missing signing target {relative_path}: {exc}"
        ) from exc
    if not is_within(path, bundle.app):
        raise UnsupportedError(f"signing target escapes application bundle: {path}")
    return path


def signing_specifications() -> tuple[tuple[str, str, str], ...]:
    codex = "Contents/Frameworks/Codex Framework.framework"
    codex_helpers = f"{codex}/Versions/Current/Helpers"
    sparkle = "Contents/Frameworks/Sparkle.framework"
    sparkle_current = f"{sparkle}/Versions/Current"
    return (
        (
            f"{codex_helpers}/Codex (Alerts).app",
            "com.openai.codex.framework.AlertNotificationService",
            ENTITLEMENTS_HELPER,
        ),
        (
            f"{codex_helpers}/Codex (GPU).app",
            "com.openai.codex.helper",
            ENTITLEMENTS_HELPER,
        ),
        (
            f"{codex_helpers}/Codex (Renderer).app",
            "com.openai.codex.helper.renderer",
            ENTITLEMENTS_HELPER,
        ),
        (
            f"{codex_helpers}/Codex (Service).app",
            "com.openai.codex.helper",
            ENTITLEMENTS_HELPER,
        ),
        (
            f"{codex_helpers}/app_mode_loader",
            "app_mode_loader",
            ENTITLEMENTS_HELPER,
        ),
        (
            f"{codex_helpers}/browser_crashpad_handler",
            "browser_crashpad_handler",
            ENTITLEMENTS_HELPER,
        ),
        (
            f"{codex_helpers}/web_app_shortcut_copier",
            "web_app_shortcut_copier",
            ENTITLEMENTS_HELPER,
        ),
        (
            f"{sparkle_current}/Updater.app",
            "org.sparkle-project.Sparkle.Updater",
            ENTITLEMENTS_HELPER,
        ),
        (
            f"{sparkle_current}/XPCServices/Downloader.xpc",
            "org.sparkle-project.DownloaderService",
            ENTITLEMENTS_HELPER,
        ),
        (
            f"{sparkle_current}/XPCServices/Installer.xpc",
            "org.sparkle-project.InstallerLauncher",
            ENTITLEMENTS_HELPER,
        ),
        (
            f"{sparkle_current}/Autoupdate",
            "Autoupdate",
            ENTITLEMENTS_HELPER,
        ),
        (
            codex,
            "com.openai.codex.framework",
            ENTITLEMENTS_OPTIONAL_SHARED,
        ),
        (
            sparkle,
            "org.sparkle-project.Sparkle",
            ENTITLEMENTS_OPTIONAL_SHARED,
        ),
        (
            "Contents/PlugIns/CodexDockTilePlugin.plugin",
            "com.openai.codex.dock-tile-plugin",
            ENTITLEMENTS_OPTIONAL_SHARED,
        ),
        (".", EXPECTED_BUNDLE_ID, ENTITLEMENTS_MAIN),
    )


def expected_runtime_version(relative_path: str) -> str:
    if relative_path == "Contents/Frameworks/Sparkle.framework" or (
        relative_path.startswith("Contents/Frameworks/Sparkle.framework/")
    ):
        return "26.5.0"
    if relative_path == "Contents/PlugIns/CodexDockTilePlugin.plugin":
        return "26.5.0"
    return "26.0.0"


def expected_signing_targets(
    bundle: Bundle,
    *,
    require_existing: bool = True,
) -> tuple[SigningTarget, ...]:
    targets: list[SigningTarget] = []
    for relative_path, expected_identifier, policy in signing_specifications():
        if require_existing:
            path = resolved_target(bundle, relative_path)
        else:
            path = (bundle.app / relative_path).resolve(strict=False)
            if not is_within(path, bundle.app):
                raise PatchError(
                    f"manifest signing target escapes application bundle: {path}"
                )
        resolved_relative = (
            "." if path == bundle.app else path.relative_to(bundle.app).as_posix()
        )
        targets.append(
            SigningTarget(
                path=path,
                relative_path=resolved_relative,
                identifier=expected_identifier,
                entitlement_policy=policy,
                flags="",
                runtime_version="",
            )
        )
    return tuple(targets)


def allowed_entitlement_policies(policy: str) -> tuple[str, ...]:
    if policy == ENTITLEMENTS_OPTIONAL_SHARED:
        return (ENTITLEMENTS_NONE, ENTITLEMENTS_HELPER)
    return (policy,)


def original_entitlements_for_policy(policy: str) -> dict[str, Any]:
    if policy == ENTITLEMENTS_NONE:
        return {}
    if policy == ENTITLEMENTS_MAIN:
        return EXPECTED_ORIGINAL_MAIN_ENTITLEMENTS
    if policy == ENTITLEMENTS_HELPER:
        return EXPECTED_ORIGINAL_SHARED_ENTITLEMENTS
    raise PatchError(f"unknown entitlement policy: {policy}")


def validate_original_entitlements(target: SigningTarget) -> str:
    try:
        actual = codesign_entitlements(target.path)
    except PatchError as exc:
        raise UnsupportedError(str(exc)) from exc
    for policy in allowed_entitlement_policies(target.entitlement_policy):
        if actual == original_entitlements_for_policy(policy):
            return policy
    raise UnsupportedError(
        f"source entitlements changed for {target.relative_path}"
    )


def discover_signing_plan(bundle: Bundle) -> SigningPlan:
    targets = expected_signing_targets(bundle)
    discovered_targets: list[SigningTarget] = []
    possible_files: set[str] = set()
    for target in targets:
        actual_identifier = codesign_identifier(target.path)
        if actual_identifier != target.identifier:
            raise UnsupportedError(
                f"signing target identifier changed for {target.relative_path}: "
                f"{actual_identifier}"
            )
        flags, runtime_version = codesign_contract_metadata(target.path)
        if flags != EXPECTED_SIGNING_FLAGS:
            raise UnsupportedError(
                f"source signing flags changed for {target.relative_path}: {flags}"
            )
        expected_runtime = expected_runtime_version(target.relative_path)
        if runtime_version != expected_runtime:
            raise UnsupportedError(
                f"source runtime changed for {target.relative_path}: "
                f"{runtime_version}"
            )
        entitlement_policy = validate_original_entitlements(target)
        discovered = SigningTarget(
            path=target.path,
            relative_path=target.relative_path,
            identifier=target.identifier,
            entitlement_policy=entitlement_policy,
            flags=flags,
            runtime_version=runtime_version,
        )
        discovered_targets.append(discovered)
        path = target.path
        possible_files.update(codesign_possible_files(bundle, path))
    if len(targets) != 15:
        raise UnsupportedError("signing target graph is not the expected size")
    if len(possible_files) != 26:
        raise UnsupportedError(
            f"signing file graph changed: expected 26, found {len(possible_files)}"
        )
    return SigningPlan(tuple(discovered_targets), tuple(sorted(possible_files)))


def codesign_file_lines(
    bundle: Bundle,
    result: subprocess.CompletedProcess[str],
    target: Path,
) -> set[str]:
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        raise PatchError(f"codesign failed for {target}: {message}")
    files: set[str] = set()
    for line in result.stdout.splitlines():
        if not line.startswith("/"):
            continue
        path = Path(line).resolve(strict=True)
        if not is_within(path, bundle.app):
            raise PatchError(f"codesign reported a path outside the app: {path}")
        require_regular_file(path, "codesign possible file")
        files.add(path.relative_to(bundle.app).as_posix())
    if not files:
        raise PatchError(f"codesign reported no possible files for {target}")
    return files


def validate_entitlements_file(path: Path) -> None:
    require_regular_file(path, "sanitized entitlements")
    try:
        data = plistlib.loads(path.read_bytes())
    except plistlib.InvalidFileException as exc:
        raise PatchError("sanitized entitlements plist is invalid") from exc
    if data != SANITIZED_ENTITLEMENTS:
        raise PatchError("sanitized entitlements do not match the required contract")


def signing_command(
    target: SigningTarget,
    entitlements: Path,
    *,
    dry_run: bool,
) -> list[str]:
    command = [
        "/usr/bin/codesign",
        "--force",
        "--sign",
        "-",
        "--preserve-metadata=identifier,flags,runtime",
        "--timestamp=none",
        "--file-list",
        "-",
    ]
    if dry_run:
        command.append("--dryrun")
    if target.entitlement_policy != ENTITLEMENTS_NONE:
        if target.entitlement_policy == ENTITLEMENTS_HELPER:
            command.append("--force-library-entitlements")
        command.extend(("--entitlements", str(entitlements)))
    command.append(str(target.path))
    return command


def run_signing_commands(
    bundle: Bundle,
    signing: SigningPlan,
    entitlements: Path,
    *,
    dry_run: bool,
) -> set[str]:
    validate_entitlements_file(entitlements)
    possible_files: set[str] = set()
    for target in signing.targets:
        result = subprocess.run(
            signing_command(target, entitlements, dry_run=dry_run),
            capture_output=True,
            text=True,
            check=False,
        )
        possible_files.update(codesign_file_lines(bundle, result, target.path))
    expected = set(signing.backup_files)
    if possible_files != expected:
        missing = sorted(expected - possible_files)
        unexpected = sorted(possible_files - expected)
        raise PatchError(
            "codesign possible-file graph changed; "
            f"missing={missing[:3]}, unexpected={unexpected[:3]}"
        )
    return possible_files


def dry_run_signing(
    bundle: Bundle,
    signing: SigningPlan,
    entitlements: Path,
) -> set[str]:
    return run_signing_commands(
        bundle,
        signing,
        entitlements,
        dry_run=True,
    )


def sign_bundle(
    bundle: Bundle,
    signing: SigningPlan,
    entitlements: Path,
) -> None:
    dry_run_signing(bundle, signing, entitlements)
    run_signing_commands(
        bundle,
        signing,
        entitlements,
        dry_run=False,
    )


def codesign_entitlements(target: Path) -> dict[str, Any]:
    result = subprocess.run(
        [
            "/usr/bin/codesign",
            "--display",
            "--entitlements",
            "-",
            "--xml",
            str(target),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        message = os.fsdecode(result.stderr).strip()
        raise PatchError(f"cannot inspect entitlements for {target}: {message}")
    if not result.stdout:
        return {}
    try:
        entitlements = plistlib.loads(result.stdout)
    except plistlib.InvalidFileException as exc:
        raise PatchError(f"invalid embedded entitlements for {target}") from exc
    if not isinstance(entitlements, dict):
        raise PatchError(f"embedded entitlements are not a dictionary: {target}")
    return entitlements


def codesign_metadata(target: Path) -> str:
    result = codesign_display(target, "--verbose=4")
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        raise PatchError(f"cannot inspect ad hoc signature {target}: {message}")
    return result.stdout + result.stderr


def validate_signed_bundle(
    bundle: Bundle,
    signing: SigningPlan,
    patch_plan: PatchPlan,
) -> None:
    generic_result = generic_signature_result(bundle.app)
    if generic_result.returncode != 0:
        message = generic_result.stderr.strip() or generic_result.stdout.strip()
        raise PatchError(f"generic ad hoc signature is invalid: {message}")
    if openai_signature_valid(bundle.app):
        raise PatchError("patched app still passes the OpenAI signature requirement")
    pair = inspect_pair(bundle.asar, bundle.info)
    if pair.asar.marker_state != STATUS_PATCHED:
        raise PatchError("signed bundle does not contain the patched marker")
    if digest_file(bundle.asar) != patch_plan.patched_asar_hash:
        raise PatchError("signed bundle app.asar hash is incorrect")
    if digest_file(bundle.info) != patch_plan.patched_info_hash:
        raise PatchError("signed bundle Info.plist hash is incorrect")
    for target in signing.targets:
        actual_identifier = codesign_identifier(target.path)
        if actual_identifier != target.identifier:
            raise PatchError(
                f"signed identifier changed for {target.relative_path}: "
                f"{actual_identifier}"
            )
        actual_entitlements = codesign_entitlements(target.path)
        expected_entitlements = (
            {} if target.entitlement_policy == ENTITLEMENTS_NONE
            else SANITIZED_ENTITLEMENTS
        )
        if actual_entitlements != expected_entitlements:
            raise PatchError(
                f"signed entitlements are incorrect for {target.relative_path}"
            )
        actual_flags, actual_runtime = codesign_contract_metadata(target.path)
        if actual_flags != EXPECTED_AD_HOC_SIGNING_FLAGS:
            raise PatchError(
                f"signed flags changed for {target.relative_path}: {actual_flags}"
            )
        if actual_runtime != target.runtime_version:
            raise PatchError(
                f"signed runtime changed for {target.relative_path}: "
                f"{actual_runtime}"
            )
    main_metadata = codesign_metadata(bundle.app)
    required_metadata = (
        "Signature=adhoc",
        "TeamIdentifier=not set",
        "Runtime Version=",
    )
    for marker in required_metadata:
        if marker not in main_metadata:
            raise PatchError(f"main ad hoc signature is missing {marker}")


def running_bundle_processes(bundle: Bundle) -> list[tuple[int, str]]:
    result = subprocess.run(
        ["/bin/ps", "-axo", "pid="],
        capture_output=True,
        text=True,
        check=True,
    )
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    libproc.proc_pidpath.argtypes = [
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    libproc.proc_pidpath.restype = ctypes.c_int
    contents = bundle.app / "Contents"
    matches: list[tuple[int, str]] = []
    for line in result.stdout.splitlines():
        try:
            pid = int(line.strip())
        except ValueError:
            continue
        if pid == os.getpid():
            continue
        buffer = ctypes.create_string_buffer(4096)
        length = libproc.proc_pidpath(pid, buffer, len(buffer))
        if length <= 0:
            continue
        command = os.fsdecode(buffer.value)
        command_path = Path(command).resolve(strict=False)
        belongs_to_bundle = command_path == bundle.executable or is_within(
            command_path,
            contents,
        )
        if belongs_to_bundle:
            matches.append((pid, command))
    return matches


def require_no_running_processes(bundle: Bundle) -> None:
    matches = running_bundle_processes(bundle)
    if not matches:
        return
    sample = ", ".join(f"{pid}:{command}" for pid, command in matches[:3])
    raise PatchError(
        f"target application still has running processes ({sample}); "
        "quit it completely and try again"
    )


def fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def require_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise PatchError(f"invalid {label} in backup manifest")
    if any(character not in "0123456789abcdef" for character in value):
        raise PatchError(f"invalid {label} in backup manifest")
    return value


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PatchError(f"invalid {label} in backup manifest")
    return value


def require_mode(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise PatchError(f"invalid {label} in backup manifest")
    try:
        mode = int(value, 8)
    except ValueError as exc:
        raise PatchError(f"invalid {label} in backup manifest") from exc
    if mode < 0 or mode > 0o7777 or oct(mode) != value:
        raise PatchError(f"invalid {label} in backup manifest")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PatchError(f"invalid {label} in backup manifest")
    return value


def require_nonnegative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise PatchError(f"invalid {label} in backup manifest")
    return value


def require_relative_path(
    value: Any,
    label: str,
    *,
    allow_dot: bool = False,
) -> str:
    path = require_string(value, label)
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or path != pure.as_posix():
        raise PatchError(f"invalid {label} in backup manifest")
    if path == "." and not allow_dot:
        raise PatchError(f"invalid {label} in backup manifest")
    return path


def entitlements_blob() -> bytes:
    return plistlib.dumps(
        SANITIZED_ENTITLEMENTS,
        fmt=plistlib.FMT_XML,
        sort_keys=True,
    )


def load_manifest(bundle: Bundle, root: Path) -> ManifestRecord:
    directory = backup_directory(root, bundle)
    validate_backup_directory(root, directory)
    manifest_path = directory / "manifest.json"
    require_regular_file(manifest_path, "backup manifest")
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PatchError(f"invalid backup manifest: {exc}") from exc
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != MANIFEST_SCHEMA_VERSION
    ):
        raise PatchError("unsupported backup manifest schema")
    expected_identity = {
        "app_realpath": str(bundle.app),
        "bundle_id": EXPECTED_BUNDLE_ID,
        "version": bundle.version,
        "build": bundle.build,
    }
    for key, expected in expected_identity.items():
        if data.get(key) != expected:
            raise PatchError(f"backup manifest {key} does not match target")

    signing_data = require_mapping(data.get("signing"), "signing section")
    raw_targets = signing_data.get("targets")
    if not isinstance(raw_targets, list) or len(raw_targets) != 15:
        raise PatchError("invalid signing targets in backup manifest")
    expected_targets = expected_signing_targets(
        bundle,
        require_existing=False,
    )
    manifest_targets: list[SigningTarget] = []
    for index, raw_target in enumerate(raw_targets):
        target = require_mapping(raw_target, f"signing target {index}")
        relative_path = require_relative_path(
            target.get("path"),
            f"signing target {index} path",
            allow_dot=True,
        )
        identifier = require_string(
            target.get("identifier"),
            f"signing target {index} identifier",
        )
        entitlement_policy = require_string(
            target.get("entitlements"),
            f"signing target {index} entitlement policy",
        )
        flags = require_string(
            target.get("flags"),
            f"signing target {index} flags",
        )
        runtime_version = require_string(
            target.get("runtime_version"),
            f"signing target {index} runtime version",
        )
        expected_target = expected_targets[index]
        if flags != EXPECTED_SIGNING_FLAGS:
            raise PatchError("backup manifest signing flags are unsupported")
        if runtime_version != expected_runtime_version(relative_path):
            raise PatchError("backup manifest runtime version is unsupported")
        if (
            relative_path,
            identifier,
        ) != (
            expected_target.relative_path,
            expected_target.identifier,
        ) or entitlement_policy not in allowed_entitlement_policies(
            expected_target.entitlement_policy
        ):
            raise PatchError(
                "backup manifest signing target graph does not match target"
            )
        manifest_targets.append(
            SigningTarget(
                path=expected_target.path,
                relative_path=relative_path,
                identifier=identifier,
                entitlement_policy=entitlement_policy,
                flags=flags,
                runtime_version=runtime_version,
            )
        )

    raw_signing_files = signing_data.get("backup_files")
    if not isinstance(raw_signing_files, list):
        raise PatchError("invalid signing backup files in backup manifest")
    signing_files = tuple(
        sorted(
            require_relative_path(value, "signing backup path")
            for value in raw_signing_files
        )
    )
    if len(signing_files) != 26 or len(set(signing_files)) != 26:
        raise PatchError("backup manifest must contain 26 signing files")

    entitlements_path = directory / "sanitized-entitlements.plist"
    require_regular_file(entitlements_path, "backup entitlements")
    expected_entitlements_hash = require_hash(
        signing_data.get("entitlements_sha256"),
        "entitlements hash",
    )
    actual_entitlements_blob = entitlements_path.read_bytes()
    if digest_bytes(actual_entitlements_blob) != expected_entitlements_hash:
        raise PatchError("backup entitlements hash does not match manifest")
    try:
        actual_entitlements = plistlib.loads(actual_entitlements_blob)
    except plistlib.InvalidFileException as exc:
        raise PatchError("backup entitlements are invalid") from exc
    if actual_entitlements != SANITIZED_ENTITLEMENTS:
        raise PatchError("backup entitlements do not match the signing contract")

    raw_files = data.get("files")
    if not isinstance(raw_files, list):
        raise PatchError("invalid file inventory in backup manifest")
    inventory_paths = {
        ASAR_RELATIVE_PATH,
        INFO_RELATIVE_PATH,
        *signing_files,
    }
    if len(inventory_paths) != 28 or len(raw_files) != 28:
        raise PatchError("backup manifest must contain 28 unique files")
    original_root = directory / "original"
    if original_root.is_symlink() or not original_root.is_dir():
        raise PatchError("original backup directory is unsafe")
    resolved_directory = directory.resolve(strict=True)
    resolved_original_root = original_root.resolve(strict=True)
    if resolved_original_root.parent != resolved_directory:
        raise PatchError("original backup directory escapes version backup")
    files: list[BackupFile] = []
    seen_paths: set[str] = set()
    for index, raw_file in enumerate(raw_files):
        entry = require_mapping(raw_file, f"file inventory entry {index}")
        relative_path = require_relative_path(
            entry.get("path"),
            f"file inventory entry {index} path",
        )
        if relative_path in seen_paths:
            raise PatchError("duplicate file path in backup manifest")
        seen_paths.add(relative_path)
        sha256 = require_hash(
            entry.get("sha256"),
            f"file inventory entry {index} hash",
        )
        size = require_nonnegative_int(
            entry.get("size"),
            f"file inventory entry {index} size",
        )
        mode = require_mode(
            entry.get("mode"),
            f"file inventory entry {index} mode",
        )
        role = require_string(
            entry.get("role"),
            f"file inventory entry {index} role",
        )
        expected_role = (
            "patch"
            if relative_path in (ASAR_RELATIVE_PATH, INFO_RELATIVE_PATH)
            else "code_resources"
            if relative_path.endswith("/_CodeSignature/CodeResources")
            else "mach_o"
        )
        if role != expected_role:
            raise PatchError("backup manifest file role is incorrect")
        backup_path = original_root / relative_path
        require_regular_file(backup_path, "original backup file")
        resolved_backup = backup_path.resolve(strict=True)
        if not is_within(resolved_backup, resolved_original_root):
            raise PatchError("backup file escapes original backup directory")
        if backup_path.stat().st_size != size:
            raise PatchError("backup file size does not match manifest")
        if digest_file(backup_path) != sha256:
            raise PatchError("backup file hash does not match manifest")
        files.append(
            BackupFile(
                relative_path,
                backup_path,
                sha256,
                size,
                mode,
                role,
            )
        )
    if seen_paths != inventory_paths:
        raise PatchError("backup file inventory does not match signing contract")

    file_map = {entry.relative_path: entry for entry in files}
    backup_asar = file_map[ASAR_RELATIVE_PATH].backup_path
    backup_info = file_map[INFO_RELATIVE_PATH].backup_path
    original = require_mapping(data.get("original"), "original section")
    patched = require_mapping(data.get("patched"), "patched section")
    original_asar_hash = require_hash(
        original.get("app_asar_sha256"),
        "original app.asar hash",
    )
    original_info_hash = require_hash(
        original.get("info_plist_sha256"),
        "original Info.plist hash",
    )
    original_header_hash = require_hash(
        original.get("asar_header_sha256"),
        "original ASAR header hash",
    )
    require_mode(original.get("app_asar_mode"), "original app.asar mode")
    require_mode(original.get("info_plist_mode"), "original Info.plist mode")
    patched_asar_hash = require_hash(
        patched.get("app_asar_sha256"),
        "patched app.asar hash",
    )
    patched_info_hash = require_hash(
        patched.get("info_plist_sha256"),
        "patched Info.plist hash",
    )
    patched_header_hash = require_hash(
        patched.get("asar_header_sha256"),
        "patched ASAR header hash",
    )
    if file_map[ASAR_RELATIVE_PATH].sha256 != original_asar_hash:
        raise PatchError("backup app.asar hash does not match original section")
    if file_map[INFO_RELATIVE_PATH].sha256 != original_info_hash:
        raise PatchError("backup Info.plist hash does not match original section")
    backup_info_data = parse_info_blob(backup_info.read_bytes(), backup_info)
    if backup_info_data.get("CFBundleIdentifier") != EXPECTED_BUNDLE_ID:
        raise PatchError("backup bundle identifier is incorrect")
    if str(backup_info_data.get("CFBundleShortVersionString")) != bundle.version:
        raise PatchError("backup version does not match target")
    if str(backup_info_data.get("CFBundleVersion")) != bundle.build:
        raise PatchError("backup build does not match target")
    plan = build_patch_plan(backup_asar, backup_info)
    if plan.target_path != data.get("target_entry"):
        raise PatchError("backup target entry does not match manifest")
    expected_plan = (
        plan.original_asar_hash,
        plan.original_info_hash,
        plan.original_header_hash,
        plan.patched_asar_hash,
        plan.patched_info_hash,
        plan.patched_header_hash,
    )
    manifest_plan = (
        original_asar_hash,
        original_info_hash,
        original_header_hash,
        patched_asar_hash,
        patched_info_hash,
        patched_header_hash,
    )
    if expected_plan != manifest_plan:
        raise PatchError("backup manifest patch hashes are inconsistent")
    return ManifestRecord(
        directory,
        backup_asar,
        backup_info,
        data,
        plan,
        tuple(sorted(files, key=lambda entry: entry.relative_path)),
        SigningPlan(tuple(manifest_targets), signing_files),
        entitlements_path,
    )


def try_load_manifest(
    bundle: Bundle,
    root: Path,
) -> tuple[ManifestRecord | None, str | None]:
    directory = backup_directory(root, bundle)
    try:
        validate_backup_directory(root, directory)
    except (OSError, PatchError, ValueError) as exc:
        return None, str(exc)
    if not directory.exists():
        return None, None
    try:
        return load_manifest(bundle, root), None
    except (OSError, PatchError, ValueError) as exc:
        return None, str(exc)


def mixed_manifest_pair(
    asar_hash: str,
    info_hash: str,
    manifest: ManifestRecord,
) -> bool:
    original = manifest.data["original"]
    patched = manifest.data["patched"]
    asar_original = original["app_asar_sha256"]
    info_original = original["info_plist_sha256"]
    asar_patched = patched["app_asar_sha256"]
    info_patched = patched["info_plist_sha256"]
    known_asar = asar_hash in (asar_original, asar_patched)
    known_info = info_hash in (info_original, info_patched)
    coherent_original = asar_hash == asar_original and info_hash == info_original
    coherent_patched = asar_hash == asar_patched and info_hash == info_patched
    return known_asar and known_info and not coherent_original and not coherent_patched


def manifest_original_files_match(
    bundle: Bundle,
    manifest: ManifestRecord,
) -> bool:
    for entry in manifest.files:
        path = bundle.app / entry.relative_path
        try:
            require_regular_file(path, "tracked application file")
        except PatchError:
            return False
        if path.stat().st_size != entry.size or digest_file(path) != entry.sha256:
            return False
    return True


def classify(bundle: Bundle, root: Path) -> StateReport:
    asar_hash = digest_file(bundle.asar)
    info_hash = digest_file(bundle.info)
    signature_valid = openai_signature_valid(bundle.app)
    directory = backup_directory(root, bundle)
    manifest, manifest_error = try_load_manifest(bundle, root)
    if manifest_error is not None:
        return StateReport(
            bundle,
            directory,
            STATUS_UNTRUSTED,
            asar_hash,
            info_hash,
            signature_valid,
            detail=manifest_error,
        )
    if manifest is not None and mixed_manifest_pair(
        asar_hash,
        info_hash,
        manifest,
    ):
        return StateReport(
            bundle,
            directory,
            STATUS_RECOVERY_REQUIRED,
            asar_hash,
            info_hash,
            signature_valid,
            target_path=manifest.plan.target_path,
            detail="bundle files are from different patch states",
        )
    try:
        pair = inspect_pair(bundle.asar, bundle.info)
    except PairMismatchError as exc:
        if manifest is not None:
            return StateReport(
                bundle,
                directory,
                STATUS_RECOVERY_REQUIRED,
                asar_hash,
                info_hash,
                signature_valid,
                target_path=manifest.plan.target_path,
                detail=f"application pair is interrupted: {exc}",
            )
        return StateReport(
            bundle,
            directory,
            STATUS_UNTRUSTED,
            asar_hash,
            info_hash,
            signature_valid,
            detail=str(exc),
        )
    except UnsupportedError as exc:
        if manifest is not None:
            return StateReport(
                bundle,
                directory,
                STATUS_RECOVERY_REQUIRED,
                asar_hash,
                info_hash,
                signature_valid,
                target_path=manifest.plan.target_path,
                detail=f"application state requires restoration: {exc}",
            )
        return StateReport(
            bundle,
            directory,
            STATUS_UNSUPPORTED,
            asar_hash,
            info_hash,
            signature_valid,
            detail=str(exc),
        )
    target_path = pair.asar.target_path
    if pair.asar.marker_state == STATUS_READY:
        if not signature_valid:
            status = (
                STATUS_RECOVERY_REQUIRED
                if manifest is not None
                else STATUS_UNTRUSTED
            )
            detail = "original marker is present but OpenAI signature is invalid"
            plan = None
        elif manifest is not None and not manifest_original_files_match(
            bundle,
            manifest,
        ):
            status = STATUS_UNTRUSTED
            detail = "ready bundle does not match its existing backup manifest"
            plan = None
        else:
            try:
                signing = discover_signing_plan(bundle)
            except UnsupportedError as exc:
                status = STATUS_UNSUPPORTED
                detail = str(exc)
                plan = None
            else:
                if manifest is not None and signing != manifest.signing:
                    status = STATUS_UNTRUSTED
                    detail = "ready signing graph does not match its backup manifest"
                    plan = None
                else:
                    status = STATUS_READY
                    detail = None
                    plan = build_patch_plan(bundle.asar, bundle.info)
        return StateReport(
            bundle,
            directory,
            status,
            asar_hash,
            info_hash,
            signature_valid,
            target_path,
            plan,
            detail,
        )
    if signature_valid:
        return StateReport(
            bundle,
            directory,
            STATUS_UNTRUSTED,
            asar_hash,
            info_hash,
            signature_valid,
            target_path,
            detail="patched marker is present but OpenAI signature still validates",
        )
    if manifest is None:
        detail = (
            "patched bundle has no matching original backup"
            if generic_signature_valid(bundle.app)
            else "patched bundle is not validly ad hoc signed and has no backup"
        )
        return StateReport(
            bundle,
            directory,
            STATUS_PATCHED_UNRESTORABLE,
            asar_hash,
            info_hash,
            signature_valid,
            target_path,
            detail=detail,
        )
    if not (
        asar_hash == manifest.data["patched"]["app_asar_sha256"]
        and info_hash == manifest.data["patched"]["info_plist_sha256"]
    ):
        return StateReport(
            bundle,
            directory,
            STATUS_RECOVERY_REQUIRED,
            asar_hash,
            info_hash,
            signature_valid,
            target_path,
            detail="patched bundle does not match its backup manifest",
        )
    try:
        validate_signed_bundle(bundle, manifest.signing, manifest.plan)
    except (OSError, PatchError, subprocess.SubprocessError) as exc:
        return StateReport(
            bundle,
            directory,
            STATUS_RECOVERY_REQUIRED,
            asar_hash,
            info_hash,
            signature_valid,
            target_path,
            detail=f"signed patch is incomplete: {exc}",
        )
    return StateReport(
        bundle,
        directory,
        STATUS_PATCHED,
        asar_hash,
        info_hash,
        signature_valid,
        target_path,
    )


def unique_directory(parent: Path, stem: str) -> Path:
    for counter in range(1000):
        candidate = parent / f".{stem}-{os.getpid()}-{counter}"
        try:
            candidate.mkdir(mode=0o700)
            return candidate
        except FileExistsError:
            continue
    raise PatchError(f"could not allocate staging directory under {parent}")


def manifest_data(
    bundle: Bundle,
    plan: PatchPlan,
    signing: SigningPlan,
    files: Sequence[BackupFile],
) -> dict[str, Any]:
    file_map = {entry.relative_path: entry for entry in files}
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "app_realpath": str(bundle.app),
        "bundle_id": EXPECTED_BUNDLE_ID,
        "version": bundle.version,
        "build": bundle.build,
        "target_entry": plan.target_path,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "files": [
            {
                "mode": entry.mode,
                "path": entry.relative_path,
                "role": entry.role,
                "sha256": entry.sha256,
                "size": entry.size,
            }
            for entry in sorted(files, key=lambda value: value.relative_path)
        ],
        "signing": {
            "backup_files": list(signing.backup_files),
            "entitlements_sha256": digest_bytes(entitlements_blob()),
            "targets": [
                {
                    "entitlements": target.entitlement_policy,
                    "flags": target.flags,
                    "identifier": target.identifier,
                    "path": target.relative_path,
                    "runtime_version": target.runtime_version,
                }
                for target in signing.targets
            ],
        },
        "original": {
            "app_asar_sha256": plan.original_asar_hash,
            "info_plist_sha256": plan.original_info_hash,
            "asar_header_sha256": plan.original_header_hash,
            "app_asar_mode": file_map[ASAR_RELATIVE_PATH].mode,
            "info_plist_mode": file_map[INFO_RELATIVE_PATH].mode,
        },
        "patched": {
            "app_asar_sha256": plan.patched_asar_hash,
            "info_plist_sha256": plan.patched_info_hash,
            "asar_header_sha256": plan.patched_header_hash,
        },
    }


def write_manifest(path: Path, data: dict[str, Any]) -> None:
    with path.open("x", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)


def ensure_backup(bundle: Bundle, root: Path, plan: PatchPlan) -> ManifestRecord:
    final_directory = backup_directory(root, bundle)
    validate_backup_directory(root, final_directory)
    if final_directory.exists():
        manifest = load_manifest(bundle, root)
        current_signing = discover_signing_plan(bundle)
        if current_signing != manifest.signing:
            raise PatchError("existing backup signing graph does not match target")
        return manifest
    signing = discover_signing_plan(bundle)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = unique_directory(
        root,
        f"{sanitize_identity(bundle.version)}-{sanitize_identity(bundle.build)}.staging",
    )
    original_root = staging / "original"
    original_root.mkdir(mode=0o700)
    relative_paths = tuple(
        sorted(
            {
                ASAR_RELATIVE_PATH,
                INFO_RELATIVE_PATH,
                *signing.backup_files,
            }
        )
    )
    if len(relative_paths) != 28:
        raise PatchError("signing backup does not contain 28 unique files")
    backup_files: list[BackupFile] = []
    created_directories = {original_root}
    for relative_path in relative_paths:
        source = bundle.app / relative_path
        require_regular_file(source, "application backup source")
        resolved_source = source.resolve(strict=True)
        if not is_within(resolved_source, bundle.app):
            raise PatchError(f"backup source escapes application bundle: {source}")
        destination = original_root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = destination.parent
        while is_within(parent, original_root) or parent == original_root:
            created_directories.add(parent)
            if parent == original_root:
                break
            parent = parent.parent
        source_hash = digest_file(source)
        source_stat = source.stat()
        shutil.copy2(source, destination)
        os.chmod(destination, 0o600)
        fsync_file(destination)
        if digest_file(destination) != source_hash:
            raise PatchError(
                f"staged backup hash mismatch; retained at {staging}: {relative_path}"
            )
        role = (
            "patch"
            if relative_path in (ASAR_RELATIVE_PATH, INFO_RELATIVE_PATH)
            else "code_resources"
            if relative_path.endswith("/_CodeSignature/CodeResources")
            else "mach_o"
        )
        backup_files.append(
            BackupFile(
                relative_path=relative_path,
                backup_path=destination,
                sha256=source_hash,
                size=source_stat.st_size,
                mode=oct(stat.S_IMODE(source_stat.st_mode)),
                role=role,
            )
        )
    file_map = {entry.relative_path: entry for entry in backup_files}
    if file_map[ASAR_RELATIVE_PATH].sha256 != plan.original_asar_hash:
        raise PatchError(f"staged backup ASAR mismatch; retained at {staging}")
    if file_map[INFO_RELATIVE_PATH].sha256 != plan.original_info_hash:
        raise PatchError(f"staged backup Info.plist mismatch; retained at {staging}")
    entitlements_path = staging / "sanitized-entitlements.plist"
    with entitlements_path.open("xb") as handle:
        handle.write(entitlements_blob())
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(entitlements_path, 0o600)
    write_manifest(
        staging / "manifest.json",
        manifest_data(bundle, plan, signing, backup_files),
    )
    for directory in sorted(
        created_directories,
        key=lambda value: len(value.parts),
        reverse=True,
    ):
        fsync_directory(directory)
    fsync_directory(staging)
    try:
        os.rename(staging, final_directory)
    except OSError as exc:
        raise PatchError(
            f"could not finalize backup; staging retained at {staging}: {exc}"
        ) from exc
    fsync_directory(root)
    return load_manifest(bundle, root)


def require_backup_filesystem(bundle: Bundle, root: Path) -> None:
    existing = root
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    if existing.stat().st_dev != bundle.asar.parent.stat().st_dev:
        raise PatchError("backup root and application must be on the same filesystem")


def require_same_filesystem(bundle: Bundle, manifest: ManifestRecord) -> None:
    device = manifest.directory.stat().st_dev
    if bundle.app.stat().st_dev != device:
        raise PatchError("backup and application must be on the same filesystem")


def patch_temporary_pair(
    bundle: Bundle,
    manifest: ManifestRecord,
) -> tuple[Path, Path, Path]:
    plan = manifest.plan
    staging = unique_directory(manifest.directory, "patch-files")
    temp_asar = staging / "app.asar.patched"
    temp_info = staging / "Info.plist.patched"
    try:
        shutil.copy2(bundle.asar, temp_asar)
        shutil.copy2(bundle.info, temp_info)
        with temp_asar.open("r+b") as handle:
            handle.seek(plan.target_start)
            handle.write(plan.changed_target)
            handle.seek(plan.json_start)
            handle.write(plan.changed_header)
            handle.flush()
            os.fsync(handle.fileno())
        with temp_info.open("r+b") as handle:
            handle.seek(0)
            handle.write(plan.changed_info)
            handle.truncate(len(plan.changed_info))
            handle.flush()
            os.fsync(handle.fileno())
        pair = inspect_pair(temp_asar, temp_info)
        if pair.asar.marker_state != STATUS_PATCHED:
            raise PatchError("temporary patch validation failed")
        if digest_file(temp_asar) != plan.patched_asar_hash:
            raise PatchError("temporary patched ASAR hash mismatch")
        if digest_file(temp_info) != plan.patched_info_hash:
            raise PatchError("temporary patched Info.plist hash mismatch")
        fsync_directory(staging)
        return temp_asar, temp_info, staging
    except (OSError, PatchError) as exc:
        raise PatchError(
            f"could not prepare temporary patch; files retained at "
            f"{staging}: {exc}"
        ) from exc


def restore_order(bundle: Bundle, entry: BackupFile) -> tuple[int, int, str]:
    executable = bundle.executable.relative_to(bundle.app).as_posix()
    main_last = {
        "Contents/_CodeSignature/CodeResources": 1,
        executable: 2,
    }.get(entry.relative_path, 0)
    depth = entry.relative_path.count("/")
    return main_last, -depth, entry.relative_path


def original_temporary_files(
    bundle: Bundle,
    manifest: ManifestRecord,
    staging: Path,
) -> list[tuple[BackupFile, Path, Path]]:
    prepared: list[tuple[BackupFile, Path, Path]] = []
    ordered_files = sorted(
        manifest.files,
        key=lambda entry: restore_order(bundle, entry),
    )
    for index, entry in enumerate(ordered_files):
        destination = bundle.app / entry.relative_path
        if destination.is_symlink() or (
            destination.exists() and not destination.is_file()
        ):
            raise PatchError(f"restore destination is unsafe: {destination}")
        if not is_within(destination.parent.resolve(strict=True), bundle.app):
            raise PatchError(f"restore destination escapes app: {destination}")
        temporary = staging / f"{index:04d}-{destination.name}.restore"
        shutil.copy2(entry.backup_path, temporary)
        os.chmod(temporary, int(entry.mode, 8))
        fsync_file(temporary)
        if temporary.stat().st_size != entry.size:
            raise PatchError(f"temporary restore size mismatch: {temporary}")
        if digest_file(temporary) != entry.sha256:
            raise PatchError(f"temporary restore hash mismatch: {temporary}")
        prepared.append((entry, temporary, destination))
    fsync_directory(staging)
    return prepared


def consume_empty_staging(staging: Path) -> None:
    try:
        staging.rmdir()
    except OSError as exc:
        print(
            f"Temporary staging directory retained at {staging}: {exc}",
            file=sys.stderr,
        )
    else:
        fsync_directory(staging.parent)


def restore_original_inventory(
    bundle: Bundle,
    manifest: ManifestRecord,
) -> None:
    require_same_filesystem(bundle, manifest)
    last_error: Exception | None = None
    retained: list[Path] = []
    for _ in range(2):
        staging = unique_directory(manifest.directory, "restore-files")
        try:
            prepared = original_temporary_files(bundle, manifest, staging)
            require_no_running_processes(bundle)
            for entry, temporary, destination in prepared:
                os.replace(temporary, destination)
                fsync_directory(destination.parent)
                if digest_file(destination) != entry.sha256:
                    raise PatchError(
                        f"restored file does not match manifest: {entry.relative_path}"
                    )
                if stat.S_IMODE(destination.stat().st_mode) != int(entry.mode, 8):
                    raise PatchError(
                        f"restored mode does not match manifest: {entry.relative_path}"
                    )
            pair = inspect_pair(bundle.asar, bundle.info)
            if pair.asar.marker_state != STATUS_READY:
                raise PatchError("restored application is not in ready state")
            if not manifest_original_files_match(bundle, manifest):
                raise PatchError("restored inventory does not match backup manifest")
            result = signature_result(bundle.app)
            if result.returncode != 0:
                message = result.stderr.strip() or result.stdout.strip()
                raise PatchError(f"restored OpenAI signature is invalid: {message}")
            consume_empty_staging(staging)
            for path in retained:
                print(
                    f"Failed restore staging directory retained at {path}",
                    file=sys.stderr,
                )
            return
        except (OSError, PatchError, subprocess.SubprocessError) as exc:
            last_error = exc
            retained.append(staging)
    retained_paths = ", ".join(str(path) for path in retained)
    raise PatchError(
        f"restore failed after retry; trusted backup remains at "
        f"{manifest.directory}; temporary files retained at "
        f"{retained_paths}: {last_error}"
    )


def apply_patch(bundle: Bundle, root: Path, report: StateReport) -> None:
    if report.plan is None:
        raise PatchError("ready state did not produce a patch plan")
    require_backup_filesystem(bundle, root)
    manifest = ensure_backup(bundle, root, report.plan)
    require_same_filesystem(bundle, manifest)
    dry_run_signing(bundle, manifest.signing, manifest.entitlements)
    temp_asar, temp_info, staging = patch_temporary_pair(bundle, manifest)
    replaced = False
    try:
        require_no_running_processes(bundle)
        os.replace(temp_asar, bundle.asar)
        replaced = True
        fsync_directory(bundle.asar.parent)
        os.replace(temp_info, bundle.info)
        fsync_directory(bundle.info.parent)
        consume_empty_staging(staging)
        run_signing_commands(
            bundle,
            manifest.signing,
            manifest.entitlements,
            dry_run=False,
        )
        validate_signed_bundle(bundle, manifest.signing, manifest.plan)
        final = classify(bundle, root)
        if final.status != STATUS_PATCHED:
            detail = f": {final.detail}" if final.detail else ""
            raise PatchError(
                f"post-apply state is {final.status}, expected {STATUS_PATCHED}"
                f"{detail}"
            )
    except (OSError, PatchError, subprocess.SubprocessError) as exc:
        retained = f"; temporary files retained at {staging}"
        if not staging.exists():
            retained = ""
        if replaced:
            try:
                restore_original_inventory(bundle, manifest)
            except PatchError as restore_exc:
                raise PatchError(
                    f"apply failed and automatic restore failed: {exc}; "
                    f"{restore_exc}{retained}"
                ) from restore_exc
            raise PatchError(
                f"apply failed; original files restored: {exc}{retained}"
            ) from exc
        raise PatchError(f"apply failed: {exc}{retained}") from exc


def print_report(report: StateReport) -> None:
    print(f"Codex app: {report.bundle.app}")
    print(f"Version: {report.bundle.version}")
    print(f"Build: {report.bundle.build}")
    print(f"Target: {report.target_path or 'unknown'}")
    print(f"Status: {report.status}")
    signature = "valid" if report.signature_valid else "invalid"
    if report.status == STATUS_PATCHED and not report.signature_valid:
        signature += " (replaced by validated ad hoc signature)"
    print(f"OpenAI signature: {signature}")
    print(f"Backup directory: {report.backup_directory}")
    print(f"Current app.asar SHA-256: {report.asar_hash}")
    print(f"Current Info.plist SHA-256: {report.info_hash}")
    if report.plan is not None:
        print(f"Planned app.asar SHA-256: {report.plan.patched_asar_hash}")
        print(f"Planned Info.plist SHA-256: {report.plan.patched_info_hash}")
    if report.detail:
        print(f"Detail: {report.detail}")


def restore_command(app: Path, root: Path) -> str:
    script = Path(__file__).resolve()
    arguments = [str(script), "restore"]
    if app != DEFAULT_APP.resolve(strict=False):
        arguments.extend(("--app", str(app)))
    if root != DEFAULT_BACKUP_ROOT.resolve(strict=False):
        arguments.extend(("--backup-root", str(root)))
    return shlex.join(arguments)


def run_check(bundle: Bundle, root: Path) -> int:
    report = classify(bundle, root)
    print_report(report)
    if report.status == STATUS_READY:
        print("Dry run only. No files were changed.")
        print("Apply will replace the OpenAI Developer ID seal with an ad hoc signature.")
        return 0
    if report.status == STATUS_PATCHED:
        print(f"Restore with: {restore_command(bundle.app, root)}")
        return 0
    if report.status == STATUS_RECOVERY_REQUIRED:
        print(f"Recovery command: {restore_command(bundle.app, root)}")
    return 2


def run_apply(
    bundle: Bundle,
    root: Path,
    acknowledged: bool,
) -> int:
    if not acknowledged:
        raise PatchError("apply requires --acknowledge-invalid-signature")
    require_no_running_processes(bundle)
    report = classify(bundle, root)
    print_report(report)
    if report.status == STATUS_PATCHED:
        print("No change needed. The target is already patched.")
        return 0
    if report.status == STATUS_RECOVERY_REQUIRED:
        raise PatchError(f"run restore first: {restore_command(bundle.app, root)}")
    if report.status != STATUS_READY:
        raise PatchError(f"refusing to apply in state: {report.status}")
    apply_patch(bundle, root, report)
    final = classify(bundle, root)
    if final.status != STATUS_PATCHED:
        raise PatchError(f"post-apply state is {final.status}")
    print("Patch applied, Electron integrity verified, and ad hoc signing validated.")
    print("The OpenAI Developer ID resource seal was replaced, as acknowledged.")
    print(f"Restore with: {restore_command(bundle.app, root)}")
    return 0


def run_restore(bundle: Bundle, root: Path) -> int:
    require_no_running_processes(bundle)
    report = classify(bundle, root)
    print_report(report)
    if report.status == STATUS_READY:
        print("No change needed. The original OpenAI-signed files are present.")
        return 0
    manifest = load_manifest(bundle, root)
    if openai_signature_valid(bundle.app):
        raise PatchError(
            "refusing to overwrite a valid OpenAI-signed bundle that differs from backup"
        )
    restore_original_inventory(bundle, manifest)
    final = classify(bundle, root)
    if final.status != STATUS_READY:
        raise PatchError(f"post-restore state is {final.status}")
    print("Original files restored and OpenAI Developer ID signature verified.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check, apply, or restore the Codex question-timeout patch."
    )
    parser.add_argument(
        "action",
        choices=("check", "apply", "restore"),
        nargs="?",
        default="check",
    )
    parser.add_argument("--app", type=Path, default=DEFAULT_APP)
    parser.add_argument(
        "--backup-root",
        type=Path,
        default=DEFAULT_BACKUP_ROOT,
    )
    parser.add_argument(
        "--acknowledge-invalid-signature",
        action="store_true",
        help="required for apply because app resources lose their OpenAI seal",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.action != "apply" and args.acknowledge_invalid_signature:
        parser.error(
            "--acknowledge-invalid-signature is valid only with apply"
        )
    try:
        bundle = bundle_from_app(args.app)
        root = normalized_backup_root(args.backup_root, bundle)
        if args.action == "check":
            return run_check(bundle, root)
        if args.action == "apply":
            return run_apply(
                bundle,
                root,
                args.acknowledge_invalid_signature,
            )
        return run_restore(bundle, root)
    except (
        OSError,
        PatchError,
        subprocess.SubprocessError,
        ValueError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"error: unexpected internal failure: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
