#!/usr/bin/env python3
"""Package this checkout's Watch-enabled SideStore using LiveContainer's built-in layout."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import plistlib
import shutil
import stat
import struct
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "build-config.json").read_text(encoding="utf-8"))
BUILD_INFO = "WatchSupportBuild.plist"
INTENT_RENAMES = {
    b"9SideStore20RefreshAllAppsIntentV": b"16SideStoreSupport20RefreshAllAppsIntentV",
    b"9SideStore26RefreshAllAppsWidgetIntentV": b"16SideStoreSupport26RefreshAllAppsWidgetIntentV",
}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_plist(path):
    with Path(path).open("rb") as stream:
        return plistlib.load(stream)


def save_plist(path, data):
    with Path(path).open("wb") as stream:
        plistlib.dump(data, stream, fmt=plistlib.FMT_BINARY, sort_keys=False)


def revision(path):
    return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()


def attest(ipa, output):
    sources = ["SideStore/Core/Watch/WatchAppSupport.swift", "scripts/watch-support/WatchGateway.swift",
               "scripts/watch-support/SideSign.patch", "scripts/watch-support/minimuxer.patch"]
    result = {
        "format": 1,
        "watch_support": True,
        "sidestore_revision": revision(ROOT),
        "sidestore_repository": os.environ.get("GITHUB_REPOSITORY", "local-workspace"),
        "sidestore_ipa_sha256": sha256(ipa),
        "watch_sources_sha256": {name: sha256(ROOT / name) for name in sources},
    }
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def extract_ipa(ipa, destination):
    """Preserve modes/symlinks while keeping every archive entry inside the temporary root."""
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)
    links = []
    seen = set()
    with zipfile.ZipFile(ipa) as archive:
        for entry in archive.infolist():
            name = entry.filename.rstrip("/")
            parts = name.split("/")
            if not name or "\\" in name or any(part in ("", ".", "..") for part in parts) or PurePosixPath(name).is_absolute():
                raise ValueError(f"Unsafe IPA entry: {entry.filename}")
            if name in seen:
                raise ValueError(f"Duplicate IPA entry: {name}")
            seen.add(name)
            target = root.joinpath(*parts)
            if not target.resolve().is_relative_to(root):
                raise ValueError("IPA path escapes extraction root")
            mode = entry.external_attr >> 16
            if stat.S_ISLNK(mode):
                link = archive.read(entry).decode("utf-8")
                if "\\" in link or PurePosixPath(link).is_absolute() or not (target.parent / link).resolve().is_relative_to(root):
                    raise ValueError(f"Unsafe IPA symlink: {name}")
                links.append((target, link))
            elif entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                    raise ValueError(f"Unsupported IPA entry type: {name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                if mode & 0o777:
                    target.chmod(mode & 0o777)
        for target, link in links:
            target.parent.mkdir(parents=True, exist_ok=True)
            if not (target.parent / link).resolve().is_relative_to(root):
                raise ValueError("IPA symlink chain escapes extraction root")
            target.symlink_to(link)
    return root


def sole_app(directory):
    apps = list((Path(directory) / "Payload").glob("*.app"))
    if len(apps) != 1 or not apps[0].is_dir() or apps[0].is_symlink():
        raise ValueError("Expected exactly one app under Payload")
    return apps[0]


def macho_types(path):
    """Return all thin/fat Mach-O slice filetypes, including validation of fat offsets."""
    with Path(path).open("rb") as stream:
        magic = stream.read(4)
        thin = {b"\xcf\xfa\xed\xfe": "<", b"\xce\xfa\xed\xfe": "<",
                b"\xfe\xed\xfa\xcf": ">", b"\xfe\xed\xfa\xce": ">"}
        if magic in thin:
            header = stream.read(12)
            if len(header) != 12:
                raise ValueError("Truncated Mach-O header")
            return [struct.unpack(thin[magic] + "III", header)[2]]
        fat = {b"\xca\xfe\xba\xbe": (">", False), b"\xbe\xba\xfe\xca": ("<", False),
               b"\xca\xfe\xba\xbf": (">", True), b"\xbf\xba\xfe\xca": ("<", True)}
        if magic not in fat:
            return []
        endian, wide = fat[magic]
        count_bytes = stream.read(4)
        if len(count_bytes) != 4:
            raise ValueError("Truncated fat Mach-O header")
        count = struct.unpack(endian + "I", count_bytes)[0]
        if not 0 < count <= 32:
            raise ValueError("Invalid fat Mach-O slice count")
        result = []
        table_size = 8 + count * (32 if wide else 20)
        file_size = Path(path).stat().st_size
        for index in range(count):
            stream.seek(8 + index * (32 if wide else 20))
            entry = stream.read(32 if wide else 20)
            if len(entry) != (32 if wide else 20):
                raise ValueError("Truncated fat Mach-O architecture")
            fields = struct.unpack(endian + ("IIQQII" if wide else "IIIII"), entry)
            offset, size = fields[2:4]
            if offset < table_size or size < 16 or offset + size > file_size:
                raise ValueError("Invalid fat Mach-O slice bounds")
            stream.seek(offset)
            slice_magic = stream.read(4)
            if slice_magic not in thin:
                raise ValueError("Invalid fat Mach-O slice")
            result.append(struct.unpack(thin[slice_magic] + "III", stream.read(12))[2])
        return result


def merge_host_metadata(app):
    info_path = app / "Info.plist"
    info = load_plist(info_path)
    if info.get("CFBundleIdentifier") != "com.kdt.livecontainer":
        raise ValueError("LiveContainer bundle ID differs from the pinned integration hooks")
    groups = info.setdefault("ALTAppGroups", [])
    if "group.com.SideStore.SideStore" not in groups:
        groups.append("group.com.SideStore.SideStore")
    url_types = info.setdefault("CFBundleURLTypes", [])
    existing = {scheme for entry in url_types for scheme in entry.get("CFBundleURLSchemes", [])}
    for scheme, name in (("sidestore", "com.kdt.livecontainer.sidestoreurlscheme"),
                         ("sidestore-com.kdt.livecontainer", "com.kdt.livecontainer.sidestorebackupurlscheme")):
        if scheme not in existing:
            url_types.append({"CFBundleURLName": name, "CFBundleURLSchemes": [scheme]})
    for key in ("INIntentsSupported", "NSUserActivityTypes"):
        values = info.setdefault(key, [])
        for name in ("RefreshAllIntent", "ViewAppIntent"):
            if name not in values:
                values.append(name)
    save_plist(info_path, info)
    settings_path = app / "Settings.bundle/Root.plist"
    settings = load_plist(settings_path)
    specifiers = settings.setdefault("PreferenceSpecifiers", [])
    if not any(item.get("Key") == "LCOpenSideStore" for item in specifiers):
        specifiers.insert(min(3, len(specifiers)), {"Type": "PSToggleSwitchSpecifier", "Title": "Open SideStore",
                                                 "Key": "LCOpenSideStore", "DefaultValue": False})
    save_plist(settings_path, settings)


def embed(app, sidestore_app, lc_source, build_info, dylibify):
    frameworks = app / "Frameworks"
    if not (frameworks / "SideStoreSupport.framework").is_dir():
        raise ValueError("LiveContainer archive lacks SideStoreSupport.framework; use the full LiveContainer scheme")
    side_info = load_plist(sidestore_app / "Info.plist")
    executable = side_info.get("CFBundleExecutable")
    if side_info.get("CFBundleIdentifier") != "com.SideStore.SideStore" or executable != "SideStore":
        raise ValueError("Expected the Release SideStore product built by this workflow")
    if not macho_types(sidestore_app / executable) or any(t != 2 for t in macho_types(sidestore_app / executable)):
        raise ValueError("SideStore input must be a Mach-O executable")
    guest = frameworks / "SideStoreApp.framework"
    if guest.exists():
        raise ValueError("Archive already contains SideStoreApp.framework; refusing to mix builds")
    shutil.copytree(sidestore_app, guest, symlinks=True)
    binary = guest / executable
    converted = guest / (executable + ".dylib")
    dylibify(binary, converted)
    if not converted.is_file() or not macho_types(converted) or any(t != 6 for t in macho_types(converted)):
        raise ValueError("dylibify did not produce MH_DYLIB for every SideStore slice")
    converted.replace(binary)
    binary.chmod(0o755)
    shutil.copyfile(lc_source / ".github/sidelc/LCAppInfo.plist", guest / "LCAppInfo.plist")

    metadata_source = guest / "Metadata.appintents"
    actions = metadata_source / "extract.actionsdata"
    if not actions.is_file():
        raise ValueError("Built SideStore lacks App Intents metadata required by LiveContainer's refresh integration")
    metadata_target = app / "Metadata.appintents"
    if metadata_target.exists():
        shutil.rmtree(metadata_target)
    shutil.copytree(metadata_source, metadata_target, symlinks=True)
    action_bytes = (metadata_target / "extract.actionsdata").read_bytes()
    # Xcode currently emits JSON here. Reject binary formats that cannot be safely string-rewritten.
    json.loads(action_bytes)
    for old, new in INTENT_RENAMES.items():
        if old not in action_bytes:
            raise ValueError(f"Missing SideStore refresh intent: {old.decode()}")
        action_bytes = action_bytes.replace(old, new)
    json.loads(action_bytes)
    (metadata_target / "extract.actionsdata").write_bytes(action_bytes)
    for name in ("Intents.intentdefinition", "ViewApp.intentdefinition"):
        if (guest / name).is_file():
            shutil.copyfile(guest / name, app / name)

    widget_source = guest / "PlugIns/AltWidgetExtension.appex"
    widget = app / "PlugIns/LiveWidgetExtension.appex"
    if not widget_source.is_dir() or widget.exists():
        raise ValueError("Missing SideStore widget or conflicting LiveContainer widget")
    widget.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(widget_source), str(widget))
    widget_info = load_plist(widget / "Info.plist")
    if widget_info.get("CFBundleExecutable") != "AltWidgetExtension":
        raise ValueError("SideStore widget executable changed")
    widget_info.update(CFBundleIdentifier="com.kdt.livecontainer.LiveWidget", CFBundleExecutable="LiveWidgetExtension")
    (widget / "AltWidgetExtension").rename(widget / "LiveWidgetExtension")
    save_plist(widget / "Info.plist", widget_info)
    merge_host_metadata(app)
    save_plist(app / BUILD_INFO, build_info)
    save_plist(guest / BUILD_INFO, build_info)
    return guest, widget


def sign_payload(app, lc_source, ldid):
    for directory in sorted(app.rglob("_CodeSignature"), key=lambda p: len(p.parts), reverse=True):
        if directory.is_dir() and not directory.is_symlink():
            shutil.rmtree(directory)
    for profile in app.rglob("embedded.mobileprovision"):
        profile.unlink()
    entitlement_files = {app / load_plist(app / "Info.plist")["CFBundleExecutable"]: lc_source / "entitlements.xml"}
    for extension in (app / "PlugIns").glob("*.appex"):
        binary = extension / load_plist(extension / "Info.plist")["CFBundleExecutable"]
        entitlements = (lc_source / ".github/sidelc/LiveWidgetExtension_adhoc.xml" if extension.name == "LiveWidgetExtension.appex"
                        else lc_source / extension.stem / (extension.stem + ".entitlements"))
        if not entitlements.is_file():
            raise ValueError(f"Missing pinned entitlement template for {extension.name}")
        entitlement_files[binary] = entitlements
    binaries = [p for p in app.rglob("*") if p.is_file() and not p.is_symlink() and macho_types(p)]
    for binary in sorted(binaries, key=lambda p: (len(p.parts), p.as_posix()), reverse=True):
        entitlements = entitlement_files.get(binary)
        ldid(binary, entitlements)


def verify_layout(app, info):
    guest = app / "Frameworks/SideStoreApp.framework"
    if load_plist(app / BUILD_INFO) != info or load_plist(guest / BUILD_INFO) != info:
        raise ValueError("Build provenance was not preserved")
    if not (app / "PlugIns/LiveProcess.appex").is_dir():
        raise ValueError("LiveProcess is required for the built-in background refresh path")
    types = macho_types(guest / "SideStore")
    if not types or any(t != 6 for t in types):
        raise ValueError("Embedded SideStore is not a dylib")
    if (guest / "PlugIns/AltWidgetExtension.appex").exists():
        raise ValueError("SideStore widget was not promoted to the host")
    actions = (app / "Metadata.appintents/extract.actionsdata").read_bytes()
    for old, new in INTENT_RENAMES.items():
        if old in actions or new not in actions:
            raise ValueError("App Intents metadata has inconsistent module names")


def write_ipa(app, output):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in sorted([app] + list(app.rglob("*"))):
            if path.name == ".DS_Store" or path.name.startswith("._"):
                continue
            name = "Payload/" + path.relative_to(app.parent).as_posix()
            if path.is_symlink():
                entry = zipfile.ZipInfo(name)
                entry.create_system = 3
                entry.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(entry, os.readlink(path).encode())
            else:
                archive.write(path, name)


def package(args):
    lc_source = Path(args.livecontainer_source).resolve()
    if revision(lc_source) != CONFIG["livecontainer_revision"]:
        raise ValueError("LiveContainer checkout differs from build-config.json")
    if revision(args.dylibify_source) != CONFIG["dylibify_revision"]:
        raise ValueError("dylibify checkout differs from build-config.json")
    info = json.loads(Path(args.provenance).read_text(encoding="utf-8"))
    if info.get("watch_support") is not True or info.get("sidestore_ipa_sha256") != sha256(args.sidestore_ipa):
        raise ValueError("SideStore IPA does not match the Watch build attestation")
    info.update(CONFIG)
    info["dylibify_binary_sha256"] = sha256(args.dylibify)
    info["variant"] = "LiveContainer+SideStore-Watch"
    applications = Path(args.archive) / "Products/Applications"
    candidates = list(applications.glob("*.app"))
    if len(candidates) != 1 or candidates[0].name != "LiveContainer.app":
        raise ValueError("Expected a LiveContainer Xcode archive")
    with tempfile.TemporaryDirectory(prefix="livecontainer-watch-") as temp:
        temp = Path(temp)
        side_root = extract_ipa(args.sidestore_ipa, temp / "sidestore")
        app = temp / "Payload/LiveContainer.app"
        shutil.copytree(candidates[0], app, symlinks=True)
        embed(app, sole_app(side_root), lc_source, info,
              lambda source, target: subprocess.run([args.dylibify, str(source), str(target)], check=True))
        sign_payload(app, lc_source, lambda binary, entitlements: subprocess.run(
            [args.ldid, "-S" + str(entitlements) if entitlements else "-S", str(binary)], check=True))
        verify_layout(app, info)
        write_ipa(app, args.output)
    info["combined_ipa_sha256"] = sha256(args.output)
    manifest = Path(args.output).with_suffix(".build-info.json")
    manifest.write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    print(f"Created {args.output}\nProvenance: {manifest}")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("attest")
    command.add_argument("--sidestore-ipa", required=True)
    command.add_argument("--output", required=True)
    command = commands.add_parser("package")
    command.add_argument("--livecontainer-source", required=True)
    command.add_argument("--archive", required=True)
    command.add_argument("--sidestore-ipa", required=True)
    command.add_argument("--provenance", required=True)
    command.add_argument("--dylibify", required=True)
    command.add_argument("--dylibify-source", required=True)
    command.add_argument("--ldid", default="ldid")
    command.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "attest":
        attest(args.sidestore_ipa, args.output)
    else:
        package(args)


if __name__ == "__main__":
    main()
