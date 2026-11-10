import json
import os
from pathlib import Path
import plistlib
import stat
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import zipfile

import package as packaging


def plist(path, values):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(values))


def macho(path, filetype=2):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(struct.pack("<IIIIIIII", 0xFEEDFACF, 0x100000C, 0, filetype, 0, 0, 0, 0) + b"test-binary")
    path.chmod(0o755)


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lc-watch-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.app = self.root / "archive/Products/Applications/LiveContainer.app"
        self.side = self.root / "side/Payload/SideStore.app"
        plist(self.app / "Info.plist", {"CFBundleIdentifier": "com.kdt.livecontainer", "CFBundleExecutable": "LiveContainer",
              "CFBundleURLTypes": [{"CFBundleURLSchemes": ["livecontainer"]}], "ExistingSetting": "preserved"})
        plist(self.app / "Settings.bundle/Root.plist", {"PreferenceSpecifiers": [{"Key": "Existing"}]})
        macho(self.app / "LiveContainer")
        macho(self.app / "Frameworks/SideStoreSupport.framework/SideStoreSupport", 6)
        plist(self.app / "PlugIns/LiveProcess.appex/Info.plist", {"CFBundleExecutable": "LiveProcess"})
        macho(self.app / "PlugIns/LiveProcess.appex/LiveProcess")
        plist(self.source / "LiveProcess/LiveProcess.entitlements", {"get-task-allow": True})
        plist(self.source / "entitlements.xml", {"com.apple.security.application-groups": ["group.com.SideStore.SideStore"]})
        plist(self.source / ".github/sidelc/LCAppInfo.plist", {"LCPatchRevision": 99999, "dontSign": True})
        plist(self.source / ".github/sidelc/LiveWidgetExtension_adhoc.xml", {"get-task-allow": True})
        plist(self.side / "Info.plist", {"CFBundleIdentifier": "com.SideStore.SideStore", "CFBundleExecutable": "SideStore"})
        macho(self.side / "SideStore")
        widget = self.side / "PlugIns/AltWidgetExtension.appex"
        plist(widget / "Info.plist", {"CFBundleIdentifier": "com.SideStore.SideStore.AltWidget", "CFBundleExecutable": "AltWidgetExtension"})
        macho(widget / "AltWidgetExtension")
        metadata = self.side / "Metadata.appintents/extract.actionsdata"
        metadata.parent.mkdir(parents=True)
        metadata.write_text(json.dumps({"intents": [old.decode() for old in packaging.INTENT_RENAMES]}))
        (self.side / "SideBackup.ipa").write_bytes(b"original-backup-resource")
        plist(self.side / "Intents.intentdefinition", {"preserve": "intent-definition"})
        (self.side / "_CodeSignature").mkdir()
        (self.side / "_CodeSignature/CodeResources").write_bytes(b"stale")
        (self.side / "embedded.mobileprovision").write_bytes(b"stale-profile")
        self.info = {"watch_support": True, "sidestore_revision": "fixture", "variant": "LiveContainer+SideStore-Watch"}

    def convert(self, source, target):
        data = bytearray(source.read_bytes())
        struct.pack_into("<I", data, 12, 6)
        target.write_bytes(data)

    def embed(self):
        return packaging.embed(self.app, self.side, self.source, self.info, self.convert)

    def test_full_layout_and_roundtrip_ipa(self):
        guest, widget = self.embed()
        signed = {}
        packaging.sign_payload(self.app, self.source, lambda binary, entitlements: signed.setdefault(binary, entitlements))
        packaging.verify_layout(self.app, self.info)
        self.assertEqual(packaging.macho_types(guest / "SideStore"), [6])
        self.assertEqual((guest / "SideBackup.ipa").read_bytes(), b"original-backup-resource")
        self.assertFalse((guest / "PlugIns/AltWidgetExtension.appex").exists())
        self.assertFalse((guest / "_CodeSignature").exists())
        self.assertFalse((guest / "embedded.mobileprovision").exists())
        self.assertEqual(packaging.load_plist(widget / "Info.plist")["CFBundleExecutable"], "LiveWidgetExtension")
        self.assertEqual(signed[widget / "LiveWidgetExtension"], self.source / ".github/sidelc/LiveWidgetExtension_adhoc.xml")
        self.assertIsNone(signed[guest / "SideStore"])
        self.assertEqual(signed[self.app / "LiveContainer"], self.source / "entitlements.xml")
        self.assertEqual(packaging.load_plist(self.app / "Info.plist")["ExistingSetting"], "preserved")
        self.assertEqual(packaging.load_plist(self.app / "Intents.intentdefinition"), {"preserve": "intent-definition"})
        output = self.root / "LiveContainer+SideStore.ipa"
        packaging.write_ipa(self.app, output)
        unpacked = packaging.extract_ipa(output, self.root / "roundtrip")
        self.assertEqual(packaging.sole_app(unpacked).name, "LiveContainer.app")
        packaging.verify_layout(packaging.sole_app(unpacked), self.info)
        with zipfile.ZipFile(output) as archive:
            self.assertNotIn("Payload/SideStore.app/Info.plist", archive.namelist())
            if os.name != "nt":
                self.assertTrue(archive.getinfo("Payload/LiveContainer.app/Frameworks/SideStoreApp.framework/SideStore").external_attr >> 16 & 0o111)

    def test_merge_preserves_existing_values_and_is_idempotent(self):
        packaging.merge_host_metadata(self.app)
        first = (self.app / "Info.plist").read_bytes(), (self.app / "Settings.bundle/Root.plist").read_bytes()
        packaging.merge_host_metadata(self.app)
        self.assertEqual(first, ((self.app / "Info.plist").read_bytes(), (self.app / "Settings.bundle/Root.plist").read_bytes()))
        info = packaging.load_plist(self.app / "Info.plist")
        self.assertEqual(info["ALTAppGroups"], ["group.com.SideStore.SideStore"])
        self.assertEqual(info["CFBundleURLTypes"][0]["CFBundleURLSchemes"], ["livecontainer"])

    def test_failed_conversion_is_detected_even_with_zero_exit(self):
        with self.assertRaisesRegex(ValueError, "MH_DYLIB"):
            packaging.embed(self.app, self.side, self.source, self.info, lambda source, target: target.write_bytes(source.read_bytes()))

    def test_missing_refresh_metadata_fails(self):
        (self.side / "Metadata.appintents/extract.actionsdata").unlink()
        with self.assertRaisesRegex(ValueError, "App Intents metadata"):
            self.embed()

    def test_missing_expected_intent_fails(self):
        (self.side / "Metadata.appintents/extract.actionsdata").write_text('{"intents": []}')
        with self.assertRaisesRegex(ValueError, "Missing SideStore refresh intent"):
            self.embed()

    def test_rejects_already_combined_archive(self):
        (self.app / "Frameworks/SideStoreApp.framework").mkdir()
        with self.assertRaisesRegex(ValueError, "already contains"):
            self.embed()

    def test_wrong_guest_product_fails(self):
        plist(self.side / "Info.plist", {"CFBundleIdentifier": "wrong.product", "CFBundleExecutable": "SideStore"})
        with self.assertRaisesRegex(ValueError, "Release SideStore"):
            self.embed()

    def test_truncated_macho_fails(self):
        path = self.root / "truncated"
        path.write_bytes(b"\xcf\xfa\xed\xfe")
        with self.assertRaisesRegex(ValueError, "Truncated"):
            packaging.macho_types(path)

    def test_fat_macho_slices_are_checked(self):
        path = self.root / "fat"
        header = struct.pack(">II", 0xCAFEBABE, 2)
        header += struct.pack(">IIIII", 0x100000C, 0, 48, 32, 0)
        header += struct.pack(">IIIII", 0x100000C, 1, 80, 32, 0)
        path.write_bytes(header + struct.pack("<IIIIIIII", 0xFEEDFACF, 0x100000C, 0, 6, 0, 0, 0, 0) * 2)
        self.assertEqual(packaging.macho_types(path), [6, 6])
        bad = bytearray(path.read_bytes())
        struct.pack_into(">I", bad, 16, 999999)
        path.write_bytes(bad)
        with self.assertRaisesRegex(ValueError, "bounds"):
            packaging.macho_types(path)

    def test_zip_path_traversal_is_rejected(self):
        path = self.root / "traversal.ipa"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("../escape", b"unsafe")
        with self.assertRaisesRegex(ValueError, "Unsafe IPA entry"):
            packaging.extract_ipa(path, self.root / "extracted")
        self.assertFalse((self.root / "escape").exists())

    def test_zip_symlink_escape_is_rejected(self):
        path = self.root / "symlink.ipa"
        with zipfile.ZipFile(path, "w") as archive:
            entry = zipfile.ZipInfo("Payload/link")
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(entry, "../../escape")
        with self.assertRaisesRegex(ValueError, "Unsafe IPA symlink"):
            packaging.extract_ipa(path, self.root / "extracted")

    def test_attestation_rejects_another_ipa(self):
        ipa = self.root / "other.ipa"
        ipa.write_bytes(b"different-build")
        provenance = self.root / "build.json"
        provenance.write_text(json.dumps({"watch_support": True, "sidestore_ipa_sha256": "wrong"}))
        args = SimpleNamespace(livecontainer_source=self.source, dylibify_source=self.root / "tool-source",
                               provenance=provenance, sidestore_ipa=ipa)
        with patch.object(packaging, "revision", side_effect=[packaging.CONFIG["livecontainer_revision"], packaging.CONFIG["dylibify_revision"]]):
            with self.assertRaisesRegex(ValueError, "attestation"):
                packaging.package(args)

    def test_cli_pipeline_keeps_exact_input_and_records_output_hash(self):
        ipa = self.root / "SideStore.ipa"
        packaging.write_ipa(self.side, ipa)
        provenance = self.root / "provenance.json"
        provenance.write_text(json.dumps({"format": 1, "watch_support": True, "sidestore_revision": "fixture",
                                          "sidestore_ipa_sha256": packaging.sha256(ipa)}))
        tool = self.root / "dylibify"
        tool.write_bytes(b"fixture-tool")
        output = self.root / "output/LiveContainer+SideStore.ipa"
        args = SimpleNamespace(livecontainer_source=self.source, dylibify_source=self.root / "tool-source",
                               provenance=provenance, sidestore_ipa=ipa, archive=self.root / "archive",
                               dylibify=str(tool), ldid="fixture-ldid", output=output)
        calls = []

        def execute(command, check):
            self.assertTrue(check)
            calls.append(command)
            if command[0] == str(tool):
                self.convert(Path(command[1]), Path(command[2]))
            else:
                self.assertEqual(command[0], "fixture-ldid")

        with patch.object(packaging, "revision", side_effect=[packaging.CONFIG["livecontainer_revision"], packaging.CONFIG["dylibify_revision"]]), \
             patch.object(packaging.subprocess, "run", side_effect=execute), patch("builtins.print"):
            packaging.package(args)
        self.assertEqual(len([call for call in calls if call[0] == str(tool)]), 1)
        manifest = json.loads(output.with_suffix(".build-info.json").read_text())
        self.assertEqual(manifest["sidestore_ipa_sha256"], packaging.sha256(ipa))
        self.assertEqual(manifest["combined_ipa_sha256"], packaging.sha256(output))
        unpacked = packaging.extract_ipa(output, self.root / "cli-result")
        root = packaging.sole_app(unpacked)
        self.assertEqual((root / "Frameworks/SideStoreApp.framework/SideBackup.ipa").read_bytes(), b"original-backup-resource")
        self.assertFalse((self.app / "Frameworks/SideStoreApp.framework").exists())


if __name__ == "__main__":
    unittest.main()
