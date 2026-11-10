#!/usr/bin/env python3
"""Offline patch reproducibility checks and tests executing production Swift fragments."""
from pathlib import Path
import argparse
import io
import os
import plistlib
import shutil
import struct
import subprocess
import tarfile
import tempfile
import zlib

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def run(*args, cwd=None):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True).stdout


def verify_patches(temp):
    for name in ("SideSign", "minimuxer"):
        repo = ROOT / "Dependencies" / name
        target = temp / name
        target.mkdir()
        archive = run("git", "-C", str(repo), "archive", "--format=tar", "HEAD")
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(target, filter="data")
        patch = HERE / f"{name}.patch"
        run("git", "apply", "--check", str(patch), cwd=target)
        run("git", "apply", str(patch), cwd=target)
        run("git", "apply", "--reverse", "--check", str(patch), cwd=target)
        for path in target.rglob("*.swift"):
            current = repo / path.relative_to(target)
            assert current.read_text(encoding="utf-8") == path.read_text(encoding="utf-8"), current
        print(f"PASS: {name} patch reproduces working sources and is reversible")


def swift_harness():
    gateway = (HERE / "WatchGateway.swift").read_text(encoding="utf-8")
    archive = gateway[gateway.index("private enum WatchArchive {"):]
    bundle = (ROOT / "Dependencies/SideSign/Sources/Models/AppBundle.swift").read_text(encoding="utf-8")
    graph = bundle[bundle.index("    public var isWatchApp:"):bundle.index("    public var isExtension:")]
    extensions = bundle[bundle.index("    private func loadExtensions()"):bundle.index("    private func loadEntitlements()")]
    return r'''
import Foundation

func watchFailure(_ text: String) -> NSError { NSError(domain: "WatchTest", code: 1, userInfo: [NSLocalizedDescriptionKey: text]) }
final class WatchSocket {
    var data = Data()
    var options: [String: Any] = [:]
    var responses: [[String: Any]] = [["InstallProgressDict": ["PercentComplete": 50]], ["Status": "DataComplete"]]
    func write(_ bytes: Data) throws { data.append(bytes) }
    func sendPlist(_ plist: [String: Any]) throws { options = plist }
    func readPlist() throws -> [String: Any] {
        guard !responses.isEmpty else { throw watchFailure("Connection closed before completion") }
        return responses.removeFirst()
    }
}
public struct AppBundle: Hashable {
    let fileURL: URL
    let infoPlist: [String: Any]
    let bundleIdentifier: String
    var isExtension: Bool { fileURL.pathExtension == "appex" }
    var appExtensions: Set<AppBundle> { loadExtensions() }
    init?(fileURL: URL) {
        guard let data = try? Data(contentsOf: fileURL.appendingPathComponent("Info.plist")),
              let plist = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any],
              let identifier = plist["CFBundleIdentifier"] as? String else { return nil }
        self.fileURL = fileURL
        self.infoPlist = plist
        self.bundleIdentifier = identifier
    }
    public static func ==(lhs: Self, rhs: Self) -> Bool { lhs.fileURL == rhs.fileURL }
    public func hash(into hasher: inout Hasher) { hasher.combine(fileURL) }
''' + graph + extensions + r'''
}
''' + archive + r'''

func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() { throw watchFailure(message) }
}
func rejects(_ action: () throws -> Void, _ message: String) throws {
    do { try action() } catch { return }
    throw watchFailure(message)
}
let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
let host = output.appendingPathComponent("Host.app")
func makeBundle(_ url: URL, _ id: String, _ other: [String: Any] = [:]) throws {
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    var plist = other
    plist["CFBundleIdentifier"] = id
    let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
    try data.write(to: url.appendingPathComponent("Info.plist"))
}
try makeBundle(host, "example.host")
try makeBundle(host.appendingPathComponent("PlugIns/Widget.appex"), "example.host.widget")
try require(AppBundle(fileURL: host)!.signingBundles.count == 2, "iPhone graph regressed")
try require(!AppBundle(fileURL: host)!.containsWatchContent, "iPhone detected as Watch")
let watch = host.appendingPathComponent("Watch/Sample.app")
try makeBundle(watch, "example.host.watch", ["DTPlatformName": "watchos", "WKCompanionAppBundleIdentifier": "example.host"])
try makeBundle(watch.appendingPathComponent("PlugIns/Extension.appex"), "example.host.watch.extension")
try makeBundle(watch.appendingPathComponent("Frameworks/Ignore.framework"), "example.framework")
let graphApp = AppBundle(fileURL: host)!
try require(graphApp.containsWatchContent, "Missing embedded Watch")
try require(graphApp.signingBundles.count == 4, "Nested graph incomplete / framework misidentified")
try require(AppBundle(fileURL: watch.appendingPathComponent("PlugIns/Extension.appex"))!.isWatchApp, "Watch extension lost its platform")
try require(graphApp.watchAppBundles.count == 1, "Companion discovery failed")
let standalone = output.appendingPathComponent("Solo.app")
try makeBundle(standalone, "example.solo", ["WKApplication": true, "WKWatchOnly": true, "UIDeviceFamily": [4]])
try require(AppBundle(fileURL: standalone)!.watchAppBundles.count == 1, "Watch-only root not selected")
try require(AppBundle(fileURL: standalone)!.signingBundles.count == 1, "Watch-only recursion")
try makeBundle(host.appendingPathComponent("Watch/Second.app"), "example.host.second", ["DTPlatformName": "watchos"])
try require(AppBundle(fileURL: host)!.watchAppBundles.count == 2, "Multiple embedded Watch apps lost")
let invalid = host.appendingPathComponent("Watch/Broken.app")
try FileManager.default.createDirectory(at: invalid, withIntermediateDirectories: true)
try require(AppBundle(fileURL: host)!.containsWatchContent, "Malformed Watch content concealed")

try Data((0..<(2 * 1024 * 1024 + 17)).map { UInt8($0 % 251) }).write(to: watch.appendingPathComponent("Executable"))
try Data().write(to: watch.appendingPathComponent("Empty"))
try Data("unicode".utf8).write(to: watch.appendingPathComponent("\u{6d4b}\u{8bd5}.bin"))
try require(WatchArchive.crc32(Data("123456789".utf8)) == 0xcbf43926, "CRC-32 known vector failed")
try rejects({ _ = try WatchArchive.header(name: String(repeating: "x", count: 65536), size: 0, crc: 0) }, "ZIP32 name limit ignored")
let socket = WatchSocket()
try WatchArchive.send(appURL: watch, to: socket)
try socket.data.write(to: output.appendingPathComponent("stream.bin"))
try PropertyListSerialization.data(fromPropertyList: socket.options, format: .xml, options: 0).write(to: output.appendingPathComponent("transfer.plist"))
let failed = WatchSocket()
failed.responses = [["InstallProgressDict": ["Error": "ApplicationVerificationFailed"]], ["Status": "DataComplete"]]
try rejects({ try WatchArchive.send(appURL: watch, to: failed) }, "watchOS installation error hidden")
let incomplete = WatchSocket()
incomplete.responses = [["InstallProgressDict": ["PercentComplete": 100]]]
try rejects({ try WatchArchive.send(appURL: watch, to: incomplete) }, "Progress 100 incorrectly treated as completion")
try FileManager.default.createSymbolicLink(at: watch.appendingPathComponent("Link"), withDestinationURL: watch.appendingPathComponent("Executable"))
try rejects({ try WatchArchive.send(appURL: watch, to: WatchSocket()) }, "Symlink silently followed")
print("PASS: production Swift graph + sparse ZIP + failure-path fixtures")
'''


def verify_stream(directory):
    stream = (directory / "stream.bin").read_bytes()
    offset = 0
    files = {}
    while stream[offset:offset + 4] != b"PK\x01\x02":
        fields = struct.unpack_from("<IHHHHHIIIHH", stream, offset)
        signature, version, flags, compression, _, _, crc, size, uncompressed, name_size, extra_size = fields
        assert signature == 0x04034B50 and version == 20 and compression == 0 and size == uncompressed
        assert flags & 0x800
        start = offset + 30
        name = stream[start:start + name_size].decode("utf-8")
        start += name_size + extra_size
        data = stream[start:start + size]
        assert zlib.crc32(data) == crc, name
        assert name not in files
        files[name] = data
        offset = start + size
    assert offset + 4 == len(stream), "Invalid end-of-transfer marker"
    metadata = plistlib.loads(files["META-INF/com.apple.ZipMetadata.plist"])
    payloads = {name: data for name, data in files.items() if name.startswith("Payload/")}
    assert metadata["RecordCount"] == len(files)
    assert metadata["TotalUncompressedBytes"] == sum(map(len, payloads.values()))
    app = directory / "Host.app/Watch/Sample.app"
    expected = {"Payload/Sample.app/" + p.relative_to(app).as_posix(): p.read_bytes()
                for p in app.rglob("*") if p.is_file() and not p.is_symlink()}
    assert expected == payloads, "ZIP changed or omitted payload bytes"
    options = plistlib.loads((directory / "transfer.plist").read_bytes())
    assert options["InstallOptionsDictionary"]["DisableDeltaTransfer"] == 1
    print(f"PASS: decoded {len(payloads)} actual Swift-produced ZIP entries, metadata, CRCs and payload bytes")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-swift", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="sidestore-watch-") as temp:
        temp = Path(temp)
        verify_patches(temp)
        source = temp / "WatchFixtures.swift"
        source.write_text(swift_harness(), encoding="utf-8")
        swift = shutil.which("swift")
        if not swift:
            if args.require_swift:
                raise RuntimeError("Swift is required to execute the Watch fixtures")
            print("SKIP: Swift execution (toolchain unavailable; CI runs with --require-swift)")
            return
        fixture = temp / "fixtures"
        fixture.mkdir()
        result = subprocess.run([swift, str(source), str(fixture)], text=True, capture_output=True)
        print(result.stdout, end="")
        if result.returncode:
            raise RuntimeError(result.stderr)
        verify_stream(fixture)


if __name__ == "__main__":
    main()
