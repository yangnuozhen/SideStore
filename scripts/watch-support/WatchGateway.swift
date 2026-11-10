// On-device adaptation of Rzbck/isideload's companion_proxy / streaming_zip_conduit flow.
// Reference: f7b9f3da570edd6824c29680545e710846d07df5 (MIT).
import Foundation
import Darwin
import IDevice
import OpenSSL
import DeviceGatewayAPI
import MinimuxerCommon

extension IdeviceGateway {
    // All synchronous Watch FFI handles stay on this queue. Forwarding ports are process-global.
    private static let watchQueue = DispatchQueue(label: "SideStore.WatchTransport", qos: .utility)

    public func fetchPairedWatch(pairingData: Data) async throws -> PairedWatchDevice {
        try Task.checkCancellation()
        return try await withFFIDispatch(on: Self.watchQueue) {
            let session = try WatchSession(host: self.deviceEndpointIp, pairingData: pairingData)
            return try session.openWatch(expectedIdentifier: nil)
        }
    }

    public func installWatchApp(at url: URL, device: PairedWatchDevice, pairingData: Data) async throws {
        try Task.checkCancellation()
        try await withFFIDispatch(on: Self.watchQueue) {
            let session = try WatchSession(host: self.deviceEndpointIp, pairingData: pairingData)
            _ = try session.openWatch(expectedIdentifier: device.identifier)
            try session.withWatchService("com.apple.streaming_zip_conduit") { socket in
                try WatchArchive.send(appURL: url, to: socket)
            }
        }
    }

    public func removeWatchApp(bundleIdentifier: String, device: PairedWatchDevice, pairingData: Data) async throws {
        try Task.checkCancellation()
        try await withFFIDispatch(on: Self.watchQueue) {
            let session = try WatchSession(host: self.deviceEndpointIp, pairingData: pairingData)
            _ = try session.openWatch(expectedIdentifier: device.identifier)
            try session.withWatchService("com.apple.mobile.installation_proxy") { socket in
                try socket.sendPlist(["Command": "Uninstall", "ApplicationIdentifier": bundleIdentifier, "ClientOptions": [:]])
                while true {
                    let reply = try socket.readPlist()
                    if reply["Status"] as? String == "Complete" { break }
                }
            }
        }
    }
}

private func watchFailure(_ reason: String) -> DeviceGatewayError {
    DeviceGatewayError(.serviceError, reason: reason)
}

private func checkWatchFFI(_ error: UnsafeMutablePointer<IdeviceFfiError>?, _ operation: String) throws {
    guard let error else { return }
    defer { idevice_error_free(error) }
    let message = error.pointee.message.map { String(cString: $0) } ?? "Unknown device error"
    throw watchFailure("\(operation): \(message)")
}

private func watchAddress<T>(host: String, port: UInt16, _ body: (UnsafePointer<sockaddr>, socklen_t) throws -> T) throws -> T {
    if host.contains(":") {
        var address = sockaddr_in6()
        address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        address.sin6_family = sa_family_t(AF_INET6)
        address.sin6_port = port.bigEndian
        let parts = host.split(separator: "%", maxSplits: 1)
        if parts.count == 2 { address.sin6_scope_id = if_nametoindex(String(parts[1])) }
        guard inet_pton(AF_INET6, String(parts[0]), &address.sin6_addr) == 1 else { throw watchFailure("Invalid iPhone endpoint") }
        return try withUnsafePointer(to: &address) {
            try $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { try body($0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
        }
    }
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = port.bigEndian
    guard inet_pton(AF_INET, host, &address.sin_addr) == 1 else { throw watchFailure("Invalid iPhone endpoint") }
    return try withUnsafePointer(to: &address) {
        try $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { try body($0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
    }
}

/// Uses the selected iPhone endpoint directly, never a usbmux 'first device' lookup.
private final class WatchSession {
    let host: String
    let phonePairing: [String: Any]
    private var provider: OpaquePointer?
    private var phoneLockdown: OpaquePointer?
    private var watchLockdown: OpaquePointer?
    private var watchPairing: OpaquePointer?
    private var watchPairingDictionary: [String: Any] = [:]
    private var forwardedLockdown = false

    init(host: String?, pairingData: Data) throws {
        guard let host, !host.isEmpty else { throw watchFailure("iPhone endpoint unavailable. Connect the SideStore VPN first.") }
        self.host = host
        guard let plist = try PropertyListSerialization.propertyList(from: pairingData, format: nil) as? [String: Any],
              plist["HostID"] is String, plist["SystemBUID"] is String else {
            throw watchFailure("An iPhone lockdown pairing file is required for Apple Watch support.")
        }
        phonePairing = plist
        var pairing: OpaquePointer?
        try pairingData.withUnsafeBytes { bytes in
            try checkWatchFFI(idevice_pairing_file_from_bytes(bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), UInt(bytes.count), &pairing), "Read iPhone pairing")
        }
        guard let pairing else { throw watchFailure("Missing iPhone pairing handle") }
        // TCP provider consumes the pairing handle on success.
        do {
            try watchAddress(host: host, port: 62078) { address, _ in
                try address.withMemoryRebound(to: idevice_sockaddr.self, capacity: 1) {
                    try checkWatchFFI(idevice_tcp_provider_new($0, pairing, "SideStore Watch", &provider), "Create iPhone provider")
                }
            }
        } catch {
            idevice_pairing_file_free(pairing)
            throw error
        }
        let connectError = lockdownd_connect(provider, &phoneLockdown)
        // This pinned FFI consumes provider on connection failure, but borrows it on success.
        if connectError != nil { provider = nil }
        try checkWatchFFI(connectError, "Connect iPhone lockdown")
        var sessionPairing: OpaquePointer?
        try checkWatchFFI(idevice_provider_get_pairing_file(provider, &sessionPairing), "Load session pairing")
        defer { idevice_pairing_file_free(sessionPairing) }
        try checkWatchFFI(lockdownd_start_session(phoneLockdown, sessionPairing), "Start iPhone session")
    }

    deinit {
        lockdownd_client_free(watchLockdown)
        idevice_pairing_file_free(watchPairing)
        if forwardedLockdown { stopForwarding(port: 62078) }
        lockdownd_client_free(phoneLockdown)
        idevice_provider_free(provider)
    }

    private func phoneService(_ name: String) throws -> WatchSocket {
        var port: UInt16 = 0
        var ssl = false
        try checkWatchFFI(lockdownd_start_service(phoneLockdown, name, &port, &ssl), "Start iPhone \(name)")
        return try WatchSocket(host: host, port: port, pairing: ssl ? phonePairing : nil)
    }

    private func companion(_ command: [String: Any]) throws -> [String: Any] {
        // The phone can invalidate companion connections after a forwarding command.
        let socket = try phoneService("com.apple.companion_proxy")
        try socket.sendPlist(command)
        return try socket.readPlist()
    }

    private func forward(port: UInt16, service: String) throws -> UInt16 {
        let reply = try companion([
            "Command": "StartForwardingServicePort", "GizmoRemotePortNumber": Int(port),
            "ForwardedServiceName": service, "IsServiceLowPriority": false, "PreferWifi": false
        ])
        guard let value = reply["CompanionProxyServicePort"] as? NSNumber,
              let port = UInt16(exactly: value.intValue), port != 0 else {
            throw watchFailure("The iPhone did not expose a forwarded Watch service port.")
        }
        return port
    }

    private func stopForwarding(port: UInt16) {
        _ = try? companion(["Command": "StopForwardingServicePort", "GizmoRemotePortNumber": Int(port)])
    }

    private func watchString(_ key: String) throws -> String {
        var value: plist_t?
        try checkWatchFFI(lockdownd_get_value(watchLockdown, key, nil, &value), "Read Watch \(key)")
        guard let value else { throw watchFailure("Watch did not return \(key)") }
        defer { plist_free(value) }
        var text: UnsafeMutablePointer<CChar>?
        plist_get_string_val(value, &text)
        guard let text else { throw watchFailure("Invalid Watch \(key)") }
        defer { free(text) }
        return String(cString: text)
    }

    func openWatch(expectedIdentifier: String?) throws -> PairedWatchDevice {
        let registry = try companion(["Command": "GetDeviceRegistry"])
        guard let identifiers = registry["PairedDevicesArray"] as? [String], identifiers.count == 1,
              let identifier = identifiers.first else {
            throw watchFailure("Exactly one paired Apple Watch is required. Connect and unlock the intended Watch and iPhone.")
        }
        if let expectedIdentifier, identifier.caseInsensitiveCompare(expectedIdentifier) != .orderedSame {
            throw watchFailure("The paired Watch changed since signing. Installation was cancelled.")
        }
        let port = try forward(port: 62078, service: "com.apple.mobile.lockdownd")
        forwardedLockdown = true
        var raw: OpaquePointer?
        // Forwarding can take a moment to start listening. All retries are bounded.
        for attempt in 0..<20 {
            do {
                try watchAddress(host: host, port: port) { address, length in
                    try address.withMemoryRebound(to: idevice_sockaddr.self, capacity: 1) {
                        try checkWatchFFI(idevice_new_tcp_socket($0, length, "SideStore Watch", &raw), "Connect forwarded Watch lockdown")
                    }
                }
                break
            } catch {
                if attempt == 19 { throw error }
                Thread.sleep(forTimeInterval: 0.05)
            }
        }
        guard let raw else { throw watchFailure("Watch lockdown unavailable") }
        // lockdownd_new consumes raw, including on the path returning an FFI error.
        try checkWatchFFI(lockdownd_new(raw, &watchLockdown), "Create Watch lockdown")
        let actualIdentifier = try watchString("UniqueDeviceID")
        guard actualIdentifier.caseInsensitiveCompare(identifier) == .orderedSame else {
            throw watchFailure("Forwarded connection reached a different Watch. Installation was cancelled.")
        }
        let device = PairedWatchDevice(identifier: actualIdentifier, name: try watchString("DeviceName"), productVersion: try watchString("ProductVersion"))
        guard let hostID = phonePairing["HostID"] as? String,
              let systemBUID = phonePairing["SystemBUID"] as? String else { throw watchFailure("Missing pairing identity") }
        try checkWatchFFI(lockdownd_pair(watchLockdown, hostID, systemBUID, "SideStore Watch", &watchPairing), "Pair Watch through iPhone")
        var bytes: UnsafeMutablePointer<UInt8>?
        var size: UInt = 0
        try checkWatchFFI(idevice_pairing_file_serialize(watchPairing, &bytes, &size), "Read Watch pairing")
        guard let bytes else { throw watchFailure("Missing Watch pairing data") }
        defer { idevice_data_free(bytes, size) }
        guard let dictionary = try PropertyListSerialization.propertyList(from: Data(bytes: bytes, count: Int(size)), format: nil) as? [String: Any] else {
            throw watchFailure("Invalid Watch pairing data")
        }
        watchPairingDictionary = dictionary
        try checkWatchFFI(lockdownd_start_session(watchLockdown, watchPairing), "Start Watch session")
        return device
    }

    func withWatchService<T>(_ name: String, body: (WatchSocket) throws -> T) throws -> T {
        var remotePort: UInt16 = 0
        var ssl = false
        try checkWatchFFI(lockdownd_start_service(watchLockdown, name, &remotePort, &ssl), "Start Watch \(name)")
        let port = try forward(port: remotePort, service: name)
        defer { stopForwarding(port: remotePort) }
        var lastError: Error = watchFailure("Forwarded Watch service unavailable")
        for attempt in 0..<20 {
            let socket: WatchSocket
            do {
                socket = try WatchSocket(host: host, port: port, pairing: ssl ? watchPairingDictionary : nil)
            } catch {
                lastError = error
                if attempt < 19 { Thread.sleep(forTimeInterval: 0.05) }
                continue
            }
            // Never retry an operation after sending data: completion may have been lost.
            return try body(socket)
        }
        throw lastError
    }
}

/// Framed plist and raw ZIP transport. TLS is pinned to the pairing record's device certificate.
private final class WatchSocket {
    private var fd: Int32 = -1
    private var context: OpaquePointer?
    private var ssl: OpaquePointer?
    private let deadline = Date().addingTimeInterval(600)

    init(host: String, port: UInt16, pairing: [String: Any]?) throws {
        do {
            try watchAddress(host: host, port: port) { address, length in
                fd = Darwin.socket(Int32(address.pointee.sa_family), SOCK_STREAM, 0)
                guard fd >= 0 else { throw watchFailure("Cannot create Watch socket") }
                let flags = fcntl(fd, F_GETFL, 0)
                guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw watchFailure("Cannot configure Watch socket") }
                if Darwin.connect(fd, address, length) != 0 {
                    guard errno == EINPROGRESS else { throw watchFailure("Cannot connect to forwarded Watch service") }
                    var pollFD = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                    guard poll(&pollFD, 1, 5000) > 0 else { throw watchFailure("Watch connection timed out") }
                    var error: Int32 = 0
                    var errorLength = socklen_t(MemoryLayout<Int32>.size)
                    guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errorLength) == 0, error == 0 else { throw watchFailure("Watch connection failed") }
                }
                guard fcntl(fd, F_SETFL, flags) == 0 else { throw watchFailure("Cannot configure Watch socket") }
                var timeout = timeval(tv_sec: 30, tv_usec: 0)
                var one: Int32 = 1
                guard setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
                      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
                      setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw watchFailure("Cannot set Watch socket timeouts") }
            }
            if let pairing { try enableTLS(pairing) }
        } catch {
            close()
            throw error
        }
    }

    deinit { close() }

    private func close() {
        if let ssl { SSL_free(ssl); self.ssl = nil }
        if let context { SSL_CTX_free(context); self.context = nil }
        if fd >= 0 { Darwin.close(fd); fd = -1 }
    }

    private func certificate(_ data: Data) throws -> OpaquePointer {
        try data.withUnsafeBytes { bytes in
            guard let bio = BIO_new_mem_buf(bytes.baseAddress, Int32(bytes.count)) else { throw watchFailure("Cannot read pairing certificate") }
            defer { BIO_free(bio) }
            guard let certificate = PEM_read_bio_X509(bio, nil, nil, nil) else { throw watchFailure("Invalid pairing certificate") }
            return certificate
        }
    }

    private func enableTLS(_ pairing: [String: Any]) throws {
        guard let certificateData = pairing["HostCertificate"] as? Data,
              let keyData = pairing["HostPrivateKey"] as? Data,
              let deviceCertificateData = pairing["DeviceCertificate"] as? Data,
              let context = SSL_CTX_new(TLS_client_method()) else { throw watchFailure("Incomplete TLS pairing identity") }
        self.context = context
        // Apple pairing certificates can use legacy signature algorithms. Trust is the pinned certificate.
        SSL_CTX_set_security_level(context, 0)
        SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nil)
        let hostCertificate = try certificate(certificateData)
        defer { X509_free(hostCertificate) }
        let key: OpaquePointer = try keyData.withUnsafeBytes { bytes in
            guard let bio = BIO_new_mem_buf(bytes.baseAddress, Int32(bytes.count)) else { throw watchFailure("Invalid pairing key") }
            defer { BIO_free(bio) }
            guard let key = PEM_read_bio_PrivateKey(bio, nil, nil, nil) else { throw watchFailure("Invalid pairing key") }
            return key
        }
        defer { EVP_PKEY_free(key) }
        guard SSL_CTX_use_certificate(context, hostCertificate) == 1, SSL_CTX_use_PrivateKey(context, key) == 1,
              SSL_CTX_check_private_key(context) == 1, let ssl = SSL_new(context) else { throw watchFailure("Cannot configure pairing TLS") }
        self.ssl = ssl
        guard SSL_set_fd(ssl, fd) == 1, SSL_connect(ssl) == 1 else { throw watchFailure("Watch TLS handshake failed. Unlock the devices and check their pairing.") }
        let expected = try certificate(deviceCertificateData)
        defer { X509_free(expected) }
        guard let peer = SSL_get1_peer_certificate(ssl) else { throw watchFailure("Missing Watch TLS certificate") }
        defer { X509_free(peer) }
        guard X509_cmp(peer, expected) == 0 else { throw watchFailure("Watch TLS certificate does not match its pairing record") }
    }

    func write(_ data: Data) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                guard Date() < deadline else { throw watchFailure("Watch transfer timed out after ten minutes") }
                let count = min(bytes.count - offset, 1024 * 1024)
                let sent: Int
                if let ssl { sent = Int(SSL_write(ssl, bytes.baseAddress!.advanced(by: offset), Int32(count))) }
                else { sent = Darwin.send(fd, bytes.baseAddress!.advanced(by: offset), count, 0) }
                if sent < 0 && ssl == nil && errno == EINTR { continue }
                guard sent > 0 else { throw watchFailure("Watch transfer failed or timed out") }
                offset += sent
            }
        }
    }

    private func read(count: Int) throws -> Data {
        var data = Data(count: count)
        try data.withUnsafeMutableBytes { (bytes: UnsafeMutableRawBufferPointer) in
            var offset = 0
            while offset < count {
                guard Date() < deadline else { throw watchFailure("Watch installation timed out") }
                let received: Int
                if let ssl { received = Int(SSL_read(ssl, bytes.baseAddress!.advanced(by: offset), Int32(count - offset))) }
                else { received = Darwin.recv(fd, bytes.baseAddress!.advanced(by: offset), count - offset, 0) }
                if received < 0 && ssl == nil && errno == EINTR { continue }
                guard received > 0 else { throw watchFailure("Watch connection closed or timed out before completion") }
                offset += received
            }
        }
        return data
    }

    func sendPlist(_ plist: [String: Any]) throws {
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        guard let size = UInt32(exactly: data.count) else { throw watchFailure("Watch message too large") }
        var length = size.bigEndian
        try write(withUnsafeBytes(of: &length) { Data($0) })
        try write(data)
    }

    func readPlist() throws -> [String: Any] {
        let prefix = try read(count: 4)
        let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size > 0, size <= 16 * 1024 * 1024 else { throw watchFailure("Invalid Watch response length") }
        guard let reply = try PropertyListSerialization.propertyList(from: read(count: Int(size)), format: nil) as? [String: Any] else { throw watchFailure("Invalid Watch response") }
        if let error = reply["Error"] as? String { throw watchFailure("watchOS: \(error): \(reply["ErrorDescription"] as? String ?? "")") }
        return reply
    }
}

private enum WatchArchive {
    static let extra: [UInt8] = [0x55,0x54,0x0d,0,7,0xf3,0xa2,0xec,0x60,0xf6,0xa2,0xec,0x60,0xf3,0xa2,0xec,0x60,0x75,0x78,0x0b,0,1,4,0xf5,1,0,0,4,0x14,0,0,0]

    static func send(appURL: URL, to socket: WatchSocket) throws {
        // Foundation can canonicalize /var to /private/var while enumerating on Darwin.
        // Derive both sides of the relative path from the same canonical root.
        let root = appURL.resolvingSymlinksInPath().standardizedFileURL
        let prefix = root.path.hasSuffix("/") ? root.path : root.path + "/"
        guard let enumerator = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey]) else { throw watchFailure("Cannot read signed Watch app") }
        var entries: [(URL, String, UInt32)] = []
        var total: UInt64 = 0
        for case let url as URL in enumerator {
            let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
            guard values.isSymbolicLink != true else { throw watchFailure("Watch archive contains a symbolic link; this topology is unsupported") }
            if values.isRegularFile == true {
                guard let size = values.fileSize, let length = UInt32(exactly: size) else { throw watchFailure("Watch archive file exceeds ZIP32 size limit") }
                let path = url.standardizedFileURL.path
                guard path.hasPrefix(prefix) else { throw watchFailure("Watch archive entry is outside the app bundle") }
                let name = "Payload/" + root.lastPathComponent + "/" + path.dropFirst(prefix.count)
                entries.append((url, name, length))
                total += UInt64(length)
            }
        }
        entries.sort { $0.1 < $1.1 }
        guard !entries.isEmpty, total <= UInt64(Int64.max) else { throw watchFailure("Invalid Watch archive size") }
        let options: [String: Any] = ["DisableDeltaTransfer": 1, "InstallDeltaTypeKey": "InstallDeltaTypeSparseIPAFiles", "IsUserInitiated": 1, "PackageType": "Customer", "PreferWifi": 1]
        try socket.sendPlist([
            "InstallOptionsDictionary": options,
            "InstallTransferredDirectory": 1, "MediaSubdir": "PublicStaging/\(appURL.lastPathComponent).ipa", "UserInitiatedTransfer": 0
        ])
        let metadataValues: [String: Any] = ["StandardDirectoryPerms": 16877, "StandardFilePerms": -32348, "RecordCount": entries.count + 2, "TotalUncompressedBytes": total, "Version": 2]
        let metadata = try PropertyListSerialization.data(fromPropertyList: metadataValues, format: .xml, options: 0)
        try socket.write(header(name: "META-INF/", size: 0, crc: 0))
        try socket.write(header(name: "META-INF/com.apple.ZipMetadata.plist", size: UInt32(metadata.count), crc: crc32(metadata)))
        try socket.write(metadata)
        for (url, name, size) in entries {
            // Two bounded-memory passes: CRC precedes file contents in the ZIP local header.
            let file = try FileHandle(forReadingFrom: url)
            defer { try? file.close() }
            var crc: UInt32 = 0xffffffff
            while let chunk = try file.read(upToCount: 1024 * 1024), !chunk.isEmpty { crc = updateCRC(crc, chunk) }
            try file.seek(toOffset: 0)
            try socket.write(header(name: name, size: size, crc: ~crc))
            var sent: UInt64 = 0
            while let chunk = try file.read(upToCount: 1024 * 1024), !chunk.isEmpty {
                sent += UInt64(chunk.count)
                guard sent <= UInt64(size) else { throw watchFailure("Watch archive changed during transfer") }
                try socket.write(chunk)
            }
            guard sent == UInt64(size) else { throw watchFailure("Watch archive changed during transfer") }
        }
        try socket.write(Data([0x50, 0x4b, 0x01, 0x02]))
        // needs proper testing across watchOS versions: only DataComplete confirms success.
        while true {
            let reply = try socket.readPlist()
            if let progress = reply["InstallProgressDict"] as? [String: Any], let error = progress["Error"] as? String {
                throw watchFailure("watchOS installation failed: \(error): \(progress["ErrorDescription"] as? String ?? "")")
            }
            if reply["Status"] as? String == "DataComplete" { return }
            guard reply["InstallProgressDict"] is [String: Any] else { throw watchFailure("Unexpected Watch installation response") }
        }
    }

    static func header(name: String, size: UInt32, crc: UInt32) throws -> Data {
        let name = Data(name.utf8)
        guard let length = UInt16(exactly: name.count) else { throw watchFailure("Watch ZIP entry name too long") }
        var data = Data()
        func u16(_ value: UInt16) { var value = value.littleEndian; withUnsafeBytes(of: &value) { data.append(contentsOf: $0) } }
        func u32(_ value: UInt32) { var value = value.littleEndian; withUnsafeBytes(of: &value) { data.append(contentsOf: $0) } }
        u32(0x04034b50); u16(20); u16(0x800); u16(0); u16(0xbdef); u16(0x52ec)
        u32(crc); u32(size); u32(size); u16(length); u16(UInt16(extra.count))
        data.append(name); data.append(contentsOf: extra)
        return data
    }

    private static let crcTable: [UInt32] = (0..<256).map { value in
        var crc = UInt32(value)
        for _ in 0..<8 { crc = (crc >> 1) ^ ((crc & 1) == 1 ? 0xedb88320 : 0) }
        return crc
    }

    static func updateCRC(_ initial: UInt32, _ data: Data) -> UInt32 {
        data.reduce(initial) { ($0 >> 8) ^ crcTable[Int(($0 ^ UInt32($1)) & 0xff)] }
    }

    static func crc32(_ data: Data) -> UInt32 { ~updateCRC(0xffffffff, data) }
}
