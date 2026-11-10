import Foundation
import SideSign
import Minimuxer
import DeviceGatewayAPI

/// Watch installs use the iPhone's existing lockdown pairing over the local VPN.
enum WatchAppSupport {
    static func validateGraph(_ app: ALTApplication) throws {
        let bundles = app.signingBundles
        guard Set(bundles.map(\.bundleIdentifier)).count == bundles.count else {
            throw OperationError.invalidApp(reason: "The Watch package contains duplicate bundle identifiers.")
        }
        for bundle in bundles {
            let plugins = (try? FileManager.default.contentsOfDirectory(at: bundle.fileURL.appendingPathComponent("PlugIns"), includingPropertiesForKeys: nil)) ?? []
            guard plugins.filter({ $0.pathExtension == "appex" }).count == bundle.appExtensions.count else {
                throw OperationError.invalidApp(reason: "The package contains an unreadable app extension.")
            }
        }
        if !app.isWatchApp {
            let watchURLs = (try? FileManager.default.contentsOfDirectory(at: app.fileURL.appendingPathComponent("Watch"), includingPropertiesForKeys: nil)) ?? []
            guard !app.watchAppBundles.isEmpty,
                  watchURLs.filter({ $0.pathExtension == "app" }).count == app.watchAppBundles.count,
                  app.watchAppBundles.allSatisfy({ $0.isWatchApp }) else {
                throw OperationError.invalidApp(reason: "The Watch directory contains an invalid watchOS app.")
            }
        }
    }

    static func pairingData() throws -> Data {
        guard let content = PairingFileManager.shared.fetchPairingFile(for: .lockdown),
              let data = content.data(using: .utf8) else {
            throw OperationError.invalidParameters("Apple Watch support requires an iPhone lockdown pairing file. Import it in Settings > Pairing File Management; RemotePairing alone is insufficient.")
        }
        return data
    }

    static func resolveDevice(expectedIdentifier: String? = nil) async throws -> PairedWatchDevice {
        try Task.checkCancellation()
        await CellularRefreshManager.shared.turnOffDataIfNeeded()
        do {
            let device = try await minimuxer.gateway.fetchPairedWatch(pairingData: pairingData())
            if let expectedIdentifier, device.identifier.caseInsensitiveCompare(expectedIdentifier) != .orderedSame {
                throw OperationError.invalidParameters("The paired Apple Watch has changed. Remove the old app record and import the app again to select the new Watch.")
            }
            await CellularRefreshManager.shared.turnOnDataIfNeeded()
            return device
        } catch {
            await CellularRefreshManager.shared.turnOnDataIfNeeded()
            throw error
        }
    }

    static func install(_ app: ALTApplication, on device: PairedWatchDevice) async throws {
        await CellularRefreshManager.shared.turnOffDataIfNeeded()
        do {
            for watchApp in app.watchAppBundles {
                try Task.checkCancellation()
                try await minimuxer.gateway.installWatchApp(at: watchApp.fileURL, device: device, pairingData: pairingData())
            }
            try Task.checkCancellation()
            await CellularRefreshManager.shared.turnOnDataIfNeeded()
        } catch {
            await CellularRefreshManager.shared.turnOnDataIfNeeded()
            throw error
        }
    }

    static func validate(_ profile: ALTProvisioningProfile, for bundle: ALTApplication, device: PairedWatchDevice) throws {
        guard profile.platforms.contains(where: { $0.lowercased() == "watchos" }),
              profile.deviceIDs.contains(where: { $0.caseInsensitiveCompare(device.identifier) == .orderedSame }) else {
            throw OperationError.invalidParameters("Apple returned a profile for '\(bundle.name)' that does not authorize the selected Apple Watch and watchOS.")
        }
        let requiredGroups = bundle.watchRuntimeAppGroups
        let authorizedGroups = profile.entitlements[.appGroups] as? [String] ?? []
        for group in requiredGroups {
            guard authorizedGroups.contains(group) || authorizedGroups.contains(group + "." + profile.teamIdentifier) else {
                throw OperationError.invalidParameters("The Watch profile does not authorize required App Group '\(group)'.")
            }
        }
    }

    static func validateOS(_ app: ALTApplication, device: PairedWatchDevice) throws {
        let parts = device.productVersion.split(separator: ".").compactMap { Int($0) }
        guard !parts.isEmpty else {
            throw OperationError.invalidParameters("Could not determine the paired Watch's watchOS version.")
        }
        let version = OperatingSystemVersion(majorVersion: parts[0], minorVersion: parts.count > 1 ? parts[1] : 0, patchVersion: parts.count > 2 ? parts[2] : 0)
        for watchApp in app.signingBundles where watchApp.isWatchApp {
            guard version >= watchApp.minimumiOSVersion else {
                throw OperationError.invalidParameters("'\(watchApp.name)' requires watchOS \(watchApp.minimumiOSVersion); the paired Watch runs \(device.productVersion).")
            }
        }
    }
}

extension ALTApplication {
    var requiresWatchHealthKit: Bool {
        entitlements[ALTEntitlement.healthKit] as? Bool == true ||
        infoPlist["NSHealthShareUsageDescription"] != nil || infoPlist["NSHealthUpdateUsageDescription"] != nil
    }

    var watchRuntimeAppGroups: [String] {
        var groups = infoPlist["ALTAppGroups"] as? [String] ?? []
        if let group = infoPlist["WatchRegionAppGroup"] as? String { groups.append(group) }
        return Array(Set(groups)).sorted()
    }
}

extension InstalledApp {
    /// Written only after watchOS reports installation complete; also survives missing payloads.
    var watchInstallationURL: URL { directoryURL.appendingPathComponent("WatchInstallation.plist") }

    var watchInstallation: [String: Any]? {
        guard let data = try? Data(contentsOf: watchInstallationURL) else { return nil }
        return (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
    }

    var isWatchOnlyApp: Bool {
        if let recorded = watchInstallation?["WatchOnly"] as? Bool { return recorded }
        return ALTApplication(fileURL: fileURL)?.isWatchApp ?? false
    }

    var containsWatchContent: Bool {
        watchInstallation != nil || (ALTApplication(fileURL: fileURL)?.containsWatchContent ?? false)
    }
}
