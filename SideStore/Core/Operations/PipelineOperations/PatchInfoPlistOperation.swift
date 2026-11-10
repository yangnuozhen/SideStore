//
//  PatchInfoPlistOperation.swift
//  SideStore
//
//  Created by Magesh K on 13/9/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation
import SideSign

final class PatchInfoPlistOperation: BasePipelineOperation<InstallAppOperationContext, Void>, @unchecked Sendable {
    override func execute(parentProgress: Progress?) async throws {
        let startTime = CFAbsoluteTimeGetCurrent()
        debugLog("[PatchInfoPlistOperation] execute() started")
        defer {
            let elapsed = CFAbsoluteTimeGetCurrent() - startTime
            debugLog("[PatchInfoPlistOperation] execute() took: \(String(format: "%.3fs", elapsed))")
        }
        try await super.executePreconditionCheck(parentProgress: parentProgress)
        
        guard let targetAppBundle = self.context.targetAppBundle else {
            debugLog("[PatchInfoPlistOperation] No targetAppBundle found. Skipping.")
            return
        }

        for bundle in targetAppBundle.allAppBundles {
            let installedEntity = self.installedEntity(for: bundle)
            
            // 1. If not already in context, load from installedApp's cache
            if self.context.customInfoPlistByBundleID[bundle.bundleIdentifier] == nil {
                if let plistURL = installedEntity?.customInfoPlistURL,
                   let customParser = try? InfoPlistParser(plistURL: plistURL) {
                    self.context.customInfoPlistByBundleID[bundle.bundleIdentifier] = customParser.rawDictionary
                }
            }
            
            if self.context.customEntitlementsByBundleID[bundle.bundleIdentifier] == nil {
                if let customEntitlements = installedEntity?.customEntitlements {
                    self.context.customEntitlementsByBundleID[bundle.bundleIdentifier] = customEntitlements
                }
            }

            // 2. Apply custom Info.plist if available
            if var customPlist = self.context.customInfoPlistByBundleID[bundle.bundleIdentifier] {
                if targetAppBundle.containsWatchContent {
                    // Cached signed identifiers belong to the prior signing graph, not the source payload.
                    customPlist.removeValue(forKey: "CFBundleIdentifier")
                    customPlist.removeValue(forKey: "WKCompanionAppBundleIdentifier")
                    if var extensionInfo = customPlist["NSExtension"] as? [String: any Sendable],
                       var attributes = extensionInfo["NSExtensionAttributes"] as? [String: any Sendable] {
                        attributes.removeValue(forKey: "WKAppBundleIdentifier")
                        extensionInfo["NSExtensionAttributes"] = attributes
                        customPlist["NSExtension"] = extensionInfo
                    }
                    self.context.customInfoPlistByBundleID[bundle.bundleIdentifier] = customPlist
                }
                do {
                    if bundle.fileURL == targetAppBundle.fileURL {
                        let customParser = InfoPlistParser(dictionary: customPlist)
                        if let customID = customParser.bundleIdentifier,
                           !customID.isEmpty,
                           customID != self.context.bundleIdentifier {
                            self.context.customBundleIdentifier = customID
                        }
                    }
                    
                    try bundle.updateInfoPlist(with: customPlist)
                    debugLog("[PatchInfoPlistOperation] Successfully patched Info.plist for \(bundle.bundleIdentifier)")
                } catch {
                    debugLog("[PatchInfoPlistOperation] Error applying custom Info.plist for \(bundle.bundleIdentifier): \(error)")
                    throw error
                }
            }

            // 3. Register custom entitlements if available
            if let customEntitlements = self.context.customEntitlementsByBundleID[bundle.bundleIdentifier] {
                if bundle.fileURL == targetAppBundle.fileURL {
                    for (key, value) in customEntitlements {
                        self.context.additionalEntitlements[ALTEntitlement(key)] = value
                    }
                }
                debugLog("[PatchInfoPlistOperation] Successfully loaded custom entitlements for \(bundle.bundleIdentifier)")
            }
        }
    }
    
    private func installedEntity(for bundle: ALTApplication) -> (any InstalledAppProtocol)? {
        if bundle.fileURL != self.context.targetAppBundle?.fileURL {
            return self.context.installedApp?.appExtensions.first(where: { $0.bundleIdentifier == bundle.bundleIdentifier })
        }
        return self.context.installedApp
    }
}
