import Foundation

public struct BrowserExtensionScanner: PersistenceScanner {
    public let category = PersistenceCategory.browserExtensions
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        let home = PathUtilities.homeDirectory
        return [
            // Safari
            "\(home)/Library/Safari/Extensions",
            "\(home)/Library/Containers/com.apple.Safari/Data/Library/Safari/AppExtensions",
            // Chrome
            "\(home)/Library/Application Support/Google/Chrome",
            // Edge
            "\(home)/Library/Application Support/Microsoft Edge",
            // Brave
            "\(home)/Library/Application Support/BraveSoftware/Brave-Browser",
            // Chromium
            "\(home)/Library/Application Support/Chromium",
            // Arc
            "\(home)/Library/Application Support/Arc/User Data",
            // Opera
            "\(home)/Library/Application Support/com.operasoftware.Opera",
            // Vivaldi
            "\(home)/Library/Application Support/Vivaldi",
            // Firefox
            "\(home)/Library/Application Support/Firefox/Profiles",
        ]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        // Run Safari, Chromium, and Firefox scans concurrently.
        // Each browser is independent — there's no reason to serialize them.
        async let safari = Task.detached { self.scanSafari() }.value
        async let chromium = Task.detached { self.scanChromiumBrowsers() }.value
        async let firefox = Task.detached { self.scanFirefox() }.value

        return await safari + chromium + firefox
    }

    // MARK: - Safari

    private func scanSafari() -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let home = PathUtilities.homeDirectory

        // Safari App Extensions (modern) — read from pluginkit
        // Also check the legacy Extensions directory
        let legacyDir = "\(home)/Library/Safari/Extensions"
        if PathUtilities.exists(legacyDir) {
            for ext in PathUtilities.listFiles(in: legacyDir) {
                let filename = (ext as NSString).lastPathComponent
                let name = (filename as NSString).deletingPathExtension
                let timestamps = PathUtilities.timestamps(for: ext)

                var meta: [String: PlistValue] = [
                    "Browser": .string("Safari"),
                    "Type": .string("Legacy Extension"),
                ]

                // Try to read Info.plist from .safariextz bundles
                if filename.hasSuffix(".safariextension") || filename.hasSuffix(".safariextz") {
                    let infoPlist = (ext as NSString).appendingPathComponent("Info.plist")
                    if let data = try? Data(contentsOf: URL(fileURLWithPath: infoPlist)),
                       let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
                        if let bid = plist["CFBundleIdentifier"] as? String {
                            meta["BundleIdentifier"] = .string(bid)
                        }
                        if let desc = plist["CFBundleDisplayName"] as? String ?? plist["Description"] as? String {
                            meta["Description"] = .string(desc)
                        }
                        if let version = plist["CFBundleShortVersionString"] as? String {
                            meta["Version"] = .string(version)
                        }
                    }
                }

                items.append(PersistenceItem(
                    category: category,
                    name: "Safari: \(name)",
                    label: meta["BundleIdentifier"]?.displayString,
                    configPath: ext,
                    isEnabled: true,
                    runContext: .onDemand,
                    owner: .user(PathUtilities.currentUser),
                    timestamps: timestamps,
                    rawMetadata: meta
                ))
            }
        }

        // Safari Web Extensions (macOS 12+) — stored via App Extension mechanism
        // Read the Safari Extensions state plist if available
        let extensionStatePaths = [
            "\(home)/Library/Safari/AppExtensions/Extensions.plist",
            "\(home)/Library/Containers/com.apple.Safari/Data/Library/Safari/AppExtensions/Extensions.plist",
        ]

        var seenBundleIDs = Set<String>()

        for statePath in extensionStatePaths {
            guard PathUtilities.exists(statePath),
                  let data = try? Data(contentsOf: URL(fileURLWithPath: statePath)),
                  let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
                continue
            }

            // Extensions.plist has extension bundle IDs as keys
            for (bundleID, value) in plist {
                guard !seenBundleIDs.contains(bundleID) else { continue }
                seenBundleIDs.insert(bundleID)

                let extInfo = value as? [String: Any] ?? [:]
                let enabled = extInfo["Enabled"] as? Bool ?? true
                let addedDate = extInfo["AddedDate"] as? Date

                // Derive a readable name from the bundle ID
                let name = readableName(fromBundleID: bundleID)

                var meta: [String: PlistValue] = [
                    "Browser": .string("Safari"),
                    "Type": .string("Web Extension"),
                    "BundleIdentifier": .string(bundleID),
                ]
                if let added = addedDate {
                    meta["InstalledDate"] = .string(added.formatted())
                }

                let timestamps = PathUtilities.timestamps(for: statePath)

                items.append(PersistenceItem(
                    category: category,
                    name: "Safari: \(name)",
                    label: bundleID,
                    configPath: statePath,
                    isEnabled: enabled,
                    runContext: .onDemand,
                    owner: .user(PathUtilities.currentUser),
                    timestamps: ItemTimestamps(
                        created: addedDate ?? timestamps.created,
                        modified: timestamps.modified
                    ),
                    rawMetadata: meta
                ))
            }
        }

        return items
    }

    // MARK: - Chromium-based Browsers

    private struct ChromiumBrowser {
        let name: String
        let basePath: String
    }

    private func scanChromiumBrowsers() -> [PersistenceItem] {
        let home = PathUtilities.homeDirectory
        let browsers: [ChromiumBrowser] = [
            .init(name: "Chrome", basePath: "\(home)/Library/Application Support/Google/Chrome"),
            .init(name: "Edge", basePath: "\(home)/Library/Application Support/Microsoft Edge"),
            .init(name: "Brave", basePath: "\(home)/Library/Application Support/BraveSoftware/Brave-Browser"),
            .init(name: "Chromium", basePath: "\(home)/Library/Application Support/Chromium"),
            .init(name: "Arc", basePath: "\(home)/Library/Application Support/Arc/User Data"),
            .init(name: "Opera", basePath: "\(home)/Library/Application Support/com.operasoftware.Opera"),
            .init(name: "Vivaldi", basePath: "\(home)/Library/Application Support/Vivaldi"),
        ]

        // Each browser's directory tree is independent — fan out across them.
        // Manifest reads dominate the time on power-user machines.
        let installedBrowsers = browsers.filter { PathUtilities.exists($0.basePath) }
        guard !installedBrowsers.isEmpty else { return [] }

        let count = installedBrowsers.count
        // Sendable-safe shared buffer for results from concurrent workers.
        let buffer = ConcurrentBuffer(count: count)
        DispatchQueue.concurrentPerform(iterations: count) { i in
            let items = self.scanOneChromiumBrowser(installedBrowsers[i])
            buffer.set(i, items)
        }
        return buffer.flattened
    }

    /// Lock-protected fixed-capacity buffer for concurrentPerform results.
    private final class ConcurrentBuffer: @unchecked Sendable {
        private let lock = NSLock()
        private var slots: [[PersistenceItem]]
        init(count: Int) { self.slots = [[PersistenceItem]](repeating: [], count: count) }
        func set(_ index: Int, _ items: [PersistenceItem]) {
            lock.lock(); defer { lock.unlock() }
            slots[index] = items
        }
        var flattened: [PersistenceItem] {
            lock.lock(); defer { lock.unlock() }
            return slots.flatMap { $0 }
        }
    }

    private func scanOneChromiumBrowser(_ browser: ChromiumBrowser) -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let profiles = discoverChromiumProfiles(basePath: browser.basePath)

        for (profileName, profilePath) in profiles {
            let extDir = (profilePath as NSString).appendingPathComponent("Extensions")
            guard PathUtilities.exists(extDir) else { continue }

            // Load Preferences once per profile for enabled/disabled state.
            let disabledExtIDs = chromiumDisabledExtensions(profilePath: profilePath)
            let extensionDirs = PathUtilities.listDirectories(in: extDir)

            for extPath in extensionDirs {
                let extID = (extPath as NSString).lastPathComponent
                if extID == "Temp" { continue }

                let timestamps = PathUtilities.timestamps(for: extPath)
                let manifest = readChromiumManifest(extensionPath: extPath)

                let name = manifest.name ?? extID
                let isEnabled = !disabledExtIDs.contains(extID)

                var meta: [String: PlistValue] = [
                    "Browser": .string(browser.name),
                    "ExtensionID": .string(extID),
                ]
                if profiles.count > 1 {
                    meta["Profile"] = .string(profileName)
                }
                if let version = manifest.version {
                    meta["Version"] = .string(version)
                }
                if let desc = manifest.description {
                    meta["Description"] = .string(desc)
                }
                if let manifestVersion = manifest.manifestVersion {
                    meta["ManifestVersion"] = .string("v\(manifestVersion)")
                }
                if !manifest.permissions.isEmpty {
                    meta["Permissions"] = .string(manifest.permissions.joined(separator: ", "))
                }
                if !manifest.hostPermissions.isEmpty {
                    meta["HostPermissions"] = .string(manifest.hostPermissions.joined(separator: ", "))
                }
                if manifest.hasBackground {
                    meta["Background"] = .string("Yes")
                }
                if !manifest.contentScriptMatches.isEmpty {
                    meta["ContentScriptMatches"] = .string(manifest.contentScriptMatches.joined(separator: ", "))
                }

                let profileSuffix = profiles.count > 1 ? " [\(profileName)]" : ""
                let displayName = resolveChromiumName(name)

                items.append(PersistenceItem(
                    category: category,
                    name: "\(browser.name): \(displayName)\(profileSuffix)",
                    label: extID,
                    configPath: extPath,
                    isEnabled: isEnabled,
                    runContext: .onDemand,
                    owner: .user(PathUtilities.currentUser),
                    timestamps: timestamps,
                    rawMetadata: meta
                ))
            }
        }

        return items
    }

    /// Discover Chromium profile directories (Default, Profile 1, etc.)
    private func discoverChromiumProfiles(basePath: String) -> [(String, String)] {
        var profiles: [(String, String)] = []

        // Always check Default
        let defaultPath = (basePath as NSString).appendingPathComponent("Default")
        if PathUtilities.exists(defaultPath) {
            profiles.append(("Default", defaultPath))
        }

        // Check numbered profiles
        let fm = FileManager.default
        if let contents = try? fm.contentsOfDirectory(atPath: basePath) {
            for item in contents where item.hasPrefix("Profile ") {
                let profilePath = (basePath as NSString).appendingPathComponent(item)
                if PathUtilities.isDirectory(profilePath) {
                    profiles.append((item, profilePath))
                }
            }
        }

        return profiles
    }

    /// Read disabled extension IDs from Chromium Preferences JSON.
    private func chromiumDisabledExtensions(profilePath: String) -> Set<String> {
        let prefsPath = (profilePath as NSString).appendingPathComponent("Preferences")
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: prefsPath)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let extensions = json["extensions"] as? [String: Any],
              let settings = extensions["settings"] as? [String: Any] else {
            return []
        }

        var disabled = Set<String>()
        for (extID, value) in settings {
            if let extInfo = value as? [String: Any],
               let state = extInfo["state"] as? Int,
               state == 0 {
                // state 0 = disabled, 1 = enabled
                disabled.insert(extID)
            }
        }
        return disabled
    }

    /// Parsed Chromium manifest.json data.
    private struct ChromiumManifest {
        var name: String?
        var version: String?
        var description: String?
        var manifestVersion: Int?
        var permissions: [String] = []
        var hostPermissions: [String] = []
        var hasBackground: Bool = false
        var contentScriptMatches: [String] = []
    }

    /// Read and parse manifest.json from a Chromium extension directory.
    private func readChromiumManifest(extensionPath: String) -> ChromiumManifest {
        var manifest = ChromiumManifest()

        // Extensions have version subdirectories; pick the latest in a single
        // pass instead of an O(n log n) sort — only the max matters.
        let versionDirs = PathUtilities.listDirectories(in: extensionPath)
        guard let latestVersion = versionDirs.max(by: {
            $0.localizedStandardCompare($1) == .orderedAscending
        }) else { return manifest }

        let manifestPath = (latestVersion as NSString).appendingPathComponent("manifest.json")
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: manifestPath)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return manifest
        }

        manifest.name = json["name"] as? String
        manifest.version = json["version"] as? String
        manifest.description = json["description"] as? String
        manifest.manifestVersion = json["manifest_version"] as? Int

        // Permissions (Manifest V2 and V3)
        if let perms = json["permissions"] as? [String] {
            manifest.permissions = perms
        }

        // Host permissions (Manifest V3)
        if let hostPerms = json["host_permissions"] as? [String] {
            manifest.hostPermissions = hostPerms
        }

        // Optional permissions
        if let optPerms = json["optional_permissions"] as? [String] {
            manifest.permissions.append(contentsOf: optPerms.map { "\($0) (optional)" })
        }

        // Background scripts/service worker
        if json["background"] != nil {
            manifest.hasBackground = true
        }

        // Content scripts
        if let contentScripts = json["content_scripts"] as? [[String: Any]] {
            for script in contentScripts {
                if let matches = script["matches"] as? [String] {
                    manifest.contentScriptMatches.append(contentsOf: matches)
                }
            }
        }

        return manifest
    }

    /// Resolve __MSG_...__ localized names to a readable string.
    private func resolveChromiumName(_ name: String) -> String {
        // Chrome uses __MSG_extName__ placeholders; strip the wrapper as a fallback
        if name.hasPrefix("__MSG_") && name.hasSuffix("__") {
            let key = String(name.dropFirst(6).dropLast(2))
            // Return the key in title case as a best-effort fallback
            return key.replacingOccurrences(of: "_", with: " ").localizedCapitalized
        }
        return name
    }

    // MARK: - Firefox

    private func scanFirefox() -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let profilesDir = "\(PathUtilities.homeDirectory)/Library/Application Support/Firefox/Profiles"
        guard PathUtilities.exists(profilesDir) else { return items }

        let profiles = PathUtilities.listDirectories(in: profilesDir)

        for profilePath in profiles {
            let profileName = (profilePath as NSString).lastPathComponent

            // Primary source: extensions.json (contains full metadata for all extensions)
            let extensionsJSON = (profilePath as NSString).appendingPathComponent("extensions.json")
            if PathUtilities.exists(extensionsJSON) {
                items.append(contentsOf: parseFirefoxExtensionsJSON(
                    path: extensionsJSON,
                    profileName: profileName,
                    profilePath: profilePath,
                    multipleProfiles: profiles.count > 1
                ))
                continue
            }

            // Fallback: scan the extensions directory for .xpi files
            let extensionsDir = (profilePath as NSString).appendingPathComponent("extensions")
            guard PathUtilities.exists(extensionsDir) else { continue }

            let exts = PathUtilities.listFiles(in: extensionsDir)
            for ext in exts {
                let filename = (ext as NSString).lastPathComponent
                let name = (filename as NSString).deletingPathExtension
                let timestamps = PathUtilities.timestamps(for: ext)

                var meta: [String: PlistValue] = [
                    "Browser": .string("Firefox"),
                ]
                if profiles.count > 1 {
                    meta["Profile"] = .string(profileName)
                }

                let profileSuffix = profiles.count > 1 ? " [\(profileName)]" : ""

                items.append(PersistenceItem(
                    category: category,
                    name: "Firefox: \(name)\(profileSuffix)",
                    label: name,
                    configPath: ext,
                    isEnabled: true,
                    runContext: .onDemand,
                    owner: .user(PathUtilities.currentUser),
                    timestamps: timestamps,
                    rawMetadata: meta
                ))
            }
        }

        return items
    }

    /// Parse Firefox's extensions.json for full extension metadata.
    private func parseFirefoxExtensionsJSON(
        path: String,
        profileName: String,
        profilePath: String,
        multipleProfiles: Bool
    ) -> [PersistenceItem] {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let addons = json["addons"] as? [[String: Any]] else {
            return []
        }

        var items: [PersistenceItem] = []

        for addon in addons {
            // Skip built-in system addons and language packs
            let location = addon["location"] as? String ?? ""
            if location == "app-system-defaults" || location == "app-builtin" {
                continue
            }
            let addonType = addon["type"] as? String ?? ""
            if addonType == "locale" || addonType == "dictionary" {
                continue
            }

            let addonID = addon["id"] as? String ?? "unknown"
            let name = firefoxDefaultLocale(addon: addon) ?? addonID
            let version = addon["version"] as? String
            let description = addon["description"] as? String
            let isActive = addon["active"] as? Bool ?? false
            let isUserDisabled = addon["userDisabled"] as? Bool ?? false

            // Install date (milliseconds since epoch)
            var installDate: Date?
            if let installDateMs = addon["installDate"] as? Double {
                installDate = Date(timeIntervalSince1970: installDateMs / 1000)
            }
            var updateDate: Date?
            if let updateDateMs = addon["updateDate"] as? Double {
                updateDate = Date(timeIntervalSince1970: updateDateMs / 1000)
            }

            // Permissions
            var permissions: [String] = []
            if let permsObj = addon["userPermissions"] as? [String: Any] {
                if let perms = permsObj["permissions"] as? [String] {
                    permissions.append(contentsOf: perms)
                }
                if let origins = permsObj["origins"] as? [String] {
                    permissions.append(contentsOf: origins)
                }
            }

            // Extension file path
            let extFile = addon["path"] as? String
                ?? ((profilePath as NSString).appendingPathComponent("extensions/\(addonID).xpi"))

            var meta: [String: PlistValue] = [
                "Browser": .string("Firefox"),
                "AddonID": .string(addonID),
                "Type": .string(addonType),
                "Location": .string(location),
            ]
            if multipleProfiles {
                meta["Profile"] = .string(profileName)
            }
            if let version = version {
                meta["Version"] = .string(version)
            }
            if let desc = description {
                meta["Description"] = .string(desc)
            }
            if !permissions.isEmpty {
                meta["Permissions"] = .string(permissions.joined(separator: ", "))
            }
            if let creator = addon["creator"] as? [String: Any],
               let creatorName = creator["name"] as? String {
                meta["Author"] = .string(creatorName)
            }
            if let homepage = addon["homepageURL"] as? String {
                meta["Homepage"] = .string(homepage)
            }
            if let installDateStr = installDate?.formatted() {
                meta["InstalledDate"] = .string(installDateStr)
            }
            if let updateDateStr = updateDate?.formatted() {
                meta["UpdatedDate"] = .string(updateDateStr)
            }

            let profileSuffix = multipleProfiles ? " [\(profileName)]" : ""

            items.append(PersistenceItem(
                category: category,
                name: "Firefox: \(name)\(profileSuffix)",
                label: addonID,
                configPath: extFile,
                isEnabled: isActive && !isUserDisabled,
                runContext: .onDemand,
                owner: .user(PathUtilities.currentUser),
                timestamps: ItemTimestamps(
                    created: installDate,
                    modified: updateDate
                ),
                rawMetadata: meta
            ))
        }

        return items
    }

    /// Extract the default-locale display name from a Firefox addon entry.
    private func firefoxDefaultLocale(addon: [String: Any]) -> String? {
        // Preferred: defaultLocale.name
        if let defaultLocale = addon["defaultLocale"] as? [String: Any],
           let name = defaultLocale["name"] as? String, !name.isEmpty {
            return name
        }
        // Fallback: top-level name field
        if let name = addon["name"] as? String, !name.isEmpty {
            return name
        }
        return nil
    }

    // MARK: - Helpers

    /// Derive a human-readable name from a bundle ID (best-effort).
    private func readableName(fromBundleID bundleID: String) -> String {
        // e.g. "com.example.MyExtension" -> "MyExtension"
        let components = bundleID.split(separator: ".")
        if let last = components.last {
            // Insert spaces before uppercase letters: "MyExtension" -> "My Extension"
            var result = ""
            for char in last {
                if char.isUppercase && !result.isEmpty && result.last?.isUppercase == false {
                    result.append(" ")
                }
                result.append(char)
            }
            return result
        }
        return bundleID
    }
}
