import Foundation

public struct PrivilegedHelperScanner: PersistenceScanner {
    public let category = PersistenceCategory.privilegedHelperTools
    public let requiresPrivilege = false

    private let directory = "/Library/PrivilegedHelperTools"

    /// Helpers registered through `SMAppService.daemon(plistName:)` live *inside*
    /// the owning application bundle rather than in
    /// `/Library/PrivilegedHelperTools`, so the bundle layout has to be walked too.
    private var applicationDirectories: [String] {
        var directories = ["/Applications", "/Applications/Utilities"]
        for (_, home) in PathUtilities.scannableHomeDirectories() {
            directories.append((home as NSString).appendingPathComponent("Applications"))
        }
        return directories
    }

    public var scanPaths: [String] { [directory] + applicationDirectories }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        var outcome = ScanOutcome()

        // Classic SMJobBless helpers. `entries` filters directories and dotfiles,
        // so a stray `.DS_Store` is no longer reported as a privileged helper.
        let (files, errors) = entries(in: directory)
        outcome.errors += errors

        for file in files {
            let name = (file as NSString).lastPathComponent
            outcome.items.append(PersistenceItem(
                category: category,
                name: name,
                label: name, // typically a reverse-DNS identifier
                configPath: file,
                executablePath: file,
                isEnabled: true,
                runContext: .onDemand,
                owner: .system,
                timestamps: PathUtilities.timestamps(for: file),
                rawMetadata: [
                    "Directory": .string(directory),
                    "Mechanism": .string("SMJobBless"),
                ]
            ))
        }

        outcome.merge(scanBundledDaemons())
        return outcome
    }

    /// Find `SMAppService` daemons and agents embedded in application bundles.
    ///
    /// `SMAppService.daemon(plistName:)` resolves its plist from
    /// `<app>/Contents/Library/LaunchDaemons/`, which means the job never appears in
    /// `/Library/LaunchDaemons` and no filesystem-driven launchd scanner sees it.
    /// LaunchAudit itself installs its helper exactly this way, so before this the
    /// tool could not detect its own persistence mechanism.
    private func scanBundledDaemons() -> ScanOutcome {
        var outcome = ScanOutcome()
        let parser = PlistParser()

        for container in applicationDirectories {
            guard PathUtilities.exists(container) else { continue }

            for app in PathUtilities.listBundles(in: container, withExtension: "app") {
                let owner: ItemOwner = {
                    for (user, home) in PathUtilities.scannableHomeDirectories()
                    where app.hasPrefix(home) {
                        return .user(user)
                    }
                    return .system
                }()

                for (suffix, context) in [
                    ("Contents/Library/LaunchDaemons", RunContext.boot),
                    ("Contents/Library/LaunchAgents", RunContext.login),
                ] {
                    let directory = (app as NSString).appendingPathComponent(suffix)
                    guard PathUtilities.exists(directory) else { continue }

                    let (plists, errors) = entries(in: directory, withExtension: "plist")
                    outcome.errors += errors

                    for plistPath in plists {
                        guard let info = try? parser.parseLaunchdPlist(at: plistPath) else {
                            continue
                        }
                        let label = info.label
                            ?? ((plistPath as NSString).lastPathComponent as NSString)
                                .deletingPathExtension

                        // `BundleProgram` is relative to the app bundle root.
                        var executable = info.resolvedExecutable
                        if let program = info.rawDictionary["BundleProgram"]?.stringValue {
                            executable = (app as NSString).appendingPathComponent(program)
                        } else if let candidate = executable, !candidate.hasPrefix("/") {
                            executable = (app as NSString).appendingPathComponent(candidate)
                        }

                        var metadata = info.rawDictionary
                        metadata["Mechanism"] = .string("SMAppService")
                        metadata["OwningApplication"] = .string(app)

                        var item = PersistenceItem(
                            category: category,
                            name: label,
                            label: label,
                            configPath: plistPath,
                            executablePath: executable,
                            arguments: info.programArguments,
                            isEnabled: !info.disabled,
                            runContext: info.runContext(loadContext: context),
                            owner: owner,
                            source: PathUtilities.isAppleOwnedPath(app) ? .apple : .unknown,
                            timestamps: PathUtilities.timestamps(for: plistPath),
                            rawMetadata: metadata
                        )
                        item.riskReasons.append(
                            "Registered by \((app as NSString).lastPathComponent) via "
                                + "SMAppService, so it does not appear in /Library/LaunchDaemons"
                        )
                        if let executable, !PathUtilities.exists(executable) {
                            item.riskReasons.append(
                                "Declared helper binary is missing: \(executable)"
                            )
                        }
                        outcome.items.append(item)
                    }
                }
            }
        }

        return outcome
    }
}
