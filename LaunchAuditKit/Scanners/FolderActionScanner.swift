import Foundation

public struct FolderActionScanner: PersistenceScanner {
    public let category = PersistenceCategory.folderActions
    public let requiresPrivilege = false

    private let workflowSuffix = "Library/Workflows/Applications/Folder Actions"
    private let dispatcherSuffix = "Library/Preferences/com.apple.FolderActionsDispatcher.plist"

    public var scanPaths: [String] {
        var paths: [String] = []
        for (_, home) in PathUtilities.scannableHomeDirectories() {
            paths.append((home as NSString).appendingPathComponent(workflowSuffix))
            paths.append((home as NSString).appendingPathComponent(dispatcherSuffix))
        }
        return paths
    }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        var outcome = ScanOutcome()

        for (user, home) in PathUtilities.scannableHomeDirectories() {
            let workflowDir = (home as NSString).appendingPathComponent(workflowSuffix)
            // `entries` filters dotfiles, so `.DS_Store` is no longer reported as a
            // Folder Action.
            let (workflows, errors) = entries(in: workflowDir, includeDirectories: true)
            outcome.errors += errors

            for workflow in workflows {
                outcome.items.append(PersistenceItem(
                    category: category,
                    name: (workflow as NSString).lastPathComponent,
                    configPath: workflow,
                    isEnabled: true,
                    runContext: .triggered,
                    owner: .user(user),
                    timestamps: PathUtilities.timestamps(for: workflow),
                    rawMetadata: ["Type": .string("Folder Action workflow")]
                ))
            }

            let dispatcherPlist = (home as NSString).appendingPathComponent(dispatcherSuffix)
            guard PathUtilities.exists(dispatcherPlist) else { continue }

            let dict: [String: Any]
            do {
                dict = try PlistParser().parse(at: dispatcherPlist)
            } catch {
                outcome.errors.append(scanError(error, path: dispatcherPlist))
                continue
            }

            let enabled = dict["folderActionsEnabled"] as? Bool ?? false

            // The actual folder→script bindings live in the `folderActions` key as a
            // nested binary plist. Reading only `folderActionsEnabled` — which is
            // what used to happen — meant even an enabled configuration produced a
            // single generic "(enabled)" row with none of the persistence data.
            let bindings = Self.parseBindings(dict["folderActions"])

            if bindings.isEmpty {
                // Only worth a row when the dispatcher is on but has no bindings.
                if enabled {
                    outcome.items.append(PersistenceItem(
                        category: category,
                        name: "Folder Actions Dispatcher (enabled, no bindings)",
                        configPath: dispatcherPlist,
                        isEnabled: true,
                        runContext: .triggered,
                        owner: .user(user),
                        rawMetadata: PlistParser().toMetadata(dict)
                    ))
                }
                continue
            }

            for binding in bindings {
                var metadata: [String: PlistValue] = [
                    "Type": .string("Folder Action binding"),
                    "WatchedFolder": .string(binding.folder),
                    "DispatcherEnabled": .bool(enabled),
                ]
                if !binding.scripts.isEmpty {
                    metadata["Scripts"] = .array(binding.scripts.map { .string($0) })
                }

                var item = PersistenceItem(
                    category: category,
                    name: "Folder Action: \((binding.folder as NSString).lastPathComponent)",
                    label: binding.folder,
                    configPath: dispatcherPlist,
                    executablePath: binding.scripts.first,
                    isEnabled: enabled,
                    runContext: .triggered,
                    owner: .user(user),
                    timestamps: PathUtilities.timestamps(for: dispatcherPlist),
                    rawMetadata: metadata
                )
                item.riskReasons.append(
                    "Runs \(binding.scripts.joined(separator: ", ")) when "
                        + "\(binding.folder) changes"
                )
                if !enabled {
                    item.riskMitigations.append("Folder Actions dispatcher is disabled")
                }
                outcome.items.append(item)
            }
        }

        return outcome
    }

    private struct Binding {
        let folder: String
        let scripts: [String]
    }

    /// The `folderActions` value is a nested binary plist (`bplist00`) holding an
    /// array of folder records, each with the scripts attached to it.
    private static func parseBindings(_ raw: Any?) -> [Binding] {
        guard let raw else { return [] }

        // Either an inlined array or embedded plist data.
        var records: [[String: Any]] = []
        if let array = raw as? [[String: Any]] {
            records = array
        } else if let data = raw as? Data,
                  let nested = try? PlistParser().parse(data: data) {
            for value in nested.values {
                if let array = value as? [[String: Any]] { records += array }
            }
            if records.isEmpty, let array = nested["folderActions"] as? [[String: Any]] {
                records = array
            }
        }

        return records.compactMap { record in
            let folder = (record["folder"] as? String)
                ?? (record["path"] as? String)
                ?? (record["FolderPath"] as? String)
            guard let folder else { return nil }

            var scripts: [String] = []
            if let scriptRecords = record["scripts"] as? [[String: Any]] {
                scripts = scriptRecords.compactMap {
                    ($0["path"] as? String) ?? ($0["script"] as? String)
                        ?? ($0["name"] as? String)
                }
            } else if let names = record["scripts"] as? [String] {
                scripts = names
            }
            return Binding(folder: folder, scripts: scripts)
        }
    }
}
