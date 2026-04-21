import Foundation

public struct EmondScanner: PersistenceScanner {
    public let category = PersistenceCategory.emondRules
    public let requiresPrivilege = true

    public var scanPaths: [String] {
        [
            "/etc/emond.d/rules",
            "/private/var/db/emondClients"
        ]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        // Scan emond rules
        let rulesDir = "/etc/emond.d/rules"
        if PathUtilities.exists(rulesDir) {
            let plistFiles = PathUtilities.listFiles(in: rulesDir, withExtension: "plist")
            for plistPath in plistFiles {
                let name = ((plistPath as NSString).lastPathComponent as NSString).deletingPathExtension
                let timestamps = PathUtilities.timestamps(for: plistPath)
                var metadata: [String: PlistValue] = ["Source": .string("emond.d/rules")]

                if let dict = try? PlistParser().parse(at: plistPath) {
                    metadata = PlistParser().toMetadata(dict)
                }

                items.append(PersistenceItem(
                    category: category,
                    name: name,
                    configPath: plistPath,
                    isEnabled: true,
                    runContext: .triggered,
                    owner: .system,
                    timestamps: timestamps,
                    rawMetadata: metadata
                ))
            }
        }

        // Scan emond clients
        let clientsDir = "/private/var/db/emondClients"
        if PathUtilities.exists(clientsDir) {
            let files = PathUtilities.listFiles(in: clientsDir)
            for file in files {
                let name = (file as NSString).lastPathComponent
                let timestamps = PathUtilities.timestamps(for: file)
                items.append(PersistenceItem(
                    category: category,
                    name: "emond client: \(name)",
                    configPath: file,
                    isEnabled: true,
                    runContext: .triggered,
                    owner: .system,
                    timestamps: timestamps,
                    rawMetadata: ["Source": .string("emondClients")]
                ))
            }
        }

        return items
    }
}
