import Foundation

public struct AppExtensionScanner: PersistenceScanner {
    public let category = PersistenceCategory.appExtensions
    public let requiresPrivilege = false

    public var scanPaths: [String] { [] }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        // Query pluginkit for all registered extensions
        guard let output = await ProcessRunner.shared.tryRun(
            "/usr/bin/pluginkit", arguments: ["-mAD"]
        ) else {
            return items
        }

        for line in output.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }

            // Format: +    identifier(version)   path
            // or:     identifier(version)
            let parts = trimmed.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
            guard !parts.isEmpty else { continue }

            var identifier: String?
            var path: String?
            var isEnabled = true

            for part in parts {
                if part == "+" {
                    isEnabled = true
                } else if part == "-" {
                    isEnabled = false
                } else if part.contains(".") && !part.hasPrefix("/") {
                    // Strip version suffix like "(1.0)"
                    identifier = part.components(separatedBy: "(").first
                } else if part.hasPrefix("/") {
                    path = parts[parts.firstIndex(of: part)!...].joined(separator: " ")
                    break
                }
            }

            guard let id = identifier else { continue }
            let name = id.components(separatedBy: ".").suffix(2).joined(separator: ".")

            // Identify Apple extensions by bundle ID prefix or system path
            let isApple = id.hasPrefix("com.apple.")
                || (path?.hasPrefix("/System/") ?? false)
                || (path?.hasPrefix("/usr/libexec/") ?? false)

            items.append(PersistenceItem(
                category: category,
                name: name,
                label: id,
                executablePath: path,
                isEnabled: isEnabled,
                runContext: .onDemand,
                owner: .user(PathUtilities.currentUser),
                source: isApple ? .apple : .unknown,
                rawMetadata: [
                    "RawLine": .string(trimmed),
                    "Source": .string("pluginkit")
                ]
            ))
        }

        return items
    }
}
