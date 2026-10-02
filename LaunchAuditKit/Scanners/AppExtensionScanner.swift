import Foundation

public struct AppExtensionScanner: PersistenceScanner {
    public let category = PersistenceCategory.appExtensions
    public let requiresPrivilege = false

    /// Extensions are enumerated through pluginkit rather than by walking the
    /// filesystem, so there are no fixed directories to declare.
    public var scanPaths: [String] { [] }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        var outcome = ScanOutcome()

        // `-mAD` lists identifiers and versions only. The bundle path needs the
        // verbose form — without it `executablePath` was always nil and no app
        // extension was ever signature-verified.
        guard let output = await ProcessRunner.shared.tryRun(
            "/usr/bin/pluginkit", arguments: ["-mAvvv"], timeout: 20
        ) else {
            outcome.errors.append(ScanError(
                category: category,
                message: "pluginkit produced no output",
                isPermissionDenied: false
            ))
            return outcome
        }

        outcome.items = parsePluginkitVerbose(output)
        return outcome
    }

    /// Parse `pluginkit -mAvvv`.
    ///
    /// Record shape:
    /// ```
    /// +    com.apple.Foo.Bar(1.0)
    ///              Path = /System/Library/.../Foo.appex
    ///              UUID = …
    ///      Display Name = iCloud Drive
    /// ```
    /// A record starts at a line beginning with `+` or `-`; indented `Key = Value`
    /// lines belong to it until the next record starts.
    func parsePluginkitVerbose(_ output: String) -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        var identifier: String?
        var version: String?
        var enabled = true
        var attributes: [String: String] = [:]

        func flush() {
            guard let id = identifier else { return }
            let path = attributes["Path"]
            let displayName = attributes["Display Name"] ?? attributes["Short Name"]
            let name = displayName?.isEmpty == false
                ? displayName!
                : id.components(separatedBy: ".").suffix(2).joined(separator: ".")

            var executablePath: String?
            if let path {
                let infoPlist = (path as NSString).appendingPathComponent("Contents/Info.plist")
                if let dict = try? PlistParser().parse(at: infoPlist),
                   let execName = dict["CFBundleExecutable"] as? String {
                    executablePath = (path as NSString)
                        .appendingPathComponent("Contents/MacOS/\(execName)")
                }
            }

            var metadata: [String: PlistValue] = [:]
            metadata["Source"] = .string("pluginkit")
            for (key, value) in attributes { metadata[key] = .string(value) }
            if let version { metadata["Version"] = .string(version) }

            // Path, not bundle identifier. An extension's identifier comes from
            // its own Info.plist and can claim `com.apple.*` freely.
            let owner: ItemOwner = {
                guard let path else { return .system }
                for (user, home) in PathUtilities.scannableHomeDirectories()
                where path.hasPrefix(home) {
                    return .user(user)
                }
                return .system
            }()

            items.append(PersistenceItem(
                category: category,
                name: name,
                label: id,
                configPath: path,
                executablePath: executablePath,
                isEnabled: enabled,
                runContext: .onDemand,
                owner: owner,
                source: path.map { PathUtilities.isAppleOwnedPath($0) ? .apple : .unknown }
                    ?? .unknown,
                timestamps: path.map { PathUtilities.timestamps(for: $0) } ?? ItemTimestamps(),
                rawMetadata: metadata
            ))

            identifier = nil
            version = nil
            enabled = true
            attributes = [:]
        }

        for line in output.components(separatedBy: "\n") {
            if line.isEmpty { continue }

            let isRecordStart = line.hasPrefix("+") || line.hasPrefix("-")
            if isRecordStart {
                flush()
                enabled = line.hasPrefix("+")
                let body = line.dropFirst().trimmingCharacters(in: .whitespaces)
                // "identifier(version)"
                if let open = body.firstIndex(of: "(") {
                    identifier = String(body[body.startIndex..<open])
                    let rest = body[body.index(after: open)...]
                    let raw = rest.hasSuffix(")") ? String(rest.dropLast()) : String(rest)
                    version = (raw == "(null)" || raw.isEmpty) ? nil : raw
                } else {
                    identifier = body
                }
                continue
            }

            // Continuation: "        Key = Value"
            guard identifier != nil else { continue }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard let equals = trimmed.range(of: " = ") else { continue }
            let key = String(trimmed[trimmed.startIndex..<equals.lowerBound])
                .trimmingCharacters(in: .whitespaces)
            let value = String(trimmed[equals.upperBound...])
                .trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else { continue }
            attributes[key] = value
        }
        flush()

        return items
    }
}
