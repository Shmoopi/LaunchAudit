import Foundation

/// Legacy `rc` scripts.
///
/// `rc.common` is a stock Apple helper-function library, not a persistence vector.
/// `rc.local` and `rc.shutdown.local` are not created by macOS at all, so their
/// presence means something else made them — which is why any hit here is high
/// risk rather than merely notable.
public struct RcScriptScanner: PersistenceScanner {
    public let category = PersistenceCategory.rcScripts
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        ["/etc/rc.local", "/etc/rc.shutdown.local"]
    }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        var outcome = ScanOutcome()

        for path in scanPaths {
            guard PathUtilities.exists(path) else { continue }
            let name = (path as NSString).lastPathComponent

            // Both entries in `scanPaths` are rc.local-family scripts, so the
            // previous `if name == "rc.local" || ...` test was unconditionally
            // true and the generic `.medium` default was unreachable. State the
            // single real verdict instead of pretending to branch.
            var reasons = [
                "macOS does not ship \(name); its presence means it was created "
                    + "by software or by an attacker",
            ]

            // Include the content preview — the whole point of an rc script is what
            // it runs, and there is no separate binary to verify.
            if let content = try? SafeRead.text(atPath: path, maxBytes: 256 * 1024) {
                let meaningful = content
                    .components(separatedBy: .newlines)
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty && !$0.hasPrefix("#") }
                if !meaningful.isEmpty {
                    reasons.append("Runs: \(meaningful.prefix(3).joined(separator: "; "))")
                }
                reasons.append(contentsOf: ShellProfileScanner.suspiciousReasons(in: content))
            } else {
                outcome.errors.append(ScanError(
                    category: category,
                    path: path,
                    message: "rc script exists but could not be read",
                    isPermissionDenied: !PathUtilities.isRoot
                ))
            }

            outcome.items.append(PersistenceItem(
                category: category,
                name: name,
                configPath: path,
                executablePath: path,
                isEnabled: true,
                runContext: name.contains("shutdown") ? .triggered : .boot,
                owner: .system,
                riskLevel: .high,
                riskReasons: reasons,
                timestamps: PathUtilities.timestamps(for: path),
                rawMetadata: ["Type": .string("rc script")]
            ))
        }

        return outcome
    }
}
