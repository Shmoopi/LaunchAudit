import Foundation

public struct LoginHookScanner: PersistenceScanner {
    public let category = PersistenceCategory.loginHooks

    /// The hook lives in root's preferences, which only root can read.
    public let requiresPrivilege = true

    /// Login and logout hooks are installed with `sudo defaults write`, so they
    /// land in root's preference domain — not the invoking user's.
    ///
    /// The previous implementation ran `defaults read com.apple.loginwindow
    /// LoginHook` with no domain qualifier, which resolves to
    /// `~/Library/Preferences/com.apple.loginwindow.plist`. Hooks are never there,
    /// so the scanner was a guaranteed false negative on a mechanism it itself
    /// rates high risk.
    private let domains = [
        "/private/var/root/Library/Preferences/com.apple.loginwindow.plist",
        "/Library/Preferences/com.apple.loginwindow.plist",
    ]

    public var scanPaths: [String] { domains }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        var outcome = ScanOutcome()

        var readAny = false

        for domain in domains {
            guard PathUtilities.exists(domain) else { continue }
            readAny = true

            let dict: [String: Any]
            do {
                dict = try PlistParser().parse(at: domain)
            } catch {
                outcome.errors.append(scanError(error, path: domain))
                continue
            }

            for hookType in ["LoginHook", "LogoutHook"] {
                guard let path = (dict[hookType] as? String)?
                    .trimmingCharacters(in: .whitespacesAndNewlines),
                      !path.isEmpty else { continue }

                // A hook is a script invoked by loginwindow; both fire on an
                // event, so neither is `.manual`.
                let context: RunContext = hookType == "LoginHook" ? .login : .triggered

                outcome.items.append(PersistenceItem(
                    category: category,
                    name: "\(hookType): \((path as NSString).lastPathComponent)",
                    label: hookType,
                    configPath: domain,
                    executablePath: path,
                    isEnabled: true,
                    runContext: context,
                    owner: .system,
                    riskLevel: .high,
                    riskReasons: [
                        "\(hookType) is a deprecated mechanism that still executes as root",
                        "Script: \(path)",
                    ],
                    timestamps: PathUtilities.timestamps(for: path),
                    rawMetadata: [
                        "HookType": .string(hookType),
                        "ScriptPath": .string(path),
                        "Domain": .string(domain),
                    ]
                ))
            }
        }

        // Root's preference domain is unreadable without privileges, so an empty
        // result here means "could not look", not "nothing installed".
        if !readAny, !PathUtilities.isRoot {
            outcome.errors.append(ScanError(
                category: category,
                message: "Login and logout hooks live in root's preference domain, "
                    + "which needs privileges to read. Re-run with "
                    + "`sudo launchaudit scan` to cover this category.",
                isPermissionDenied: true
            ))
        }

        return outcome
    }
}
