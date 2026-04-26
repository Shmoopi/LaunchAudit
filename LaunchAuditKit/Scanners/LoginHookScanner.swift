import Foundation

public struct LoginHookScanner: PersistenceScanner {
    public let category = PersistenceCategory.loginHooks
    public let requiresPrivilege = false

    public var scanPaths: [String] { [] }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        for hookType in ["LoginHook", "LogoutHook"] {
            if let output = await ProcessRunner.shared.tryRun(
                "/usr/bin/defaults",
                arguments: ["read", "com.apple.loginwindow", hookType]
            ) {
                let path = output.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !path.isEmpty else { continue }

                items.append(PersistenceItem(
                    category: category,
                    name: "\(hookType): \(path)",
                    executablePath: path,
                    isEnabled: true,
                    runContext: hookType == "LoginHook" ? .login : .manual,
                    owner: .system,
                    riskLevel: .high, // deprecated mechanism, inherently suspicious
                    riskReasons: ["Uses deprecated \(hookType) mechanism"],
                    rawMetadata: ["HookType": .string(hookType)]
                ))
            }
        }

        return items
    }
}
