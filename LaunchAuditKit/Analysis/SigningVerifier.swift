import Foundation
import Security

/// Verifies code signatures. NOT an actor — verification is CPU-bound and
/// safe to call from multiple tasks concurrently. The in-memory cache is
/// protected by NSCache's internal thread-safety.
///
/// # Trust model
///
/// Trust decisions are made **only** by asking Security.framework to evaluate a
/// code requirement. Certificate subject strings (`signingAuthority`) are
/// captured for *display* and are never used to decide anything, because the
/// subject Common Name is chosen by whoever issued the certificate and is
/// therefore attacker-controlled.
///
/// Results are deliberately **not** persisted to disk. A cache in a location the
/// audited user can write is a forgery primitive: malware running as that user
/// could pre-seed "Apple-signed, notarized" verdicts for its own payload and the
/// verifier would return them without ever consulting Security.framework.
public final class SigningVerifier: Sendable {

    private let cache = InMemoryCache()

    public init() {}

    /// Verify the code signature of a binary at the given path.
    /// Safe to call from any task — no actor serialization.
    public func verify(path: String) -> SigningInfo {
        verify(path: path, knownModDate: nil)
    }

    /// Verify with a pre-fetched modification date — avoids a redundant `stat`
    /// when the caller has already gathered timestamps in bulk.
    public func verify(path: String, knownModDate: Date?) -> SigningInfo {
        let modDate = knownModDate ?? PathUtilities.timestamps(for: path).modified
        let key = path as NSString

        if let cached = cache.object(forKey: key), cached.modDate == modDate {
            return cached.info
        }

        let info = performVerification(path: path)
        cache.setObject(CacheEntry(modDate: modDate, info: info), forKey: key)
        return info
    }

    // MARK: - Internal verification

    private func performVerification(path: String) -> SigningInfo {
        // NOTE: stderr is deliberately left alone.
        //
        // This used to `dup2` /dev/null over fd 2 to hide Security.framework's
        // validation chatter, saving and restoring the descriptor per call. Under
        // the coordinator's 12-way concurrency that races: a later caller can
        // snapshot fd 2 while it already points at /dev/null and then "restore"
        // that, permanently discarding the process's stderr — which is where the
        // CLI writes its banner, progress and "written to <path>" confirmation, and
        // where a test harness collects results. Reference-counting fixed the race
        // but not the fact that a library should not redirect a process-global
        // descriptor at all. The chatter is cosmetic; losing stderr is not.

        let url = URL(fileURLWithPath: path) as CFURL
        var staticCode: SecStaticCode?

        let createStatus = SecStaticCodeCreateWithPath(url, SecCSFlags(), &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            return .unsigned
        }

        // Validate the signature itself. Stronger than a basic check:
        //   - kSecCSCheckAllArchitectures: validate every slice of a universal
        //     binary, not just the host-native one. Without it, a fat Mach-O
        //     with a good arm64 slice and a tampered x86_64 slice verifies clean
        //     on Apple Silicon while Rosetta happily runs the bad slice.
        //   - kSecCSStrictValidate: catch resource-envelope tricks.
        // kSecCSCheckNestedCode is deliberately omitted — it is very slow on
        // large app bundles and we verify nested helpers as their own items.
        var flags = Self.validationFlags
        let validityStatus = SecStaticCodeCheckValidity(code, flags, nil)
        if validityStatus == errSecCSWeakResourceRules {
            // A valid signature whose resource envelope uses legacy custom omit
            // rules. XProtect ships this way (it updates its own definitions in
            // place), and was reported as *unsigned*, which also kept it visible
            // with Apple items hidden. Re-check with the main executable still
            // under strict validation, so appended or altered code is caught
            // exactly as before, but without the resource envelope; and accept
            // it only as Apple's own platform signature.
            flags = Self.weakResourceRulesValidationFlags
            guard Self.satisfies(code, Requirements.shared.appleAnchor, flags: flags) else {
                return .unsigned
            }
        } else if validityStatus != errSecSuccess {
            return .unsigned
        }

        var cfInfo: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(
            code, SecCSFlags(rawValue: kSecCSSigningInformation), &cfInfo
        )

        guard infoStatus == errSecSuccess, let info = cfInfo as? [String: Any] else {
            return SigningInfo(isSigned: true)
        }

        let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String

        // Display-only. Never used for a trust decision — see the type doc.
        var authorities: [String] = []
        if let certs = info[kSecCodeInfoCertificates as String] as? [Any] {
            for element in certs {
                let ref = element as CFTypeRef
                guard CFGetTypeID(ref) == SecCertificateGetTypeID() else { continue }
                let cert = unsafeDowncast(ref as AnyObject, to: SecCertificate.self)
                if let name = SecCertificateCopySubjectSummary(cert) as? String {
                    authorities.append(name)
                }
            }
        }

        // The authoritative trust checks, evaluated by Security.framework.
        //
        //   "anchor apple"         → signed by Apple itself (platform binaries).
        //   "anchor apple generic" → chains to an Apple root, i.e. Developer ID.
        //   "notarized"            → carries a valid notarization ticket.
        //
        // Apple platform binaries are signed, not notarized — notarization is
        // for third-party software — so `anchor apple` implies trusted without
        // implying a notarization ticket exists.
        let isAppleSigned = Self.satisfies(code, Requirements.shared.appleAnchor, flags: flags)
        let isAppleIssued = Self.satisfies(code, Requirements.shared.appleGenericAnchor, flags: flags)
        let isNotarized = Self.satisfies(code, Requirements.shared.notarized, flags: flags)

        // Ad-hoc: a valid signature with no identity behind it at all.
        let isAdHoc = !isAppleSigned && !isAppleIssued && teamID == nil

        let bundleID = info[kSecCodeInfoIdentifier as String] as? String

        var cdHash: String?
        if let uniqueID = info[kSecCodeInfoUnique as String] as? Data {
            cdHash = uniqueID.map { String(format: "%02x", $0) }.joined()
        }

        return SigningInfo(
            isSigned: true,
            isAppleSigned: isAppleSigned,
            isNotarized: isNotarized,
            isAdHocSigned: isAdHoc,
            teamIdentifier: teamID,
            signingAuthority: authorities,
            bundleIdentifier: bundleID,
            cdHash: cdHash,
            entitlements: Self.riskyEntitlements(in: info)
        )
    }

    private static let validationFlags = SecCSFlags(
        rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate
    )

    /// Strict validation of every slice of the executable, without the resource
    /// envelope. Used only for Apple code reporting `errSecCSWeakResourceRules`.
    private static let weakResourceRulesValidationFlags = SecCSFlags(
        rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSDoNotValidateResources
    )

    /// Evaluate a pre-built code requirement against the binary.
    private static func satisfies(
        _ code: SecStaticCode,
        _ requirement: SecRequirement?,
        flags: SecCSFlags
    ) -> Bool {
        guard let requirement else { return false }
        return SecStaticCodeCheckValidity(code, flags, requirement) == errSecSuccess
    }

    /// Entitlements that materially widen a binary's attack surface. A notarized
    /// binary carrying these is a legitimate injection target, so the risk model
    /// must be able to see them rather than capping on notarization alone.
    private static let dangerousEntitlements: Set<String> = [
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.cs.allow-jit",
        "com.apple.security.get-task-allow",
        "com.apple.security.cs.debugger",
    ]

    private static func riskyEntitlements(in info: [String: Any]) -> [String] {
        guard let data = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any] else {
            return []
        }
        var found: [String] = []
        for (key, value) in data {
            let isEnabled = (value as? Bool) ?? ((value as? NSNumber)?.boolValue ?? false)
            guard isEnabled else { continue }
            if dangerousEntitlements.contains(key) || key.hasPrefix("com.apple.private.") {
                found.append(key)
            }
        }
        return found.sorted()
    }
}

// MARK: - Requirement cache

/// Code requirements are immutable once built and safe to evaluate concurrently,
/// so build each one once for the process lifetime.
private final class Requirements: @unchecked Sendable {
    static let shared = Requirements()

    let appleAnchor: SecRequirement?
    let appleGenericAnchor: SecRequirement?
    let notarized: SecRequirement?

    private init() {
        appleAnchor = Self.make("anchor apple")
        appleGenericAnchor = Self.make("anchor apple generic")
        notarized = Self.make("notarized")
    }

    private static func make(_ text: String) -> SecRequirement? {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, SecCSFlags(), &requirement)
            == errSecSuccess else { return nil }
        return requirement
    }
}

// MARK: - Cache types

private final class CacheEntry {
    let modDate: Date?
    let info: SigningInfo
    init(modDate: Date?, info: SigningInfo) {
        self.modDate = modDate
        self.info = info
    }
}

/// Thread-safe wrapper for NSCache. NSCache is documented as thread-safe.
private final class InMemoryCache: @unchecked Sendable {
    private let storage = NSCache<NSString, CacheEntry>()

    func object(forKey key: NSString) -> CacheEntry? {
        storage.object(forKey: key)
    }

    func setObject(_ obj: CacheEntry, forKey key: NSString) {
        storage.setObject(obj, forKey: key)
    }
}
