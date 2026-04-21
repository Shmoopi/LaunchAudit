import Foundation
import Security

/// Verifies code signatures. NOT an actor — verification is CPU-bound and
/// safe to call from multiple tasks concurrently. The cache is protected
/// by NSCache's internal thread-safety (it's documented as thread-safe).
public final class SigningVerifier: Sendable {
    /// Thread-safe wrapper for NSCache. NSCache is documented as thread-safe,
    /// so we use @unchecked Sendable to satisfy the compiler.
    private final class Cache: @unchecked Sendable {
        private let storage = NSCache<NSString, CacheEntry>()
        
        func object(forKey key: NSString) -> CacheEntry? {
            storage.object(forKey: key)
        }
        
        func setObject(_ obj: CacheEntry, forKey key: NSString) {
            storage.setObject(obj, forKey: key)
        }
    }
    
    private let cache = Cache()

    private final class CacheEntry {
        let modDate: Date?
        let info: SigningInfo
        init(modDate: Date?, info: SigningInfo) {
            self.modDate = modDate
            self.info = info
        }
    }

    public init() {}

    /// Verify the code signature of a binary at the given path.
    /// Safe to call from any task — no actor serialization.
    public func verify(path: String) -> SigningInfo {
        let key = path as NSString
        let currentMod = PathUtilities.timestamps(for: path).modified

        if let cached = cache.object(forKey: key), cached.modDate == currentMod {
            return cached.info
        }

        let info = performVerification(path: path)
        cache.setObject(CacheEntry(modDate: currentMod, info: info), forKey: key)
        return info
    }

    private func performVerification(path: String) -> SigningInfo {
        // Suppress stderr noise from Security.framework
        // (e.g. "open(/private/var/db/DetachedSignatures) - No such file or directory")
        let originalStderr = dup(STDERR_FILENO)
        let devNull = open("/dev/null", O_WRONLY)
        if devNull >= 0 {
            dup2(devNull, STDERR_FILENO)
            close(devNull)
        }
        defer {
            if originalStderr >= 0 {
                dup2(originalStderr, STDERR_FILENO)
                close(originalStderr)
            }
        }

        let url = URL(fileURLWithPath: path) as CFURL
        var staticCode: SecStaticCode?

        let createStatus = SecStaticCodeCreateWithPath(url, SecCSFlags(), &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            return .unsigned
        }

        // Use kSecCSBasicValidateOnly for speed — full validation is very slow
        // on large binaries because it hashes every page.
        let validityStatus = SecStaticCodeCheckValidity(
            code, SecCSFlags(rawValue: kSecCSBasicValidateOnly), nil
        )
        let isSigned = validityStatus == errSecSuccess

        guard isSigned else {
            return .unsigned
        }

        // Only request signing info (not entitlements/requirements — they're slow)
        var cfInfo: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(
            code, SecCSFlags(rawValue: kSecCSSigningInformation), &cfInfo
        )

        guard infoStatus == errSecSuccess, let info = cfInfo as? [String: Any] else {
            return SigningInfo(isSigned: true)
        }

        let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String

        var authorities: [String] = []
        if let certs = info[kSecCodeInfoCertificates as String] as? [Any] {
            for cert in certs {
                if let secCert = cert as! SecCertificate? {
                    if let name = SecCertificateCopySubjectSummary(secCert) as? String {
                        authorities.append(name)
                    }
                }
            }
        }

        // Check the leaf certificate (first in chain) to determine if
        // this is Apple's own binary vs. a third-party Developer ID binary.
        // Apple's own apps use leaf certs like "Software Signing" or
        // "Apple Mac OS Application Signing".  Third-party apps use
        // "Developer ID Application: ..." — their chain also includes
        // "Apple Root CA", so checking any cert would be too broad.
        let isAppleSigned: Bool = {
            guard let leaf = authorities.first else { return false }
            // Apple's own signing identities
            if leaf == "Software Signing" { return true }
            if leaf.hasPrefix("Apple ") { return true }
            // Apple system software (some internal certs)
            if leaf == "Software Update" { return true }
            return false
        }()

        let isAdHoc = teamID == nil && authorities.isEmpty && isSigned
        let bundleID = info[kSecCodeInfoIdentifier as String] as? String

        var cdHash: String?
        if let uniqueID = info[kSecCodeInfoUnique as String] as? Data {
            cdHash = uniqueID.map { String(format: "%02x", $0) }.joined()
        }

        // Skip spctl for Apple-signed binaries (they're always notarized)
        // and for ad-hoc signed binaries (they can't be notarized).
        // spctl is extremely slow (~2-5s per binary, contacts Apple servers).
        let isNotarized: Bool
        if isAppleSigned {
            isNotarized = true
        } else if isAdHoc {
            isNotarized = false
        } else {
            isNotarized = checkNotarization(path: path)
        }

        return SigningInfo(
            isSigned: true,
            isAppleSigned: isAppleSigned,
            isNotarized: isNotarized,
            isAdHocSigned: isAdHoc,
            teamIdentifier: teamID,
            signingAuthority: authorities,
            bundleIdentifier: bundleID,
            cdHash: cdHash
        )
    }

    /// Check notarization via spctl with a timeout.
    private func checkNotarization(path: String) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/spctl")
        process.arguments = ["--assess", "--type", "execute", path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            return false
        }

        // 5-second timeout — spctl can hang if network is slow
        let deadline = DispatchTime.now() + .seconds(5)
        let semaphore = DispatchSemaphore(value: 0)

        DispatchQueue.global().async {
            process.waitUntilExit()
            semaphore.signal()
        }

        if semaphore.wait(timeout: deadline) == .timedOut {
            process.terminate()
            return false
        }

        return process.terminationStatus == 0
    }
}
