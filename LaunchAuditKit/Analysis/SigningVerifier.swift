import Foundation
import Security

/// Verifies code signatures. NOT an actor — verification is CPU-bound and
/// safe to call from multiple tasks concurrently. The in-memory cache is
/// protected by NSCache's internal thread-safety; the disk store has its
/// own internal lock.
public final class SigningVerifier: Sendable {

    private let cache = InMemoryCache()
    private let diskStore: DiskStore?

    /// Default initializer — uses the user's Caches directory for persistence.
    public init() {
        self.diskStore = DiskStore.defaultStore()
        diskStore?.warmInMemoryCache(cache)
    }

    /// Inject a custom cache directory (or `nil` to disable persistence).
    /// Used by tests and for opting out of disk caching.
    public init(cacheDirectory: URL?) {
        self.diskStore = cacheDirectory.map { DiskStore(directory: $0) }
        diskStore?.warmInMemoryCache(cache)
    }

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
        let entry = CacheEntry(modDate: modDate, info: info)
        cache.setObject(entry, forKey: key)
        diskStore?.record(path: path, modDate: modDate, info: info)
        return info
    }

    /// Persist the in-memory cache delta to disk. Cheap if no new entries
    /// have been added since the last flush.
    public func flushDiskCache() {
        diskStore?.flush()
    }

    // MARK: - Internal verification

    private func performVerification(path: String) -> SigningInfo {
        // Suppress stderr noise from Security.framework
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

        let isAppleSigned: Bool = {
            guard let leaf = authorities.first else { return false }
            if leaf == "Software Signing" { return true }
            if leaf.hasPrefix("Apple ") { return true }
            if leaf == "Software Update" { return true }
            return false
        }()

        let isAdHoc = teamID == nil && authorities.isEmpty && isSigned
        let bundleID = info[kSecCodeInfoIdentifier as String] as? String

        var cdHash: String?
        if let uniqueID = info[kSecCodeInfoUnique as String] as? Data {
            cdHash = uniqueID.map { String(format: "%02x", $0) }.joined()
        }

        // Determine notarization. Order matters — each step is much cheaper
        // than the last, so prefer the early-exit paths.
        //
        //   1. Apple-signed → always notarized (no work)
        //   2. Ad-hoc → can never be notarized (no work)
        //   3. csreq "notarized" check via Security.framework — local only,
        //      uses stapled ticket if present (~1ms)
        //   4. spctl --assess — last resort, contacts Apple (2s timeout)
        let isNotarized: Bool
        if isAppleSigned {
            isNotarized = true
        } else if isAdHoc {
            isNotarized = false
        } else if Self.checkNotarizedRequirement(code) {
            isNotarized = true
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

    /// Local-only notarization check via the csreq "notarized" requirement.
    /// Returns true when the binary has a stapled notarization ticket.
    /// Avoids the spctl subprocess entirely (no fork, no network).
    private static func checkNotarizedRequirement(_ code: SecStaticCode) -> Bool {
        var requirement: SecRequirement?
        let createStatus = SecRequirementCreateWithString(
            "notarized" as CFString, SecCSFlags(), &requirement
        )
        guard createStatus == errSecSuccess, let req = requirement else {
            return false
        }
        let status = SecStaticCodeCheckValidity(
            code, SecCSFlags(rawValue: kSecCSBasicValidateOnly), req
        )
        return status == errSecSuccess
    }

    /// Check notarization via spctl with a tight timeout. Last-resort fallback;
    /// the SecRequirement fast-path above handles the common case.
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

        let deadline = DispatchTime.now() + .seconds(2)
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

// MARK: - Cache types

fileprivate final class CacheEntry {
    let modDate: Date?
    let info: SigningInfo
    init(modDate: Date?, info: SigningInfo) {
        self.modDate = modDate
        self.info = info
    }
}

/// Thread-safe wrapper for NSCache. NSCache is documented as thread-safe.
fileprivate final class InMemoryCache: @unchecked Sendable {
    private let storage = NSCache<NSString, CacheEntry>()

    func object(forKey key: NSString) -> CacheEntry? {
        storage.object(forKey: key)
    }

    func setObject(_ obj: CacheEntry, forKey key: NSString) {
        storage.setObject(obj, forKey: key)
    }
}

// MARK: - Persistent disk store

/// Persists signing-verification results across app launches.
/// Storage format: a single plist `[String: Record]` keyed by absolute path.
/// Atomic writes only happen on `flush()` so verification stays fast.
fileprivate final class DiskStore: @unchecked Sendable {
    private let storeURL: URL
    private let lock = NSLock()
    private var entries: [String: Record] = [:]
    private var isDirty = false

    init(directory: URL) {
        self.storeURL = directory.appendingPathComponent("SigningCache.plist")
        try? FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true
        )
        self.entries = Self.load(from: storeURL)
    }

    static func defaultStore() -> DiskStore? {
        let fm = FileManager.default
        guard let cachesDir = try? fm.url(
            for: .cachesDirectory, in: .userDomainMask, appropriateFor: nil, create: true
        ) else {
            return nil
        }
        let appDir = cachesDir.appendingPathComponent("LaunchAudit", isDirectory: true)
        return DiskStore(directory: appDir)
    }

    /// Pre-populate the in-memory cache from the persisted dict so that the
    /// first `verify()` calls hit instantly without going to disk.
    func warmInMemoryCache(_ cache: InMemoryCache) {
        lock.lock()
        let snapshot = entries
        lock.unlock()
        for (path, record) in snapshot {
            let entry = CacheEntry(modDate: record.modDate, info: record.info)
            cache.setObject(entry, forKey: path as NSString)
        }
    }

    func record(path: String, modDate: Date?, info: SigningInfo) {
        lock.lock()
        defer { lock.unlock() }
        entries[path] = Record(modDate: modDate, info: info)
        isDirty = true
    }

    func flush() {
        lock.lock()
        guard isDirty else {
            lock.unlock()
            return
        }
        let snapshot = entries
        isDirty = false
        lock.unlock()

        guard let data = try? PropertyListEncoder().encode(snapshot) else {
            return
        }
        try? data.write(to: storeURL, options: .atomic)
    }

    private static func load(from url: URL) -> [String: Record] {
        guard let data = try? Data(contentsOf: url) else { return [:] }
        return (try? PropertyListDecoder().decode([String: Record].self, from: data)) ?? [:]
    }

    fileprivate struct Record: Codable {
        let modDate: Date?
        let info: SigningInfo
    }
}
