import Foundation

public struct SigningInfo: Codable, Hashable, Sendable {
    public let isSigned: Bool
    /// Signed by Apple itself — satisfies the `anchor apple` code requirement.
    /// Never inferred from certificate subject strings.
    public let isAppleSigned: Bool
    public let isNotarized: Bool
    public let isAdHocSigned: Bool
    public let teamIdentifier: String?
    /// Certificate subject summaries, for display only. The subject Common Name
    /// is chosen by the certificate's issuer and must never drive a trust
    /// decision — see `SigningVerifier`.
    public let signingAuthority: [String]
    public let bundleIdentifier: String?
    public let cdHash: String?
    /// Entitlements that widen the binary's attack surface (library-validation
    /// disabled, dyld environment variables allowed, and similar).
    public let entitlements: [String]

    public init(
        isSigned: Bool,
        isAppleSigned: Bool = false,
        isNotarized: Bool = false,
        isAdHocSigned: Bool = false,
        teamIdentifier: String? = nil,
        signingAuthority: [String] = [],
        bundleIdentifier: String? = nil,
        cdHash: String? = nil,
        entitlements: [String] = []
    ) {
        self.isSigned = isSigned
        self.isAppleSigned = isAppleSigned
        self.isNotarized = isNotarized
        self.isAdHocSigned = isAdHocSigned
        self.teamIdentifier = teamIdentifier
        self.signingAuthority = signingAuthority
        self.bundleIdentifier = bundleIdentifier
        self.cdHash = cdHash
        self.entitlements = entitlements
    }

    public static let unsigned = SigningInfo(isSigned: false)

    /// True when the signature is valid but backed by no identity we can trust —
    /// neither Apple nor an Apple-issued developer certificate.
    public var hasTrustedIdentity: Bool {
        isAppleSigned || teamIdentifier != nil
    }

    // Hand-written so reports produced by older versions (which had no
    // `entitlements` key) still decode through `launchaudit export`.
    private enum CodingKeys: String, CodingKey {
        case isSigned, isAppleSigned, isNotarized, isAdHocSigned
        case teamIdentifier, signingAuthority, bundleIdentifier, cdHash, entitlements
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        isSigned = try c.decode(Bool.self, forKey: .isSigned)
        isAppleSigned = try c.decodeIfPresent(Bool.self, forKey: .isAppleSigned) ?? false
        isNotarized = try c.decodeIfPresent(Bool.self, forKey: .isNotarized) ?? false
        isAdHocSigned = try c.decodeIfPresent(Bool.self, forKey: .isAdHocSigned) ?? false
        teamIdentifier = try c.decodeIfPresent(String.self, forKey: .teamIdentifier)
        signingAuthority = try c.decodeIfPresent([String].self, forKey: .signingAuthority) ?? []
        bundleIdentifier = try c.decodeIfPresent(String.self, forKey: .bundleIdentifier)
        cdHash = try c.decodeIfPresent(String.self, forKey: .cdHash)
        entitlements = try c.decodeIfPresent([String].self, forKey: .entitlements) ?? []
    }
}
