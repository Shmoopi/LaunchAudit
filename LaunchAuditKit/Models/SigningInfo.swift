import Foundation

public struct SigningInfo: Codable, Hashable, Sendable {
    public let isSigned: Bool
    public let isAppleSigned: Bool
    public let isNotarized: Bool
    public let isAdHocSigned: Bool
    public let teamIdentifier: String?
    public let signingAuthority: [String]
    public let bundleIdentifier: String?
    public let cdHash: String?

    public init(
        isSigned: Bool,
        isAppleSigned: Bool = false,
        isNotarized: Bool = false,
        isAdHocSigned: Bool = false,
        teamIdentifier: String? = nil,
        signingAuthority: [String] = [],
        bundleIdentifier: String? = nil,
        cdHash: String? = nil
    ) {
        self.isSigned = isSigned
        self.isAppleSigned = isAppleSigned
        self.isNotarized = isNotarized
        self.isAdHocSigned = isAdHocSigned
        self.teamIdentifier = teamIdentifier
        self.signingAuthority = signingAuthority
        self.bundleIdentifier = bundleIdentifier
        self.cdHash = cdHash
    }

    public static let unsigned = SigningInfo(isSigned: false)
}
