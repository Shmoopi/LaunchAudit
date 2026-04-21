import Foundation

public struct JSONExporter: Sendable {

    public init() {}

    public func export(_ result: ScanResult) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(result)
    }

    public func exportToString(_ result: ScanResult) throws -> String {
        let data = try export(result)
        return String(data: data, encoding: .utf8) ?? ""
    }
}
