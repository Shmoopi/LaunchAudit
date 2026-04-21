import Foundation

/// A type-erased plist value for storing arbitrary metadata.
public enum PlistValue: Codable, Hashable, Sendable {
    case string(String)
    case int(Int)
    case double(Double)
    case bool(Bool)
    case date(Date)
    case data(Data)
    case array([PlistValue])
    case dictionary([String: PlistValue])
    case null

    public init(from any: Any) {
        switch any {
        case let s as String:
            self = .string(s)
        case let n as NSNumber:
            if CFBooleanGetTypeID() == CFGetTypeID(n) {
                self = .bool(n.boolValue)
            } else if n.doubleValue != Double(n.intValue) {
                self = .double(n.doubleValue)
            } else {
                self = .int(n.intValue)
            }
        case let d as Date:
            self = .date(d)
        case let data as Data:
            self = .data(data)
        case let arr as [Any]:
            self = .array(arr.map { PlistValue(from: $0) })
        case let dict as [String: Any]:
            self = .dictionary(dict.mapValues { PlistValue(from: $0) })
        default:
            self = .null
        }
    }

    public var stringValue: String? {
        if case .string(let s) = self { return s }
        return nil
    }

    public var boolValue: Bool? {
        if case .bool(let b) = self { return b }
        return nil
    }

    public var intValue: Int? {
        if case .int(let i) = self { return i }
        return nil
    }

    public var arrayValue: [PlistValue]? {
        if case .array(let a) = self { return a }
        return nil
    }

    public var dictionaryValue: [String: PlistValue]? {
        if case .dictionary(let d) = self { return d }
        return nil
    }

    /// Convert back to Foundation type for plist serialization.
    public var foundationValue: Any {
        switch self {
        case .string(let s): return s
        case .int(let i): return i
        case .double(let d): return d
        case .bool(let b): return b
        case .date(let d): return d
        case .data(let d): return d
        case .array(let a): return a.map(\.foundationValue)
        case .dictionary(let d): return d.mapValues(\.foundationValue)
        case .null: return NSNull()
        }
    }

    /// Pretty-print for display.
    public var displayString: String {
        switch self {
        case .string(let s): return s
        case .int(let i): return "\(i)"
        case .double(let d): return "\(d)"
        case .bool(let b): return b ? "true" : "false"
        case .date(let d): return d.formatted()
        case .data(let d): return "<\(d.count) bytes>"
        case .array(let a): return "[\(a.count) items]"
        case .dictionary(let d): return "{\(d.count) keys}"
        case .null: return "null"
        }
    }
}
