import Foundation

public struct PlistParser: Sendable {

    public init() {}

    /// Parse a plist file at the given path into a dictionary.
    public func parse(at path: String) throws -> [String: Any] {
        let url = URL(fileURLWithPath: path)
        let data = try Data(contentsOf: url)
        return try parse(data: data)
    }

    /// Parse plist data into a dictionary.
    public func parse(data: Data) throws -> [String: Any] {
        var format = PropertyListSerialization.PropertyListFormat.xml
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: &format)
        guard let dict = plist as? [String: Any] else {
            throw PlistParserError.notADictionary
        }
        return dict
    }

    /// Extract a launchd plist into structured data.
    public func parseLaunchdPlist(at path: String) throws -> LaunchdPlistInfo {
        let dict = try parse(at: path)
        return LaunchdPlistInfo(path: path, dictionary: dict)
    }

    /// Convert a raw dictionary to PlistValue metadata.
    public func toMetadata(_ dict: [String: Any]) -> [String: PlistValue] {
        dict.mapValues { PlistValue(from: $0) }
    }
}

public enum PlistParserError: Error, LocalizedError {
    case notADictionary

    public var errorDescription: String? {
        switch self {
        case .notADictionary: return "Plist root is not a dictionary"
        }
    }
}

/// Represents a single calendar interval entry from StartCalendarInterval.
public struct CalendarInterval: Sendable, Equatable {
    public let month: Int?
    public let day: Int?
    public let weekday: Int?
    public let hour: Int?
    public let minute: Int?

    public init(from dict: [String: Any]) {
        self.month = dict["Month"] as? Int
        self.day = dict["Day"] as? Int
        self.weekday = dict["Weekday"] as? Int
        self.hour = dict["Hour"] as? Int
        self.minute = dict["Minute"] as? Int
    }
}

/// Structured representation of a launchd plist.
public struct LaunchdPlistInfo: Sendable {
    public let path: String
    public let label: String?
    public let program: String?
    public let programArguments: [String]
    public let runAtLoad: Bool
    public let keepAlive: Bool
    public let disabled: Bool
    public let startInterval: Int?
    public let startCalendarIntervals: [CalendarInterval]
    public let watchPaths: [String]
    public let queueDirectories: [String]
    public let environmentVariables: [String: String]
    public let workingDirectory: String?
    public let userName: String?
    public let groupName: String?
    public let rawDictionary: [String: PlistValue]

    public init(path: String, dictionary dict: [String: Any]) {
        self.path = path
        self.label = dict["Label"] as? String
        self.program = dict["Program"] as? String

        if let args = dict["ProgramArguments"] as? [String] {
            self.programArguments = args
        } else {
            self.programArguments = []
        }

        self.runAtLoad = dict["RunAtLoad"] as? Bool ?? false
        self.disabled = dict["Disabled"] as? Bool ?? false
        self.startInterval = dict["StartInterval"] as? Int

        // StartCalendarInterval can be a single dict or an array of dicts
        if let singleInterval = dict["StartCalendarInterval"] as? [String: Any] {
            self.startCalendarIntervals = [CalendarInterval(from: singleInterval)]
        } else if let intervals = dict["StartCalendarInterval"] as? [[String: Any]] {
            self.startCalendarIntervals = intervals.map { CalendarInterval(from: $0) }
        } else {
            self.startCalendarIntervals = []
        }
        self.workingDirectory = dict["WorkingDirectory"] as? String
        self.userName = dict["UserName"] as? String
        self.groupName = dict["GroupName"] as? String

        if let watchPaths = dict["WatchPaths"] as? [String] {
            self.watchPaths = watchPaths
        } else {
            self.watchPaths = []
        }

        if let queueDirs = dict["QueueDirectories"] as? [String] {
            self.queueDirectories = queueDirs
        } else {
            self.queueDirectories = []
        }

        if let env = dict["EnvironmentVariables"] as? [String: String] {
            self.environmentVariables = env
        } else {
            self.environmentVariables = [:]
        }

        // KeepAlive can be a bool or a dictionary of conditions
        if let ka = dict["KeepAlive"] as? Bool {
            self.keepAlive = ka
        } else if dict["KeepAlive"] != nil {
            self.keepAlive = true // has conditions, so it's kept alive conditionally
        } else {
            self.keepAlive = false
        }

        self.rawDictionary = dict.mapValues { PlistValue(from: $0) }
    }

    /// Resolve the executable path from Program or ProgramArguments[0].
    public var resolvedExecutable: String? {
        program ?? programArguments.first
    }

    /// Determine the run context from plist configuration.
    public var runContext: RunContext {
        if keepAlive { return .always }
        if runAtLoad { return .login }
        if startInterval != nil || !startCalendarIntervals.isEmpty { return .scheduled }
        if !watchPaths.isEmpty || !queueDirectories.isEmpty { return .onDemand }
        return .manual
    }
}
