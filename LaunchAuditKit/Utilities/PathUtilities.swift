import Foundation

public struct PathUtilities: Sendable {

    public static let homeDirectory = FileManager.default.homeDirectoryForCurrentUser.path
    public static let currentUser = NSUserName()

    /// Expand ~ to the current user's home directory.
    public static func expandTilde(_ path: String) -> String {
        if path.hasPrefix("~/") {
            return homeDirectory + String(path.dropFirst(1))
        }
        return path
    }

    /// Get file timestamps (creation and modification dates).
    public static func timestamps(for path: String) -> ItemTimestamps {
        let fm = FileManager.default
        guard let attrs = try? fm.attributesOfItem(atPath: path) else {
            return ItemTimestamps()
        }
        return ItemTimestamps(
            created: attrs[.creationDate] as? Date,
            modified: attrs[.modificationDate] as? Date
        )
    }

    /// Check if a path exists.
    public static func exists(_ path: String) -> Bool {
        FileManager.default.fileExists(atPath: path)
    }

    /// Check if a path is a directory.
    public static func isDirectory(_ path: String) -> Bool {
        var isDir: ObjCBool = false
        return FileManager.default.fileExists(atPath: path, isDirectory: &isDir) && isDir.boolValue
    }

    /// List files in a directory, optionally filtering by extension.
    public static func listFiles(
        in directory: String,
        withExtension ext: String? = nil
    ) -> [String] {
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(atPath: directory) else {
            return []
        }
        let paths = items.map { (directory as NSString).appendingPathComponent($0) }
        if let ext = ext {
            return paths.filter { ($0 as NSString).pathExtension == ext }
        }
        return paths
    }

    /// List subdirectories in a directory.
    public static func listDirectories(in directory: String) -> [String] {
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(atPath: directory) else {
            return []
        }
        return items
            .map { (directory as NSString).appendingPathComponent($0) }
            .filter { isDirectory($0) }
    }

    /// List bundles (directories with a given extension) in a directory.
    public static func listBundles(
        in directory: String,
        withExtension ext: String
    ) -> [String] {
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(atPath: directory) else {
            return []
        }
        return items
            .filter { ($0 as NSString).pathExtension == ext }
            .map { (directory as NSString).appendingPathComponent($0) }
    }

    /// Check if a file is writable by the current user.
    public static func isWritable(_ path: String) -> Bool {
        FileManager.default.isWritableFile(atPath: path)
    }

    /// Check if a path is in a world-writable directory.
    public static func isInWorldWritableDirectory(_ path: String) -> Bool {
        let worldWritablePaths = ["/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp"]
        return worldWritablePaths.contains { path.hasPrefix($0) }
    }

    /// Check if a filename/path is hidden (starts with a dot).
    public static func isHidden(_ path: String) -> Bool {
        let filename = (path as NSString).lastPathComponent
        return filename.hasPrefix(".")
    }

    /// Check if a path is under /System/ (SIP-protected).
    public static func isSystemPath(_ path: String) -> Bool {
        path.hasPrefix("/System/")
    }

    /// Get the owner UID of a file.
    public static func fileOwner(_ path: String) -> String? {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let owner = attrs[.ownerAccountName] as? String else {
            return nil
        }
        return owner
    }
}
