import Foundation

public struct PathUtilities: Sendable {

    public static let homeDirectory = FileManager.default.homeDirectoryForCurrentUser.path
    public static let currentUser = NSUserName()

    /// True when the process is running with root privileges.
    public static var isRoot: Bool { getuid() == 0 }

    /// Expand ~ to the current user's home directory.
    public static func expandTilde(_ path: String) -> String {
        if path.hasPrefix("~/") {
            return homeDirectory + String(path.dropFirst(1))
        }
        return path
    }

    /// Home directories to scan for user-scoped persistence.
    ///
    /// Under `sudo`, `homeDirectoryForCurrentUser` is root's home, so scanning
    /// only that directory means a privileged scan sees *less* user data than an
    /// unprivileged one — it misses every real account's `~/Library`. When root,
    /// enumerate the actual user accounts instead.
    public static func scannableHomeDirectories() -> [(user: String, home: String)] {
        guard isRoot else { return [(currentUser, homeDirectory)] }

        var results: [(user: String, home: String)] = []
        setpwent()
        while let entry = getpwent() {
            let uid = entry.pointee.pw_uid
            // Skip service accounts; real accounts start at 500 on macOS.
            guard uid >= 500 else { continue }
            let name = String(cString: entry.pointee.pw_name)
            let home = String(cString: entry.pointee.pw_dir)
            guard home.hasPrefix("/Users/"), home != "/Users/Deleted Users",
                  isDirectory(home) else { continue }
            results.append((name, home))
        }
        endpwent()

        if results.isEmpty { results.append((currentUser, homeDirectory)) }
        return results
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

    /// Whether a path is a bundle that carries its own code signature (a kext,
    /// plugin or app), as opposed to a plain directory such as a `.savedState`
    /// folder or a document bundle such as an Automator `.workflow`.
    public static func isSignedBundle(_ path: String) -> Bool {
        guard isDirectory(path) else { return false }
        let base = path as NSString
        return exists(base.appendingPathComponent("Contents/_CodeSignature"))
            || exists(base.appendingPathComponent("_CodeSignature"))
    }

    /// List files in a directory, optionally filtering by extension.
    ///
    /// Directories and dotfiles are excluded by default: a stray `.DS_Store` or
    /// subdirectory is not a persistence item, and reporting one as a privileged
    /// helper or a folder action is a false positive.
    public static func listFiles(
        in directory: String,
        withExtension ext: String? = nil,
        includeHidden: Bool = false,
        includeDirectories: Bool = false
    ) -> [String] {
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(atPath: directory) else {
            return []
        }
        var paths = items
            .filter { includeHidden || !$0.hasPrefix(".") }
            .map { (directory as NSString).appendingPathComponent($0) }
        if !includeDirectories {
            paths = paths.filter { !isDirectory($0) }
        }
        if let ext {
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
            .filter { !$0.hasPrefix(".") }
            .map { (directory as NSString).appendingPathComponent($0) }
            .filter { isDirectory($0) }
    }

    /// List bundles (directories with a given extension) in a directory.
    public static func listBundles(
        in directory: String,
        withExtension ext: String
    ) -> [String] {
        listBundles(in: directory, withExtensions: [ext])
    }

    /// List bundles matching any of the given extensions.
    public static func listBundles(
        in directory: String,
        withExtensions exts: [String]
    ) -> [String] {
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(atPath: directory) else {
            return []
        }
        let wanted = Set(exts)
        return items
            .filter { wanted.contains(($0 as NSString).pathExtension) }
            .map { (directory as NSString).appendingPathComponent($0) }
    }

    /// Check if a file is writable by the current user.
    public static func isWritable(_ path: String) -> Bool {
        FileManager.default.isWritableFile(atPath: path)
    }

    /// Whether anyone other than root can modify `path`.
    ///
    /// This is the question every "writable" finding is really asking: could a
    /// less-privileged account plant or alter this file. `isWritable` answers
    /// "can *this process* write it", which is the same thing in an unprivileged
    /// scan but not under `sudo`: root ignores permission bits, so a privileged
    /// scan reported every file in `/etc` and `/usr/libexec`, including
    /// `r--r--r-- root:wheel` ones, as writable and therefore Critical.
    public static func isWritableByNonRoot(_ path: String) -> Bool {
        // Unprivileged, the process's own answer is exact and also covers ACLs.
        guard isRoot else { return isWritable(path) }
        var st = stat()
        guard stat(path, &st) == 0 else { return false }
        return modeAllowsNonRootWrite(mode: st.st_mode, owner: st.st_uid, group: st.st_gid)
    }

    /// Permission bits that let a non-root account write a file: anyone, a group
    /// other than `wheel`, or an owner other than root.
    static func modeAllowsNonRootWrite(mode: mode_t, owner: uid_t, group: gid_t) -> Bool {
        if mode & S_IWOTH != 0 { return true }
        if mode & S_IWGRP != 0, group != 0 { return true }
        if mode & S_IWUSR != 0, owner != 0 { return true }
        return false
    }

    /// Directories that are attacker-controlled without being world-writable —
    /// per-user temporary storage, which any process running as that user owns.
    private static let userControlledPrefixes = [
        "/private/var/folders/", "/var/folders/",
    ]

    /// Well-known world-writable roots. Kept as a fast path so the answer does not
    /// depend on the directory existing or being statable.
    private static let worldWritablePrefixes = [
        "/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/",
        "/Users/Shared/",
    ]

    /// Check whether a path lives in a directory anyone can write to.
    ///
    /// Mode bits are consulted in addition to the prefix list, so a world-writable
    /// directory created by an installer is caught too. Note this uses `stat` rather
    /// than `lstat`: the question is about the *effective* directory, and `/tmp` is a
    /// symlink whose own mode bits are not world-writable — `lstat` would inspect
    /// the link and answer "no" for everything under `/tmp`.
    ///
    /// When the immediate parent does not exist, the nearest existing ancestor is
    /// used, so a reference to a not-yet-created file in a world-writable directory
    /// is still flagged.
    public static func isInWorldWritableDirectory(_ path: String) -> Bool {
        if worldWritablePrefixes.contains(where: { path.hasPrefix($0) }) { return true }
        if userControlledPrefixes.contains(where: { path.hasPrefix($0) }) { return true }

        var directory = (path as NSString).deletingLastPathComponent
        var depth = 0
        while !directory.isEmpty, directory != "/", depth < 64 {
            var st = stat()
            if stat(directory, &st) == 0 {
                return (st.st_mode & S_IWOTH) != 0
            }
            directory = (directory as NSString).deletingLastPathComponent
            depth += 1
        }
        return false
    }

    /// Check if a filename/path is hidden (starts with a dot).
    public static func isHidden(_ path: String) -> Bool {
        let filename = (path as NSString).lastPathComponent
        return filename.hasPrefix(".")
    }

    /// Locations that hold operating-system configuration, where an unexpected
    /// or recently modified entry is meaningful.
    ///
    /// `/System/` alone is too narrow: `/etc` is a symlink to `/private/etc` on
    /// the *writable* Data volume, and it is where PAM, sudoers, periodic and
    /// shell-profile persistence live.
    public static func isSystemPath(_ path: String) -> Bool {
        let prefixes = [
            "/System/", "/Library/Apple/",
            "/etc/", "/private/etc/",
            "/usr/lib/", "/usr/libexec/", "/usr/sbin/", "/usr/bin/",
            "/bin/", "/sbin/",
        ]
        return prefixes.contains { path.hasPrefix($0) }
    }

    /// Paths where only Apple ships content. Used to decide whether an
    /// Apple-signed binary was registered by Apple or pointed at by a third
    /// party. `/Library/Apple/` is included because that is where Apple delivers
    /// out-of-band updates (XProtect, MRT) outside the sealed system volume.
    public static func isAppleOwnedPath(_ path: String) -> Bool {
        path.hasPrefix("/System/") || path.hasPrefix("/Library/Apple/")
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

// MARK: - Interpreters

/// General-purpose interpreters and command runners.
///
/// When one of these is the registered executable, its signature says nothing
/// about the code that actually runs — the payload is in the arguments. `/bin/sh`
/// is Apple-signed; `/bin/sh -c "curl evil | sh"` is not Apple software.
public enum Interpreters {
    public static let paths: Set<String> = [
        "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/csh", "/bin/tcsh", "/bin/ksh",
        "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/zsh",
        "/usr/bin/env",
        "/usr/bin/python", "/usr/bin/python2", "/usr/bin/python3",
        "/usr/bin/perl", "/usr/bin/ruby", "/usr/bin/php", "/usr/bin/tclsh",
        "/usr/bin/osascript", "/usr/bin/automator",
        "/usr/bin/curl", "/usr/bin/ftp", "/usr/bin/nscurl",
        "/usr/bin/open", "/usr/bin/login", "/usr/bin/sudo",
        "/usr/bin/xargs", "/usr/bin/nohup",
        "/usr/bin/swift", "/usr/bin/arch", "/usr/bin/caffeinate",
        "/usr/bin/screen", "/usr/bin/script",
        "/usr/bin/defaults", "/bin/launchctl", "/usr/bin/launchctl",
    ]

    /// Match on the resolved basename too, so `/opt/homebrew/bin/bash` and a
    /// relative `python3` are both recognized.
    private static let basenames: Set<String> = [
        "sh", "bash", "zsh", "csh", "tcsh", "ksh", "env",
        "python", "python2", "python3", "perl", "ruby", "php", "tclsh",
        "osascript", "curl", "xargs", "nohup", "node", "deno", "bun",
    ]

    public static func isInterpreter(_ path: String) -> Bool {
        if paths.contains(path) { return true }
        return basenames.contains((path as NSString).lastPathComponent)
    }

    /// Given an interpreter invocation, find the payload it will execute.
    ///
    /// Handles the two shapes that matter: an inline script (`-c`, `-e`) and a
    /// script file passed as the first non-flag argument.
    public static func payload(interpreter: String, arguments: [String]) -> InterpreterPayload? {
        // Drop argv[0] when it is the interpreter itself.
        var args = arguments
        if let first = args.first,
           first == interpreter || (first as NSString).lastPathComponent
               == (interpreter as NSString).lastPathComponent {
            args.removeFirst()
        }

        // `env` prefixes: skip VAR=value pairs and re-dispatch on the real command.
        if (interpreter as NSString).lastPathComponent == "env" {
            let remainder = Array(args.drop { $0.contains("=") && !$0.hasPrefix("/") })
            guard let next = remainder.first else { return nil }
            if isInterpreter(next) {
                return payload(interpreter: next, arguments: Array(remainder.dropFirst()))
            }
            return .script(next)
        }

        var index = 0
        while index < args.count {
            let arg = args[index]
            // Inline script bodies.
            if arg == "-c" || arg == "-e" || arg == "--command" || arg == "-command" {
                let body = args[(index + 1)...].joined(separator: " ")
                return body.isEmpty ? nil : .inlineScript(body)
            }
            if !arg.hasPrefix("-") {
                return .script(arg)
            }
            index += 1
        }
        return nil
    }
}

public enum InterpreterPayload: Sendable, Equatable {
    /// A script file the interpreter will run.
    case script(String)
    /// An inline command body passed with `-c` / `-e`.
    case inlineScript(String)

    public var scriptPath: String? {
        if case .script(let path) = self { return path }
        return nil
    }

    public var displayText: String {
        switch self {
        case .script(let path): return path
        case .inlineScript(let body): return body
        }
    }
}
