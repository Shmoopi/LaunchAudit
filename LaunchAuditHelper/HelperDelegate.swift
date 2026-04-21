import Foundation

/// NSXPCListener delegate that validates incoming connections.
class HelperDelegate: NSObject, NSXPCListenerDelegate {

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        // Validate the connecting process
        // In production, verify the code signing of the connecting app
        let interface = NSXPCInterface(with: LaunchAuditHelperProtocol.self)
        newConnection.exportedInterface = interface
        newConnection.exportedObject = HelperService()
        newConnection.resume()
        return true
    }
}

/// Implementation of the XPC helper service.
class HelperService: NSObject, LaunchAuditHelperProtocol {

    func readPlistFiles(inDirectory path: String, reply: @escaping ([Data]?, String?) -> Void) {
        guard HelperConstants.isPathAllowed(path) else {
            reply(nil, "Path not in allowlist: \(path)")
            return
        }

        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(atPath: path) else {
            reply(nil, "Cannot read directory: \(path)")
            return
        }

        var plistData: [Data] = []
        for file in files where file.hasSuffix(".plist") {
            let fullPath = (path as NSString).appendingPathComponent(file)
            if let data = fm.contents(atPath: fullPath) {
                plistData.append(data)
            }
        }

        reply(plistData, nil)
    }

    func dumpBTM(reply: @escaping (String?, String?) -> Void) {
        runCommand("/usr/bin/sfltool", arguments: ["dumpbtm"], reply: reply)
    }

    func listLoadedKexts(reply: @escaping (String?, String?) -> Void) {
        runCommand("/usr/bin/kmutil", arguments: ["showloaded", "--show", "loaded"], reply: reply)
    }

    func listConfigurationProfiles(reply: @escaping (String?, String?) -> Void) {
        runCommand("/usr/bin/profiles", arguments: ["list", "-output", "stdout-xml"], reply: reply)
    }

    func checkLaunchdStatus(label: String, domain: String, reply: @escaping (String?, String?) -> Void) {
        // Sanitize label to prevent injection
        let sanitized = label.replacingOccurrences(of: ";", with: "")
            .replacingOccurrences(of: "&", with: "")
            .replacingOccurrences(of: "|", with: "")
        runCommand("/bin/launchctl", arguments: ["print", "\(domain)/\(sanitized)"], reply: reply)
    }

    func readFileContents(atPath path: String, reply: @escaping (Data?, String?) -> Void) {
        guard HelperConstants.isPathAllowed(path) else {
            reply(nil, "Path not in allowlist: \(path)")
            return
        }

        guard let data = FileManager.default.contents(atPath: path) else {
            reply(nil, "Cannot read file: \(path)")
            return
        }

        reply(data, nil)
    }

    // MARK: - Private

    private func runCommand(_ executable: String, arguments: [String], reply: @escaping (String?, String?) -> Void) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr

        do {
            try process.run()
            process.waitUntilExit()

            let data = stdout.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""

            if process.terminationStatus == 0 {
                reply(output, nil)
            } else {
                let errData = stderr.fileHandleForReading.readDataToEndOfFile()
                let errOutput = String(data: errData, encoding: .utf8) ?? ""
                reply(output, errOutput)
            }
        } catch {
            reply(nil, error.localizedDescription)
        }
    }
}
