import XCTest
@testable import LaunchAudit

/// Fixture-driven tests for the command-output parsers.
///
/// All input here is real output captured from the tools in question. Previously
/// these parsers had no tests at all, and three of them could not have worked:
/// `systemextensionsctl` output was split on whitespace so the name column was
/// discarded, `pluginkit -mAD` was parsed for a path column it does not emit, and
/// the authorization-database correlation compared full mechanism strings against
/// bundle basenames, making the two sets disjoint by construction.
final class ParserTests: XCTestCase {

    // MARK: - systemextensionsctl

    /// Real `systemextensionsctl list` output. Fields are tab-separated.
    private let systemExtensionsOutput = """
    3 extension(s)
    --- com.apple.system_extension.network_extension (Go to 'System Settings')
    enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
    *\t*\tJ6S6Q257EK\tch.protonvpn.mac.WireGuard-Extension (4.8.0/2102561)\tProtonVPN WireGuard\t[activated enabled]
    *\t*\tVBG97UB4TA\tcom.objective-see.lulu.extension (4.5.1/4.5.1)\tLuLu\t[activated enabled]
    \t\tW5364U7YZB\tio.tailscale.ipn.macsys.network-extension (1.96.2/101.96.2)\tTailscale Network Extension\t[terminated waiting to uninstall]
    """

    func testSystemExtensionNamesComeFromTheNameColumn() {
        let items = SystemExtensionScanner().parseSystemExtensionsList(systemExtensionsOutput)
        XCTAssertEqual(items.count, 3)

        // The old parser derived the name from the last dot-component of the bundle
        // identifier, so LuLu displayed as "extension".
        XCTAssertEqual(items[0].name, "ProtonVPN WireGuard")
        XCTAssertEqual(items[1].name, "LuLu")
        XCTAssertEqual(items[2].name, "Tailscale Network Extension")
        XCTAssertFalse(items.contains { $0.name == "extension" })
    }

    func testSystemExtensionMetadataIsExtracted() {
        let items = SystemExtensionScanner().parseSystemExtensionsList(systemExtensionsOutput)
        XCTAssertEqual(items[1].label, "com.objective-see.lulu.extension")
        XCTAssertEqual(items[1].source, .thirdParty("VBG97UB4TA"))
        XCTAssertEqual(items[1].rawMetadata["Version"]?.stringValue, "4.5.1/4.5.1")
        XCTAssertEqual(items[1].rawMetadata["State"]?.stringValue, "activated enabled")
    }

    func testSystemExtensionEnabledFlagReflectsTheColumn() {
        let items = SystemExtensionScanner().parseSystemExtensionsList(systemExtensionsOutput)
        XCTAssertTrue(items[0].isEnabled)
        // Third row has empty enabled/active columns.
        XCTAssertFalse(items[2].isEnabled)
    }

    func testSystemExtensionHeaderLinesAreSkipped() {
        let items = SystemExtensionScanner().parseSystemExtensionsList("""
        0 extension(s)
        --- com.apple.system_extension.network_extension
        enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
        """)
        XCTAssertTrue(items.isEmpty)
    }

    // MARK: - pluginkit

    /// Real `pluginkit -mAvvv` output: a record line, then indented attributes.
    private let pluginkitOutput = """
    +    com.apple.CloudDocsDaemon.StorageManagement(1.0)
    \t            Path = /System/Library/PrivateFrameworks/iCloudDriveCore.framework/PlugIns/CloudDocsStorageManagement.appex
    \t            UUID = 5F1EE67B-563D-54C3-B9FE-BB45F7B12FC1
    \t             SDK = com.apple.storagemanagement
    \t    Display Name = iCloud Drive
    \t        Platform = macOS
    -    com.example.Disabled.Extension((null))
    \t            Path = /Applications/Example.app/Contents/PlugIns/Disabled.appex
    \t    Display Name = Example Share
    """

    func testPluginkitExtractsPathAndDisplayName() {
        let items = AppExtensionScanner().parsePluginkitVerbose(pluginkitOutput)
        XCTAssertEqual(items.count, 2)

        XCTAssertEqual(items[0].label, "com.apple.CloudDocsDaemon.StorageManagement")
        XCTAssertEqual(items[0].name, "iCloud Drive")
        XCTAssertEqual(
            items[0].configPath,
            "/System/Library/PrivateFrameworks/iCloudDriveCore.framework/PlugIns/"
                + "CloudDocsStorageManagement.appex"
        )
        XCTAssertEqual(items[0].rawMetadata["Version"]?.stringValue, "1.0")
    }

    func testPluginkitEnabledFlagFollowsLeadingSign() {
        let items = AppExtensionScanner().parsePluginkitVerbose(pluginkitOutput)
        XCTAssertTrue(items[0].isEnabled)
        XCTAssertFalse(items[1].isEnabled, "a leading '-' marks a disabled extension")
    }

    func testPluginkitHandlesNullVersion() {
        let items = AppExtensionScanner().parsePluginkitVerbose(pluginkitOutput)
        XCTAssertEqual(items[1].label, "com.example.Disabled.Extension")
        XCTAssertNil(items[1].rawMetadata["Version"], "(null) is not a version")
    }

    func testPluginkitAppleAttributionUsesPathNotIdentifier() {
        // A bundle identifier is chosen by whoever wrote the bundle; the path is not.
        let items = AppExtensionScanner().parsePluginkitVerbose("""
        +    com.apple.TotallyLegit(1.0)
        \t            Path = /Users/alice/Library/Evil.appex
        """)
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(
            items[0].source, .unknown,
            "a com.apple.* identifier outside an Apple-owned path must not be Apple"
        )
    }

    // MARK: - authorizationdb mechanisms

    private let authorizationDB = """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>class</key>
        <string>evaluate-mechanisms</string>
        <key>mechanisms</key>
        <array>
            <string>builtin:prelogin</string>
            <string>loginwindow:login</string>
            <string>HomeDirMechanism:login,privileged</string>
            <string>MCXMechanism:login</string>
            <string>CryptoTokenKit:login</string>
            <string>EvilPlugin:login,privileged</string>
        </array>
    </dict>
    </plist>
    """

    func testAuthorizationMechanismsAreParsedFromPlist() {
        let mechanisms = AuthPluginScanner.parseMechanisms(authorizationDB)
        XCTAssertEqual(mechanisms.count, 6)
        // The old string-matching approach only admitted lines containing
        // "privileged" or "plugin", so these two were dropped entirely.
        XCTAssertTrue(mechanisms.contains("MCXMechanism:login"))
        XCTAssertTrue(mechanisms.contains("CryptoTokenKit:login"))
    }

    func testPluginNameIsTheSegmentBeforeTheColon() {
        // `HomeDirMechanism:login,privileged` must reduce to `HomeDirMechanism`,
        // which is what a bundle is actually named on disk.
        XCTAssertEqual(
            AuthPluginScanner.pluginName(from: "HomeDirMechanism:login,privileged"),
            "HomeDirMechanism"
        )
        XCTAssertEqual(
            AuthPluginScanner.pluginName(from: "MCXMechanism:login"), "MCXMechanism"
        )
    }

    func testBuiltInMechanismsAreNotLoadablePlugins() {
        XCTAssertNil(AuthPluginScanner.pluginName(from: "builtin:prelogin"))
        XCTAssertNil(AuthPluginScanner.pluginName(from: "loginwindow:login"))
    }

    func testMalformedAuthorizationDBYieldsNoMechanisms() {
        XCTAssertTrue(AuthPluginScanner.parseMechanisms("not a plist").isEmpty)
        XCTAssertTrue(AuthPluginScanner.parseMechanisms("").isEmpty)
    }

    // MARK: - System Events login items

    func testLoginItemsParsedAsOneRecordPerLine() {
        // Tab-delimited, one record per line. The previous two-parallel-lists
        // format collapsed N items into a single item named "A, B, C".
        let output = """
        Dropbox\t/Applications/Dropbox.app
        Rectangle, Pro\t/Applications/Rectangle Pro.app
        NoPathItem\t
        """
        let items = LoginItemScanner().parseSystemEventsOutput(output)
        XCTAssertEqual(items.count, 3)
        XCTAssertEqual(items[0].name, "Dropbox")
        // A comma in an application name no longer splits the record.
        XCTAssertEqual(items[1].name, "Rectangle, Pro")
        XCTAssertEqual(items[2].name, "NoPathItem")
        XCTAssertNil(items[2].configPath)
    }

    func testLoginItemsHandlesEmptyAndMissingValue() {
        XCTAssertTrue(LoginItemScanner().parseSystemEventsOutput("").isEmpty)
        XCTAssertTrue(LoginItemScanner().parseSystemEventsOutput("missing value").isEmpty)
    }

    // MARK: - profiles

    func testProfilesXMLIncludesPerUserDomains() {
        // Reading only `_computerlevel`, as the old parser did, dropped every
        // user-scoped profile.
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0">
        <dict>
            <key>_computerlevel</key>
            <array>
                <dict>
                    <key>ProfileDisplayName</key><string>Device Config</string>
                    <key>ProfileIdentifier</key><string>com.corp.device</string>
                </dict>
            </array>
            <key>alice</key>
            <array>
                <dict>
                    <key>ProfileDisplayName</key><string>User Config</string>
                    <key>ProfileIdentifier</key><string>com.corp.user</string>
                </dict>
            </array>
        </dict>
        </plist>
        """
        let items = ProfileScanner().parseProfilesXML(xml)
        XCTAssertEqual(items.count, 2)
        XCTAssertTrue(items.contains { $0.owner == .system && $0.name == "Device Config" })
        XCTAssertTrue(items.contains { $0.owner == .user("alice") && $0.name == "User Config" })
    }

    func testProfilesTextKeepsValuesContainingColons() {
        // `components(separatedBy: ":").last` truncated at the last colon, so a
        // display name like "MDM: Corp Profile" lost its first half.
        let text = """
        attribute: profileIdentifier: com.corp.profile
        attribute: profileDisplayName: MDM: Corp Profile

        """
        let items = ProfileScanner().parseProfilesText(text)
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(items.first?.name, "MDM: Corp Profile")
        XCTAssertEqual(items.first?.label, "com.corp.profile")
    }
}
