import XCTest
@testable import LaunchAudit

/// Tests for the three exporters, which previously had no coverage at all.
///
/// The output of this tool is opened in spreadsheets and browsers by people
/// investigating a possible compromise, and every string in it — item names, paths,
/// arguments, risk reasons — originates in a file an attacker may control. These
/// tests pin the escaping that makes that safe.
final class ExporterTests: XCTestCase {

    private func result(items: [PersistenceItem], errors: [ScanError] = []) -> ScanResult {
        ScanResult(
            hostname: "test-host",
            osVersion: "macOS 99.0",
            items: items,
            errors: errors,
            scanDuration: 1.25,
            ranAsRoot: false
        )
    }

    private func item(
        name: String,
        path: String? = "/Library/LaunchDaemons/x.plist",
        reasons: [String] = []
    ) -> PersistenceItem {
        PersistenceItem(
            category: .launchDaemons,
            name: name,
            label: name,
            configPath: path,
            executablePath: "/usr/local/bin/x",
            riskLevel: .high,
            riskReasons: reasons
        )
    }

    // MARK: - CSV formula injection

    func testCSVNeutralizesFormulaTriggers() {
        // An attacker fully controls `item.name` — it is the launchd `Label`. A
        // payload beginning `=` or `@` contains no comma, quote or newline, so the
        // old escaper emitted it unquoted and Excel evaluated it on open.
        let exporter = CSVExporter()
        for payload in ["=1+1", "+1+1", "-1+1", "@SUM(1+1)", "\tTAB", "\rCR",
                        "=HYPERLINK(\"http://evil\",\"Click\")",
                        "=cmd|' /C calc'!A0"] {
            // Assert on the escaper directly: the field-level contract is that the
            // emitted cell never *starts* with a formula trigger.
            let cell = exporter.escapeCSV(payload)
            let unquoted = cell.hasPrefix("\"") ? String(cell.dropFirst()) : cell
            XCTAssertTrue(
                unquoted.hasPrefix("'"),
                "formula trigger emitted unguarded: \(payload) -> \(cell)"
            )

            // And end to end, the raw payload never appears immediately after a
            // delimiter in the rendered file.
            let csv = exporter.export(result(items: [item(name: payload)]))
            XCTAssertFalse(
                csv.contains(",\(payload)"),
                "formula trigger reached the file unguarded: \(payload)"
            )
        }
    }

    func testCSVStillQuotesStructuralCharacters() {
        let csv = CSVExporter().export(result(items: [item(name: "a,b")]))
        XCTAssertTrue(csv.contains("\"a,b\""))

        let quoted = CSVExporter().export(result(items: [item(name: "say \"hi\"")]))
        XCTAssertTrue(quoted.contains("\"say \"\"hi\"\"\""))
    }

    func testCSVQuotesBareCarriageReturn() {
        // A lone \r would otherwise split the row for strict readers.
        XCTAssertEqual(CSVExporter().escapeCSV("a\rb"), "\"a\rb\"")
    }

    func testCSVHeaderAndRowArityMatch() {
        let csv = CSVExporter().export(result(items: [item(name: "one")]))
        let lines = csv.components(separatedBy: "\n").filter { !$0.isEmpty }
        XCTAssertGreaterThanOrEqual(lines.count, 2)
        // Count only unquoted commas so embedded ones do not skew the count.
        func columns(_ line: String) -> Int {
            var count = 1
            var inQuotes = false
            for character in line {
                if character == "\"" { inQuotes.toggle() }
                if character == ",", !inQuotes { count += 1 }
            }
            return count
        }
        XCTAssertEqual(columns(lines[0]), columns(lines[1]),
                       "header and data row must have the same column count")
    }

    // MARK: - HTML escaping

    func testHTMLEscapesItemFields() {
        let payload = "<script>alert(1)</script>"
        let html = HTMLExporter().export(result(items: [
            item(name: payload, path: "/tmp/\(payload)", reasons: [payload]),
        ]))
        XCTAssertFalse(html.contains("<script>alert(1)</script>"))
        XCTAssertTrue(html.contains("&lt;script&gt;"))
    }

    func testHTMLEscapesHostnameAndOSVersion() {
        // These two were interpolated raw while every item field was escaped. They
        // are reachable with attacker-controlled content through
        // `launchaudit export tampered.json --format html`.
        let hostile = ScanResult(
            hostname: "<script>alert('host')</script>",
            osVersion: "<img src=x onerror=alert(1)>",
            items: [],
            errors: [],
            scanDuration: 0
        )
        let html = HTMLExporter().export(hostile)
        XCTAssertFalse(html.contains("<script>alert('host')</script>"))
        XCTAssertFalse(html.contains("<img src=x onerror=alert(1)>"))
        XCTAssertTrue(html.contains("&lt;script&gt;"))
    }

    func testHTMLEscapesQuotesAndAmpersands() {
        let html = HTMLExporter().export(result(items: [item(name: "a & b \"c\" 'd'")]))
        XCTAssertTrue(html.contains("&amp;"))
        XCTAssertTrue(html.contains("&quot;") || html.contains("&#39;"))
    }

    func testHTMLIncludesProvenanceAndCoverage() {
        // A reader who did not run the scan needs to know what it covered.
        let html = HTMLExporter().export(result(
            items: [item(name: "x")],
            errors: [ScanError(
                category: .backgroundTaskManagement,
                message: "requires root",
                isPermissionDenied: true
            )]
        ))
        XCTAssertTrue(html.contains("test-host"))
        XCTAssertTrue(html.lowercased().contains("coverage"))
        XCTAssertTrue(html.contains("requires root"),
                      "permission errors must appear in the report, not just the terminal")
    }

    func testHTMLCategoryTablesAreOpenForPrinting() {
        let html = HTMLExporter().export(result(items: [item(name: "x")]))
        // Collapsed <details> printed as a PDF loses the whole body.
        XCTAssertFalse(html.contains("<details>"),
                       "category sections must be open so print-to-PDF keeps them")
    }

    /// The filter script is the only script, admitted by a per-report nonce.
    func testHTMLAllowsOnlyItsOwnNoncedScript() throws {
        let html = HTMLExporter().export(result(items: [item(name: "x")]))
        let csp = try XCTUnwrap(html.range(of: #"script-src 'nonce-([0-9A-F]+)'"#,
                                           options: .regularExpression))
        let nonce = html[csp].dropFirst("script-src 'nonce-".count).dropLast()
        XCTAssertEqual(html.components(separatedBy: "<script").count - 1, 1,
                       "exactly one script element")
        XCTAssertTrue(html.contains("<script nonce=\"\(nonce)\">"))
        XCTAssertTrue(html.contains("default-src 'none'"))

        let other = HTMLExporter().export(result(items: [item(name: "x")]))
        XCTAssertFalse(other.contains(String(nonce)), "nonce must differ per report")
    }

    /// Filter attributes carry item text too, and must be escaped like the cells.
    func testHTMLEscapesFilterAttributes() {
        let payload = "\"><img src=x onerror=alert(1)>"
        let html = HTMLExporter().export(result(items: [
            item(name: payload, path: "/tmp/\(payload)", reasons: [payload]),
        ]))
        XCTAssertFalse(html.contains("<img src=x"))
        XCTAssertTrue(html.contains("data-search=\"&quot;&gt;&lt;img"))
    }

    // MARK: - JSON

    func testJSONRoundTripsThroughTheExportPath() throws {
        // `launchaudit export scan.json` decodes this back, so the Codable contract
        // is load-bearing.
        let original = result(items: [
            item(name: "com.example.daemon", reasons: ["Unsigned binary"]),
        ])
        let data = try JSONExporter().export(original)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(ScanResult.self, from: data)

        XCTAssertEqual(decoded.items.count, 1)
        XCTAssertEqual(decoded.items[0].name, "com.example.daemon")
        XCTAssertEqual(decoded.items[0].riskLevel, .high)
        XCTAssertEqual(decoded.hostname, "test-host")
        XCTAssertEqual(decoded.schemaVersion, ScanResult.currentSchemaVersion)
    }

    func testJSONCarriesStableIdentityForDiffing() throws {
        let data = try JSONExporter().export(result(items: [item(name: "x")]))
        let json = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        let items = try XCTUnwrap(json["items"] as? [[String: Any]])
        // `id` is a fresh UUID per scan; `stableID` is what lets two scans be
        // compared at all.
        XCTAssertNotNil(items.first?["stableID"])
    }

    func testStableIDIsStableAcrossRunsAndDistinctPerItem() {
        let a = item(name: "com.example.one")
        let b = item(name: "com.example.one")
        let c = item(name: "com.example.two")

        XCTAssertEqual(a.stableID, b.stableID, "same identity must hash the same")
        XCTAssertNotEqual(a.stableID, c.stableID)
        XCTAssertNotEqual(a.id, b.id, "the per-scan UUID still differs")
    }

    func testStableIDIgnoresVolatileState() {
        var a = item(name: "com.example.one")
        var b = item(name: "com.example.one")
        a.riskLevel = .critical
        b.riskLevel = .informational
        a.signingInfo = SigningInfo(isSigned: true)
        // Risk and signing are what a diff should report as *changed*, not what
        // makes it a different item.
        XCTAssertEqual(a.stableID, b.stableID)
    }

    // MARK: - Schema compatibility

    func testDecodesReportFromAnEarlierSchema() throws {
        // A v1 report: no schemaVersion, no toolVersion, no riskMitigations,
        // no entitlements. It must still load through `launchaudit export`.
        let legacy = """
        {
          "scanDate": "2026-04-18T13:18:00Z",
          "hostname": "old-host",
          "osVersion": "macOS 14.0",
          "scanDuration": 2.0,
          "errors": [],
          "items": [
            {
              "id": "6C4C1E3E-0000-4000-8000-000000000001",
              "category": "launchDaemons",
              "name": "legacy.item",
              "arguments": [],
              "isEnabled": true,
              "runContext": "boot",
              "owner": { "system": {} },
              "riskLevel": "high",
              "riskReasons": ["Unsigned binary"],
              "source": { "unknown": {} },
              "timestamps": {},
              "rawMetadata": {}
            }
          ]
        }
        """
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(ScanResult.self, from: Data(legacy.utf8))

        XCTAssertEqual(decoded.schemaVersion, 1)
        XCTAssertEqual(decoded.toolVersion, "unknown")
        XCTAssertEqual(decoded.items.count, 1)
        XCTAssertEqual(decoded.items[0].riskMitigations, [])
        XCTAssertFalse(decoded.ranAsRoot)
    }
}
