import SwiftUI
import UniformTypeIdentifiers

struct ExportView: View {
    @EnvironmentObject var viewModel: ScanViewModel
    @Environment(\.dismiss) var dismiss

    @State private var includeFilteredOnly = false
    @State private var isExporting = false
    @State private var savedURL: URL?
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Export Scan Results")
                .font(.title2.bold())

            Picker("Format", selection: $viewModel.exportFormat) {
                Text("JSON").tag(ExportFormat.json)
                Text("CSV").tag(ExportFormat.csv)
                Text("HTML Report").tag(ExportFormat.html)
            }
            .pickerStyle(.segmented)

            Text(formatDescription)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)

            // The GUI used to export `lastResult` — the *unfiltered* set — while the
            // window showed a filtered view, so the operator sent a file containing
            // items they had never seen. Now the choice is explicit, and either way
            // the report records which filters produced it.
            Toggle(isOn: $includeFilteredOnly) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Export only what is currently shown")
                    Text(scopeDescription)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .toggleStyle(.checkbox)
            .disabled(!viewModel.hasActiveFilters)

            if let savedURL {
                Label("Saved to \(savedURL.lastPathComponent)", systemImage: "checkmark.circle.fill")
                    .font(.callout)
                    .foregroundStyle(.green)
            }
            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)

                Spacer()

                if let savedURL {
                    Button("Reveal in Finder") {
                        NSWorkspace.shared.activateFileViewerSelecting([savedURL])
                    }
                }

                Button("Export…") { isExporting = true }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(viewModel.lastResult == nil)
            }
        }
        .padding()
        .frame(width: 440)
        // `fileExporter` handles sheet attachment, the save panel, the error path
        // and dismissal ordering. The previous `NSSavePanel.begin { }` opened a
        // detached panel and then dismissed this sheet immediately, so the window
        // vanished while the panel was still up — and a write failure was reported
        // only as `print("Export error: …")` to the console.
        .fileExporter(
            isPresented: $isExporting,
            document: exportDocument,
            contentType: contentType,
            defaultFilename: defaultFilename
        ) { result in
            switch result {
            case .success(let url):
                savedURL = url
                errorMessage = nil
            case .failure(let error):
                errorMessage = "Could not save the report: \(error.localizedDescription)"
                savedURL = nil
            }
        }
    }

    // MARK: - Content

    private var exportedResult: ScanResult? {
        guard let result = viewModel.lastResult else { return nil }
        guard includeFilteredOnly, viewModel.hasActiveFilters else { return result }
        return result.filtered(
            items: viewModel.filteredItems,
            describedBy: viewModel.activeFilterDescriptions
        )
    }

    private var exportDocument: ExportDocument? {
        guard let result = exportedResult else { return nil }
        return ExportDocument(result: result, format: viewModel.exportFormat)
    }

    private var scopeDescription: String {
        guard viewModel.hasActiveFilters else {
            return "No filters are active — the full scan will be exported."
        }
        let shown = viewModel.filteredItems.count
        let total = viewModel.lastResult?.items.count ?? 0
        return includeFilteredOnly
            ? "\(shown) of \(total) items"
            : "All \(total) items, including those hidden by the current filters"
    }

    private var contentType: UTType {
        switch viewModel.exportFormat {
        case .json: return .json
        case .csv: return .commaSeparatedText
        case .html: return .html
        }
    }

    private var defaultFilename: String {
        let host = viewModel.lastResult?.hostname ?? "scan"
        let safeHost = host.replacingOccurrences(of: "/", with: "-")
        return "launchaudit-\(safeHost)-\(dateString())"
    }

    private var formatDescription: String {
        switch viewModel.exportFormat {
        case .json:
            return "Full scan data in JSON, including a schema version and a stable "
                + "identifier per item so two scans can be compared."
        case .csv:
            return "One row per item, with risk findings and signing state. "
                + "Opens in Numbers or Excel."
        case .html:
            return "A self-contained report with a coverage summary, findings and a "
                + "risk legend — readable by someone who did not run the scan."
        }
    }

    private func dateString() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd-HHmm"
        return formatter.string(from: Date())
    }
}

/// Wraps a rendered report for `fileExporter`.
struct ExportDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.json, .commaSeparatedText, .html] }

    let data: Data

    init(result: ScanResult, format: ExportFormat) {
        switch format {
        case .json:
            data = (try? JSONExporter().export(result)) ?? Data()
        case .csv:
            data = Data(CSVExporter().export(result).utf8)
        case .html:
            data = Data(HTMLExporter().export(result).utf8)
        }
    }

    init(configuration: ReadConfiguration) throws {
        data = configuration.file.regularFileContents ?? Data()
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

public enum ExportFormat: String, Sendable {
    case json, csv, html
}
