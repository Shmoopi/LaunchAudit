import SwiftUI
import UniformTypeIdentifiers

struct ExportView: View {
    @EnvironmentObject var viewModel: ScanViewModel
    @Environment(\.dismiss) var dismiss

    var body: some View {
        VStack(spacing: 20) {
            Text("Export Scan Results")
                .font(.title2.bold())

            Picker("Format", selection: $viewModel.exportFormat) {
                Text("JSON").tag(ExportFormat.json)
                Text("CSV").tag(ExportFormat.csv)
                Text("HTML Report").tag(ExportFormat.html)
            }
            .pickerStyle(.segmented)

            Text(formatDescription)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)

                Spacer()

                Button("Export...") {
                    exportFile()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding()
        .frame(width: 400)
    }

    private var formatDescription: String {
        switch viewModel.exportFormat {
        case .json:
            return "Full scan data in JSON format. Machine-readable, suitable for SIEM ingestion or scripting."
        case .csv:
            return "Flat table with one row per item. Suitable for spreadsheets and data analysis."
        case .html:
            return "Self-contained HTML report with risk highlighting. Suitable for sharing or printing."
        }
    }

    private func exportFile() {
        guard let result = viewModel.lastResult else { return }

        let panel = NSSavePanel()
        panel.canCreateDirectories = true

        switch viewModel.exportFormat {
        case .json:
            panel.allowedContentTypes = [.json]
            panel.nameFieldStringValue = "launchaudit-\(dateString()).json"
        case .csv:
            panel.allowedContentTypes = [.commaSeparatedText]
            panel.nameFieldStringValue = "launchaudit-\(dateString()).csv"
        case .html:
            panel.allowedContentTypes = [.html]
            panel.nameFieldStringValue = "launchaudit-\(dateString()).html"
        }

        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            do {
                let data: Data
                switch viewModel.exportFormat {
                case .json:
                    data = try JSONExporter().export(result)
                case .csv:
                    data = CSVExporter().export(result).data(using: .utf8) ?? Data()
                case .html:
                    data = HTMLExporter().export(result).data(using: .utf8) ?? Data()
                }
                try data.write(to: url)
            } catch {
                print("Export error: \(error)")
            }
        }

        dismiss()
    }

    private func dateString() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd-HHmm"
        return formatter.string(from: Date())
    }
}

public enum ExportFormat: String, Sendable {
    case json, csv, html
}
