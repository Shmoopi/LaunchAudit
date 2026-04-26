import SwiftUI

struct LaunchAuditApp: App {
    @StateObject private var scanViewModel = ScanViewModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(scanViewModel)
                .frame(minWidth: 900, minHeight: 600)
        }
        .windowStyle(.titleBar)
        .defaultSize(width: 1200, height: 800)
        .commands {
            CommandGroup(after: .newItem) {
                Button("New Scan") {
                    Task { await scanViewModel.startScan() }
                }
                .keyboardShortcut("r", modifiers: .command)

                Divider()

                Button("Export as JSON...") {
                    scanViewModel.showExportSheet = true
                    scanViewModel.exportFormat = .json
                }
                .keyboardShortcut("e", modifiers: [.command, .shift])
                .disabled(scanViewModel.lastResult == nil)

                Button("Export as CSV...") {
                    scanViewModel.showExportSheet = true
                    scanViewModel.exportFormat = .csv
                }
                .disabled(scanViewModel.lastResult == nil)

                Button("Export as HTML Report...") {
                    scanViewModel.showExportSheet = true
                    scanViewModel.exportFormat = .html
                }
                .disabled(scanViewModel.lastResult == nil)
            }

            CommandGroup(after: .sidebar) {
                Toggle("Hide Apple-Signed Items", isOn: $scanViewModel.hideAppleSigned)
                    .keyboardShortcut("h", modifiers: [.command, .shift])
            }
        }
    }
}
