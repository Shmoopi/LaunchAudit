import SwiftUI

struct LaunchAuditApp: App {
    @StateObject private var scanViewModel = ScanViewModel()
    @Environment(\.openURL) private var openURL

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(scanViewModel)
        }
        .windowStyle(.titleBar)
        .defaultSize(width: 1200, height: 800)
        // Let the split view's own column minimums drive the window's minimum size
        // instead of pinning the content view to 900×600, which fought them.
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(after: .newItem) {
                Button("New Scan") {
                    scanViewModel.startScanTask()
                }
                .keyboardShortcut("r", modifiers: .command)
                // The toolbar and banner buttons were disabled during a scan but
                // this one was not, so ⌘R could start a second concurrent scan.
                .disabled(scanViewModel.isScanning)

                Button("Cancel Scan") {
                    scanViewModel.cancelScan()
                }
                .keyboardShortcut(".", modifiers: .command)
                .disabled(!scanViewModel.isScanning)

                Divider()

                // Set the format *before* presenting the sheet. The previous order
                // showed the sheet first, so the presentation could be evaluated
                // against the previous format.
                Button("Export as JSON…") {
                    scanViewModel.exportFormat = .json
                    scanViewModel.showExportSheet = true
                }
                .keyboardShortcut("e", modifiers: [.command, .shift])
                .disabled(scanViewModel.lastResult == nil)

                Button("Export as CSV…") {
                    scanViewModel.exportFormat = .csv
                    scanViewModel.showExportSheet = true
                }
                .disabled(scanViewModel.lastResult == nil)

                Button("Export as HTML Report…") {
                    scanViewModel.exportFormat = .html
                    scanViewModel.showExportSheet = true
                }
                .disabled(scanViewModel.lastResult == nil)
            }

            CommandGroup(after: .sidebar) {
                Toggle("Hide Apple System Items", isOn: $scanViewModel.hideAppleSigned)
                    .keyboardShortcut("h", modifiers: [.command, .shift])
                Toggle("Hide Empty Categories", isOn: $scanViewModel.hideEmptyCategories)
                Divider()
                Button("Clear All Filters") { scanViewModel.clearFilters() }
                    .disabled(!scanViewModel.hasActiveFilters)
            }

            // The app previously had no Help menu at all, and everything explaining
            // what it does, what it reads and why it wants privileges lived in a
            // one-time welcome sheet that could never be reopened.
            CommandGroup(replacing: .help) {
                Button("LaunchAudit Help") {
                    openURL(URL(string: "https://github.com/shmoopi/LaunchAudit#readme")!)
                }
                Button("Show Welcome Screen") {
                    UserDefaults.standard.set(false, forKey: "hasSeenWelcome")
                }
                Divider()
                Button("Open Login Items & Extensions Settings") {
                    scanViewModel.openLoginItemsSettings()
                }
                Button("Report an Issue") {
                    openURL(URL(string: "https://github.com/shmoopi/LaunchAudit/issues/new/choose")!)
                }
            }
        }
    }
}
