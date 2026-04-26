import SwiftUI

struct ContentView: View {
    @EnvironmentObject var viewModel: ScanViewModel
    @State private var selectedCategory: PersistenceCategory?
    @State private var selectedItem: PersistenceItem?
    @State private var showDashboard = true
    @State private var showInspector = false

    /// Persists across launches — the welcome sheet only appears once.
    @AppStorage("hasSeenWelcome") private var hasSeenWelcome = false
    @State private var showWelcomeSheet = false

    var body: some View {
        mainContent
            .navigationTitle("LaunchAudit")
            .sheet(isPresented: $showWelcomeSheet) {
                WelcomeView {
                    hasSeenWelcome = true
                    showWelcomeSheet = false
                    Task { await viewModel.startScan() }
                }
            }
            .onAppear {
                if !hasSeenWelcome {
                    showWelcomeSheet = true
                } else {
                    Task { await viewModel.startScan() }
                }
            }
    }

    private var mainContent: some View {
        NavigationSplitView {
            SidebarView(
                selectedCategory: $selectedCategory,
                showDashboard: $showDashboard
            )
            .navigationSplitViewColumnWidth(min: 220, ideal: 250)
        } detail: {
            VStack(spacing: 0) {
                filterBar
                Divider()

                if showDashboard {
                    DashboardView(
                        selectedCategory: $selectedCategory,
                        showDashboard: $showDashboard,
                        selectedItem: $selectedItem
                    )
                } else if let category = selectedCategory {
                    ItemListView(
                        category: category,
                        selectedItem: $selectedItem
                    )
                } else {
                    ContentUnavailableView(
                        "Select a Category",
                        systemImage: "sidebar.left",
                        description: Text("Choose a persistence category from the sidebar to view items.")
                    )
                }
            }
        }
        .inspector(isPresented: $showInspector) {
            Group {
                if let item = selectedItem {
                    ItemDetailView(item: item)
                } else {
                    ContentUnavailableView(
                        "No Selection",
                        systemImage: "doc.text.magnifyingglass",
                        description: Text("Select an item to view its details.")
                    )
                }
            }
            .inspectorColumnWidth(min: 280, ideal: 380, max: 500)
        }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    Task { await viewModel.startScan() }
                } label: {
                    Label("Scan", systemImage: "arrow.clockwise")
                }
                .disabled(viewModel.isScanning)
                .help("Run a new scan")

                Toggle(isOn: $showInspector) {
                    Label("Inspector", systemImage: "sidebar.trailing")
                }
                .toggleStyle(.button)
                .help("Toggle the detail inspector")
            }
        }
        .sheet(isPresented: $viewModel.showExportSheet) {
            ExportView()
                .environmentObject(viewModel)
        }
        .overlay {
            if viewModel.isScanning {
                ScanProgressView()
                    .environmentObject(viewModel)
            }
        }
    }

    /// Inline filter bar that sits inside the content column.
    private var filterBar: some View {
        HStack(spacing: 12) {
            Toggle(isOn: $viewModel.hideAppleSigned) {
                Label("Hide System", systemImage: "apple.logo")
            }
            .toggleStyle(.button)
            .controlSize(.small)
            .help("Hide Apple-signed and notarized items")

            Picker("Risk", selection: $viewModel.minimumRiskFilter) {
                Text("All Risks").tag(RiskLevel?.none as RiskLevel?)
                Divider()
                ForEach(RiskLevel.allCases, id: \.self) { level in
                    Label(level.displayName, systemImage: "circle.fill")
                        .foregroundStyle(level.color)
                        .tag(Optional(level))
                }
            }
            .controlSize(.small)
            .frame(maxWidth: 150)
            .help("Filter by minimum risk level")

            if viewModel.showOnlyUnsigned {
                Button {
                    viewModel.showOnlyUnsigned = false
                } label: {
                    Label("Unsigned", systemImage: "xmark.circle.fill")
                }
                .controlSize(.small)
                .buttonStyle(.bordered)
                .tint(.purple)
            }

            if viewModel.showOnlyThirdParty {
                Button {
                    viewModel.showOnlyThirdParty = false
                } label: {
                    Label("Third-Party", systemImage: "xmark.circle.fill")
                }
                .controlSize(.small)
                .buttonStyle(.bordered)
                .tint(.teal)
            }

            Spacer()

            TextField("Search", text: $viewModel.searchText)
                .textFieldStyle(.roundedBorder)
                .controlSize(.small)
                .frame(maxWidth: 220)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.bar)
    }
}
