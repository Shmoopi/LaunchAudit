import SwiftUI

struct ContentView: View {
    @EnvironmentObject var viewModel: ScanViewModel
    @State private var selection: SidebarSelection? = .dashboard
    @State private var selectedItem: PersistenceItem?
    @State private var showInspector = false

    /// Persists across launches — the welcome sheet only appears once.
    @AppStorage("hasSeenWelcome") private var hasSeenWelcome = false
    @State private var showWelcomeSheet = false

    var body: some View {
        mainContent
            .navigationTitle("LaunchAudit")
            .navigationSubtitle(subtitle)
            .sheet(isPresented: $showWelcomeSheet) {
                WelcomeView(
                    onBeginScan: {
                        hasSeenWelcome = true
                        showWelcomeSheet = false
                        viewModel.startScanTask()
                    },
                    onDismiss: {
                        // Declining is not a dead end: the window opens, empty, and
                        // the user can scan whenever they are ready.
                        hasSeenWelcome = true
                        showWelcomeSheet = false
                    }
                )
            }
            .onAppear {
                // Only the first launch is automatic. Scanning on every window
                // appearance meant the app shelled out to `ps`, `osascript` and
                // `profiles` — and registered a root daemon — before the user had
                // asked for anything.
                if !hasSeenWelcome { showWelcomeSheet = true }
            }
    }

    /// Plain text only: `navigationSubtitle` does not render Markdown, so the
    /// previous `^[N item](inflect: true)` appeared literally in the title bar.
    /// The item count is already on the sidebar badge and the dashboard, so the
    /// subtitle just says when the results are from.
    private var subtitle: String {
        if viewModel.isScanning { return "Scanning…" }
        guard let result = viewModel.lastResult else { return "" }
        let time = result.scanDate.formatted(date: .abbreviated, time: .shortened)
        return "Last scanned \(time)"
    }

    private var mainContent: some View {
        NavigationSplitView {
            SidebarView(selection: $selection)
                .navigationSplitViewColumnWidth(min: 220, ideal: 250)
        } detail: {
            // The inspector is our own trailing panel inside the detail column,
            // not SwiftUI's `.inspector`. On this macOS the system inspector adds
            // its width to the window's minimum size even while hidden, and while
            // shown that minimum follows its live width as it animates or is
            // dragged. With `.windowResizability(.contentMinSize)` the window
            // resized itself on ordinary clicks, grew past the screen edge, and
            // during a zoom renegotiated sizes until AppKit aborted with "more
            // Update Constraints in Window passes than there are views in the
            // window". This panel shares the column's space and never resizes
            // the window.
            TrailingInspector(isPresented: showInspector) {
                detailContent
                    .safeAreaInset(edge: .top, spacing: 0) {
                        VStack(spacing: 0) {
                            if viewModel.isScanning {
                                ScanProgressBar(progress: viewModel.scanProgress)
                                Divider()
                            }
                            // There is nothing to filter before the first scan;
                            // the bar used to sit over the "No Scan Yet" placeholder.
                            if viewModel.lastResult != nil, viewModel.hasActiveFilters {
                                activeFilterBar
                                Divider()
                            }
                        }
                    }
            } panel: {
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
            // A fixed minimum, independent of the content. Several detail views
            // contain wrapping text whose height depends on the width it is
            // given; left to report its own minimum, the column's minimum height
            // changed with every width step of a window zoom or resize, which
            // re-triggered split-view layout without end.
            .frame(minWidth: 420, maxWidth: .infinity, minHeight: 300, maxHeight: .infinity)
        }
        .toolbar { toolbarContent }
        .sheet(isPresented: $viewModel.showExportSheet) {
            ExportView().environmentObject(viewModel)
        }
        .onChange(of: selectedItem?.id) { _, newValue in
            // Selecting a row with the inspector closed used to produce no visible
            // change at all.
            if newValue != nil && !showInspector { showInspector = true }
        }
        .onChange(of: viewModel.searchText) { _, query in
            // Typing a global query should show global results.
            if !query.isEmpty, selection == .dashboard { selection = .allItems }
        }
    }

    @ViewBuilder
    private var detailContent: some View {
        switch selection {
        case .dashboard, nil:
            DashboardView(selection: $selection, selectedItem: $selectedItem)
        case .allItems:
            ItemListView(scope: .everything, selectedItem: $selectedItem)
        case .category(let category):
            ItemListView(scope: .category(category), selectedItem: $selectedItem)
        }
    }

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            // One button whose label swaps between Scan and Stop, so the toolbar
            // never changes shape mid-scan. The progress itself is drawn below the
            // toolbar by `ScanProgressBar`; a 120pt linear bar crammed into this
            // item overflowed its toolbar capsule.
            if viewModel.isScanning {
                Button {
                    viewModel.cancelScan()
                } label: {
                    Label("Stop Scan", systemImage: "stop.circle")
                }
                .help("Stop the scan and keep what has been found so far")
            } else {
                Button {
                    viewModel.startScanTask()
                } label: {
                    Label("Scan", systemImage: "arrow.clockwise")
                }
                .help("Run a new scan")
            }

            Menu {
                Toggle("Hide Apple System Items", isOn: $viewModel.hideAppleSigned)
                Toggle("Hide Empty Categories", isOn: $viewModel.hideEmptyCategories)
                Divider()
                Toggle("Unsigned Only", isOn: $viewModel.showOnlyUnsigned)
                Toggle("Third-Party Only", isOn: $viewModel.showOnlyThirdParty)
                Divider()
                Picker("Minimum Risk", selection: $viewModel.minimumRiskFilter) {
                    Text("Any Risk").tag(RiskLevel?.none)
                    ForEach(RiskLevel.allCases.reversed(), id: \.self) { level in
                        // "Low" on its own reads as "only Low"; the filter is a floor.
                        Text("\(level.displayName) and above").tag(Optional(level))
                    }
                }
                .pickerStyle(.inline)
            } label: {
                Label("Filter", systemImage: viewModel.hasActiveFilters
                      ? "line.3.horizontal.decrease.circle.fill"
                      : "line.3.horizontal.decrease.circle")
            }
            .help("Filter which items are shown")
        }

        // Search is global — it used to look only inside the selected category,
        // so you had to already know where an item lived in order to find it.
        //
        // An ordinary toolbar item rather than `.searchable`, so the inspector
        // toggle can sit to its right, at the trailing edge beside the panel it
        // opens. SwiftUI always appends the `.searchable` field after every other
        // item, and `DefaultToolbarItem(kind: .search)` does not move it in a Mac
        // window toolbar.
        ToolbarItem(placement: .primaryAction) {
            ToolbarSearchField(text: $viewModel.searchText,
                               prompt: "Name, path, label, or developer")
                .frame(minWidth: 160, idealWidth: 240, maxWidth: 280)
        }

        ToolbarItem(placement: .primaryAction) {
            Toggle(isOn: $showInspector) {
                Label("Inspector", systemImage: "sidebar.trailing")
            }
            .toggleStyle(.button)
            .help("Toggle the detail inspector")
        }
    }

    /// Shown only when a filter is active, so the numbers on screen can always be
    /// explained. Previously the dashboard silently reflected filters with no
    /// indication of why its counts had changed.
    private var activeFilterBar: some View {
        HStack(spacing: 8) {
            Image(systemName: "line.3.horizontal.decrease.circle.fill")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)

            Text(viewModel.activeFilterDescriptions.joined(separator: " · "))
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(1)

            Spacer(minLength: 0)

            Button("Clear Filters") { viewModel.clearFilters() }
                .controlSize(.small)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(.bar)
        .accessibilityElement(children: .combine)
    }
}

/// Full-width scan progress, pinned under the toolbar while a scan runs.
///
/// Observes `ScanProgressModel` directly so its updates redraw only this strip,
/// not the window around it.
struct ScanProgressBar: View {
    @ObservedObject var progress: ScanProgressModel

    var body: some View {
        HStack(spacing: 10) {
            Text(progress.statusText)
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.tail)
                .frame(maxWidth: .infinity, alignment: .leading)

            ProgressView(value: progress.fractionComplete)
                .progressViewStyle(.linear)
                .controlSize(.small)
                .frame(width: 140)

            Text(progress.fractionComplete, format: .percent.precision(.fractionLength(0)))
                .font(.callout)
                .monospacedDigit()
                .foregroundStyle(.secondary)
                .frame(width: 40, alignment: .trailing)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(.bar)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(progress.statusText)
        .accessibilityValue(Text(progress.fractionComplete, format: .percent))
    }
}

/// A resizable panel on the trailing edge of the detail column.
///
/// Laid out inside a `GeometryReader`, so neither the content nor the panel can
/// push a minimum size up to the window: the panel's width is clamped to the
/// space the column already has.
struct TrailingInspector<Content: View, Panel: View>: View {
    let isPresented: Bool
    @ViewBuilder let content: Content
    @ViewBuilder let panel: Panel

    @AppStorage("inspectorWidth") private var storedWidth: Double = 380
    @State private var dragStartWidth: Double?
    @State private var cursorPushed = false

    private let panelRange: ClosedRange<Double> = 300...560
    /// Space always left for the main content when the panel is open.
    private let minimumContentWidth: Double = 240

    var body: some View {
        GeometryReader { geometry in
            let available = geometry.size.width
            HStack(spacing: 0) {
                content
                    .frame(maxWidth: .infinity, maxHeight: .infinity)

                if isPresented {
                    resizeHandle(available: available)
                    panel
                        .frame(width: panelWidth(storedWidth, available: available))
                        .frame(maxHeight: .infinity)
                        .background(.background)
                        .transition(.move(edge: .trailing))
                        .accessibilityElement(children: .contain)
                        .accessibilityLabel("Inspector")
                }
            }
            .animation(.easeInOut(duration: 0.2), value: isPresented)
        }
        .onDisappear(perform: popCursor)
    }

    private func panelWidth(_ proposed: Double, available: Double) -> Double {
        let upper = min(panelRange.upperBound, available - minimumContentWidth)
        let lower = min(panelRange.lowerBound, upper)
        return max(0, min(max(proposed, lower), upper))
    }

    /// The divider doubles as the drag handle; the hit area is wider than the line.
    private func resizeHandle(available: Double) -> some View {
        Divider()
            .overlay {
                Color.clear
                    .frame(width: 8)
                    .contentShape(Rectangle())
                    .onHover { inside in
                        if inside, !cursorPushed {
                            NSCursor.resizeLeftRight.push()
                            cursorPushed = true
                        } else if !inside, dragStartWidth == nil {
                            popCursor()
                        }
                    }
                    .gesture(
                        DragGesture(minimumDistance: 1, coordinateSpace: .global)
                            .onChanged { value in
                                let start = dragStartWidth ?? panelWidth(storedWidth, available: available)
                                dragStartWidth = start
                                storedWidth = panelWidth(start - value.translation.width, available: available)
                            }
                            .onEnded { _ in
                                dragStartWidth = nil
                                popCursor()
                            }
                    )
            }
            .accessibilityHidden(true)
    }

    private func popCursor() {
        if cursorPushed {
            NSCursor.pop()
            cursorPushed = false
        }
    }
}

/// The native `NSSearchField` as a toolbar item: system look, clear button, and
/// Escape to clear. ⌘F focuses it, as it did when it came from `.searchable`.
struct ToolbarSearchField: NSViewRepresentable {
    @Binding var text: String
    let prompt: String

    func makeNSView(context: Context) -> NSSearchField {
        let field = NSSearchField()
        field.placeholderString = prompt
        field.setAccessibilityLabel("Search items")
        field.delegate = context.coordinator
        // The clear button sends the action without a text-change notification.
        field.target = context.coordinator
        field.action = #selector(Coordinator.searchFieldChanged(_:))
        context.coordinator.field = field
        context.coordinator.installFindShortcut()
        return field
    }

    func updateNSView(_ field: NSSearchField, context: Context) {
        context.coordinator.text = $text
        // Keep in step with changes made elsewhere, such as Clear Filters.
        if field.stringValue != text { field.stringValue = text }
    }

    static func dismantleNSView(_ field: NSSearchField, coordinator: Coordinator) {
        coordinator.removeFindShortcut()
    }

    func makeCoordinator() -> Coordinator { Coordinator(text: $text) }

    @MainActor
    final class Coordinator: NSObject, NSSearchFieldDelegate {
        var text: Binding<String>
        weak var field: NSSearchField?
        private var monitor: Any?

        init(text: Binding<String>) { self.text = text }

        func controlTextDidChange(_ notification: Notification) {
            if let field { text.wrappedValue = field.stringValue }
        }

        @objc func searchFieldChanged(_ sender: NSSearchField) {
            text.wrappedValue = sender.stringValue
        }

        /// ⌘F in this field's window moves focus to it. A local monitor sees the
        /// key before menu key equivalents, so it does not depend on what the Edit
        /// menu's Find item is wired to.
        func installFindShortcut() {
            monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
                guard event.modifierFlags.intersection(.deviceIndependentFlagsMask) == .command,
                      event.charactersIgnoringModifiers == "f"
                else { return event }
                let windowNumber = event.windowNumber
                let handled = MainActor.assumeIsolated { () -> Bool in
                    guard let field = self?.field, let window = field.window,
                          window.windowNumber == windowNumber
                    else { return false }
                    return window.makeFirstResponder(field)
                }
                return handled ? nil : event
            }
        }

        func removeFindShortcut() {
            if let monitor { NSEvent.removeMonitor(monitor) }
            monitor = nil
        }
    }
}
