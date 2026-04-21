import SwiftUI

struct WelcomeView: View {
    var onBeginAudit: () -> Void

    var body: some View {
        ScrollView(.vertical, showsIndicators: true) {
            VStack(spacing: 20) {
                // App icon and title
                VStack(spacing: 8) {
                    Image(nsImage: NSApp.applicationIconImage)
                        .resizable()
                        .scaledToFit()
                        .frame(width: 64, height: 64)

                    Text("Welcome to LaunchAudit")
                        .font(.title2.bold())

                    Text("Comprehensive macOS persistence auditor")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .padding(.top, 8)

                // What it does
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("What LaunchAudit Does", systemImage: "magnifyingglass")
                            .font(.subheadline.bold())

                        Text("Scans your Mac for every known persistence mechanism \u{2014} software registered to run automatically at boot, login, on a schedule, or in response to system events.")
                            .font(.caption)
                            .fixedSize(horizontal: false, vertical: true)

                        VStack(alignment: .leading, spacing: 6) {
                            FeatureRow(
                                icon: "checklist",
                                title: "35 Persistence Categories",
                                detail: "Launch daemons, login items, cron jobs, kernel extensions, browser extensions, and more"
                            )
                            FeatureRow(
                                icon: "checkmark.seal",
                                title: "Code Signature Verification",
                                detail: "Validates signing status, notarization, and developer identity"
                            )
                            FeatureRow(
                                icon: "exclamationmark.shield",
                                title: "Risk Analysis",
                                detail: "Scores each item from Informational to Critical"
                            )
                            FeatureRow(
                                icon: "square.and.arrow.up",
                                title: "Exportable Reports",
                                detail: "Export as JSON, CSV, or self-contained HTML"
                            )
                        }
                    }
                    .padding(2)
                }

                // Why permissions are needed
                GroupBox {
                    VStack(alignment: .leading, spacing: 10) {
                        Label("Administrator Access", systemImage: "lock.shield")
                            .font(.subheadline.bold())

                        Text("Many system locations require elevated privileges. LaunchAudit never modifies files \u{2014} it only reads system state.")
                            .font(.caption)
                            .fixedSize(horizontal: false, vertical: true)

                        VStack(alignment: .leading, spacing: 4) {
                            PermissionRow(title: "System Launch Daemons & Agents")
                            PermissionRow(title: "Privileged Helper Tools")
                            PermissionRow(title: "Security & Auth Plugins")
                            PermissionRow(title: "Kernel & System Extensions")
                            PermissionRow(title: "Background Task Management DB")
                            PermissionRow(title: "Configuration Profiles")
                        }

                        Text("You can decline \u{2014} the scan will still cover items readable by your user account.")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                    .padding(2)
                }

                // Begin button
                Button(action: onBeginAudit) {
                    Label("Begin Audit", systemImage: "play.fill")
                        .font(.headline)
                        .frame(maxWidth: 220)
                        .padding(.vertical, 4)
                }
                .controlSize(.large)
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)

                Text("You may be prompted for your password.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .padding(.bottom, 8)
            }
            .padding(.horizontal, 24)
        }
        .scrollBounceBehavior(.basedOnSize)
        .frame(width: 420, height: 520)
    }
}

// MARK: - Subviews

private struct FeatureRow: View {
    let icon: String
    let title: String
    let detail: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .foregroundStyle(.blue)
                .frame(width: 16)
                .font(.caption)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.caption.bold())
                Text(detail)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct PermissionRow: View {
    let title: String

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .font(.caption2)
            Text(title)
                .font(.caption)
        }
    }
}
