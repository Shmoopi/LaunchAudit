import SwiftUI

/// Surfaces the helper-daemon status to the user. Appears when the
/// privileged helper is not enabled — i.e. some scanners had to be skipped
/// because they need administrator access.
///
/// Pairs with `ScanViewModel.shouldShowPrivilegeBanner` for visibility logic
/// and `openLoginItemsSettings()` for the deep-link to System Settings.
struct PrivilegeBanner: View {
    @EnvironmentObject var viewModel: ScanViewModel

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "lock.shield.fill")
                .font(.title2)
                .foregroundStyle(.orange)
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 4) {
                Text(headlineText)
                    .font(.subheadline.bold())

                Text(bodyText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                if let failure = viewModel.privilegeFailureMessage {
                    Text(failure)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .padding(.top, 2)
                }

                HStack(spacing: 10) {
                    Button {
                        viewModel.openLoginItemsSettings()
                    } label: {
                        Label("Open Login Items Settings", systemImage: "arrow.up.right.square")
                    }
                    .controlSize(.small)
                    .buttonStyle(.borderedProminent)

                    Button {
                        Task { await viewModel.startScan() }
                    } label: {
                        Label("Re-Scan", systemImage: "arrow.clockwise")
                    }
                    .controlSize(.small)
                    .buttonStyle(.bordered)
                    .disabled(viewModel.isScanning)
                }
                .padding(.top, 4)
            }

            Spacer(minLength: 8)

            Button {
                viewModel.dismissPrivilegeBanner()
            } label: {
                Image(systemName: "xmark")
                    .font(.caption.bold())
                    .foregroundStyle(.secondary)
                    .padding(4)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help("Dismiss until next scan")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(Color.orange.opacity(0.10))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .strokeBorder(Color.orange.opacity(0.35), lineWidth: 1)
        )
    }

    private var headlineText: String {
        switch viewModel.privilegeStatus {
        case .failed:
            return "Privileged helper unavailable"
        default:
            return "Some scans need administrator access"
        }
    }

    private var bodyText: String {
        switch viewModel.privilegeStatus {
        case .failed:
            return "LaunchAudit couldn't start the helper daemon, so privileged scanners (Background Items, Configuration Profiles) are showing partial or empty results. The helper only runs while LaunchAudit is open — it isn't a persistent background process."
        default:
            return "Categories like Background Items and Configuration Profiles need the LaunchAudit helper. It's listed under \u{201C}Allow in the Background\u{201D} in System Settings, but only runs while LaunchAudit is open — never on its own. Enable it in System Settings \u{2192} General \u{2192} Login Items & Extensions, then re-scan."
        }
    }
}
