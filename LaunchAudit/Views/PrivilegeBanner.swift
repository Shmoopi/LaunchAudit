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

    /// What the helper actually is.
    ///
    /// This used to claim the helper "only runs while LaunchAudit is open — never
    /// on its own" and "isn't a persistent background process". Both were false as
    /// implemented: the daemon publishes a Mach service, so launchd starts it on
    /// demand whether or not the app is running. Consent obtained against an
    /// inaccurate description is not consent. The helper now exits after 30s idle,
    /// and the text says what it does.
    private var bodyText: String {
        switch viewModel.privilegeStatus {
        case .failed:
            return "LaunchAudit couldn't start its helper, so Background Items and "
                + "Configuration Profiles could not be scanned. Those categories are "
                + "reported as incomplete rather than empty. You can also get full "
                + "coverage without the helper by running `sudo launchaudit scan`."
        default:
            return "Background Items and Configuration Profiles can only be read with "
                + "administrator privileges. LaunchAudit installs a small helper that "
                + "runs as root, answers only those two questions for this app, and "
                + "quits 30 seconds after it is last used — macOS may start it again "
                + "on demand. Enable it in System Settings → General → Login Items & "
                + "Extensions, then scan again. Prefer not to? `sudo launchaudit scan` "
                + "covers the same ground with no background item at all."
        }
    }
}
