# This file is generated on release.
#
# `update-cask.yml` rewrites `version` and `sha256` when a release is published,
# and fails the job if either placeholder survives. Until the first release is
# actually *published* (both existing releases are drafts, which is why this cask
# was stuck at 1.0.0 with a placeholder hash and every `brew install --cask`
# failed), the checksum below is intentionally invalid: a loud failure is the
# correct behavior for a security tool, and far better than `sha256 :no_check`,
# which would install an unverified archive.
cask "launchaudit" do
  version "1.2.0"
  sha256 "PLACEHOLDER_SHA256"

  url "https://github.com/shmoopi/LaunchAudit/releases/download/v#{version}/LaunchAudit-v#{version}.zip",
      verified: "github.com/shmoopi/LaunchAudit/"
  name "LaunchAudit"
  desc "Comprehensive macOS persistence auditor"
  homepage "https://github.com/shmoopi/LaunchAudit"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on macos: ">= :sonoma"

  app "LaunchAudit.app"

  # The same universal binary is the CLI. Without this stanza `brew install`
  # gave users no `launchaudit` command at all, and the README had to tell
  # people to hand-create a symlink into /usr/local/bin — which also fails on a
  # clean Apple Silicon Mac where that directory is root-owned or absent.
  binary "#{appdir}/LaunchAudit.app/Contents/MacOS/LaunchAudit", target: "launchaudit"

  uninstall launchctl: "net.shmoopi.launchaudit.helper",
            quit:      "net.shmoopi.launchaudit"

  zap trash: [
    "~/Library/Caches/net.shmoopi.launchaudit",
    "~/Library/Preferences/net.shmoopi.launchaudit.plist",
    "~/Library/Saved Application State/net.shmoopi.launchaudit.savedState",
  ]

  caveats <<~EOS
    LaunchAudit installs a privileged helper the first time you scan, so it can
    read Background Task Management and configuration profiles. Approve it in
    System Settings → General → Login Items & Extensions.

    Prefer not to install a background item? `sudo launchaudit scan` covers the
    same ground with no helper at all.
  EOS
end
