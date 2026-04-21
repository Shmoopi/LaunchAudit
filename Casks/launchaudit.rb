cask "launchaudit" do
  version "1.0.0"
  sha256 "PLACEHOLDER_SHA256"

  url "https://github.com/shmoopi/LaunchAudit/releases/download/v#{version}/LaunchAudit-v#{version}.zip",
      verified: "github.com/shmoopi/LaunchAudit/"
  name "LaunchAudit"
  desc "Comprehensive macOS persistence auditor"
  homepage "https://github.com/shmoopi/LaunchAudit"

  depends_on macos: ">= :sonoma"

  app "LaunchAudit.app"

  zap trash: [
    "~/Library/Caches/net.shmoopi.launchaudit",
    "~/Library/Preferences/net.shmoopi.launchaudit.plist",
    "~/Library/Saved Application State/net.shmoopi.launchaudit.savedState",
  ]
end
