import Foundation

// Interpretation and remediation guidance.
//
// Findings previously ended at a verdict: a user saw "High risk — Unsigned binary"
// and had no way to tell whether that was dangerous or what to do next. These
// additions give every category three things a reader actually needs: what normal
// looks like, how to investigate, and the ATT&CK technique to put in a ticket.
extension PersistenceCategory {

    /// What a legitimate entry in this category usually looks like, so a reader can
    /// calibrate before reacting.
    public var whatIsNormal: String {
        switch self {
        case .launchDaemons:
            return "Apple system services plus a handful of notarized third-party "
                + "daemons from software you installed (VPNs, backup tools, drivers)."
        case .launchAgents:
            return "Per-user helpers for apps you installed — updaters, sync clients, "
                + "menu-bar tools. Normally notarized and named after their vendor."
        case .loginItems, .backgroundTaskManagement:
            return "Applications you chose to open at login. Managed in System "
                + "Settings → General → Login Items & Extensions."
        case .cronJobs:
            return "Usually empty on macOS — launchd replaced cron. A populated "
                + "crontab is worth reading line by line."
        case .periodicTasks:
            return "Apple's stock daily/weekly/monthly maintenance scripts. "
                + "Third-party additions here are unusual."
        case .loginHooks:
            return "Empty. Login hooks were deprecated years ago; anything present "
                + "was deliberately installed."
        case .startupItems:
            return "Empty. macOS no longer executes StartupItems at all."
        case .kernelExtensions:
            return "A small number of vendor kexts for VPNs, audio interfaces or "
                + "virtualization. Modern software uses System Extensions instead."
        case .systemExtensions:
            return "Network filters and endpoint security agents you installed. "
                + "Each one is listed in System Settings and shows its team ID."
        case .authorizationPlugins:
            return "Apple's login mechanisms, plus SSO or smart-card plugins in "
                + "managed environments."
        case .directoryServicesPlugins:
            return "Normally empty outside of directory-bound enterprise Macs."
        case .privilegedHelperTools:
            return "Root helpers installed by apps that need elevated operations — "
                + "updaters, disk tools, virtualization."
        case .configurationProfiles:
            return "MDM-delivered configuration in managed environments; usually "
                + "empty on a personal Mac."
        case .scriptingAdditions:
            return "Normally empty. Scripting additions load code into any app that "
                + "runs AppleScript."
        case .inputMethods:
            return "Third-party keyboards and IMEs you installed. InputManagers "
                + "should be empty — macOS no longer loads them."
        case .spotlightImporters, .quickLookGenerators:
            return "Format plugins from apps that handle specialist file types."
        case .emondRules:
            return "Empty. emond was removed in macOS 13."
        case .dylibInjection:
            return "Empty. Any DYLD_INSERT_LIBRARIES configuration is worth "
                + "understanding in full."
        case .shellProfiles:
            return "Your own PATH and prompt customizations, plus lines added by "
                + "tools like Homebrew, nvm or conda."
        case .folderActions:
            return "Usually empty unless you set up folder automation yourself."
        case .rcScripts:
            return "Empty. macOS does not ship rc.local."
        case .pamModules:
            return "Apple's stock modules. A third-party module here participates "
                + "in authentication for every login and sudo."
        case .networkScripts:
            return "Usually empty; PPP is largely obsolete."
        case .xpcServices:
            return "Helper processes embedded in the apps that own them."
        case .screenSavers, .audioPlugins, .printerPlugins, .dockTilePlugins:
            return "Plugins belonging to software you installed."
        case .reopenAtLogin:
            return "Window state macOS saved so apps reopen as you left them. "
                + "Not an execution vector on its own."
        case .appExtensions:
            return "Share sheets, widgets, Finder and Safari extensions from your "
                + "installed apps."
        case .browserExtensions:
            return "Extensions you installed. Native messaging hosts and "
                + "policy-forced extensions deserve a closer look."
        case .automatorWorkflows:
            return "Quick Actions you or your software created."
        case .widgets:
            return "Empty. Dashboard was removed in macOS 10.15."
        case .filelessProcesses:
            return "Empty. A running process whose binary is gone from disk is "
                + "abnormal and worth immediate attention."
        }
    }

    /// A concrete next step. Read-only commands only — LaunchAudit never changes
    /// system state, and neither does anything suggested here.
    public var investigationHint: String? {
        switch self {
        case .launchDaemons:
            return "Inspect with: launchctl print system/<label>"
        case .launchAgents:
            return "Inspect with: launchctl print gui/$UID/<label>"
        case .loginItems, .backgroundTaskManagement:
            return "Review in System Settings → General → Login Items & Extensions"
        case .cronJobs:
            return "Review with: crontab -l   (and cat /etc/crontab)"
        case .kernelExtensions:
            return "Check load state with: kmutil showloaded"
        case .systemExtensions:
            return "Check state with: systemextensionsctl list"
        case .configurationProfiles:
            return "List payloads with: sudo profiles list -output stdout-xml"
        case .privilegedHelperTools:
            return "Verify the signature with: codesign -dv --verbose=4 <path>"
        case .browserExtensions:
            return "Cross-check the extension ID in the browser's own extensions page"
        case .pamModules:
            return "Read the config it appears in under /etc/pam.d/"
        case .shellProfiles:
            return "Read the file and look for anything that fetches or evaluates code"
        case .dylibInjection:
            return "Identify the injected library, then: codesign -dv <dylib>"
        case .filelessProcesses:
            return "Inspect the live process with: ps -p <pid> -o command  and lsof -p <pid>"
        case .appExtensions:
            return "Inspect with: pluginkit -m -i <identifier> -vvv"
        case .authorizationPlugins:
            return "Review the rule with: security authorizationdb read system.login.console"
        case .loginHooks, .startupItems, .rcScripts, .emondRules, .widgets:
            return "This mechanism is obsolete — confirm why the entry exists at all"
        default:
            return nil
        }
    }

    /// MITRE ATT&CK technique IDs, so a finding can be reported in the vocabulary
    /// security teams already triage in.
    public var attackTechniques: [String] {
        switch self {
        case .launchDaemons: return ["T1543.004"]
        case .launchAgents: return ["T1543.001"]
        case .loginItems, .backgroundTaskManagement: return ["T1547.015"]
        case .cronJobs, .periodicTasks: return ["T1053.003"]
        case .loginHooks: return ["T1037.002"]
        case .startupItems: return ["T1037.005"]
        case .kernelExtensions, .systemExtensions: return ["T1547.006"]
        case .authorizationPlugins: return ["T1547.002"]
        case .directoryServicesPlugins: return ["T1547.011"]
        case .privilegedHelperTools: return ["T1543"]
        case .configurationProfiles: return ["T1176"]
        case .scriptingAdditions: return ["T1547.011"]
        case .inputMethods: return ["T1547.011"]
        case .spotlightImporters, .quickLookGenerators: return ["T1547.011"]
        case .emondRules: return ["T1546.014"]
        case .dylibInjection: return ["T1574.006"]
        case .shellProfiles: return ["T1546.004"]
        case .folderActions: return ["T1546.014"]
        case .rcScripts: return ["T1037.004"]
        case .pamModules: return ["T1556.003"]
        case .networkScripts: return ["T1546"]
        case .xpcServices: return ["T1543"]
        case .screenSavers: return ["T1546.016"]
        case .audioPlugins, .printerPlugins, .dockTilePlugins: return ["T1547.011"]
        case .reopenAtLogin: return ["T1547.015"]
        case .appExtensions: return ["T1547.011"]
        case .browserExtensions: return ["T1176"]
        case .automatorWorkflows: return ["T1546"]
        case .widgets: return ["T1547.011"]
        case .filelessProcesses: return ["T1055"]
        }
    }
}
