import Foundation

/// Every known macOS persistence mechanism category.
public enum PersistenceCategory: String, Codable, CaseIterable, Identifiable, Hashable, Sendable {
    case launchDaemons
    case launchAgents
    case loginItems
    case backgroundTaskManagement
    case cronJobs
    case periodicTasks
    case loginHooks
    case startupItems
    case kernelExtensions
    case systemExtensions
    case authorizationPlugins
    case directoryServicesPlugins
    case privilegedHelperTools
    case configurationProfiles
    case scriptingAdditions
    case inputMethods
    case spotlightImporters
    case quickLookGenerators
    case emondRules
    case dylibInjection
    case shellProfiles
    case folderActions
    case rcScripts
    case pamModules
    case networkScripts
    case xpcServices
    case screenSavers
    case audioPlugins
    case printerPlugins
    case reopenAtLogin
    case appExtensions
    case browserExtensions
    case automatorWorkflows
    case widgets
    case dockTilePlugins
    case filelessProcesses

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .launchDaemons: return "Launch Daemons"
        case .launchAgents: return "Launch Agents"
        case .loginItems: return "Login Items"
        case .backgroundTaskManagement: return "Background Task Management"
        case .cronJobs: return "Cron Jobs"
        case .periodicTasks: return "Periodic Tasks"
        case .loginHooks: return "Login/Logout Hooks"
        case .startupItems: return "Startup Items"
        case .kernelExtensions: return "Kernel Extensions"
        case .systemExtensions: return "System Extensions"
        case .authorizationPlugins: return "Authorization Plugins"
        case .directoryServicesPlugins: return "Directory Services Plugins"
        case .privilegedHelperTools: return "Privileged Helper Tools"
        case .configurationProfiles: return "Configuration Profiles"
        case .scriptingAdditions: return "Scripting Additions"
        case .inputMethods: return "Input Methods"
        case .spotlightImporters: return "Spotlight Importers"
        case .quickLookGenerators: return "QuickLook Generators"
        case .emondRules: return "Event Monitor Rules"
        case .dylibInjection: return "Dynamic Library Injection"
        case .shellProfiles: return "Shell Profiles"
        case .folderActions: return "Folder Actions"
        case .rcScripts: return "RC Scripts"
        case .pamModules: return "PAM Modules"
        case .networkScripts: return "Network Scripts"
        case .xpcServices: return "XPC Services"
        case .screenSavers: return "Screen Savers"
        case .audioPlugins: return "Audio Plugins"
        case .printerPlugins: return "Printer Plugins"
        case .reopenAtLogin: return "Saved Application State"
        case .appExtensions: return "App Extensions"
        case .browserExtensions: return "Browser Extensions"
        case .automatorWorkflows: return "Automator Workflows"
        case .widgets: return "Widgets"
        case .dockTilePlugins: return "Dock Tile Plugins"
        case .filelessProcesses: return "Fileless Processes"
        }
    }

    public var sfSymbol: String {
        switch self {
        case .launchDaemons: return "gearshape.2"
        case .launchAgents: return "person.crop.circle.badge.clock"
        case .loginItems: return "person.badge.key"
        case .backgroundTaskManagement: return "clock.badge.checkmark"
        case .cronJobs: return "calendar.badge.clock"
        case .periodicTasks: return "repeat"
        case .loginHooks: return "arrow.right.to.line"
        case .startupItems: return "power"
        case .kernelExtensions: return "cpu"
        case .systemExtensions: return "puzzlepiece.extension"
        case .authorizationPlugins: return "lock.shield"
        case .directoryServicesPlugins: return "folder.badge.person.crop"
        case .privilegedHelperTools: return "wrench.and.screwdriver"
        case .configurationProfiles: return "doc.badge.gearshape"
        case .scriptingAdditions: return "applescript"
        case .inputMethods: return "keyboard"
        case .spotlightImporters: return "magnifyingglass"
        case .quickLookGenerators: return "eye"
        case .emondRules: return "bell.badge"
        case .dylibInjection: return "syringe"
        case .shellProfiles: return "terminal"
        case .folderActions: return "folder.badge.plus"
        case .rcScripts: return "scroll"
        case .pamModules: return "lock.open"
        case .networkScripts: return "network"
        case .xpcServices: return "arrow.left.arrow.right"
        case .screenSavers: return "sparkles.tv"
        case .audioPlugins: return "hifispeaker"
        case .printerPlugins: return "printer"
        case .reopenAtLogin: return "arrow.counterclockwise"
        case .appExtensions: return "puzzlepiece"
        case .browserExtensions: return "globe"
        case .automatorWorkflows: return "gearshape.arrow.triangle.2.circlepath"
        case .widgets: return "square.grid.2x2"
        case .dockTilePlugins: return "dock.rectangle"
        case .filelessProcesses: return "memorychip"
        }
    }

    public var group: CategoryGroup {
        switch self {
        case .launchDaemons, .launchAgents:
            return .systemServices
        case .loginItems, .backgroundTaskManagement, .reopenAtLogin:
            return .loginItems
        case .cronJobs, .periodicTasks:
            return .scheduledTasks
        case .kernelExtensions, .systemExtensions:
            return .extensions
        case .authorizationPlugins, .directoryServicesPlugins, .pamModules:
            return .securityPlugins
        case .scriptingAdditions, .inputMethods, .spotlightImporters,
             .quickLookGenerators, .screenSavers, .audioPlugins,
             .printerPlugins, .dockTilePlugins, .appExtensions,
             .browserExtensions:
            return .plugins
        case .dylibInjection, .shellProfiles, .filelessProcesses:
            return .environment
        case .configurationProfiles, .privilegedHelperTools, .xpcServices:
            return .configuration
        case .emondRules, .folderActions, .automatorWorkflows:
            return .eventDriven
        case .loginHooks, .startupItems, .rcScripts, .widgets, .networkScripts:
            return .deprecated
        }
    }

    public var description: String {
        switch self {
        case .launchDaemons:
            return "System-wide daemons managed by launchd, running as root at boot time"
        case .launchAgents:
            return "Per-user or system-wide agents managed by launchd, running in user sessions"
        case .loginItems:
            return "Applications and helpers registered to launch at user login"
        case .backgroundTaskManagement:
            return "macOS 13+ Background Task Management registered items"
        case .cronJobs:
            return "Scheduled tasks using the cron daemon"
        case .periodicTasks:
            return "Scripts run daily, weekly, or monthly via the periodic system"
        case .loginHooks:
            return "Deprecated scripts triggered at login/logout via loginwindow"
        case .startupItems:
            return "Legacy startup bundles (deprecated since macOS 10.5)"
        case .kernelExtensions:
            return "Kernel extensions (kexts) loaded into the kernel at boot"
        case .systemExtensions:
            return "Modern user-space system extensions (Network, Endpoint Security, DriverKit)"
        case .authorizationPlugins:
            return "Plugins loaded by SecurityAgent during authentication"
        case .directoryServicesPlugins:
            return "Plugins for Open Directory / directory services"
        case .privilegedHelperTools:
            return "Helper tools installed with elevated privileges via SMJobBless"
        case .configurationProfiles:
            return "MDM or manually installed configuration profiles"
        case .scriptingAdditions:
            return "AppleScript scripting additions (OSAX) loaded by script hosts"
        case .inputMethods:
            return "Custom input methods and input managers"
        case .spotlightImporters:
            return "Plugins for Spotlight metadata indexing"
        case .quickLookGenerators:
            return "Plugins for Quick Look file previews"
        case .emondRules:
            return "Event Monitor daemon rules triggered by system events"
        case .dylibInjection:
            return "Dynamic library injection via DYLD environment variables"
        case .shellProfiles:
            return "Shell initialization scripts executed on terminal session start"
        case .folderActions:
            return "Automator workflows attached to folders, triggered on file changes"
        case .rcScripts:
            return "Legacy rc initialization scripts"
        case .pamModules:
            return "Pluggable Authentication Modules executed during authentication"
        case .networkScripts:
            return "Scripts triggered by PPP/network state changes"
        case .xpcServices:
            return "Standalone XPC services registered with launchd"
        case .screenSavers:
            return "Screen saver bundles that execute code when activated"
        case .audioPlugins:
            return "CoreAudio HAL plugins loaded by coreaudiod"
        case .printerPlugins:
            return "Printer drivers and CUPS filter plugins"
        case .reopenAtLogin:
            return "Applications with saved state that reopen at next login"
        case .appExtensions:
            return "App extensions (Finder Sync, Share, etc.) loaded by the system"
        case .browserExtensions:
            return "Web browser extensions that run background processes"
        case .automatorWorkflows:
            return "Automator Quick Actions installed as system services"
        case .widgets:
            return "Dashboard/Notification Center widgets"
        case .dockTilePlugins:
            return "Plugins loaded by the Dock for custom tile rendering"
        case .filelessProcesses:
            return "Running processes whose backing binary no longer exists on disk"
        }
    }
}

public enum CategoryGroup: String, Codable, CaseIterable, Identifiable, Hashable, Sendable {
    case systemServices = "System Services"
    case loginItems = "Login Items"
    case scheduledTasks = "Scheduled Tasks"
    case extensions = "Extensions"
    case securityPlugins = "Security Plugins"
    case plugins = "Plugins"
    case environment = "Environment"
    case configuration = "Configuration"
    case eventDriven = "Event-Driven"
    case deprecated = "Deprecated / Legacy"

    public var id: String { rawValue }

    public var categories: [PersistenceCategory] {
        PersistenceCategory.allCases.filter { $0.group == self }
    }
}
