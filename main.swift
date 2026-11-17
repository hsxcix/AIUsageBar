// AIUsageBar: menu bar indicator for Claude and ChatGPT (Codex) usage limits.
// Each service is a UsageProvider; to add one implement the
// protocol and append it to `providers` in AppDelegate.
//
// Claude auth: reuses the Claude desktop app's cached OAuth token (config.json, encrypted
// with Electron safeStorage; key from the "Claude Safe Storage" keychain item).
// The token is never refreshed here (that would rotate it away from the desktop app).

import AppKit
import CommonCrypto
import Darwin
import ServiceManagement

// MARK: - Provider protocol

protocol UsageProvider: AnyObject {
    var id: String { get }
    var name: String { get }
    /// Whether the provider's segment should currently appear in the menu bar.
    var shouldShow: Bool { get }
    /// Short value under the label, e.g. "7%".
    var valueText: String { get }
    var tooltip: String { get }
    /// Called every few seconds; update visibility state and fetch if due. Call `changed` after async updates.
    func tick(changed: @escaping () -> Void)
    func refreshNow(changed: @escaping () -> Void)
    /// Detail rows and actions for the menu (shown indented under the provider's toggle).
    func menuItems(changed: @escaping () -> Void) -> [NSMenuItem]
}

/// NSMenuItem that runs a closure.
final class ActionItem: NSMenuItem {
    private let handler: () -> Void
    init(_ title: String, state: NSControl.StateValue = .off, handler: @escaping () -> Void) {
        self.handler = handler
        super.init(title: title, action: #selector(run), keyEquivalent: "")
        self.target = self
        self.state = state
    }
    required init(coder: NSCoder) { fatalError() }
    @objc private func run() { handler() }
}

func infoItem(_ s: String) -> NSMenuItem {
    let i = NSMenuItem(title: s, action: nil, keyEquivalent: "")
    i.isEnabled = false
    return i
}

/// UI language: German if that's the user's first preferred language, otherwise English.
let isGerman = Locale.preferredLanguages.first?.hasPrefix("de") ?? false
func L(_ en: String, _ de: String) -> String { isGerman ? de : en }

func fmtTime(_ d: Date?) -> String {
    guard let d else { return "?" }
    let f = DateFormatter()
    f.locale = Locale.current
    f.dateFormat = Calendar.current.isDateInToday(d) ? "HH:mm" : "EE HH:mm"
    return f.string(from: d)
}

final class AppWindowVisibility {
    private var seenOnscreen = Set<Int>()

    func isVisible(bundleID: String, includeWithoutWindow: Bool) -> Bool {
        let pids = Set(NSWorkspace.shared.runningApplications.filter { $0.bundleIdentifier == bundleID }.map { $0.processIdentifier })
        guard !pids.isEmpty else { seenOnscreen.removeAll(); return false }
        if includeWithoutWindow { return true }
        guard let list = CGWindowListCopyWindowInfo([.optionAll], kCGNullWindowID) as? [[String: Any]] else { return false }
        var existing = Set<Int>()
        for w in list {
            guard let pid = w[kCGWindowOwnerPID as String] as? Int32, pids.contains(pid),
                  (w[kCGWindowLayer as String] as? Int) == 0,
                  let num = w[kCGWindowNumber as String] as? Int,
                  let b = w[kCGWindowBounds as String] as? [String: CGFloat],
                  (b["Width"] ?? 0) >= 300, (b["Height"] ?? 0) >= 200 else { continue }
            existing.insert(num)
            if (w[kCGWindowIsOnscreen as String] as? Bool) == true { seenOnscreen.insert(num) }
        }
        // Keep counting windows that are minimised, hidden or on another Space.
        seenOnscreen.formIntersection(existing)
        return !seenOnscreen.isEmpty
    }
}

// MARK: - Claude

enum AuthError: Error { case noKey, noConfig, decrypt, noToken }

final class ClaudeAuth {
    static let configPath = NSHomeDirectory() + "/Library/Application Support/Claude/config.json"
    private var aesKey: Data?

    private func loadKey() throws -> Data {
        if let k = aesKey { return k }
        // Use the system tool so macOS can apply the item's existing Keychain permissions.
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["find-generic-password", "-s", "Claude Safe Storage", "-w"]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        try p.run()
        let output = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let pw = String(data: output, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard p.terminationStatus == 0, !pw.isEmpty else { throw AuthError.noKey }
        var key = Data(count: 16)
        let salt = Array("saltysalt".utf8)
        let status = key.withUnsafeMutableBytes { kp in
            CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw, pw.utf8.count, salt, salt.count,
                                 CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1), 1003,
                                 kp.baseAddress!.assumingMemoryBound(to: UInt8.self), 16)
        }
        guard status == kCCSuccess else { throw AuthError.noKey }
        aesKey = key
        return key
    }

    private func decrypt(_ blob: Data, key: Data) throws -> Data {
        guard blob.count > 3, blob.prefix(3) == Data("v10".utf8) else { throw AuthError.decrypt }
        let cipher = blob.dropFirst(3)
        let iv = [UInt8](repeating: 0x20, count: 16)
        var out = Data(count: cipher.count + kCCBlockSizeAES128)
        var outLen = 0
        let outCap = out.count
        let st = out.withUnsafeMutableBytes { op in
            cipher.withUnsafeBytes { cp in
                key.withUnsafeBytes { kp in
                    CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                            kp.baseAddress, key.count, iv, cp.baseAddress, cipher.count,
                            op.baseAddress, outCap, &outLen)
                }
            }
        }
        guard st == kCCSuccess else { throw AuthError.decrypt }
        return out.prefix(outLen)
    }

    /// Valid (unexpired) tokens from the desktop app's cache, longest-lived first.
    func tokens() throws -> [String] {
        guard let data = FileManager.default.contents(atPath: Self.configPath),
              let cfg = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw AuthError.noConfig }
        let raw = (cfg["oauth:tokenCacheV2"] as? String) ?? (cfg["oauth:tokenCache"] as? String)
        guard let b64 = raw, let blob = Data(base64Encoded: b64) else { throw AuthError.noToken }
        let hadCachedKey = aesKey != nil
        let key = try loadKey()
        let plain: Data
        do { plain = try decrypt(blob, key: key) }
        catch where hadCachedKey {
            aesKey = nil
            plain = try decrypt(blob, key: try loadKey())
        }
        guard let cache = try JSONSerialization.jsonObject(with: plain) as? [String: [String: Any]] else { throw AuthError.noToken }
        let now = Date().timeIntervalSince1970 * 1000
        let valid = cache.values.compactMap { e -> (String, Double)? in
            guard let t = e["token"] as? String, let exp = e["expiresAt"] as? Double, exp > now + 30_000 else { return nil }
            return (t, exp)
        }
        guard !valid.isEmpty else { throw AuthError.noToken }
        return valid.sorted { $0.1 > $1.1 }.map { $0.0 }
    }
}

struct LimitWindow {
    let pct: Double
    let resetsAt: Date?

    var hasReset: Bool { resetsAt.map { $0 <= Date() } ?? false }
}

final class ClaudeProvider: UsageProvider {
    let id = "claude"
    let name = "Claude"
    private let bundleID = "com.anthropic.claudefordesktop"
    private let usageURL = URL(string: "https://api.anthropic.com/api/oauth/usage")!
    private let pollInterval: TimeInterval = 120

    private let auth = ClaudeAuth()
    private var fiveHour: LimitWindow?
    private var sevenDay: LimitWindow?
    private var fetched: Date?
    private var lastError: String?
    private var lastAttempt: Date = .distantPast
    private var backoffUntil: Date = .distantPast
    private var fetching = false
    private let visibility = AppWindowVisibility()
    private(set) var shouldShow = false

    private var alwaysShow: Bool {
        get { UserDefaults.standard.bool(forKey: "claude.alwaysShow") }
        set { UserDefaults.standard.set(newValue, forKey: "claude.alwaysShow") }
    }

    var valueText: String {
        guard let window = fiveHour, !window.hasReset else { return "–" }
        return "\(Int(window.pct.rounded()))%"
    }

    var tooltip: String {
        guard let w = fiveHour else { return lastError ?? L("Claude: loading…", "Claude: wird geladen…") }
        return detail(w, label: L("Claude 5h limit", "Claude 5h-Limit")) + (lastError.map { "\n\($0)" } ?? "")
    }

    func tick(changed: @escaping () -> Void) {
        shouldShow = visibility.isVisible(bundleID: bundleID, includeWithoutWindow: alwaysShow)
        guard shouldShow else { return }
        if Date().timeIntervalSince(lastAttempt) >= pollInterval, Date() >= backoffUntil { fetch(changed) }
    }

    func refreshNow(changed: @escaping () -> Void) { backoffUntil = .distantPast; fetch(changed) }

    private func fetch(_ changed: @escaping () -> Void) {
        guard !fetching else { return }
        fetching = true
        lastAttempt = Date()
        // The Keychain may wait for user input. Keep that wait off the main thread.
        DispatchQueue.global(qos: .utility).async { [auth, weak self] in
            let result = Result { try auth.tokens() }
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                switch result {
                case .success(let tokens):
                    self.attempt(tokens[...], changed)
                case .failure(let error):
                    self.fetching = false
                    self.lastError = (error as? AuthError) == .noToken
                        ? L("No valid token (open Claude)", "Kein gültiges Token (Claude öffnen)")
                        : L("Auth error", "Auth-Fehler") + ": \(error)"
                    changed()
                }
            }
        }
    }

    private func attempt(_ tokens: ArraySlice<String>, _ changed: @escaping () -> Void) {
        guard let token = tokens.first else { fetching = false; lastError = L("Token rejected", "Token abgelehnt"); changed(); return }
        var req = URLRequest(url: usageURL, timeoutInterval: 15)
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("oauth-2025-04-20", forHTTPHeaderField: "anthropic-beta")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        URLSession.shared.dataTask(with: req) { [weak self] data, resp, err in
            DispatchQueue.main.async {
                guard let self else { return }
                let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
                if code == 401 || code == 403 { self.attempt(tokens.dropFirst(), changed); return }
                self.fetching = false
                if code == 429 {
                    self.backoffUntil = Date().addingTimeInterval(600)
                    self.lastError = L("Rate limited, retrying in 10 min", "Rate-Limit, neuer Versuch in 10 Min.")
                } else if let data, code == 200,
                          let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    self.fiveHour = Self.parse(j["five_hour"])
                    self.sevenDay = Self.parse(j["seven_day"])
                    self.fetched = Date()
                    self.lastError = nil
                } else {
                    self.lastError = err?.localizedDescription ?? "HTTP \(code)"
                }
                changed()
            }
        }.resume()
    }

    private static func parse(_ any: Any?) -> LimitWindow? {
        guard let d = any as? [String: Any], let u = d["utilization"] as? Double else { return nil }
        var reset: Date?
        if let s = d["resets_at"] as? String {
            let f = ISO8601DateFormatter()
            f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            reset = f.date(from: s) ?? ISO8601DateFormatter().date(from: s)
        }
        return LimitWindow(pct: u, resetsAt: reset)
    }

    private func detail(_ window: LimitWindow, label: String) -> String {
        if window.hasReset {
            return label + " · " + L("Waiting for new usage data", "Warte auf neue Nutzungsdaten")
        }
        return "\(label): \(Int(window.pct.rounded())) %  ·  Reset \(fmtTime(window.resetsAt))"
    }

    func menuItems(changed: @escaping () -> Void) -> [NSMenuItem] {
        var items: [NSMenuItem] = []
        if let w = fiveHour { items.append(infoItem(detail(w, label: L("5 hours", "5 Stunden")))) }
        if let w = sevenDay { items.append(infoItem(detail(w, label: L("7 days", "7 Tage")))) }
        if let f = fetched { items.append(infoItem(L("Updated", "Aktualisiert") + " \(fmtTime(f))")) }
        if fetching { items.append(infoItem(L("Loading usage…", "Nutzung wird geladen…"))) }
        else if let e = lastError { items.append(infoItem(e)) }
        items.append(ActionItem(L("Open usage on claude.ai", "Nutzung auf claude.ai öffnen")) {
            NSWorkspace.shared.open(URL(string: "https://claude.ai/settings/usage")!)
        })
        items.append(ActionItem(L("Show even without an open Claude window", "Auch ohne offenes Claude-Fenster anzeigen"),
                                state: alwaysShow ? .on : .off) { [weak self] in
            self?.alwaysShow.toggle(); self?.tick(changed: changed); changed()
        })
        return items
    }
}

// MARK: - ChatGPT

private struct CodexLimit: Decodable {
    let usedPercent: Int
    let windowDurationMins: Int?
    let resetsAt: Date?

    var durationText: String? {
        guard let windowDurationMins, windowDurationMins > 0 else { return nil }
        let formatter = DateComponentsFormatter()
        formatter.allowedUnits = [.day, .hour, .minute]
        formatter.unitsStyle = .full
        return formatter.string(from: Double(windowDurationMins) * 60)
    }
}

private enum CodexUsage {
    static let appID = "com.openai.codex"

    enum FetchError: Error {
        case appUnavailable, signInRequired, noLimits, timedOut, invalidResponse

        var menuText: String {
            switch self {
            case .appUnavailable: return L("ChatGPT app with Codex not found", "ChatGPT-App mit Codex nicht gefunden")
            case .signInRequired: return L("Sign in to the ChatGPT app", "In der ChatGPT-App anmelden")
            case .noLimits: return L("No Codex limits available", "Keine Codex-Limits verfügbar")
            case .timedOut: return L("Codex did not respond in time", "Codex hat nicht rechtzeitig geantwortet")
            case .invalidResponse: return L("Could not load Codex usage", "Codex-Nutzung konnte nicht geladen werden")
            }
        }
    }

    private struct LimitsResponse: Decodable {
        struct Snapshot: Decodable {
            let primary: CodexLimit?
            let secondary: CodexLimit?
        }

        struct RateLimits: Decodable {
            let rateLimits: Snapshot
            let rateLimitsByLimitId: [String: Snapshot]?
        }

        let result: RateLimits
    }

    static func executableURL() -> URL? {
        let workspace = NSWorkspace.shared
        let app = workspace.runningApplications.first { $0.bundleIdentifier == appID }?.bundleURL
            ?? workspace.urlForApplication(withBundleIdentifier: appID)
        let executable = app?.appendingPathComponent("Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex")
        return executable.flatMap { FileManager.default.isExecutableFile(atPath: $0.path) ? $0 : nil }
    }

    static func fetch(executable: URL) throws -> [CodexLimit] {
        let process = Process()
        let input = Pipe()
        let output = Pipe()
        process.executableURL = executable
        process.arguments = ["app-server", "-c", "analytics.enabled=false"]
        process.currentDirectoryURL = FileManager.default.homeDirectoryForCurrentUser
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        // A helper that exits between requests should raise an I/O error instead of SIGPIPE.
        guard fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) != -1 else {
            throw FetchError.invalidResponse
        }
        try process.run()
        defer {
            try? input.fileHandleForWriting.close()
            if process.isRunning { process.terminate() }
        }

        // App Server uses one JSON message per line over stdio. Only keep replies to our requests.
        var buffer = Data()
        let fd = output.fileHandleForReading.fileDescriptor
        let deadline = ProcessInfo.processInfo.systemUptime + 15

        func send(_ line: String) throws {
            try input.fileHandleForWriting.write(contentsOf: Data((line + "\n").utf8))
        }

        func reply(to id: Int) throws -> (Data, [String: Any]) {
            while true {
                while let newline = buffer.firstIndex(of: 0x0A) {
                    let line = buffer.prefix(upTo: newline)
                    buffer.removeSubrange(...newline)
                    guard let message = try JSONSerialization.jsonObject(with: line) as? [String: Any],
                          message["id"] as? Int == id else { continue }
                    guard let result = message["result"] as? [String: Any] else { throw FetchError.invalidResponse }
                    return (line, result)
                }

                let remaining = deadline - ProcessInfo.processInfo.systemUptime
                guard remaining > 0 else { throw FetchError.timedOut }
                var ready = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                let status = poll(&ready, 1, Int32((remaining * 1000).rounded(.up)))
                if status < 0 && errno == EINTR { continue }
                guard status != 0 else { throw FetchError.timedOut }
                guard status > 0 else { throw FetchError.invalidResponse }
                let chunk = output.fileHandleForReading.availableData
                guard !chunk.isEmpty, buffer.count + chunk.count <= 1_048_576 else { throw FetchError.invalidResponse }
                buffer.append(chunk)
            }
        }

        try send(#"{"id":1,"method":"initialize","params":{"clientInfo":{"name":"ai_usage_bar","title":"AIUsageBar","version":"0.2"}}}"#)
        _ = try reply(to: 1)
        try send(#"{"method":"initialized"}"#)
        try send(#"{"id":2,"method":"account/read","params":{"refreshToken":false}}"#)
        let (_, state) = try reply(to: 2)
        let account = state["account"] as? [String: Any]
        guard account?["type"] as? String == "chatgpt" else { throw FetchError.signInRequired }
        try send(#"{"id":3,"method":"account/rateLimits/read"}"#)
        let (data, _) = try reply(to: 3)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        let response = try decoder.decode(LimitsResponse.self, from: data).result
        let snapshot = response.rateLimitsByLimitId?["codex"] ?? response.rateLimits
        let limits = [snapshot.primary, snapshot.secondary].compactMap { $0 }
        guard !limits.isEmpty else { throw FetchError.noLimits }
        return limits
    }
}

final class ChatGPTProvider: UsageProvider {
    let id = "chatgpt"
    let name = "ChatGPT"
    private let visibility = AppWindowVisibility()
    private var limits: [CodexLimit] = []
    private var fetched: Date?
    private var lastError: String?
    private var lastAttempt: Date = .distantPast
    private var fetching = false
    private(set) var shouldShow = false

    private var alwaysShow: Bool {
        get { UserDefaults.standard.bool(forKey: "chatgpt.alwaysShow") }
        set { UserDefaults.standard.set(newValue, forKey: "chatgpt.alwaysShow") }
    }

    var valueText: String {
        guard let limit = limits.first, limit.resetsAt.map({ $0 > Date() }) ?? true else { return "–" }
        return "\(limit.usedPercent)%"
    }

    var tooltip: String {
        let rows = [L("ChatGPT (Codex limits)", "ChatGPT (Codex-Limits)")] + limits.map(detail)
        return (rows + [lastError].compactMap { $0 }).joined(separator: "\n")
    }

    func tick(changed: @escaping () -> Void) {
        shouldShow = visibility.isVisible(bundleID: CodexUsage.appID, includeWithoutWindow: alwaysShow)
        if shouldShow, Date().timeIntervalSince(lastAttempt) >= 120 {
            refreshNow(changed: changed)
        }
    }

    func refreshNow(changed: @escaping () -> Void) {
        guard !fetching else { return }
        lastAttempt = Date()
        guard let executable = CodexUsage.executableURL() else {
            lastError = CodexUsage.FetchError.appUnavailable.menuText
            changed()
            return
        }
        fetching = true
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let result = Result { try CodexUsage.fetch(executable: executable) }
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.fetching = false
                switch result {
                case .success(let limits):
                    self.limits = limits
                    self.fetched = Date()
                    self.lastError = nil
                case .failure(let error):
                    let failure = error as? CodexUsage.FetchError ?? .invalidResponse
                    if failure == .signInRequired || failure == .noLimits {
                        self.limits = []
                        self.fetched = nil
                    }
                    self.lastError = failure.menuText
                }
                changed()
            }
        }
    }

    private func detail(_ limit: CodexLimit) -> String {
        let duration = limit.durationText ?? L("Usage", "Nutzung")
        if let reset = limit.resetsAt, reset <= Date() {
            return duration + " · " + L("Waiting for new usage data", "Warte auf neue Nutzungsdaten")
        }
        return "\(duration): \(limit.usedPercent) %" + (limit.resetsAt.map { "  ·  Reset " + fmtTime($0) } ?? "")
    }

    func menuItems(changed: @escaping () -> Void) -> [NSMenuItem] {
        var items = [infoItem(L("Codex limits", "Codex-Limits"))]
        items += limits.map { infoItem(detail($0)) }
        if let fetched { items.append(infoItem(L("Updated", "Aktualisiert") + " " + fmtTime(fetched))) }
        if let lastError { items.append(infoItem(lastError)) }
        else if fetching { items.append(infoItem(L("Loading usage…", "Nutzung wird geladen…"))) }
        items.append(ActionItem(L("Open Codex usage dashboard", "Codex-Nutzungsübersicht öffnen")) {
            NSWorkspace.shared.open(URL(string: "https://chatgpt.com/codex/settings/usage")!)
        })
        items.append(ActionItem(L("Show even without an open ChatGPT window", "Auch ohne offenes ChatGPT-Fenster anzeigen"),
                                state: alwaysShow ? .on : .off) { [weak self] in
            self?.alwaysShow.toggle(); self?.tick(changed: changed); changed()
        })
        return items
    }
}

// MARK: - Rendering (Stats-style: small label on top, value below)

// Slightly bolder than Stats (regular label, medium value), vertically centred.
func renderSegment(label: String, value: String) -> NSImage {
    let labelAttrs: [NSAttributedString.Key: Any] = [
        .font: NSFont.systemFont(ofSize: 7, weight: .regular), .foregroundColor: NSColor.black]
    let valueAttrs: [NSAttributedString.Key: Any] = [
        .font: NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .medium), .foregroundColor: NSColor.black]
    let l = NSAttributedString(string: label, attributes: labelAttrs)
    let v = NSAttributedString(string: value, attributes: valueAttrs)
    let width = ceil(max(l.size().width, v.size().width))
    return NSImage(size: NSSize(width: width, height: 22), flipped: false) { _ in
        l.draw(at: NSPoint(x: 0, y: 12.5))
        v.draw(at: NSPoint(x: 0, y: -0.5))
        return true
    }
}

/// Several segments side by side, as one template image.
func renderBar(_ segments: [(String, String)]) -> NSImage {
    let imgs = segments.map { renderSegment(label: $0.0, value: $0.1) }
    let gap: CGFloat = 10
    let width = imgs.reduce(0) { $0 + $1.size.width } + gap * CGFloat(max(imgs.count - 1, 0))
    let img = NSImage(size: NSSize(width: width, height: 22), flipped: false) { _ in
        var x: CGFloat = 0
        for i in imgs { i.draw(at: NSPoint(x: x, y: 0), from: .zero, operation: .sourceOver, fraction: 1); x += i.size.width + gap }
        return true
    }
    img.isTemplate = true
    return img
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let providers: [UsageProvider] = [ClaudeProvider(), ChatGPTProvider()]
    private var showMenuWhenHidden = false

    func isEnabled(_ p: UsageProvider) -> Bool {
        UserDefaults.standard.object(forKey: "enabled.\(p.id)") as? Bool ?? true
    }
    func setEnabled(_ p: UsageProvider, _ on: Bool) { UserDefaults.standard.set(on, forKey: "enabled.\(p.id)") }

    func applicationDidFinishLaunching(_ n: Notification) {
        if CommandLine.arguments.contains("--enable-login") { try? SMAppService.mainApp.register() }
        if CommandLine.arguments.contains("--disable-login") { try? SMAppService.mainApp.unregister() }
        item.autosaveName = "AIUsageBar"
        item.button?.imagePosition = .imageOnly
        let menu = NSMenu()
        menu.delegate = self
        item.menu = menu
        Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.tick() }
        NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
            guard let self else { return }
            self.providers.filter(self.isEnabled).forEach { $0.refreshNow { [weak self] in self?.render() } }
        }
        tick()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !item.isVisible {
            showMenuWhenHidden = true
            render()
        }
        return false
    }

    func tick() {
        for p in providers where isEnabled(p) { p.tick { [weak self] in self?.render() } }
        render()
    }

    func render() {
        let visible = providers.filter { isEnabled($0) && $0.shouldShow }
        let anyEnabled = providers.contains(where: isEnabled)
        if !visible.isEmpty { showMenuWhenHidden = false }
        if visible.isEmpty && anyEnabled && !showMenuWhenHidden {
            if item.isVisible { item.isVisible = false }
            return
        }
        if !item.isVisible { item.isVisible = true }
        // Keep the menu reachable when the user reopens the app or disables every service.
        let segments = visible.isEmpty ? [("AI", "–")] : visible.map { ($0.name, $0.valueText) }
        item.button?.image = renderBar(segments)
        if visible.isEmpty {
            item.button?.toolTip = anyEnabled ? "AIUsageBar" : L("AIUsageBar: no service enabled", "AIUsageBar: kein Dienst aktiviert")
        } else {
            item.button?.toolTip = visible.map(\.tooltip).joined(separator: "\n")
        }
    }

    // Menu is rebuilt each time it opens
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        let changed: () -> Void = { [weak self] in self?.render() }
        for p in providers {
            let on = isEnabled(p)
            let toggle = ActionItem(p.name, state: on ? .on : .off) { [weak self] in
                guard let self else { return }
                self.setEnabled(p, !on)
                if !on { p.refreshNow(changed: changed) }
                self.tick()
            }
            menu.addItem(toggle)
            if on {
                for i in p.menuItems(changed: changed) { i.indentationLevel = 1; menu.addItem(i) }
            }
            menu.addItem(.separator())
        }
        let refresh = ActionItem(L("Refresh now", "Jetzt aktualisieren")) { [weak self] in
            guard let self else { return }
            self.providers.filter(self.isEnabled).forEach { $0.refreshNow(changed: changed) }
        }
        refresh.keyEquivalent = "r"
        menu.addItem(refresh)
        menu.addItem(ActionItem(L("Launch at login", "Bei Anmeldung starten"), state: SMAppService.mainApp.status == .enabled ? .on : .off) {
            if SMAppService.mainApp.status == .enabled { try? SMAppService.mainApp.unregister() }
            else { try? SMAppService.mainApp.register() }
        })
        menu.addItem(.separator())
        menu.addItem(withTitle: L("Quit", "Beenden"), action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
