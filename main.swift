// AIUsageBar: menu bar indicator for Claude and ChatGPT (Codex) usage limits.
// Indicators are always shown; polling pauses while the display is off.
// Each service is a UsageProvider; to add one implement the
// protocol and append it to `providers` in AppDelegate.
//
// Claude auth: reuses the Claude desktop app's cached OAuth token (config.json, encrypted
// with Electron safeStorage; key from the "Claude Safe Storage" keychain item), falling back
// to Claude Code's token ("Claude Code-credentials" keychain item).
// Tokens are never refreshed here (that would rotate it away from the desktop app).

import AppKit
import CommonCrypto
import Darwin
import ServiceManagement

// MARK: - Provider protocol

protocol UsageProvider: AnyObject {
    var id: String { get }
    var name: String { get }
    /// Bundle IDs of apps whose launch should trigger a fresh fetch (their sign-in may just have been refreshed).
    var appBundleIDs: [String] { get }
    /// Short value under the label, e.g. "7%".
    var valueText: String { get }
    /// The value comes from a failed or overdue fetch; it is drawn dimmed.
    var isStale: Bool { get }
    var tooltip: String { get }
    /// Called periodically while the display is on; fetch if due. Call `changed` after async updates.
    func tick(changed: @escaping () -> Void)
    /// The menu opened: fetch unless the last attempt was very recent.
    func menuOpened(changed: @escaping () -> Void)
    /// Fetch now, ignoring interval and backoff.
    func refreshNow(changed: @escaping () -> Void)
    /// Detail rows under the provider's toggle; read again when data changes while the menu is open.
    func infoLines() -> [String]
    /// Actions shown after the detail rows.
    func actionItems() -> [NSMenuItem]
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

/// Debug overrides for testing without real requests, see README.
let env = ProcessInfo.processInfo.environment
func debugLog(_ s: String) {
    guard env["AIUSAGEBAR_DEBUG"] != nil else { return }
    print("[\(fmtTime(Date()))] \(s)")
    fflush(stdout)
}

/// Reads a generic password through the system tool, so macOS applies the item's existing Keychain permissions.
func keychainPassword(service: String) -> String? {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
    p.arguments = ["find-generic-password", "-s", service, "-w"]
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = FileHandle.nullDevice
    guard (try? p.run()) != nil else { return nil }
    let output = pipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    let pw = String(data: output, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return p.terminationStatus == 0 && !pw.isEmpty ? pw : nil
}

// MARK: - Claude

enum AuthError: Error { case noKey, noConfig, decrypt, noToken }

final class ClaudeAuth {
    static let configPath = NSHomeDirectory() + "/Library/Application Support/Claude/config.json"
    private var aesKey: Data?

    private func loadKey() throws -> Data {
        if let k = aesKey { return k }
        guard let pw = keychainPassword(service: "Claude Safe Storage") else { throw AuthError.noKey }
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

/// Fallback: the OAuth token Claude Code keeps in the Keychain. Read only, never refreshed (same rule as above).
enum ClaudeCodeAuth {
    /// Skip lookups for a while after the item is missing or access was denied, to avoid repeated Keychain prompts.
    private static var unavailableUntil = Date.distantPast

    static func token() -> String? {
        guard Date() >= unavailableUntil else { return nil }
        guard let pw = keychainPassword(service: "Claude Code-credentials"),
              let j = try? JSONSerialization.jsonObject(with: Data(pw.utf8)) as? [String: Any],
              let o = j["claudeAiOauth"] as? [String: Any],
              let token = o["accessToken"] as? String else {
            unavailableUntil = Date().addingTimeInterval(3600)
            return nil
        }
        // An expired token is not marked unavailable: Claude Code refreshes it on its next run.
        if let exp = o["expiresAt"] as? Double, exp <= Date().timeIntervalSince1970 * 1000 + 30_000 { return nil }
        return token
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
    let appBundleIDs = ["com.anthropic.claudefordesktop"]
    private let usageURL = URL(string: env["AIUSAGEBAR_USAGE_URL"] ?? "https://api.anthropic.com/api/oauth/usage")!
    private let pollInterval: TimeInterval = 120
    private let authBackoff: TimeInterval = 900

    private let auth = ClaudeAuth()
    private var fiveHour: LimitWindow?
    private var sevenDay: LimitWindow?
    private var fetched: Date?
    private var lastError: String?
    private var lastAttempt: Date = .distantPast
    private var backoffUntil: Date = .distantPast
    private var fetching = false

    var valueText: String {
        guard let window = fiveHour, !window.hasReset else { return "–" }
        return "\(Int(window.pct.rounded()))%"
    }

    var isStale: Bool {
        guard let fetched, !fetching else { return false }
        return lastError != nil || Date().timeIntervalSince(fetched) > 2 * pollInterval
    }

    var tooltip: String {
        guard let w = fiveHour else { return lastError ?? L("Claude: loading…", "Claude: wird geladen…") }
        return detail(w, label: L("Claude 5h limit", "Claude 5h-Limit")) + (lastError.map { "\n\($0)" } ?? "")
    }

    private func due(after age: TimeInterval) -> Bool {
        Date() >= backoffUntil && Date().timeIntervalSince(lastAttempt) >= age
    }

    func tick(changed: @escaping () -> Void) { if due(after: pollInterval) { fetch(changed) } }
    func menuOpened(changed: @escaping () -> Void) { if due(after: 60) { fetch(changed) } }
    func refreshNow(changed: @escaping () -> Void) { backoffUntil = .distantPast; fetch(changed) }

    private func fetch(_ changed: @escaping () -> Void) {
        guard !fetching else { return }
        fetching = true
        lastAttempt = Date()
        changed()
        let fake = env["AIUSAGEBAR_FAKE_TOKEN"]
        let source = env["AIUSAGEBAR_CLAUDE_SOURCE"]
        // The Keychain may wait for user input. Keep that wait off the main thread.
        DispatchQueue.global(qos: .utility).async { [auth, weak self] in
            let tokens = fake.map { [$0] } ?? (source == "claudecode" ? [] : ((try? auth.tokens()) ?? []))
            DispatchQueue.main.async { [weak self] in
                self?.attempt(tokens[...], claudeCodeTried: fake != nil || source == "desktop", changed)
            }
        }
    }

    /// Tries the desktop app's tokens first, then Claude Code's.
    private func attempt(_ tokens: ArraySlice<String>, claudeCodeTried: Bool, _ changed: @escaping () -> Void) {
        guard let token = tokens.first else {
            if !claudeCodeTried {
                DispatchQueue.global(qos: .utility).async { [weak self] in
                    let cc = ClaudeCodeAuth.token().map { [$0] } ?? []
                    DispatchQueue.main.async { [weak self] in self?.attempt(cc[...], claudeCodeTried: true, changed) }
                }
                return
            }
            fetching = false
            backoffUntil = Date().addingTimeInterval(authBackoff)
            lastError = L("No valid token (open Claude or Claude Code)", "Kein gültiges Token (Claude oder Claude Code öffnen)")
            debugLog("claude: no valid token, next try in \(Int(authBackoff / 60)) min")
            changed()
            return
        }
        var req = URLRequest(url: usageURL, timeoutInterval: 15)
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("oauth-2025-04-20", forHTTPHeaderField: "anthropic-beta")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        URLSession.shared.dataTask(with: req) { [weak self] data, resp, err in
            DispatchQueue.main.async {
                guard let self else { return }
                let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
                debugLog("claude: HTTP \(code)")
                if code == 401 || code == 403 { self.attempt(tokens.dropFirst(), claudeCodeTried: claudeCodeTried, changed); return }
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

    func infoLines() -> [String] {
        var rows: [String] = []
        if let w = fiveHour { rows.append(detail(w, label: L("5 hours", "5 Stunden"))) }
        if let w = sevenDay { rows.append(detail(w, label: L("7 days", "7 Tage"))) }
        if let f = fetched { rows.append(L("Updated", "Aktualisiert") + " \(fmtTime(f))") }
        if fetching { rows.append(L("Loading usage…", "Nutzung wird geladen…")) }
        else if let e = lastError { rows.append(e) }
        return rows
    }

    func actionItems() -> [NSMenuItem] {
        [ActionItem(L("Open usage on claude.ai", "Nutzung auf claude.ai öffnen")) {
            NSWorkspace.shared.open(URL(string: "https://claude.ai/settings/usage")!)
        }]
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
        let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: appID)
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

        try send(#"{"id":1,"method":"initialize","params":{"clientInfo":{"name":"ai_usage_bar","title":"AIUsageBar","version":"0.3"}}}"#)
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
    let appBundleIDs = [CodexUsage.appID]
    /// Each fetch starts the bundled Codex helper, so poll rarely and refresh when the menu opens.
    private let pollInterval: TimeInterval = 600
    private let setupBackoff: TimeInterval = 900
    private var limits: [CodexLimit] = []
    private var fetched: Date?
    private var lastError: String?
    private var lastAttempt: Date = .distantPast
    private var backoffUntil: Date = .distantPast
    private var fetching = false

    var valueText: String {
        guard let limit = limits.first, limit.resetsAt.map({ $0 > Date() }) ?? true else { return "–" }
        return "\(limit.usedPercent)%"
    }

    var isStale: Bool {
        guard let fetched, !fetching else { return false }
        return lastError != nil || Date().timeIntervalSince(fetched) > 2 * pollInterval
    }

    var tooltip: String {
        let rows = [L("ChatGPT (Codex limits)", "ChatGPT (Codex-Limits)")] + limits.map(detail)
        return (rows + [lastError].compactMap { $0 }).joined(separator: "\n")
    }

    private func due(after age: TimeInterval) -> Bool {
        Date() >= backoffUntil && Date().timeIntervalSince(lastAttempt) >= age
    }

    func tick(changed: @escaping () -> Void) { if due(after: pollInterval) { fetch(changed) } }
    func menuOpened(changed: @escaping () -> Void) { if due(after: 60) { fetch(changed) } }
    func refreshNow(changed: @escaping () -> Void) { backoffUntil = .distantPast; fetch(changed) }

    private func fetch(_ changed: @escaping () -> Void) {
        guard !fetching else { return }
        lastAttempt = Date()
        guard let executable = CodexUsage.executableURL() else {
            lastError = CodexUsage.FetchError.appUnavailable.menuText
            backoffUntil = Date().addingTimeInterval(setupBackoff)
            changed()
            return
        }
        fetching = true
        changed()
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let result = Result { try CodexUsage.fetch(executable: executable) }
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.fetching = false
                switch result {
                case .success(let limits):
                    debugLog("chatgpt: \(limits.count) limits")
                    self.limits = limits
                    self.fetched = Date()
                    self.lastError = nil
                case .failure(let error):
                    let failure = error as? CodexUsage.FetchError ?? .invalidResponse
                    debugLog("chatgpt: \(failure)")
                    if failure == .signInRequired || failure == .noLimits {
                        self.limits = []
                        self.fetched = nil
                        self.backoffUntil = Date().addingTimeInterval(self.setupBackoff)
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

    func infoLines() -> [String] {
        var rows = [L("Codex limits", "Codex-Limits")] + limits.map(detail)
        if let fetched { rows.append(L("Updated", "Aktualisiert") + " " + fmtTime(fetched)) }
        if fetching { rows.append(L("Loading usage…", "Nutzung wird geladen…")) }
        else if let lastError { rows.append(lastError) }
        return rows
    }

    func actionItems() -> [NSMenuItem] {
        [ActionItem(L("Open Codex usage dashboard", "Codex-Nutzungsübersicht öffnen")) {
            NSWorkspace.shared.open(URL(string: "https://chatgpt.com/codex/settings/usage")!)
        }]
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

/// Several segments side by side, as one template image. Dimmed segments show stale values.
func renderBar(_ segments: [(label: String, value: String, dimmed: Bool)]) -> NSImage {
    let imgs = segments.map { (renderSegment(label: $0.label, value: $0.value), $0.dimmed) }
    let gap: CGFloat = 10
    let width = imgs.reduce(0) { $0 + $1.0.size.width } + gap * CGFloat(max(imgs.count - 1, 0))
    let img = NSImage(size: NSSize(width: width, height: 22), flipped: false) { _ in
        var x: CGFloat = 0
        for (i, dimmed) in imgs {
            i.draw(at: NSPoint(x: x, y: 0), from: .zero, operation: .sourceOver, fraction: dimmed ? 0.4 : 1)
            x += i.size.width + gap
        }
        return true
    }
    img.isTemplate = true
    return img
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let providers: [UsageProvider] = [ClaudeProvider(), ChatGPTProvider()]
    /// No polling while the display is off: nobody looks, and the Mac may stay awake all night on power.
    private var displayAsleep = false
    private var lastWakeRefresh = Date.distantPast
    private var menuOpen = false
    /// Toggles and detail rows of the open menu, per provider id, so data updates can replace rows in place.
    private var toggles: [String: NSMenuItem] = [:]
    private var infoRows: [String: [NSMenuItem]] = [:]
    private lazy var changed: () -> Void = { [weak self] in self?.dataChanged() }

    func isEnabled(_ p: UsageProvider) -> Bool {
        UserDefaults.standard.object(forKey: "enabled.\(p.id)") as? Bool ?? true
    }
    func setEnabled(_ p: UsageProvider, _ on: Bool) { UserDefaults.standard.set(on, forKey: "enabled.\(p.id)") }

    func applicationDidFinishLaunching(_ n: Notification) {
        if CommandLine.arguments.contains("--enable-login") { try? SMAppService.mainApp.register() }
        if CommandLine.arguments.contains("--disable-login") { try? SMAppService.mainApp.unregister() }
        // Settings from 0.2, when indicators were tied to open app windows.
        for key in ["claude.alwaysShow", "chatgpt.alwaysShow"] { UserDefaults.standard.removeObject(forKey: key) }
        item.autosaveName = "AIUsageBar"
        item.isVisible = true  // 0.2 could leave the item hidden, and the autosave would restore that
        item.button?.imagePosition = .imageOnly
        let menu = NSMenu()
        menu.delegate = self
        item.menu = menu
        Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in self?.tick() }

        let center = NSWorkspace.shared.notificationCenter
        center.addObserver(forName: NSWorkspace.screensDidSleepNotification, object: nil, queue: .main) { [weak self] _ in
            debugLog("display off, pausing")
            self?.displayAsleep = true
        }
        for name in [NSWorkspace.screensDidWakeNotification, NSWorkspace.didWakeNotification] {
            center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                guard let self else { return }
                self.displayAsleep = false
                // Both notifications usually arrive together after sleep; refresh once.
                guard Date().timeIntervalSince(self.lastWakeRefresh) > 10 else { return }
                self.lastWakeRefresh = Date()
                debugLog("wake, refreshing")
                self.providers.filter(self.isEnabled).forEach { $0.refreshNow(changed: self.changed) }
            }
        }
        center.addObserver(forName: NSWorkspace.didLaunchApplicationNotification, object: nil, queue: .main) { [weak self] note in
            guard let self,
                  let id = (note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication)?.bundleIdentifier else { return }
            for p in self.providers where self.isEnabled(p) && p.appBundleIDs.contains(id) {
                debugLog("\(id) launched, refreshing \(p.id) in 15 s")
                // Give the app time to refresh its sign-in first; this also clears an auth backoff.
                DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
                    guard let self else { return }
                    p.refreshNow(changed: self.changed)
                }
            }
        }
        tick()
    }

    func tick() {
        if !displayAsleep {
            for p in providers where isEnabled(p) { p.tick(changed: changed) }
        }
        render()
    }

    private func dataChanged() {
        render()
        if menuOpen { updateOpenMenu() }
    }

    func render() {
        let enabled = providers.filter(isEnabled)
        // Keep a placeholder when every service is off, so the menu stays reachable.
        let segments = enabled.isEmpty
            ? [(label: "AI", value: "–", dimmed: false)]
            : enabled.map { (label: $0.name, value: $0.valueText, dimmed: $0.isStale) }
        item.button?.image = renderBar(segments)
        item.button?.toolTip = enabled.isEmpty
            ? L("AIUsageBar: no service enabled", "AIUsageBar: kein Dienst aktiviert")
            : enabled.map(\.tooltip).joined(separator: "\n")
    }

    private func makeRows(_ p: UsageProvider) -> [NSMenuItem] {
        let rows = p.infoLines().map(infoItem)
        rows.forEach { $0.indentationLevel = 1 }
        return rows
    }

    /// Replaces detail rows in the open menu without rebuilding it.
    private func updateOpenMenu() {
        guard let menu = item.menu else { return }
        for p in providers {
            guard let old = infoRows[p.id], let toggle = toggles[p.id] else { continue }
            let lines = p.infoLines()
            if lines.count == old.count {
                for (row, line) in zip(old, lines) where row.title != line { row.title = line }
                continue
            }
            old.forEach(menu.removeItem)
            let rows = makeRows(p)
            let start = menu.index(of: toggle) + 1
            for (k, row) in rows.enumerated() { menu.insertItem(row, at: start + k) }
            infoRows[p.id] = rows
        }
    }

    // Menu is rebuilt each time it opens
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        toggles = [:]
        infoRows = [:]
        for p in providers {
            let on = isEnabled(p)
            let toggle = ActionItem(p.name, state: on ? .on : .off) { [weak self] in
                guard let self else { return }
                self.setEnabled(p, !on)
                if !on { p.refreshNow(changed: self.changed) }
                self.render()
            }
            menu.addItem(toggle)
            if on {
                let rows = makeRows(p)
                toggles[p.id] = toggle
                infoRows[p.id] = rows
                rows.forEach(menu.addItem)
                for i in p.actionItems() { i.indentationLevel = 1; menu.addItem(i) }
            }
            menu.addItem(.separator())
        }
        let refresh = ActionItem(L("Refresh now", "Jetzt aktualisieren")) { [weak self] in
            guard let self else { return }
            self.providers.filter(self.isEnabled).forEach { $0.refreshNow(changed: self.changed) }
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

    func menuWillOpen(_ menu: NSMenu) {
        menuOpen = true
        for p in providers where isEnabled(p) { p.menuOpened(changed: changed) }
    }

    func menuDidClose(_ menu: NSMenu) {
        menuOpen = false
        toggles = [:]
        infoRows = [:]
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
