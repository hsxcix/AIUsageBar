# AIUsageBar

A tiny macOS menu bar app that shows how much of your **Claude and ChatGPT (Codex) usage limits** you have used, styled like the two-line indicators of [Stats](https://github.com/exelban/stats).

![AIUsageBar next to a Stats-style CPU indicator](docs/preview.png)

*Rendered mock-up: the Claude tile next to a Stats-style CPU tile.*

- **No extra login.** It uses your existing Claude desktop (or Claude Code) and ChatGPT desktop sign-ins.
- **Always in view, light on resources.** Each enabled service is always shown. Claude refreshes every 2 minutes, ChatGPT every 10 minutes and whenever you open the menu. Polling pauses while the display is off. Values from a failed or overdue refresh are dimmed.
- **Click for details.** See usage and reset times for the available limits, refresh the data, open the usage dashboards or enable launch at login.
- **Native and light.** One Swift file, Apple frameworks only, no dependencies. Menu in English or German, following your system language.

## Requirements

- macOS 14 or later. The release ZIP is built for Apple Silicon.
- For Claude usage, the [Claude desktop app](https://claude.ai/download) with an active sign-in
- For Codex usage, the [ChatGPT desktop app](https://chatgpt.com/download/) with Codex and an active ChatGPT sign-in
- For building: Xcode Command Line Tools (`xcode-select --install`)

## Install

### Download

Grab `AIUsageBar.zip` from [Releases](../../releases), unzip it and move `AIUsageBar.app` to `/Applications`.

The app is not notarized by Apple, so on first launch macOS will block it as unverified. Open **System Settings → Privacy & Security**, scroll down and click **Open Anyway** next to AIUsageBar (on older macOS: right-click the app and choose **Open**). Or build it yourself (below), which avoids the warning.

### Build from source

```bash
git clone https://github.com/hsxcix/AIUsageBar.git
cd AIUsageBar
./build.sh
```

This compiles `main.swift`, creates `AIUsageBar.app` in the same folder, signs it ad hoc and starts it. New menu bar items appear on the left; hold ⌘ and drag to move it.

Use `./build.sh --build-only` to build and sign the app without restarting it.

## How it works

### Claude

AIUsageBar does **not** ask for your password or have its own login. Instead it borrows the token the Claude desktop app has already stored:

1. The Claude desktop app (Electron) keeps its OAuth tokens in `~/Library/Application Support/Claude/config.json`, encrypted with Electron's `safeStorage`.
2. AIUsageBar reads the decryption password from the macOS keychain item **"Claude Safe Storage"** using Apple's `/usr/bin/security` tool. macOS may ask you once to allow this.
3. It decrypts the token locally (PBKDF2 + AES-128-CBC, the standard Chromium scheme) and calls `https://api.anthropic.com/api/oauth/usage`, the same endpoint Claude Code's `/usage` command uses.
4. If the desktop app has no valid token, it falls back to the token Claude Code keeps in the keychain item **"Claude Code-credentials"** (again via `/usr/bin/security`).
5. It **never refreshes** either token, because that would invalidate the owning app's copy. Each app keeps its token fresh while it is running, so after a long break the indicator may show "No valid token" until you open Claude or Claude Code again. After a failed sign-in it waits 15 minutes before trying again, or refreshes right away when the Claude app starts or you choose **Refresh now**.

The Claude token is held in memory and sent only to `api.anthropic.com`.

**Caveats:** the usage endpoint and the desktop app's storage format are not public APIs. Anthropic can change either at any time, which would break this app until it is updated. This project is not affiliated with or endorsed by Anthropic.

### ChatGPT (Codex)

AIUsageBar runs the Codex helper bundled with the ChatGPT desktop app and requests the account's Codex limits over its local App Server protocol. The helper uses your existing sign-in and manages its own credentials. The menu shows the available quota windows, such as 5 hours and 7 days, with their reset times. [OpenAI App Server documentation](https://learn.chatgpt.com/docs/app-server#6-rate-limits-chatgpt)

## Testing

Environment variables for testing without real requests (run the binary directly, e.g. `AIUsageBar.app/Contents/MacOS/AIUsageBar`):

- `AIUSAGEBAR_DEBUG=1` prints fetch results and pauses to stdout.
- `AIUSAGEBAR_USAGE_URL=http://127.0.0.1:8000/` sends Claude requests to a local server instead.
- `AIUSAGEBAR_FAKE_TOKEN=test` uses this token instead of reading the keychain.
- `AIUSAGEBAR_CLAUDE_SOURCE=desktop` or `claudecode` restricts Claude to one token source.

## Adding other services

Each service is a `UsageProvider` (see `main.swift`). To add one, implement the protocol and append it to `providers` in `AppDelegate`; it gets its own tile in the menu bar and its own toggle in the menu.

## License

**All rights reserved**, provided as is without any warranty. See [LICENSE](LICENSE).

In practice I don't really mind if you use it. I just keep all rights and decide case by case. If you want explicit permission (for example to fork, redistribute or build on it), open an issue or contact me on GitHub.
