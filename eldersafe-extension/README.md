# ElderSafe Chrome Extension

ElderSafe is a Manifest V3 Chrome extension that helps protect seniors from common online scams by analyzing pages in real time and showing clear, non-intrusive warnings.

## Features

- **Real-time scanning** — Heuristic checks for urgency language, common scam phrases, risky password fields, HTTP pages, and suspicious hostnames.
- **Warning banner** — A high-contrast banner at the top of the page with “Go back”, “I understand the risk”, and “Report scam”.
- **Whitelist** — Trusted domains can be added from the popup so legitimate sites stay quiet.
- **Maximum Protection Mode** — Optional family password (SHA-256 hashed) required each new browser session (`chrome.storage.session`) before browsing.
- **Popup dashboard** — Live status, blocked attempts today, lifetime counter, and confidence meter for the last threat.
- **Notifications** — Toasts for install, unlock, and scam reports.
- **Keyboard shortcuts** — `Alt+Shift+E` focuses the warning banner (when visible); `Alt+Shift+S` shows a help toast (Chrome cannot programmatically open the popup from a shortcut on all versions).

## Install (developer mode)

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the `eldersafe-extension` folder.

## Icons

PNG icons in `icons/` are required for the Chrome Web Store. Regenerate them if you replace branding.

## Privacy

Page content is analyzed locally in the browser. Reporting sends a message to the background worker to log a notification only — wire this to your backend if you need centralized reporting.

## Disclaimer

ElderSafe uses heuristics, not a remote AI model, in this reference implementation. It does not guarantee detection of all scams. Combine with caregiver guidance and official support channels.
