# ElderSafe Chrome Extension

ElderSafe is a Manifest V3 Chrome extension that helps protect seniors from common online scams by analyzing pages in real time and blocking interaction with risky pages.

## Features

- **Real-time scanning** — Heuristic checks for urgency language, common scam phrases, risky password fields, HTTP pages, and suspicious hostnames.
- **Full-screen block** — When a threat is detected, the page is covered by a full-viewport overlay (blurred page behind). There is **no “continue anyway”** on the page — only **Go back**, **Close this tab**, or **Report scam**. Caregivers can **whitelist** a domain in settings.
- **Settings page** — Click the toolbar icon or use **Alt+Shift+S** to open **Options** (stats, protection toggle, whitelist, Maximum Protection).
- **Maximum Protection Mode** — Optional family password (SHA-256 hashed) required each new browser session (`chrome.storage.session`) before browsing. Shown **above** the threat overlay when enabled.
- **Notifications** — Toasts for install, unlock, and scam reports.
- **Keyboard shortcuts** — `Alt+Shift+E` pulses the warning panel (when visible); `Alt+Shift+S` opens settings.

## Install (developer mode)

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the `eldersafe-extension` folder.
4. Click the ElderSafe icon to open **Settings** (no popup).

## Icons

PNG icons in `icons/` are required for the Chrome Web Store. Regenerate them if you replace branding.

## Privacy

Page content is analyzed locally in the browser. Reporting sends a message to the background worker to log a notification only — wire this to your backend if you need centralized reporting.

## Disclaimer

ElderSafe uses heuristics, not a remote AI model, in this reference implementation. It does not guarantee detection of all scams. Combine with caregiver guidance and official support channels.

**Note:** Determined users can still disable the extension in `chrome://extensions`. This tool adds friction and guidance; it is not enterprise device lockdown.
