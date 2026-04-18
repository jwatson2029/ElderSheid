# Safe URLs for testing ElderSafe

Do **not** hunt for real phishing links to “test” the extension. Use the resources below instead.

## URLs that always work (benign / negative test)

These should load reliably and **should not** look like scams to ElderSafe (unless you add odd whitelist tests):

| URL | Purpose |
|-----|---------|
| https://example.com | Minimal placeholder page |
| https://www.wikipedia.org | Normal browsing |
| https://www.ftc.gov/business-guidance/resources/protecting-small-businesses-cybersecurity | Legit consumer safety content |
| https://www.google.com/chrome/ | Official Chrome page |

## Official “bad URL” tests (safe, controlled)

Google hosts **fake** malware/phishing URLs used only to verify browser protection:

- **Dashboard:** https://testsafebrowsing.appspot.com/

Open individual test links from that page to see how **Chrome Safe Browsing** reacts. ElderSafe uses its **own** heuristics, so behavior may differ—that’s expected.

## Trigger ElderSafe warnings locally (recommended)

No public scam site required.

1. Load the extension (Developer mode → Load unpacked → `eldersafe-extension`).
2. Open the demo file in Chrome (drag-and-drop into a tab, or **File → Open**):

   **`test-fixtures/suspicious-demo.html`**

   That page uses urgency language + common scam phrases + a password field so the content script can reach the **warning threshold** on `file://` or `localhost`.

3. For a **clean** page, open **`test-fixtures/clean-demo.html`** — you should **not** get a warning.

### Optional: serve over HTTP

From repo root:

```bash
cd eldersafe-extension/test-fixtures && python3 -m http.server 8765
```

Then visit:

- http://localhost:8765/suspicious-demo.html — should warn (if score threshold met)
- http://localhost:8765/clean-demo.html — should stay quiet

`localhost` is treated as safe for HTTP in ElderSafe’s insecure-page check.

## Summary

| Goal | What to use |
|------|-------------|
| See Chrome’s built-in blocking | https://testsafebrowsing.appspot.com/ |
| See ElderSafe banner | `suspicious-demo.html` (local) |
| Confirm no false alarm on simple pages | `clean-demo.html` or https://example.com |
