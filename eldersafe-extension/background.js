/**
 * ElderSafe — background service worker (Manifest V3)
 * Handles storage, notifications, password verification, shortcuts, and reporting.
 */

const LOG_PREFIX = '[ElderSafe]';

function log(...args) {
  console.log(LOG_PREFIX, ...args);
}

function logError(...args) {
  console.error(LOG_PREFIX, ...args);
}

/** Simple string hash for demo PIN/password (use Web Crypto in production for stronger schemes). */
async function sha256Hex(text) {
  const enc = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function getLocal(keys) {
  return chrome.storage.local.get(keys);
}

async function getSession(keys) {
  return chrome.storage.session.get(keys);
}

async function setSession(items) {
  return chrome.storage.session.set(items);
}

function showToast(title, message) {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title,
    message,
    priority: 2,
  });
}

async function incrementBlocked() {
  const { blockedToday = 0, blockedTotal = 0 } = await getLocal(['blockedToday', 'blockedTotal']);
  const today = new Date().toDateString();
  const { lastBlockDay } = await getLocal(['lastBlockDay']);
  let next = blockedToday;
  if (lastBlockDay !== today) next = 0;
  next += 1;
  await chrome.storage.local.set({
    blockedToday: next,
    blockedTotal: blockedTotal + 1,
    lastBlockDay: today,
  });
  return next;
}

chrome.runtime.onInstalled.addListener((details) => {
  log('Installed / updated', details.reason);
  if (details.reason === 'install') {
    chrome.storage.local.set({
      whitelist: [],
      maxProtection: false,
      maxPasswordHash: '',
      blockedToday: 0,
      blockedTotal: 0,
      lastBlockDay: new Date().toDateString(),
      lastConfidence: 0,
      protectionActive: true,
    });
    showToast('ElderSafe is ready', 'Real-time scam protection is active.');
  }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    try {
      if (message?.type === 'THREAT_DETECTED') {
        const count = await incrementBlocked();
        const conf = Math.min(99, Math.max(50, Number(message.confidence) || 85));
        await chrome.storage.local.set({ lastConfidence: conf, lastThreatReason: message.reason || '' });
        log('Threat:', message.reason, 'confidence', conf);
        sendResponse({ ok: true, blockedToday: count });
        return;
      }

      if (message?.type === 'REPORT_SCAM') {
        const url = message.url || 'unknown';
        log('Report scam:', url);
        showToast('Report sent', 'Thank you — ElderSafe logged this page for review.');
        sendResponse({ ok: true });
        return;
      }

      if (message?.type === 'CLOSE_TAB') {
        const tabId = _sender?.tab?.id;
        if (tabId != null) {
          await chrome.tabs.remove(tabId);
          sendResponse({ ok: true });
        } else {
          sendResponse({ ok: false, error: 'no_tab' });
        }
        return;
      }

      if (message?.type === 'VERIFY_MAX_PASSWORD') {
        const { maxPasswordHash } = await getLocal(['maxPasswordHash']);
        const attempt = String(message.password || '');
        if (!maxPasswordHash) {
          sendResponse({ ok: false, error: 'not_configured' });
          return;
        }
        const hash = await sha256Hex(attempt);
        if (hash === maxPasswordHash) {
          await setSession({ maxUnlocked: true });
          showToast('ElderSafe', 'Maximum Protection session unlocked.');
          sendResponse({ ok: true });
        } else {
          sendResponse({ ok: false, error: 'incorrect' });
        }
        return;
      }

      if (message?.type === 'GET_STATS') {
        const data = await getLocal([
          'blockedToday',
          'blockedTotal',
          'protectionActive',
          'maxProtection',
          'lastConfidence',
        ]);
        const sess = await getSession(['maxUnlocked']);
        sendResponse({ ok: true, ...data, maxUnlocked: !!sess.maxUnlocked });
        return;
      }

      if (message?.type === 'SET_MAX_PASSWORD') {
        const pwd = String(message.password || '');
        if (pwd.length < 4) {
          sendResponse({ ok: false, error: 'short' });
          return;
        }
        const maxPasswordHash = await sha256Hex(pwd);
        await chrome.storage.local.set({ maxPasswordHash, maxProtection: true });
        await setSession({ maxUnlocked: false });
        sendToastOptional('Maximum Protection enabled', 'A password is required to browse each session.');
        sendResponse({ ok: true });
        return;
      }

      if (message?.type === 'DISABLE_MAX_PROTECTION') {
        await chrome.storage.local.set({ maxProtection: false, maxPasswordHash: '' });
        await setSession({ maxUnlocked: true });
        sendResponse({ ok: true });
        return;
      }

      sendResponse({ ok: false, error: 'unknown_message' });
    } catch (e) {
      logError(e);
      sendResponse({ ok: false, error: String(e) });
    }
  })();
  return true;
});

function sendToastOptional(title, msg) {
  showToast(title, msg);
}

chrome.action.onClicked.addListener(() => {
  chrome.runtime.openOptionsPage();
});

chrome.commands.onCommand.addListener(async (command) => {
  log('Command:', command);
  if (command === 'open-eldersafe-popup') {
    chrome.runtime.openOptionsPage();
  }
  if (command === 'toggle-protection-overlay') {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.id) {
        await chrome.tabs.sendMessage(tab.id, { type: 'FOCUS_BANNER' });
      }
    } catch (_) {
      showToast('ElderSafe', 'No active warning on this page — protection is still running.');
    }
  }
});

// Notify all tabs when max protection / unlock changes
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && (changes.maxProtection || changes.whitelist)) {
    log('Storage changed (local)', Object.keys(changes));
  }
});
