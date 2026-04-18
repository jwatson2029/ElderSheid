/**
 * ElderSafe — content script
 * Full-screen block when a threat is detected (no “continue anyway” on the page).
 * Maximum Protection lock uses a separate, higher z-index overlay.
 */

(function () {
  'use strict';

  const LOG = '[ElderSafe:content]';

  const URGENCY_PATTERNS = [
    /\bact\s+now\b/i,
    /\bimmediately\b/i,
    /\bwithin\s+\d+\s*(hour|minute|second)/i,
    /\burgen(t|cy)\b/i,
    /\bsuspended\b/i,
    /\bverify\s+(your\s+)?account\b/i,
    /\blimited\s+time\b/i,
    /\bclick\s+here\s+now\b/i,
    /\bor\s+else\b/i,
    /\blegal\s+action\b/i,
  ];

  const SCAM_PATTERNS = [
    /\bgift\s*card\b/i,
    /\bwire\s+transfer\b/i,
    /\bwestern\s+union\b/i,
    /\bcryptocurrency\b/i,
    /\bbitcoin\b/i,
    /\brecover\s+your\s+funds\b/i,
    /\birs\b.*\bcall\b/i,
    /\bsocial\s+security\b.*\bsuspend/i,
    /\bgrandchild\b.*\bhelp\b/i,
    /\bsend\s+money\b/i,
  ];

  const WHITELIST_KEY = 'whitelist';
  const SCAN_INTERVAL_MS = 2500;

  let blockRoot = null;
  let blockOverlay = null;
  let lockEl = null;
  let scanTimer = null;
  let protectionActive = true;
  let blockVisible = false;
  let lockVisible = false;

  function log(...args) {
    console.log(LOG, ...args);
  }

  function getHostname() {
    try {
      return window.location.hostname.toLowerCase();
    } catch (_) {
      return '';
    }
  }

  function isWhitelisted(host, list) {
    if (!host || !Array.isArray(list)) return false;
    return list.some((entry) => {
      const h = String(entry).toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
      return host === h || host.endsWith('.' + h);
    });
  }

  function collectVisibleText() {
    if (!document.body) return '';
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        if (!node.parentElement) return NodeFilter.FILTER_REJECT;
        const tag = node.parentElement.tagName;
        if (['SCRIPT', 'STYLE', 'NOSCRIPT', 'IFRAME'].includes(tag)) {
          return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      },
    });
    const chunks = [];
    let n;
    while ((n = walker.nextNode())) {
      const t = n.textContent.trim();
      if (t.length > 2) chunks.push(t);
    }
    return chunks.join('\n').slice(0, 80000);
  }

  function countMatches(text, patterns) {
    let c = 0;
    for (const p of patterns) {
      if (p.test(text)) c++;
    }
    return c;
  }

  function hasPasswordField() {
    return !!document.querySelector('input[type="password"]');
  }

  function isInsecurePage() {
    return window.location.protocol === 'http:' && window.location.hostname !== 'localhost';
  }

  function suspiciousHost(host) {
    if (!host) return false;
    const parts = host.split('.');
    if (parts.length > 4) return true;
    const joined = host.replace(/\./g, '');
    const digitRatio = (joined.match(/\d/g) || []).length / Math.max(joined.length, 1);
    if (digitRatio > 0.3 && host.length > 12) return true;
    if (/secure-|verify-|login-|account-|update-/.test(host)) return true;
    return false;
  }

  function computeThreat() {
    const text = collectVisibleText();
    const urgency = countMatches(text, URGENCY_PATTERNS);
    const scam = countMatches(text, SCAM_PATTERNS);
    const pwd = hasPasswordField();
    const insecure = isInsecurePage();
    const hostRisk = suspiciousHost(getHostname());

    let score = 0;
    const reasons = [];

    if (urgency) {
      score += Math.min(urgency * 18, 45);
      reasons.push('Urgent or threatening language');
    }
    if (scam) {
      score += Math.min(scam * 15, 40);
      reasons.push('Common scam payment or impersonation phrases');
    }
    if (pwd && (hostRisk || scam > 0 || urgency > 1)) {
      score += 25;
      reasons.push('Password field on a suspicious page');
    }
    if (insecure && pwd) {
      score += 20;
      reasons.push('Password field on non-HTTPS connection');
    }
    if (hostRisk && (pwd || urgency || scam)) {
      score += 15;
      reasons.push('Unusual or misleading website address');
    }

    score = Math.min(99, Math.round(score));
    const primary = reasons[0] || 'Multiple risk signals';
    return { score, reason: primary, reasons };
  }

  function setPageScrollLocked(locked) {
    const o = locked ? 'hidden' : '';
    document.documentElement.style.overflow = o;
    document.body.style.overflow = o;
  }

  function updateScrollLock() {
    setPageScrollLocked(blockVisible || lockVisible);
  }

  function trapEscape(e) {
    if (!blockVisible) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  }

  function ensureBlockOverlay() {
    if (blockOverlay) return blockOverlay;

    blockRoot = document.createElement('div');
    blockRoot.id = 'eldersafe-root';

    blockOverlay = document.createElement('div');
    blockOverlay.id = 'eldersafe-block-overlay';
    blockOverlay.setAttribute('role', 'alertdialog');
    blockOverlay.setAttribute('aria-modal', 'true');
    blockOverlay.setAttribute('aria-labelledby', 'eldersafe-block-title');
    blockOverlay.innerHTML = `
      <div class="eldersafe-block-backdrop" aria-hidden="true"></div>
      <div class="eldersafe-block-panel">
        <span class="eldersafe-badge">⚠ ElderSafe — full-screen block</span>
        <h2 class="eldersafe-title" id="eldersafe-block-title">This page may be dangerous</h2>
        <p class="eldersafe-msg" id="eldersafe-msg"></p>
        <p class="eldersafe-sub">The site underneath stays visible but blurred. You cannot use it until you leave or close this tab. There is no “continue anyway” button here — a caregiver can whitelist the domain in ElderSafe settings.</p>
        <div class="eldersafe-meter" aria-hidden="true"><span id="eldersafe-meter-fill" style="width:0%"></span></div>
        <div class="eldersafe-actions">
          <button type="button" class="btn-primary" id="eldersafe-back">Go back safely</button>
          <button type="button" class="btn-ghost" id="eldersafe-close-tab">Close this tab</button>
          <button type="button" class="btn-danger-outline" id="eldersafe-report">Report scam</button>
        </div>
      </div>
    `;

    blockRoot.appendChild(blockOverlay);
    document.documentElement.appendChild(blockRoot);

    blockOverlay.addEventListener(
      'click',
      (e) => {
        if (e.target === blockOverlay || e.target.classList.contains('eldersafe-block-backdrop')) {
          e.preventDefault();
          e.stopPropagation();
        }
      },
      true
    );

    document.getElementById('eldersafe-back').addEventListener('click', () => {
      window.history.back();
    });
    document.getElementById('eldersafe-close-tab').addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: 'CLOSE_TAB' }, () => void chrome.runtime.lastError);
    });
    document.getElementById('eldersafe-report').addEventListener('click', () => {
      chrome.runtime.sendMessage({
        type: 'REPORT_SCAM',
        url: window.location.href,
      });
    });

    document.addEventListener('keydown', trapEscape, true);

    return blockOverlay;
  }

  function showBlockOverlay(threat) {
    const el = ensureBlockOverlay();
    document.getElementById('eldersafe-msg').textContent =
      threat.reason + ' — do not enter passwords, codes, or send money. Talk to a family member first.';
    const fill = document.getElementById('eldersafe-meter-fill');
    fill.style.width = threat.score + '%';
    el.classList.add('eldersafe-block-visible');
    blockVisible = true;
    updateScrollLock();

    chrome.runtime.sendMessage(
      { type: 'THREAT_DETECTED', confidence: threat.score, reason: threat.reason },
      () => void chrome.runtime.lastError
    );
  }

  function hideBlockOverlay() {
    if (!blockOverlay) return;
    blockOverlay.classList.remove('eldersafe-block-visible');
    blockVisible = false;
    updateScrollLock();
  }

  function ensureLockOverlay() {
    if (lockEl) return lockEl;
    lockEl = document.createElement('div');
    lockEl.id = 'eldersafe-lock-overlay';
    lockEl.innerHTML = `
      <div class="eldersafe-lock-card">
        <h2>Maximum Protection</h2>
        <p>This browser session is locked until the family password is entered. If you did not turn this on, contact your caregiver.</p>
        <input type="password" id="eldersafe-lock-input" autocomplete="off" placeholder="Family password" />
        <div class="lock-actions">
          <button type="button" class="unlock-btn" id="eldersafe-unlock">Unlock</button>
        </div>
        <p class="lock-err" id="eldersafe-lock-err"></p>
      </div>
    `;
    document.documentElement.appendChild(lockEl);

    const input = lockEl.querySelector('#eldersafe-lock-input');
    const err = lockEl.querySelector('#eldersafe-lock-err');

    lockEl.querySelector('#eldersafe-unlock').addEventListener('click', () => {
      err.textContent = '';
      chrome.runtime.sendMessage(
        { type: 'VERIFY_MAX_PASSWORD', password: input.value },
        (res) => {
          if (chrome.runtime.lastError) {
            err.textContent = 'Could not verify — try again.';
            return;
          }
          if (res?.ok) {
            hideLock();
            input.value = '';
          } else {
            err.textContent = 'Incorrect password.';
          }
        }
      );
    });

    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') lockEl.querySelector('#eldersafe-unlock').click();
    });

    return lockEl;
  }

  function showLock() {
    const el = ensureLockOverlay();
    el.classList.add('eldersafe-lock-visible');
    lockVisible = true;
    updateScrollLock();
  }

  function hideLock() {
    if (lockEl) {
      lockEl.classList.remove('eldersafe-lock-visible');
    }
    lockVisible = false;
    updateScrollLock();
  }

  async function refreshLockState() {
    const local = await chrome.storage.local.get(['maxProtection']);
    const sess = await chrome.storage.session.get(['maxUnlocked']);
    if (local.maxProtection && !sess.maxUnlocked) {
      showLock();
    } else {
      hideLock();
    }
  }

  function runScan() {
    if (!protectionActive) {
      hideBlockOverlay();
      return;
    }

    chrome.storage.local.get([WHITELIST_KEY, 'protectionActive'], (data) => {
      if (chrome.runtime.lastError) return;
      protectionActive = data.protectionActive !== false;
      if (!protectionActive) {
        hideBlockOverlay();
        return;
      }

      const host = getHostname();
      if (isWhitelisted(host, data[WHITELIST_KEY])) {
        hideBlockOverlay();
        return;
      }

      const threat = computeThreat();
      if (threat.score >= 55) {
        showBlockOverlay(threat);
      } else if (blockOverlay?.classList.contains('eldersafe-block-visible') && threat.score < 40) {
        hideBlockOverlay();
      }
    });
  }

  function start() {
    refreshLockState();
    runScan();
    scanTimer = window.setInterval(runScan, SCAN_INTERVAL_MS);
    log('Scanner started (full-screen block mode)');
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.maxProtection) {
      refreshLockState();
    }
    if (area === 'session' && changes.maxUnlocked) {
      refreshLockState();
    }
    if (area === 'local' && changes.protectionActive) {
      runScan();
    }
  });

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type === 'FOCUS_BANNER' && blockOverlay?.classList.contains('eldersafe-block-visible')) {
      const panel = blockOverlay.querySelector('.eldersafe-block-panel');
      if (panel) {
        panel.classList.remove('eldersafe-pulse');
        void panel.offsetWidth;
        panel.classList.add('eldersafe-pulse');
      }
    }
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
