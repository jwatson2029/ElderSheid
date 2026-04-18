/**
 * ElderSafe — content script
 * Scans the DOM for scam signals, shows banner, enforces Maximum Protection lock.
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

  let bannerEl = null;
  let lockEl = null;
  let lastScore = 0;
  let scanTimer = null;
  let protectionActive = true;

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

  function ensureBanner() {
    if (bannerEl) return bannerEl;
    const root = document.createElement('div');
    root.id = 'eldersafe-root';
    bannerEl = document.createElement('div');
    bannerEl.id = 'eldersafe-banner';
    bannerEl.setAttribute('role', 'alert');
    bannerEl.innerHTML = `
      <div class="eldersafe-inner">
        <span class="eldersafe-badge">⚠ ElderSafe Alert</span>
        <div class="eldersafe-body">
          <p class="eldersafe-title">This page may be dangerous</p>
          <p class="eldersafe-msg" id="eldersafe-msg"></p>
          <div class="eldersafe-meter" aria-hidden="true"><span id="eldersafe-meter-fill" style="width:0%"></span></div>
          <div class="eldersafe-actions">
            <button type="button" class="btn-primary" id="eldersafe-back">Go back safely</button>
            <button type="button" class="btn-ghost" id="eldersafe-dismiss">I understand the risk</button>
            <button type="button" class="btn-danger-outline" id="eldersafe-report">Report scam</button>
          </div>
        </div>
      </div>
    `;
    root.appendChild(bannerEl);
    document.documentElement.appendChild(root);

    document.getElementById('eldersafe-back').addEventListener('click', () => {
      window.history.back();
    });
    document.getElementById('eldersafe-dismiss').addEventListener('click', () => {
      hideBanner();
    });
    document.getElementById('eldersafe-report').addEventListener('click', () => {
      chrome.runtime.sendMessage({
        type: 'REPORT_SCAM',
        url: window.location.href,
      });
    });

    return bannerEl;
  }

  function showBanner(threat) {
    const el = ensureBanner();
    document.getElementById('eldersafe-msg').textContent =
      threat.reason + ' — ask a family member before entering personal information or sending money.';
    const fill = document.getElementById('eldersafe-meter-fill');
    fill.style.width = threat.score + '%';
    el.classList.add('eldersafe-visible');
    document.body.style.marginTop = el.offsetHeight + 'px';
    lastScore = threat.score;

    chrome.runtime.sendMessage(
      { type: 'THREAT_DETECTED', confidence: threat.score, reason: threat.reason },
      () => void chrome.runtime.lastError
    );
  }

  function hideBanner() {
    if (!bannerEl) return;
    bannerEl.classList.remove('eldersafe-visible');
    document.body.style.marginTop = '';
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
  }

  function hideLock() {
    if (lockEl) lockEl.classList.remove('eldersafe-lock-visible');
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
      hideBanner();
      return;
    }

    chrome.storage.local.get([WHITELIST_KEY, 'protectionActive'], (data) => {
      if (chrome.runtime.lastError) return;
      protectionActive = data.protectionActive !== false;
      if (!protectionActive) {
        hideBanner();
        return;
      }

      const host = getHostname();
      if (isWhitelisted(host, data[WHITELIST_KEY])) {
        hideBanner();
        return;
      }

      const threat = computeThreat();
      if (threat.score >= 55) {
        showBanner(threat);
      } else if (bannerEl?.classList.contains('eldersafe-visible') && threat.score < 40) {
        hideBanner();
      }
    });
  }

  function start() {
    refreshLockState();
    runScan();
    scanTimer = window.setInterval(runScan, SCAN_INTERVAL_MS);
    log('Scanner started');
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
    if (msg?.type === 'FOCUS_BANNER' && bannerEl?.classList.contains('eldersafe-visible')) {
      bannerEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
      bannerEl.style.outline = '2px solid #00d4aa';
      window.setTimeout(() => {
        bannerEl.style.outline = '';
      }, 1600);
    }
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
