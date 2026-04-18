/**
 * ElderSafe — popup dashboard
 */

(function () {
  const el = (id) => document.getElementById(id);

  const statusPill = el('status-pill');
  const toggleProt = el('toggle-protection');
  const statBlocked = el('stat-blocked');
  const statTotal = el('stat-total');
  const meterFill = el('meter-fill');
  const lastReason = el('last-reason');
  const maxSetup = el('max-setup');
  const maxActive = el('max-active');
  const maxPassword = el('max-password');
  const maxErr = el('max-err');
  const btnEnableMax = el('btn-enable-max');
  const btnDisableMax = el('btn-disable-max');
  const whitelistInput = el('whitelist-input');

  function setProtectionUi(active) {
    if (active) {
      statusPill.textContent = '● Active';
      statusPill.className = 'pill on';
      toggleProt.classList.add('active');
    } else {
      statusPill.textContent = '○ Paused';
      statusPill.className = 'pill off';
      toggleProt.classList.remove('active');
    }
  }

  function refreshStats() {
    chrome.runtime.sendMessage({ type: 'GET_STATS' }, (res) => {
      if (chrome.runtime.lastError || !res?.ok) return;
      statBlocked.textContent = String(res.blockedToday ?? 0);
      statTotal.textContent = String(res.blockedTotal ?? 0);
      const conf = Math.min(99, Math.max(0, Number(res.lastConfidence) || 0));
      meterFill.style.width = conf + '%';
      setProtectionUi(res.protectionActive !== false);

      if (res.maxProtection) {
        maxSetup.style.display = 'none';
        maxActive.style.display = 'block';
      } else {
        maxSetup.style.display = 'block';
        maxActive.style.display = 'none';
      }

      chrome.storage.local.get(['lastThreatReason'], (d) => {
        if (d.lastThreatReason) {
          lastReason.textContent = 'Last signal: ' + d.lastThreatReason;
        }
      });
    });
  }

  toggleProt.addEventListener('click', () => {
    chrome.storage.local.get(['protectionActive'], (d) => {
      const currentlyOn = d.protectionActive !== false;
      const next = !currentlyOn;
      chrome.storage.local.set({ protectionActive: next }, () => {
        setProtectionUi(next);
      });
    });
  });

  btnEnableMax.addEventListener('click', () => {
    maxErr.textContent = '';
    const pwd = maxPassword.value.trim();
    chrome.runtime.sendMessage({ type: 'SET_MAX_PASSWORD', password: pwd }, (res) => {
      if (res?.ok) {
        maxPassword.value = '';
        refreshStats();
      } else if (res?.error === 'short') {
        maxErr.textContent = 'Use at least 4 characters.';
      } else {
        maxErr.textContent = 'Could not enable — try again.';
      }
    });
  });

  btnDisableMax.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'DISABLE_MAX_PROTECTION' }, () => refreshStats());
  });

  document.getElementById('btn-whitelist').addEventListener('click', () => {
    const host = whitelistInput.value.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (!host) return;
    chrome.storage.local.get(['whitelist'], (d) => {
      const list = Array.isArray(d.whitelist) ? d.whitelist : [];
      if (!list.includes(host)) list.push(host);
      chrome.storage.local.set({ whitelist: list }, () => {
        whitelistInput.value = '';
        whitelistInput.placeholder = 'Added ' + host;
        setTimeout(() => {
          whitelistInput.placeholder = 'e.g. chase.com';
        }, 2000);
      });
    });
  });

  refreshStats();
  setInterval(refreshStats, 4000);
})();
