const escapeCSS = (s) => (typeof CSS !== 'undefined' && CSS.escape) ? CSS.escape(s) : s.replace(/([\x00-\x1f\x7f]|^-?\d|^-$|\.)/g, '\\$&').replace(/[\[\](){}|\\^$*+?."'`~!@#%&=<>,;:/]/g, '\\$&');
const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
let ajfListenersAdded = false;


const sanitizeProfileData = (data) => {
    if (typeof data !== 'object' || data === null || Array.isArray(data)) return {};
    const clean = {};
    for (const key in data) {
        if (!Object.prototype.hasOwnProperty.call(data, key)) continue;
        if (typeof key === 'string' && typeof data[key] === 'string') {
            clean[key] = data[key];
        }
    }
    return clean;
};

function getTargetMap(profileData) {
  const safeData = sanitizeProfileData(profileData);
  const getWords = (s) => (s || '').replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean).join(' ');
  const normRaw = (s) => (s || '').toLowerCase().replace(/[\s\-_]/g, '');

  const inputs = document.querySelectorAll('input:not([type="hidden"]), select, textarea');
  const targetMap = new Map();

  inputs.forEach(input => {
    const type = input.type ? input.type.toLowerCase() : 'text';
    const validTypes = ['text', 'email', 'tel', 'url', 'number', 'textarea', 'search', 'password', 'date'];
    
    if (input.tagName.toLowerCase() === 'input' && !validTypes.includes(type)) return;
    if (input.readOnly || input.disabled) return;

    let labelText = '';
    const id = input.id || '';
    if (id) {
       const safeId = escapeCSS(id);
       const label = document.querySelector(`label[for="${safeId}"]`);
       if (label) labelText = label.innerText;
       if (!labelText) {
           const anyLabel = document.querySelector(`[for="${safeId}"]`);
           if (anyLabel) labelText = anyLabel.innerText;
       }
    }
    if (!labelText) {
       const label = input.closest('label');
       if (label) labelText = label.innerText;
    }
    if (!labelText) {
       const ariaLabelledBy = input.getAttribute('aria-labelledby');
       if (ariaLabelledBy) {
           const el = document.getElementById(ariaLabelledBy);
           if (el) labelText = el.innerText;
       }
    }
    if (!labelText) {
       let curr = input;
       let depth = 0;
       while (curr && curr !== document.body && depth < 5) {
           let prev = curr.previousElementSibling;
           while (prev) {
               if (prev.querySelector('input, select, textarea')) break;
               const t = prev.innerText || prev.textContent;
               if (t && t.trim().length > 1 && window.getComputedStyle(prev).display !== 'none') {
                   labelText = t.trim();
                   break;
               }
               prev = prev.previousElementSibling;
           }
           if (labelText) break;
           curr = curr.parentElement;
           depth++;
       }
    }

    if (!labelText && input.parentElement) {
       const inputsInParent = input.parentElement.querySelectorAll('input:not([type="hidden"]), select, textarea');
       if (inputsInParent.length === 1) {
           const text = input.parentElement.innerText;
           if (text && text.length < 100) labelText = text.trim();
       }
    }

    const name = input.name || '';
    const placeholder = input.placeholder || '';
    const ariaLabel = input.getAttribute('aria-label') || '';
    
    let groupText = '';
    if (type === 'radio' || type === 'checkbox') {
        const fieldset = input.closest('fieldset');
        if (fieldset) {
            const legend = fieldset.querySelector('legend');
            if (legend) groupText = legend.innerText.trim();
        }
        if (!groupText) {
            let parent = input.parentElement;
            for (let depth = 0; depth < 10 && parent; depth++) {
                let prev = parent.previousElementSibling;
                while (prev) {
                    const txt = prev.innerText || prev.textContent || '';
                    if (txt.length > 3 && txt.length < 200) {
                        groupText = txt.trim(); break;
                    }
                    prev = prev.previousElementSibling;
                }
                if (groupText) break;
                const pText = parent.innerText || '';
                if (pText.includes('?') && pText.length < 300) {
                    groupText = pText.split('?')[0] + '?'; break;
                }
                parent = parent.parentElement;
            }
        }
        if (!labelText) {
            let next = input.nextElementSibling;
            if (next && (next.tagName === 'SPAN' || next.tagName === 'LABEL' || next.tagName === 'B' || next.tagName === 'DIV')) {
                labelText = next.innerText.trim();
            } else if (input.nextSibling && input.nextSibling.nodeType === 3) {
                labelText = input.nextSibling.textContent.trim();
            }
        }
        if (!labelText && input.parentElement) {
            const pt = input.parentElement.innerText.trim();
            if (pt.length < 50) labelText = pt;
        }
    }
    
    if (!id && !name && !placeholder && !ariaLabel && !labelText) return;

    const targets = [id, name, placeholder, ariaLabel, labelText, groupText];
    const wordTargets = targets.map(getWords);
    const rawTargets = targets.map(normRaw);

    let bestMatchVal = null;
    let bestMatchKey = null;
    let bestScore = -1;

    for (const [keyStr, value] of Object.entries(safeData)) {
      const variations = keyStr.split(',').map(k => k.trim()).filter(k => k);
      for (const v of variations) {
        if (!v) continue;
        const wordV = getWords(v);
        const rawV = normRaw(v);
        for (let i = 0; i < targets.length; i++) {
            const target = targets[i]; if (!target) continue;
            const wordT = wordTargets[i];
            const rawT = rawTargets[i];
            let score = -1;
            if (target.toLowerCase() === v.toLowerCase()) score = 100;
            else if (wordT === wordV) score = 95;
            else if (wordV && wordT && new RegExp(`\\b${escapeRegex(wordV)}\\b`).test(wordT)) score = 85;
            else if (wordV && wordT && wordT.includes(wordV)) score = 70;
            else if (rawV && rawT && rawT.includes(rawV) && rawV.length >= 3) score = 50;
            
            if (score < 70 && wordV && wordT) {
                const wordsV = wordV.split(' ');
                const wordsT = wordT.split(' ');
                let matches = 0;
                for (const wv of wordsV) {
                    if (wv.length < 3) { if (wordsT.includes(wv)) matches++; } 
                    else if (wordsT.some(wt => wt === wv || (Math.abs(wt.length - wv.length) <= 1 && wv.split('').filter((c, idx) => wt[idx] === c).length >= wv.length - 1))) matches++;
                }
                const matchRatio = matches / wordsV.length;
                if (matchRatio >= 0.7) score = 72;
                else if (matchRatio >= 0.5) score = 45;
            }
            if (score > 0) {
              const lowerV = v.toLowerCase();
              const isTypeMatch = (type === 'tel' && (lowerV.includes('phone') || lowerV.includes('tel'))) || (type === 'email' && lowerV.includes('email'));
              if (isTypeMatch) score += 5;
              const lenDiff = Math.abs(target.length - v.length);
              score -= Math.min(lenDiff * 0.5, 10); 
            }
            if (score > bestScore) { bestScore = score; bestMatchVal = value; bestMatchKey = v; }
        }
      }
    }
    if (bestScore >= 50 && bestMatchVal !== null) targetMap.set(input, bestMatchVal);
  });
  return targetMap;
}

function selectOptionByValue(input, val) {
    if (!input || !input.options) return false;
    let matchedIndex = -1;
    const lowerVal = val.toLowerCase().trim();
    for (let i = 0; i < input.options.length; i++) {
        const opt = input.options[i];
        if (opt.value.toLowerCase().trim() === lowerVal || opt.text.toLowerCase().trim() === lowerVal) { matchedIndex = i; break; }
    }
    if (matchedIndex === -1) {
        for (let i = 0; i < input.options.length; i++) {
            const opt = input.options[i];
            if (opt.value.toLowerCase().includes(lowerVal) || opt.text.toLowerCase().includes(lowerVal) || lowerVal.includes(opt.text.toLowerCase())) { matchedIndex = i; break; }
        }
    }
    if (matchedIndex !== -1) { input.selectedIndex = matchedIndex; return true; }
    return false;
}

function dispatchEvents(element) {
  const tag = element.tagName.toLowerCase();
  const proto = tag === 'textarea' ? window.HTMLTextAreaElement.prototype : (tag === 'select' ? window.HTMLSelectElement.prototype : window.HTMLInputElement.prototype);
  const nativeSetter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
  if (nativeSetter) nativeSetter.call(element, element.value);
  element.dispatchEvent(new Event('input', { bubbles: true }));
  element.dispatchEvent(new Event('change', { bubbles: true }));
  element.dispatchEvent(new FocusEvent('focus', { bubbles: true }));
  element.dispatchEvent(new FocusEvent('blur', { bubbles: true }));
  if (element._valueTracker) element._valueTracker.setValue(element.value);
}

function scrapeForm() {
    const validTypes = ['text', 'email', 'tel', 'url', 'number', 'search'];
    const inputs = document.querySelectorAll('input:not([type="hidden"]):not([type="password"]), textarea, select');
    const captured = [];
    inputs.forEach(input => {
        try {
            const type = input.type ? input.type.toLowerCase() : 'text';
            if (input.tagName.toLowerCase() === 'input' && !validTypes.includes(type)) return;
            if (input.readOnly || input.disabled) return;
            const val = input.value ? input.value.trim() : '';
            if (!val || val.length < 1) return;
            if (input.tagName.toLowerCase() === 'select' && input.selectedIndex <= 0) return;
            let labelText = '';
            const id = input.id || '';
            if (id) {
               try { const label = document.querySelector(`label[for="${escapeCSS(id)}"]`) || document.querySelector(`[for="${escapeCSS(id)}"]`); if (label) labelText = label.innerText; } catch(e) {}
            }
            if (!labelText) {
                let curr = input; let depth = 0;
                while (curr && curr !== document.body && depth < 5) {
                    let prev = curr.previousElementSibling;
                    while (prev) {
                        if (prev.querySelector('input, select, textarea')) break;
                        const t = prev.innerText || prev.textContent;
                        if (t && t.trim().length > 1 && window.getComputedStyle(prev).display !== 'none') { labelText = t.trim(); break; }
                        prev = prev.previousElementSibling;
                    }
                    if (labelText) break;
                    curr = curr.parentElement; depth++;
                }
            }
            if (!labelText) {
                const iInP = input.parentElement?.querySelectorAll('input:not([type="hidden"]), select, textarea');
                if (iInP && iInP.length === 1) { const text = input.parentElement.innerText; if (text && text.length < 100) labelText = text.trim(); }
            }
            if (!labelText) labelText = input.placeholder || input.name || input.getAttribute('aria-label') || '';
            const cleanKey = (labelText || '').replace(/[:*]/g, '').replace(/\s+/g, ' ').trim();
            if (cleanKey && cleanKey.length > 1) captured.push({ key: cleanKey, val: val });
        } catch(e) {}
    });
    return captured;
}

const attemptInject = () => {
    if (window !== window.top) {
        // Prevent injecting widget in tiny, invisible ad/tracker iframes
        if (window.innerWidth < 200 || window.innerHeight < 200) return false;
    }

    const validInputs = Array.from(document.querySelectorAll('input:not([type="hidden"]), select, textarea')).filter(input => {
        const type = input.type ? input.type.toLowerCase() : 'text';
        const vTypes = ['text', 'email', 'tel', 'url', 'number', 'textarea', 'search', 'password', 'date'];
        return !(input.tagName.toLowerCase() === 'input' && !vTypes.includes(type)) && !input.readOnly && !input.disabled;
    });
    if (validInputs.length > 0) { initFloatingWidget(); return true; }
    return false;
};

if (document.readyState === 'complete' || document.readyState === 'interactive') { 
    attemptInject(); 
    setupObserver(); 
} else { 
    window.addEventListener('DOMContentLoaded', () => { 
        attemptInject(); 
        setupObserver(); 
    }); 
}

function setupObserver() {
    let debounceTimer = null;
    const observer = new MutationObserver(() => { 
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => attemptInject(), 800); 
    });
    const target = document.body || document.documentElement;
    if (target) {
        observer.observe(target, { 
            childList: true, 
            subtree: true,
            attributes: true,
            attributeFilter: ['class', 'style', 'hidden']
        });
    }
}

function initFloatingWidget() {
  if (document.getElementById('ajf-shadow-host')) return;
  const host = document.createElement('div');
  host.id = 'ajf-shadow-host';
  host.style.position = 'fixed';
  host.style.zIndex = '2147483647';
  host.style.bottom = '0';
  host.style.right = '0';
  if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get(['isWidgetHidden'], (res) => {
          if (res.isWidgetHidden) host.style.display = 'none';
      });
  }
  document.body.appendChild(host);

  const shadow = host.attachShadow({ mode: 'open' });
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = chrome.runtime.getURL('content/content.css');
  shadow.appendChild(link);

  const widget = document.createElement('div');
  widget.id = 'ajf-floating-widget'; widget.innerHTML = '✨'; widget.title = "Form Auto Filler";
  const panel = document.createElement('div');
  panel.id = 'ajf-floating-panel';
  shadow.appendChild(widget); shadow.appendChild(panel);

  const previewValues = new Map();
  const cleanTooltips = () => {
      previewValues.forEach((origMap, input) => {
         input.classList.remove('ajf-highlight');
         if (input.tagName.toLowerCase() === 'select') input.selectedIndex = origMap.selectedIndex;
         else { input.value = origMap.value; input.style.color = origMap.color; }
         dispatchEvents(input);
      });
      previewValues.clear();
      document.querySelectorAll('.ajf-highlight').forEach(el => el.classList.remove('ajf-highlight'));
  };

  const togglePanel = () => {
    if (panel.classList.contains('show')) {
      panel.classList.remove('show'); widget.classList.remove('open'); cleanTooltips();
      setTimeout(() => widget.innerHTML = '✨', 150);
    } else {
      try {
        if (typeof chrome === 'undefined' || !chrome.storage) {
            panel.innerHTML = '<div class="ajf-header">⚠️ Extension reloaded</div><div style="font-size:13px;opacity:0.8;line-height:1.4;">Please close and reopen the widget.</div>';
            void panel.offsetWidth; panel.classList.add('show'); widget.classList.add('open'); widget.innerHTML = '✕'; return;
        }
        chrome.storage.sync.get(['theme', 'pin'], (res) => {
          if (chrome.runtime.lastError) {
            panel.innerHTML = '<div class="ajf-header">⚠️ Connection lost</div><div style="font-size:13px;opacity:0.8;line-height:1.4;">Please close and reopen the widget.</div>';
            void panel.offsetWidth; panel.classList.add('show'); widget.classList.add('open'); widget.innerHTML = '✕'; return;
          }
          widget.classList.add('open'); widget.innerHTML = '✕';
          if (res.theme === 'light') panel.classList.remove('ajf-dark-theme'); else panel.classList.add('ajf-dark-theme');

          chrome.runtime.sendMessage({ action: 'checkLockState' }, (status) => {
               if (status && status.isLocked) {
                   panel.innerHTML = `
                       <div style="display:flex; flex-direction:column; align-items:center; text-align:center; padding: 10px 0;">
                           <span style="font-size:32px; margin-bottom:8px;">🔒</span>
                           <div class="ajf-header" style="justify-content:center; margin-bottom: 2px;">Vault Locked</div>
                           <div style="font-size:12px; color:inherit; opacity: 0.8; line-height: 1.4;">
                               ${status.lockedUntil ? `Too many attempts. Locked for ${Math.round((status.lockedUntil - Date.now())/1000)}s.` : 'Open extension to unlock.'}
                           </div>
                       </div>`;
                   void panel.offsetWidth; panel.classList.add('show'); return;
               }
                chrome.storage.local.get(['profiles', 'activeProfile'], (pRes) => {
                    let profiles = pRes.profiles || null;
                   panel.innerHTML = ''; 
                    if (!profiles || Object.keys(profiles).length === 0) {
                        panel.innerHTML = '<div class="ajf-header">🤷 No profiles</div><div style="font-size:13px; color:inherit; opacity:0.8; margin-top: 4px; line-height: 1.4;">Open extension to add data.</div>';
                    } else {
                        panel.innerHTML = `<div class="ajf-header">⚡ Magic Actions</div>`;
                        const captureBtn = document.createElement('button');
                        captureBtn.className = 'ajf-capture-btn'; captureBtn.innerHTML = `<span>✨ Capture Filled Form</span>`;
                        const esc = (s) => (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
                        captureBtn.addEventListener('click', (e) => {
                            e.stopPropagation(); const captured = scrapeForm();
                            if (captured.length === 0) { captureBtn.innerHTML = "🤷 No filled data found"; setTimeout(() => { if(captureBtn) captureBtn.innerHTML = "<span>✨ Capture Filled Form</span>"; }, 2000); return; }
                            panel.innerHTML = '<div class="ajf-header">🔍 Review Capture</div>';
                            const list = document.createElement('div'); list.className = 'ajf-review-list';
                            captured.forEach((item) => {
                                const row = document.createElement('div'); row.className = 'ajf-review-row';
                                row.innerHTML = `<div class="ajf-key-cell"><input type="text" value="${esc(item.key)}"></div><div class="ajf-val-cell"><input type="text" value="${esc(item.val)}"></div><div class="ajf-remove-cell" title="Remove">&times;</div>`;
                                row.querySelector('.ajf-remove-cell').onclick = (ev) => { ev.stopPropagation(); row.remove(); };
                                list.appendChild(row);
                            });
                            panel.appendChild(list);
                            const btnRow = document.createElement('div'); btnRow.className = 'ajf-btn-row';
                            const cancelBtn = document.createElement('button'); cancelBtn.className = 'ajf-btn ajf-btn-cancel'; cancelBtn.textContent = 'Cancel';
                            const confirmBtn = document.createElement('button'); confirmBtn.className = 'ajf-btn ajf-btn-save'; confirmBtn.textContent = 'Save This Data';
                            btnRow.appendChild(cancelBtn); btnRow.appendChild(confirmBtn); panel.appendChild(btnRow);
                            cancelBtn.onclick = () => togglePanel();
                            confirmBtn.onclick = () => {
                                const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
                                const newData = Object.create(null);
                                panel.querySelectorAll('.ajf-review-row').forEach(r => {
                                    const k = r.querySelector('.ajf-key-cell input').value.trim();
                                    const v = r.querySelector('.ajf-val-cell input').value.trim();
                                    if (k && !dangerousKeys.includes(k)) newData[k] = v;
                                });
                                 chrome.storage.local.get(['activeProfile', 'profiles'], (res) => {
                                     const act = res.activeProfile || Object.keys(res.profiles || {})[0] || "Default Profile";
                                     const p = res.profiles || {}; if (!p[act]) p[act] = {}; Object.assign(p[act], newData);
                                     chrome.storage.local.set({ profiles: p }, () => { confirmBtn.textContent = '✓ Saved!'; setTimeout(() => togglePanel(), 800); });
                                 });
                            };
                        });
                        panel.appendChild(captureBtn);
                        const expandSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px;"><polyline points="6 9 12 15 18 9"></polyline></svg>`;
                        const copySvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="width:12px;height:12px;"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"></path><rect x="8" y="2" width="8" height="4" rx="1" ry="1"></rect></svg>`;
                        let delay = 0.05; const activePName = pRes.activeProfile || Object.keys(profiles)[0];
                        Object.keys(profiles).forEach(pName => {
                            const row = document.createElement('div'); row.className = 'ajf-profile-row'; if (pName === activePName) row.classList.add('active-profile-row');
                            row.style.animationDelay = `${delay}s`; delay += 0.07;
                            const btnGroup = document.createElement('div'); btnGroup.className = 'ajf-btn-group';
                            const btn = document.createElement('button'); btn.className = 'ajf-profile-btn'; btn.textContent = pName; btn.style.flex = "1";
                            const toggle = document.createElement('div'); toggle.className = 'ajf-copy-toggle'; toggle.innerHTML = expandSvg; toggle.title = "View fields to copy";
                            btnGroup.appendChild(btn); btnGroup.appendChild(toggle); row.appendChild(btnGroup);
                            const fieldsList = document.createElement('div'); fieldsList.className = 'ajf-field-list';
                            const fieldsHeader = document.createElement('div'); fieldsHeader.className = 'ajf-field-header'; fieldsHeader.innerHTML = '<span>Identifiers</span><span>Values</span>';
                            fieldsList.appendChild(fieldsHeader);
                            Object.entries(profiles[pName]).forEach(([k, v]) => {
                                const item = document.createElement('div'); item.className = 'ajf-field-item';
                                item.innerHTML = `<span class="ajf-field-label">${esc(k)}</span><span class="ajf-field-val">${esc(v)}</span><button class="ajf-field-copy" title="Copy value">${copySvg}</button>`;
                                item.querySelector('.ajf-field-copy').onclick = (e) => { e.stopPropagation(); navigator.clipboard.writeText(v).then(() => {
                                    const b = item.querySelector('.ajf-field-copy'); const o = b.innerHTML; b.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round" style="width:12px;height:12px;color:#10b981;"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
                                    setTimeout(() => b.innerHTML = o, 1500);
                                }).catch(() => {
                                    const b = item.querySelector('.ajf-field-copy'); const o = b.innerHTML; b.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="width:12px;height:12px;color:#ef4444;"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`;
                                    setTimeout(() => b.innerHTML = o, 1500);
                                }); };
                                fieldsList.appendChild(item);
                            });
                            row.appendChild(fieldsList);
                            toggle.onclick = (e) => { e.stopPropagation(); const isOpen = fieldsList.classList.toggle('open'); toggle.style.transform = isOpen ? 'rotate(180deg)' : 'rotate(0)'; };
                            btn.addEventListener('mouseenter', () => {
                               const tMap = getTargetMap(profiles[pName]);
                               tMap.forEach((val, input) => {
                                  input.classList.add('ajf-highlight'); previewValues.set(input, { value: input.value, color: input.style.color, selectedIndex: input.selectedIndex });
                                  if (input.tagName.toLowerCase() === 'select') { selectOptionByValue(input, val); dispatchEvents(input); } else { input.value = val; input.style.color = '#10b981'; dispatchEvents(input); }
                               });
                            });
                            btn.addEventListener('mouseleave', () => { cleanTooltips(); });
                            btn.addEventListener('click', () => {
                                cleanTooltips(); const tMap = getTargetMap(profiles[pName]); let filled = 0;
                                tMap.forEach((val, input) => { if (input.tagName.toLowerCase() === 'select') { if (selectOptionByValue(input, val)) { dispatchEvents(input); filled++; } } else { input.value = val; dispatchEvents(input); filled++; } });
                                if (filled === 0) { btn.textContent = `🤷 No matches`; btn.classList.add('error-flash'); setTimeout(() => togglePanel(), 1800); }
                                else {
                                    btn.textContent = `✓ Filled ${filled}`; btn.classList.add('success-flash'); 
                                    const comp = document.title.split('-')[0].split('|')[0].trim() || window.location.hostname;
                                    const MAX_HISTORY = 5000;
                                    chrome.storage.local.get(['appHistory'], (rh) => { 
                                        const h = rh.appHistory || []; 
                                        h.unshift({ company: comp, url: window.location.href, date: new Date().toISOString(), profile: pName }); 
                                        if (h.length > MAX_HISTORY) h.length = MAX_HISTORY;
                                        chrome.storage.local.set({ appHistory: h, activeProfile: pName }); 
                                    });
                                    setTimeout(() => togglePanel(), 900);
                                }
                            });
                            panel.appendChild(row);
                        });
                        void panel.offsetWidth; panel.classList.add('show');
                    }
               });
          });
        });
      } catch (e) {
          console.warn('Magic Fill connection lost.', e);
          panel.innerHTML = '<div class="ajf-header">⚠️ Extension reloaded</div><div style="font-size:13px;opacity:0.8;line-height:1.4;">Please close and reopen the widget.</div>';
          void panel.offsetWidth; panel.classList.add('show'); widget.classList.add('open'); widget.innerHTML = '✕';
      }
    }
  };

  widget.addEventListener('click', togglePanel);
  document.addEventListener('click', (e) => { if (!e.composedPath().includes(widget) && !e.composedPath().includes(panel) && panel.classList.contains('show')) togglePanel(); });
  if (!ajfListenersAdded) {
      ajfListenersAdded = true;
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
          chrome.runtime.onMessage.addListener((msg) => {
              const currentHost = document.getElementById('ajf-shadow-host');
              const currentPanel = currentHost?.shadowRoot?.getElementById('ajf-floating-panel');
              if (!currentHost || !currentPanel) return;
              
              if (msg.action === 'vaultLocked') {
                  if (currentPanel.classList.contains('show')) {
                      currentPanel.innerHTML = `
                          <div style="display:flex; flex-direction:column; align-items:center; text-align:center; padding: 10px 0;">
                              <span style="font-size:32px; margin-bottom:8px;">🔒</span>
                              <div class="ajf-header" style="justify-content:center; margin-bottom: 2px;">Vault Locked</div>
                              <div style="font-size:12px; color:inherit; opacity: 0.8; line-height: 1.4;">
                                  Security timeout reached.<br>Open extension to unlock.
                              </div>
                          </div>`;
                      document.querySelectorAll('.ajf-highlight').forEach(el => el.classList.remove('ajf-highlight'));
                  }
              }
          });
      }

      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.onChanged) {
          chrome.storage.onChanged.addListener((changes, namespace) => {
             const currentHost = document.getElementById('ajf-shadow-host');
             const currentPanel = currentHost?.shadowRoot?.getElementById('ajf-floating-panel');
             if (!currentHost) return;
             
             if (namespace === 'sync' && changes.theme && currentPanel) { 
                 if (changes.theme.newValue === 'dark') currentPanel.classList.add('ajf-dark-theme'); 
                 else currentPanel.classList.remove('ajf-dark-theme'); 
             }
             
             if (namespace === 'local' && changes.isWidgetHidden !== undefined) {
                 if (changes.isWidgetHidden.newValue) {
                     currentHost.style.display = 'none';
                     if (currentPanel && currentPanel.classList.contains('show')) {
                         currentPanel.classList.remove('show');
                         const widgetNode = currentHost.shadowRoot.getElementById('ajf-floating-widget');
                         if (widgetNode) widgetNode.classList.remove('open');
                         document.querySelectorAll('.ajf-highlight').forEach(el => el.classList.remove('ajf-highlight'));
                         setTimeout(() => { if (widgetNode) widgetNode.innerHTML = '✨'; }, 150);
                     }
                 } else {
                     currentHost.style.display = 'block';
                 }
             }
          });
      }
  }
}
