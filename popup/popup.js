document.addEventListener('DOMContentLoaded', () => {
  const sanitize = (val) => {
      if (typeof val === 'string') {
          return val.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').substring(0, 10000);
      }
      if (typeof val === 'object' && val !== null) {
          if (Array.isArray(val)) return val.map(sanitize);
          const out = {};
          const dangerous = ['__proto__', 'constructor', 'prototype'];
          for (const key in val) {
              if (Object.prototype.hasOwnProperty.call(val, key)) {
                  const cleanKey = sanitize(key);
                  if (dangerous.includes(cleanKey)) continue;
                  out[cleanKey] = sanitize(val[key]);
              }
          }
          return out;
      }
      return val;
  };

  // HTML entity escaper for safe innerHTML usage
  const escHTML = (s) => (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');

  // PBKDF2 PIN hashing — 100k iterations, per-user random salt
  const hashPIN = async (pin, salt) => {
      const encoder = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
          'raw', encoder.encode(pin), 'PBKDF2', false, ['deriveBits']
      );
      const hashBuffer = await crypto.subtle.deriveBits(
          { name: 'PBKDF2', salt: encoder.encode(salt), iterations: 100000, hash: 'SHA-256' },
          keyMaterial, 256
      );
      return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  };

  const generateSalt = () => {
      const saltBytes = crypto.getRandomValues(new Uint8Array(16));
      return Array.from(saltBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  };

  const lockScreen = document.getElementById('lock-screen');
  const mainContainer = document.getElementById('main-container');
  const pinInput = document.getElementById('pin-input');
  const unlockBtn = document.getElementById('unlock-btn');
  const lockError = document.getElementById('lock-error');


  const showDialog = (title, msg, type = 'alert', callback = null, options = {}) => {
      const dialog = document.getElementById('custom-dialog-modal');
      const closeBtn = document.getElementById('custom-dialog-close');
      document.getElementById('custom-dialog-title').innerText = title;
      document.getElementById('custom-dialog-msg').innerText = msg;
      
      const input = document.getElementById('custom-dialog-input');
      const cancel = document.getElementById('custom-dialog-cancel');
      const confirm = document.getElementById('custom-dialog-confirm');
      const footer = document.getElementById('custom-dialog-footer');

      // Reset footer layout
      footer.className = type === 'options' ? 'option-list-footer' : '';
      const optionButtons = footer.querySelectorAll('.option-btn');
      optionButtons.forEach(b => b.remove());

      const cleanup = () => { 
          dialog.classList.remove('show'); 
          confirm.onclick = null; cancel.onclick = null; closeBtn.onclick = null;
          const obs = footer.querySelectorAll('.option-btn'); obs.forEach(b => b.remove());
          footer.className = '';
      };

      closeBtn.onclick = () => cleanup();

      if (type === 'options' && options.choices) {
          confirm.style.display = 'none';
          cancel.style.display = 'none';
          options.choices.forEach(choice => {
              const btn = document.createElement('button');
              btn.className = `action-btn option-btn ${choice.danger ? 'danger' : ''}`;
              btn.innerHTML = `
                <div style="width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; background: rgba(255,255,255,0.03); border-radius: 8px;">
                    ${choice.icon || ''}
                </div>
                <span style="flex: 1;">${escHTML(choice.label)}</span>
                ${choice.isCurrent ? '<span class="option-badge current">Current</span>' : ''}
              `;
              btn.onclick = () => { cleanup(); if(callback) callback(choice.value); };
              footer.appendChild(btn);
          });
      } else {
          confirm.style.display = 'inline-flex';
          cancel.style.display = type === 'alert' ? 'none' : 'inline-flex';
          confirm.innerText = options.confirmText || 'OK';
          cancel.innerText = options.cancelText || 'Cancel';
      }

      input.style.display = type === 'prompt' ? 'block' : 'none';
      // Clear previous input value to prevent sensitive data leakage
      input.value = options.defaultValue || '';

      dialog.classList.add('show');

      confirm.onclick = () => { 
          let result = true;
          if (type === 'prompt') result = sanitize(input.value);
          cleanup(); 
          if(callback) callback(result); 
      };
      cancel.onclick = () => { cleanup(); if(callback) callback(false); };
  };

  const encryptVault = async (dataObj, passphrase) => {
      const encoder = new TextEncoder();
      const data = encoder.encode(JSON.stringify(dataObj));
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));

      const keyMaterial = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
      const key = await crypto.subtle.deriveKey(
          { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
          keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt"]
      );

      const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, data);
      
      const toB64 = (buf) => {
          let binary = '';
          const bytes = new Uint8Array(buf);
          for (let i = 0; i < bytes.byteLength; i++) {
              binary += String.fromCharCode(bytes[i]);
          }
          return btoa(binary);
      };
      return {
          ciphertext: toB64(encrypted),
          salt: toB64(salt),
          iv: toB64(iv)
      };
  };

  const decryptVault = async (vaultObj, passphrase) => {
      if (!vaultObj.iv || !vaultObj.salt) throw new Error('Unsupported vault format. Only v3+ AES-GCM encrypted vaults can be imported.');
      const fromB64 = (s) => new Uint8Array(atob(s).split('').map(c => c.charCodeAt(0)));
      const ciphertext = fromB64(vaultObj.ciphertext || vaultObj.data);
      const salt = fromB64(vaultObj.salt);
      const iv = fromB64(vaultObj.iv);
      const encoder = new TextEncoder();

      const keyMaterial = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
      const key = await crypto.subtle.deriveKey(
          { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
          keyMaterial, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
      );

      const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ciphertext);
      return JSON.parse(new TextDecoder().decode(decrypted));
  };

  const timeLabels = {"-1":"Browser Close", "0":"On Popup Close", "1":"1 Min", "5":"5 Min", "15":"15 Min", "60":"1 Hour"};

  // MODERN 2026 MARQUEE LOGIC (SINGLE PASS + INSTANT RESET)
  const initModernMarquee = () => {
      const getTargetViewport = (target) => {
          let vp = target.closest('.marquee-viewport');
          if (vp) return vp;
          const container = target.closest('.management-row, .custom-option, .history-row, .setting-row, .custom-select-trigger');
          if (container) return container.querySelector('.marquee-viewport');
          return null;
      };

      const getTargetContainer = (target) => {
          return target.closest('.management-row, .custom-option, .history-row, .setting-row, .custom-select-trigger') || target.closest('.marquee-viewport');
      };

      const handleMouseEnter = (e) => {
          const viewport = getTargetViewport(e.target);
          if (!viewport) return;

          const content = viewport.querySelector('span, #active-profile-name, #active-timeout-name');
          if (!content || getComputedStyle(content).display === 'none') return;
          if (content.classList.contains('marquee-active')) return;

          const distance = content.scrollWidth - viewport.offsetWidth;
          
          if (distance > 0) {
              viewport.classList.add('has-overflow');
              const speed = 35;
              const duration = (distance + 12) / speed;
              
              content.style.setProperty('--marquee-duration', `${duration}s`);
              content.style.setProperty('--marquee-x', `-${distance + 12}px`);
              content.classList.add('marquee-active');
          } else {
              viewport.classList.remove('has-overflow');
          }
      };

      const handleMouseLeave = (e) => {
          const viewport = getTargetViewport(e.target);
          if (!viewport) return;
          
          const content = viewport.querySelector('span, #active-profile-name, #active-timeout-name');
          if (content) {
              content.classList.remove('marquee-active');
              // Instant snap-back to start
              content.style.transition = 'none';
              content.style.transform = 'translateX(0)';
              // Use timeout to properly reset the transition for the next hover
              setTimeout(() => { if (content) content.style.transition = ''; }, 10);
          }
      };

      document.body.addEventListener('mouseover', (e) => {
          const container = getTargetContainer(e.target);
          if (container && !container.contains(e.relatedTarget)) {
              handleMouseEnter({target: container});
          }
      });
      document.body.addEventListener('mouseout', (e) => {
          const container = getTargetContainer(e.target);
          if (container && !container.contains(e.relatedTarget)) {
              handleMouseLeave({target: container});
          }
      });
  };
  initModernMarquee();


  chrome.storage.sync.get(['theme', 'pin', 'lockTimeout', 'onboarded'], (prefs) => {

      const onboarded = prefs.onboarded;
      if (!onboarded) {
          document.getElementById('onboarding-modal').classList.add('show');
      }

      const themeSwitch = document.getElementById('theme-switch');
      document.body.classList.remove('dark-mode', 'light-mode');

      if (prefs.theme === 'dark') {
          document.body.classList.add('dark-mode');
          if (themeSwitch) themeSwitch.checked = true;
      } else if (prefs.theme === 'light') {
          document.body.classList.add('light-mode');
          if (themeSwitch) themeSwitch.checked = false;
      } else {
          document.body.classList.add('dark-mode');
          if (themeSwitch) themeSwitch.checked = true;
          chrome.storage.sync.set({ theme: 'dark' });
      }

      if (prefs.pin) {
          document.getElementById('timeout-row').style.display = 'block';
          document.getElementById('lock-now-row').style.display = 'flex';
          const toValue = prefs.lockTimeout || '5';
          document.getElementById('active-timeout-name').textContent = timeLabels[toValue] || "5 Min";
          document.getElementById('pin-btn').innerHTML = '🔒 Change PIN';
          
          // Ask background script for current lock status
          chrome.runtime.sendMessage({ action: 'checkLockState' }, (status) => {
              if (status && status.isLocked) {
                  lockScreen.style.display = 'flex';
                  mainContainer.style.display = 'none';
                  
                  if (status.lockedUntil) {
                      const remaining = Math.ceil((status.lockedUntil - Date.now()) / 1000);
                      if (remaining > 0) {
                          lockError.textContent = `Too many attempts. Try again in ${remaining}s.`;
                          lockError.style.opacity = 1;
                          pinInput.disabled = true;
                          unlockBtn.disabled = true;
                          setTimeout(() => { window.location.reload(); }, status.lockedUntil - Date.now());
                      }
                  }
              } else {
                  lockScreen.style.display = 'none';
                  mainContainer.style.display = 'flex';
                  chrome.storage.local.set({ lastUnlocked: Date.now() });
              }
          });
      }
  });

  const runUnlock = async () => {
      const pin = pinInput.value;
      if (!pin) return;

      chrome.storage.sync.get(['pin', 'pinSalt'], async (res) => {
          if (chrome.runtime.lastError || !res.pin || !res.pinSalt) return;

          const hashed = await hashPIN(pin, res.pinSalt);

          if (hashed === res.pin) {
              chrome.storage.local.set({ lastUnlocked: Date.now(), failedAttempts: 0, lockoutUntil: 0 }, () => {
                  chrome.runtime.sendMessage({ action: 'unlockSession' }, () => {
                      lockScreen.style.display = 'none';
                      mainContainer.style.display = 'flex';
                      pinInput.value = '';
                  });
              });
          } else {
              chrome.storage.local.get(['failedAttempts'], (lRes) => {
                  const attempts = (lRes.failedAttempts || 0) + 1;
                  let msg = "Incorrect PIN.";
                  let lockout = 0;

                  if (attempts >= 5) {
                      lockout = Date.now() + (Math.min(attempts - 4, 5) * 30000); // 30s, 60s, 90s...
                      msg = `Too many attempts. Locked for ${Math.round((lockout - Date.now())/1000)}s.`;
                      chrome.storage.local.set({ lockoutUntil: lockout });
                  }

                  chrome.storage.local.set({ failedAttempts: attempts }, () => {
                      lockError.textContent = msg;
                      lockError.style.opacity = 1;
                      pinInput.value = '';
                      if (lockout > 0) {
                          pinInput.disabled = true;
                          unlockBtn.disabled = true;
                          setTimeout(() => window.location.reload(), lockout - Date.now());
                      }
                      setTimeout(() => { if (!pinInput.disabled) lockError.style.opacity = 0; }, 2000);
                  });
              });
          }
      });
  };
  unlockBtn.addEventListener('click', runUnlock);
  pinInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') runUnlock(); });
  pinInput.addEventListener('input', () => { pinInput.value = pinInput.value.replace(/[^0-9]/g, ''); });
  


  const themeSwitch = document.getElementById('theme-switch');
  themeSwitch.addEventListener('change', (e) => {
      const newTheme = e.target.checked ? 'dark' : 'light';
      document.body.classList.remove('dark-mode', 'light-mode');
      document.body.classList.add(`${newTheme}-mode`);
      chrome.storage.sync.set({ theme: newTheme });
  });

  const settingsModal = document.getElementById('settings-modal');
  document.getElementById('settings-btn').addEventListener('click', () => settingsModal.classList.add('show'));
  document.getElementById('close-settings-btn').addEventListener('click', () => settingsModal.classList.remove('show'));
  
  const tTrigger = document.getElementById('timeout-trigger');
  const tContainer = document.getElementById('timeout-dropdown-container');
  const tActive = document.getElementById('active-timeout-name');

  tTrigger.addEventListener('click', () => tContainer.classList.toggle('open'));
  document.addEventListener('click', (e) => { if(!tContainer.contains(e.target)) tContainer.classList.remove('open'); });

  document.querySelectorAll('#timeout-options .custom-option').forEach(opt => {
      opt.addEventListener('click', () => {
          const val = opt.getAttribute('data-val');
          tActive.textContent = opt.textContent;
          chrome.storage.sync.set({ lockTimeout: val });
          tContainer.classList.remove('open');
          
          if (val === "0") showDialog("Auto-Lock Updated", "The extension will lock immediately whenever you close the popup window.", "alert");
          if (val === "-1") showDialog("Auto-Lock Updated", `The extension will remain unlocked globally until you completely exit the ${(globalThis.MagicFill?.isFirefox) ? 'Firefox' : 'Chrome'} browser.`, "alert");
      });
  });

  document.getElementById('lock-now-btn').addEventListener('click', () => {
        chrome.runtime.sendMessage({ action: 'lockSession' }, (response) => {
           if (chrome.runtime.lastError) {
               console.error("Lock failed:", chrome.runtime.lastError);
               window.location.reload();
               return;
           }
           showDialog("Session Locked", "Your vault has been manually secured.", "alert", () => window.location.reload());
        });
  });

  document.getElementById('pin-btn').addEventListener('click', (e) => {
      chrome.storage.sync.get(['pin', 'pinSalt'], (res) => {
          if (chrome.runtime.lastError || !res.pinSalt) return;
          if (res.pin) {
              showDialog('Change PIN', 'Enter your current PIN to authorize change:', 'prompt', async (oldPin) => {
                  if (oldPin && await hashPIN(oldPin, res.pinSalt) === res.pin) {
                      showDialog('Set New PIN', 'Enter a new 4-8 digit PIN:', 'prompt', (newPin) => {
                          const rawPin = (newPin || '').replace(/[^0-9]/g, '');
                          if (rawPin.length >= 4 && rawPin.length <= 8) {
                              showDialog('Confirm New PIN', 'Retype new PIN to verify:', 'prompt', async (confirmPin) => {
                                  if (confirmPin === rawPin) {
                                      const newSalt = generateSalt();
                                      const newHash = await hashPIN(rawPin, newSalt);
                                      chrome.storage.sync.set({ pin: newHash, pinSalt: newSalt });
                                      showDialog('Security Updated', 'Your PIN has been changed successfully.', 'alert');
                                  } else if (confirmPin !== null) {
                                      showDialog("Mismatch", "The PINs you entered did not match.", "alert");
                                  }
                              });
                          } else if (newPin !== null) {
                              showDialog('Invalid PIN', 'PIN must contain 4 to 8 digits.', 'alert');
                          }
                      });
                  } else if (oldPin) showDialog('Authentication Failed', 'The PIN you entered was incorrect.', 'alert');
              });
          }
      });
  });

  // Onboarding Logic
  document.getElementById('onboarding-next-1').addEventListener('click', () => {
      document.getElementById('onboarding-step-1').style.display = 'none';
      document.getElementById('onboarding-step-2').style.display = 'block';
  });

  document.getElementById('onboarding-next-2').addEventListener('click', () => {
      document.getElementById('onboarding-step-2').style.display = 'none';
      document.getElementById('onboarding-step-3').style.display = 'block';
  });

  document.getElementById('onboarding-next-3').addEventListener('click', () => {
      document.getElementById('onboarding-step-3').style.display = 'none';
      document.getElementById('onboarding-step-4').style.display = 'block';
  });

  document.getElementById('onboarding-next-4').addEventListener('click', () => {
      document.getElementById('onboarding-step-4').style.display = 'none';
      document.getElementById('onboarding-step-5').style.display = 'block';
  });

  document.getElementById('onboarding-next-5').addEventListener('click', () => {
      document.getElementById('onboarding-step-5').style.display = 'none';
      document.getElementById('onboarding-step-6').style.display = 'block';
  });

  document.getElementById('onboarding-next-6').addEventListener('click', () => {
      document.getElementById('onboarding-step-6').style.display = 'none';
      document.getElementById('onboarding-step-7').style.display = 'block';
  });

  document.getElementById('onboarding-save-pin').addEventListener('click', async () => {
      const pin1 = document.getElementById('onboarding-pin-1').value;
      const pin2 = document.getElementById('onboarding-pin-2').value;
      const profileName = document.getElementById('onboarding-profile-name').value.trim() || 'Default';
      const rawPin = (pin1 || '').replace(/[^0-9]/g, '');

      if (rawPin.length < 4 || rawPin.length > 8) {
          showDialog('Invalid PIN', "PIN must be between 4 and 8 digits.", "alert");
          return;
      }
      if (pin1 !== pin2) {
          showDialog('Mismatch', "PINs do not match.", "alert");
          return;
      }

      const initialProfiles = {};
      initialProfiles[profileName] = {};

      const newSalt = generateSalt();
      const hashedPin = await hashPIN(rawPin, newSalt);
      chrome.storage.sync.set({ 
          pin: hashedPin,
          pinSalt: newSalt,
          lockTimeout: '5',
          onboarded: true
      }, () => {
          chrome.storage.local.set({
              profiles: initialProfiles,
              activeProfile: profileName
          }, () => {
              document.getElementById('onboarding-modal').classList.remove('show');
              showDialog("🎉 Ready!", `Magic Fill is set up with your '${profileName}' profile. Security PIN is active.`, "alert", () => window.location.reload());
          });
      });
  });

  document.getElementById('edit-lock-btn').addEventListener('click', () => {
      const isLocked = document.body.classList.contains('locked-ui');
      if (isLocked) document.body.classList.remove('locked-ui');
      else document.body.classList.add('locked-ui');
  });

  const runProtected = (callback) => {
      chrome.storage.sync.get(['pin', 'pinSalt'], (res) => {
          if (chrome.runtime.lastError || !res.pin || !res.pinSalt) return callback(null);
          showDialog("Action Requires Authentication", "Please enter your Security PIN to proceed:", "prompt", async (promptPin) => {
              if (promptPin && await hashPIN(promptPin, res.pinSalt) === res.pin) callback(promptPin);
              else if (promptPin) showDialog("Authentication Failed", "The PIN provided was incorrect.", "alert");
          });
      });
  };

  const container = document.getElementById('pairs-container');
  let state = { profiles: { "Default Profile": { 'first_name': '', 'last_name': '' } }, activeProfile: "Default Profile" };

  function loadState() {
    chrome.storage.local.get(['profiles', 'activeProfile'], (res) => {
        if (res.profiles && Object.keys(res.profiles).length > 0) {
            state.profiles = res.profiles;
            state.activeProfile = res.activeProfile || Object.keys(res.profiles)[0];
        }
        updateCustomDropdown();
        renderPairs(document.getElementById('search-input').value);
    });
  }

  const dTrigger = document.getElementById('profile-trigger');
  const dContainer = document.getElementById('profile-dropdown-container');
  const dList = document.getElementById('profile-list-container');
  const activePName = document.getElementById('active-profile-name');

  dTrigger.addEventListener('click', () => dContainer.classList.toggle('open'));
  document.addEventListener('click', (e) => { if(!dContainer.contains(e.target)) dContainer.classList.remove('open'); });


  const renameSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px;"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>`;
  const deleteSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px;"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>`;

  function updateCustomDropdown(searchTerm = '') {
      activePName.textContent = state.activeProfile;
      dList.innerHTML = '';
      const lowerSearch = searchTerm.toLowerCase();

      Object.keys(state.profiles).forEach(pName => {
          const hasMatch = !lowerSearch || pName.toLowerCase().includes(lowerSearch) || 
                           Object.entries(state.profiles[pName]).some(([k, v]) => k.toLowerCase().includes(lowerSearch) || v.toLowerCase().includes(lowerSearch));
          
          if (lowerSearch && !hasMatch) return;

          const opt = document.createElement('div');
          opt.className = 'custom-option';
          if (pName === state.activeProfile) opt.classList.add('selected');
          
          const vPort = document.createElement('div');
          vPort.className = 'marquee-viewport';
          
          const vSpan = document.createElement('span');
          vSpan.textContent = pName;
          
          vPort.appendChild(vSpan);
          opt.appendChild(vPort);

          opt.addEventListener('click', () => {
             saveCurrentUiToState(); state.activeProfile = pName; renderPairs(document.getElementById('search-input').value);
             chrome.storage.local.set({ activeProfile: state.activeProfile });
             updateCustomDropdown(document.getElementById('search-input').value); dContainer.classList.remove('open');
          });
          dList.appendChild(opt);
      });
      renderProfileManagement();
  }

  function renderProfileManagement() {
      const pContainer = document.getElementById('profile-management-container');
      if (!pContainer) return;
      pContainer.innerHTML = '';
      
   Object.keys(state.profiles).forEach(pName => {
       const row = document.createElement('div');
       row.className = 'management-row';
       if (pName === state.activeProfile) row.classList.add("active-row");
       
       const nameViewport = document.createElement('div');
       nameViewport.className = 'marquee-viewport';
       nameViewport.style.marginRight = '12px';
       
       const nameSpan = document.createElement('span');
       nameSpan.style.fontSize = '0.85rem';
       nameSpan.style.fontWeight = '700';
       nameSpan.style.color = 'var(--text)';
       nameSpan.textContent = pName;
       
       if (pName === state.activeProfile) {
           const activeLabel = document.createElement('small');
           activeLabel.className = 'active-badge';
           activeLabel.textContent = 'Active';
           row.appendChild(activeLabel);
       }
       
       nameViewport.appendChild(nameSpan);
       
       const actionsDiv = document.createElement('div');
       actionsDiv.className = 'management-actions';
       
       const renameBtn = document.createElement('button');
       renameBtn.className = 'action-btn mini-action-btn';
       renameBtn.innerHTML = renameSvg;
       renameBtn.title = 'Rename Profile';
       renameBtn.onclick = () => renameProfile(pName);
       
       const deleteBtn = document.createElement('button');
       deleteBtn.className = 'action-btn mini-action-btn danger';
       deleteBtn.innerHTML = deleteSvg;
       deleteBtn.title = 'Delete Profile';
       deleteBtn.onclick = () => deleteProfile(pName);
       
       actionsDiv.appendChild(renameBtn);
       actionsDiv.appendChild(deleteBtn);
       
       row.appendChild(nameViewport);
       row.appendChild(actionsDiv);
       pContainer.appendChild(row);
       

   });
  }

  function renameProfile(oldName) {
      showDialog('Rename Profile', `Rename profile "${oldName}" to:`, 'prompt', (newName) => {
          if (newName && newName !== oldName) {
              if (state.profiles[newName]) return showDialog('Invalid Name', "A profile with this name already exists.", 'alert');
              saveCurrentUiToState();
              state.profiles[newName] = state.profiles[oldName];
              delete state.profiles[oldName];
              if (state.activeProfile === oldName) state.activeProfile = newName;
              updateCustomDropdown(); 
              renderPairs();
              chrome.storage.local.set({ profiles: state.profiles, activeProfile: state.activeProfile });
          }
      });
  }

  function deleteProfile(pName) {
      runProtected(() => {
          showDialog('Delete Profile', `Are you sure you want to permanently delete the profile "${pName}"?`, 'confirm', (agreed) => {
              if (agreed) {
                  delete state.profiles[pName];
                  
                  if (Object.keys(state.profiles).length === 0) {
                      state.profiles["Default Profile"] = {};
                      state.activeProfile = "Default Profile";
                  } else if (state.activeProfile === pName) {
                      state.activeProfile = Object.keys(state.profiles)[0];
                  }
                  
                  updateCustomDropdown();
                  renderPairs();
                  chrome.storage.local.set({ profiles: state.profiles, activeProfile: state.activeProfile });
              }
          });
      });
  }

  document.getElementById('add-profile-setting-btn').addEventListener('click', () => {
    showDialog('Create Profile', 'Enter a new unique profile name:', 'prompt', (name) => {
        if (name && !state.profiles[name]) { 
            saveCurrentUiToState(); state.profiles[name] = {}; state.activeProfile = name; 
            updateCustomDropdown(); renderPairs(); 
            chrome.storage.local.set({ profiles: state.profiles, activeProfile: state.activeProfile }); 
        } 
        else if (name) showDialog('Invalid Name', "A profile with this name already exists.", 'alert');
    });
  });

  function renderPairs(searchTerm = '') {
    container.innerHTML = ''; 
    const data = state.profiles[state.activeProfile] || {};
    let delay = 0; 
    const lowerSearch = searchTerm.toLowerCase();
    
    for (const [key, val] of Object.entries(data)) { 
      if (!lowerSearch || key.toLowerCase().includes(lowerSearch) || val.toLowerCase().includes(lowerSearch)) {
        addRow(key, val, delay); 
        delay += 0.05; 
      }
    }
  }

  const searchInput = document.getElementById('search-input');
  searchInput.addEventListener('input', (e) => {
    const val = e.target.value;
    renderPairs(val);
    updateCustomDropdown(val);
  });

  function addRow(keyText, valText, animDelay = 0) {
    const div = document.createElement('div'); div.className = 'pair-row'; div.style.animationDelay = `${animDelay}s`; div.draggable = true;
    
    const dragHandle = document.createElement('div'); dragHandle.className = 'drag-handle'; for(let i=0;i<6;i++){const d=document.createElement('span');dragHandle.appendChild(d);}
    const keyContainer = document.createElement('div'); keyContainer.className = 'key-container marquee-viewport';
    const keyInput = document.createElement('input'); keyInput.className = 'key-input'; keyInput.value = keyText; keyInput.placeholder = 'e.g. lastName, surname';
    const keySpan = document.createElement('span'); keySpan.className = 'marquee-span'; keySpan.textContent = keyText || 'Untitled';
    keyContainer.appendChild(keyInput); keyContainer.appendChild(keySpan);

    const separator = document.createElement('div'); separator.className = 'val-separator';

    const valContainer = document.createElement('div'); valContainer.className = 'val-container marquee-viewport';
    const valInput = document.createElement('input'); valInput.className = 'val-input'; valInput.value = valText; valInput.placeholder = 'e.g. Doe';
    const valSpan = document.createElement('span'); valSpan.className = 'marquee-span'; valSpan.textContent = valText || '';
    valContainer.appendChild(valInput); valContainer.appendChild(valSpan);
    const copyIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"></path><rect x="8" y="2" width="8" height="4" rx="1" ry="1"></rect></svg>`;
    const checkIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
    
    const copyBtn = document.createElement('button'); 
    copyBtn.className = 'copy-btn read-only-show'; 
    copyBtn.innerHTML = copyIcon; 
    copyBtn.title = 'Copy Value';
    
    const removeBtn = document.createElement('button'); 
    removeBtn.className = 'remove-btn'; 
    removeBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>`;
    


    div.addEventListener('dragstart', () => div.classList.add('dragging'));
    div.addEventListener('dragend', () => { div.classList.remove('dragging'); saveCurrentUiToState(); });
    
    copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(valInput.value).then(() => {
            copyBtn.innerHTML = checkIcon; copyBtn.style.color = '#10b981';
            setTimeout(() => { copyBtn.innerHTML = copyIcon; copyBtn.style.color = ''; }, 1500);
        }).catch(() => {
            copyBtn.innerHTML = '✕'; copyBtn.style.color = '#ef4444';
            setTimeout(() => { copyBtn.innerHTML = copyIcon; copyBtn.style.color = ''; }, 1500);
        });
    });

    removeBtn.addEventListener('click', () => { 
        runProtected(() => {
            showDialog('Remove Field', `Are you sure you want to delete the field '${keyInput.value || 'Untitled'}' from this profile?`, 'confirm', (agreed) => {
                if (agreed) {
                    div.classList.add('removing'); 
                    setTimeout(() => { div.remove(); saveCurrentUiToState(); }, 250); 
                }
            });
        });
    });
    
    div.appendChild(dragHandle); div.appendChild(keyContainer); div.appendChild(separator); div.appendChild(valContainer); div.appendChild(copyBtn); div.appendChild(removeBtn); container.appendChild(div);
  }

  container.addEventListener('dragover', e => {
      e.preventDefault(); const dragging = document.querySelector('.dragging'); if (!dragging) return;
      const draggableElements = [...container.querySelectorAll('.pair-row:not(.dragging)')];
      const afterElement = draggableElements.reduce((closest, child) => {
          const box = child.getBoundingClientRect(); const offset = e.clientY - box.top - box.height / 2;
          if (offset < 0 && offset > closest.offset) { return { offset: offset, element: child }; } 
          else { return closest; }
      }, { offset: Number.NEGATIVE_INFINITY }).element;
      if (afterElement == null) container.appendChild(dragging); else container.insertBefore(dragging, afterElement);
  });

  function saveCurrentUiToState() {
    const rows = container.querySelectorAll('.pair-row'); const newData = {};
    rows.forEach(row => {
      if (row.classList.contains('removing')) return;
      const keyInput = row.querySelector('.key-input');
      const valInput = row.querySelector('.val-input');
      const key = keyInput.value.trim(); 
      const val = valInput.value; 
      
      const keySpan = row.querySelector('.key-container .marquee-span');
      if (keySpan) keySpan.textContent = key || 'Untitled';
      const valSpan = row.querySelector('.val-container .marquee-span');
      if (valSpan) valSpan.textContent = val || '';

      if (key) newData[key] = val;
    });
    if (state.activeProfile) state.profiles[state.activeProfile] = newData;
  }

  document.getElementById('add-btn').addEventListener('click', () => {
      addRow('', '', 0);
      setTimeout(() => container.scrollTop = container.scrollHeight, 10);
  });
  container.addEventListener('focusin', (e) => { 
      if (e.target.closest('.copy-btn')) return;
      if (document.body.classList.contains('locked-ui')) document.body.classList.remove('locked-ui'); 
  });
  
  document.getElementById('save-btn').addEventListener('click', () => {
    saveCurrentUiToState(); const btn = document.getElementById('save-btn'); const orig = btn.textContent;
    btn.textContent = '✓ Saved Successfully'; btn.classList.add('success');
    document.body.classList.add('locked-ui'); 
    chrome.storage.local.set({ profiles: state.profiles, activeProfile: state.activeProfile }, () => {
      if (chrome.runtime.lastError) {
          btn.textContent = '❌ Capacity Full';
          btn.classList.add('danger');
          const errMsg = chrome.runtime.lastError.message || '';
          if (errMsg.includes('MAX_WRITE_OPERATIONS')) {
              showDialog("Slow Down", "Too many saves in a short time. Please wait a minute.", "alert");
          } else if (errMsg.includes('QUOTA_BYTES')) {
              showDialog("Vault Full", "The profile data is too large to sync. Try removing some fields or deleting unused profiles.", "alert");
          } else {
              showDialog("Save Failed", "Storage error: " + errMsg, "alert");
          }
          setTimeout(() => { btn.textContent = orig; btn.classList.remove('danger'); }, 3000);
          return;
      }
      setTimeout(() => { btn.textContent = orig; btn.classList.remove('success'); }, 1500);
    });
  });

  document.getElementById('export-btn').addEventListener('click', () => {
    saveCurrentUiToState();
    const profileCount = Object.keys(state.profiles).length;
    if (profileCount === 0) {
        return showDialog('Export Failed', 'There are no profiles to export.', 'alert');
    }

    showDialog('Set Export Passphrase', 'Create a passphrase to encrypt your vault backup. This is separate from your PIN.', 'prompt', (pass1) => {
        if (!pass1 || pass1.trim().length < 6) {
            if (pass1 !== null) showDialog('Export Failed', 'Passphrase must be at least 6 characters for security.', 'alert');
            return;
        }
        showDialog('Confirm Passphrase', 'Re-enter the passphrase to verify:', 'prompt', async (pass2) => {
            if (pass2 === null) return;
            if (pass1 !== pass2) {
                return showDialog('Mismatch', 'The passphrases did not match. Export aborted.', 'alert');
            }
            try {
                const result = await encryptVault(state.profiles, pass1);
                const vaultBlob = {
                    _magic_fill_vault: true,
                    version: 3,
                    created: new Date().toISOString(),
                    profileCount: profileCount,
                    data: result.ciphertext,
                    salt: result.salt,
                    iv: result.iv
                };
                const jsonStr = JSON.stringify(vaultBlob, null, 2);
                const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `magic_fill_vault_${new Date().toISOString().slice(0, 10)}.json`;
                document.body.appendChild(a);
                a.click();
                setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 100);
                showDialog('Export Complete', `${profileCount} profile(s) exported successfully. Remember your passphrase — it is required to import this vault.`, 'alert');
            } catch (err) {
                showDialog('Export Failed', 'An unexpected error occurred while exporting: ' + (err.message || 'Unknown error'), 'alert');
            }
        });
    });
  });


  document.getElementById('import-btn').addEventListener('click', () => {
      chrome.tabs.create({ url: chrome.runtime.getURL('popup/import.html') });
  });

  // History Modal Logic
  const historyModal = document.getElementById('history-modal');
  const historyList = document.getElementById('history-list-container');

  const renderHistory = (filter = 'all') => {
      chrome.storage.local.get(['appHistory'], (res) => {
          let history = res.appHistory || [];
          historyList.innerHTML = ''; // Clear existing logs
          let filteredHistory = [...history];
          
          if (filter !== 'all') {
              const now = new Date();
              const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();

              if (typeof filter === 'object' && filter.from && filter.to) {
                  const fromTime = new Date(filter.from).getTime();
                  const toTime = new Date(filter.to).setHours(23, 59, 59, 999);
                  filteredHistory = filteredHistory.filter(item => {
                      const t = new Date(item.date).getTime();
                      return t >= fromTime && t <= toTime;
                  });
              } else {
                  const days = parseInt(filter);
                  if (days === 1) {
                      filteredHistory = filteredHistory.filter(item => {
                          const itemDate = new Date(item.date);
                          return itemDate.getFullYear() === now.getFullYear() &&
                                 itemDate.getMonth() === now.getMonth() &&
                                 itemDate.getDate() === now.getDate();
                      });
                  } else {
                      const cutoff = todayStart - ((days - 1) * 24 * 60 * 60 * 1000);
                      filteredHistory = filteredHistory.filter(item => new Date(item.date).getTime() >= cutoff);
                  }
              }
          }

          document.getElementById('history-count-badge').textContent = `${filteredHistory.length} Entries`;
          
          if (filteredHistory.length === 0) {
              historyList.innerHTML = `
                <div style="text-align: center; padding: 40px 20px; opacity: 0.4;">
                    <div style="font-size: 32px; margin-bottom: 10px;">📋</div>
                    <div style="font-size: 13px; font-weight: 600;">${filter === 'all' ? 'No history yet.' : 'No items in this period.'}</div>
                    <div style="font-size: 11px;">Forms you fill will appear here.</div>
                </div>`;
              return;
          }

          historyList.innerHTML = '';
          filteredHistory.forEach(item => {
              const row = document.createElement('div');
              row.className = 'history-row';
              
              const itemUrl = item.url || '';
              const itemCompany = item.company || 'Unknown Site';
              const itemProfile = item.profile || 'Default';
              
              let hostname = '';
              try { hostname = new URL(itemUrl).hostname; } catch(e) { hostname = ''; }

              const dateStr = new Date(item.date).toLocaleDateString(undefined, { 
                  month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' 
              });

              // Skip Chrome-only _favicon API on Firefox
              const isFirefox = globalThis.MagicFill?.isFirefox;
              const faviconUrl = isFirefox
                  ? (hostname ? `https://www.google.com/s2/favicons?domain=${hostname}&sz=32` : '../icons/icon128.png')
                  : (itemUrl ? chrome.runtime.getURL(`/_favicon/?pageUrl=${encodeURIComponent(itemUrl)}&size=32`) : '../icons/icon128.png');
              const fallbackUrl = hostname ? `https://www.google.com/s2/favicons?domain=${hostname}&sz=32` : '../icons/icon128.png';
              
              const firstChar = (itemCompany || ' ').trim().charAt(0).toUpperCase() || '?';
              const bgColors = ['#6366f1', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4'];
              const charCode = firstChar.charCodeAt(0);
              const fallbackBg = bgColors[charCode % bgColors.length];

              // Use escHTML() for all user-controlled data in innerHTML
              row.innerHTML = `
                <div class="history-card-inner">
                    <div class="history-icon-wrapper" style="position: relative;">
                        <div class="history-letter-fallback" style="display:none; position:absolute; top:0; left:0; width:100%; height:100%; align-items:center; justify-content:center; background:${fallbackBg}; color:#fff; font-size:18px; font-weight:800; border-radius:12px; z-index: 1;">${escHTML(firstChar)}</div>
                    </div>
                    <div class="history-body">
                        <div class="history-header-line">
                            <div class="marquee-viewport history-company-viewport" style="display: flex; align-items: center; overflow: hidden; position: relative; flex: 1;">
                                <span class="history-company">${escHTML(itemCompany)}</span>
                            </div>
                        </div>
                        <div class="history-footer-line">
                            <span class="history-profile-badge">${escHTML(itemProfile)}</span>
                            <span class="history-dot">•</span>
                            <span class="history-date-text">${dateStr}</span>
                        </div>
                    </div>
                    <div class="history-action-hint">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                            <polyline points="15 3 21 3 21 9"></polyline>
                            <line x1="10" y1="14" x2="21" y2="3"></line>
                        </svg>
                    </div>
                </div>
              `;

              // Build favicon img programmatically (no inline onerror handlers)
              const iconWrapper = row.querySelector('.history-icon-wrapper');
              const letterFallback = row.querySelector('.history-letter-fallback');
              const img = document.createElement('img');
              img.src = faviconUrl;
              img.style.cssText = 'width:100%; height:100%; object-fit:contain; z-index: 2;';
              img.addEventListener('load', () => { img.style.display = 'block'; });
              img.addEventListener('error', () => {
                  if (!isFirefox && img.src.includes('_favicon')) {
                      img.src = fallbackUrl;
                  } else if (img.src === fallbackUrl && hostname) {
                      img.src = `https://icons.duckduckgo.com/ip3/${hostname}.ico`;
                  } else {
                      img.style.display = 'none';
                      letterFallback.style.display = 'flex';
                  }
              });
              iconWrapper.prepend(img);
              if (itemUrl) row.onclick = () => window.open(itemUrl, '_blank', 'noopener,noreferrer');
              historyList.appendChild(row);
          });
      });
  };

  document.getElementById('history-btn').addEventListener('click', () => {
      renderHistory();
      historyModal.classList.add('show');
  });

  document.getElementById('close-history-btn').addEventListener('click', () => {
      historyModal.classList.remove('show');
  });

  const inlineDateRange = document.getElementById('inline-date-range');
  const inlineFrom = document.getElementById('inline-date-from');
  const inlineTo = document.getElementById('inline-date-to');

  document.querySelectorAll('#history-filter-pills .filter-pill').forEach(pill => {
      pill.addEventListener('click', () => {
          document.querySelectorAll('#history-filter-pills .filter-pill').forEach(p => p.classList.remove('active'));
          pill.classList.add('active');
          
          if (pill.classList.contains('custom')) {
              inlineDateRange.style.display = 'block';
              
              // Initialize default dates if not set
              if (!inlineFrom.value || !inlineTo.value) {
                  chrome.storage.local.get(['appHistory'], (res) => {
                      const history = res.appHistory || [];
                      if (history.length > 0) {
                          const dates = history.map(h => new Date(h.date).toISOString().split('T')[0]).sort();
                          inlineFrom.min = dates[0]; inlineFrom.max = dates[dates.length-1];
                          inlineTo.min = dates[0]; inlineTo.max = dates[dates.length-1];
                          inlineFrom.value = dates[0]; inlineTo.value = dates[dates.length-1];
                          renderHistory({ from: inlineFrom.value, to: inlineTo.value });
                      }
                  });
              } else {
                  renderHistory({ from: inlineFrom.value, to: inlineTo.value });
              }
          } else {
              inlineDateRange.style.display = 'none';
              renderHistory(pill.getAttribute('data-val'));
          }
      });
  });

  const updateInlineHistory = () => {
      if (inlineFrom.value && inlineTo.value) {
          if (new Date(inlineFrom.value) > new Date(inlineTo.value)) {
              // Quick flip if user picks wrong order
              const temp = inlineFrom.value;
              inlineFrom.value = inlineTo.value;
              inlineTo.value = temp;
          }
          renderHistory({ from: inlineFrom.value, to: inlineTo.value });
      }
  };

  inlineFrom.addEventListener('change', updateInlineHistory);
  inlineTo.addEventListener('change', updateInlineHistory);

  const gearSVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px;"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>';
  const trashSVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px;"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>';
  const backSVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px;opacity:0.6;"><polyline points="15 18 9 12 15 6"></polyline></svg>';
  const checkSVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px;opacity:0.6;"><polyline points="20 6 9 17 4 12"></polyline></svg>';

  document.getElementById('auto-cleanup-btn').addEventListener('click', () => {
      chrome.storage.local.get(['appHistoryRetention'], (res) => {
          const currentRetention = res.appHistoryRetention || 0;
          
          showDialog('Audit Strategy', 'Maintain your filling history:', 'options', (choice) => {
              if (choice === 'wipe') {
                  showDialog('Purge All', 'Wipe your entire filling history forever?', 'confirm', (confirmWipe) => {
                      if (confirmWipe) chrome.storage.local.set({ appHistory: [] }, () => renderHistory());
                  });
              } else if (choice === 'policy') {
                  showDialog('Retention Policy', 'Set automatic background cleanup:', 'options', (days) => {
                      if (days !== 'back' && days !== false) {
                          chrome.storage.local.set({ appHistoryRetention: days });
                          showDialog('Updated', `History will keep for ${days === 0 ? 'forever' : days + ' days'}.`, 'alert');
                      } else if (days === 'back') {
                          document.getElementById('auto-cleanup-btn').click();
                      }
                  }, {
                      choices: [
                          { label: 'Keep 24 Hours', value: 1, icon: gearSVG, isCurrent: currentRetention === 1 },
                          { label: 'Keep 1 Week', value: 7, icon: gearSVG, isCurrent: currentRetention === 7 },
                          { label: 'Keep 1 Month', value: 30, icon: gearSVG, isCurrent: currentRetention === 30 },
                          { label: 'Keep Forever', value: 0, icon: gearSVG, isCurrent: currentRetention === 0 },
                          { label: 'Go Back', value: 'back', icon: backSVG }
                      ]
                  });
              }
          }, {
              choices: [
                  { label: 'Wipe All Records', value: 'wipe', icon: trashSVG, danger: true },
                  { label: 'Set Auto-Retention', value: 'policy', icon: gearSVG }
              ]
          });
      });
  });

  loadState();
});
