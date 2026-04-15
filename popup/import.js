document.addEventListener('DOMContentLoaded', () => {

  const sanitize = (val) => {
      if (typeof val === 'string') return val.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').substring(0, 10000);
      if (typeof val === 'object' && val !== null) {
          if (Array.isArray(val)) return val.map(sanitize);
          const out = {};
          const dangerous = ['__proto__', 'constructor', 'prototype'];
          for (const k in val) {
              if (Object.prototype.hasOwnProperty.call(val, k)) {
                  const cleanKey = sanitize(k);
                  if (dangerous.includes(cleanKey)) continue;
                  out[cleanKey] = sanitize(val[k]);
              }
          }
          return out;
      }
      return val;
  };

  const decryptVault = async (vaultObj, passphrase) => {
      if (!vaultObj.salt || !vaultObj.iv) throw new Error('Unsupported vault format. Only v3+ AES-GCM encrypted vaults are accepted.');
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

  const statusBox = document.getElementById('status-box');
  const fileInfo = document.getElementById('file-info');
  const passphraseArea = document.getElementById('passphrase-area');
  const conflictArea = document.getElementById('conflict-area');
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');

  let pendingRaw = null;
  let pendingProfiles = null;

  const showStatus = (msg, type = '') => {
      statusBox.textContent = msg;
      statusBox.className = 'status-box show' + (type ? ' ' + type : '');
  };

  const hideStatus = () => {
      statusBox.className = 'status-box';
  };

  const resetUI = () => {
      hideStatus();
      fileInfo.innerHTML = '';
      passphraseArea.classList.remove('show');
      conflictArea.classList.remove('show');
      document.getElementById('passphrase').value = '';
      pendingRaw = null;
      pendingProfiles = null;
  };

  const validateProfiles = (imp) => {
      if (typeof imp !== 'object' || imp === null || Array.isArray(imp)) throw new Error('Invalid profile structure');
      if (Object.keys(imp).length === 0) throw new Error('The vault file contains no profiles');
      const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
      for (const profileName in imp) {
          if (!Object.prototype.hasOwnProperty.call(imp, profileName)) continue;
          if (dangerousKeys.includes(profileName)) { delete imp[profileName]; continue; }
          if (typeof imp[profileName] !== 'object' || imp[profileName] === null || Array.isArray(imp[profileName])) {
              throw new Error(`Profile "${profileName}" has invalid data`);
          }
          for (const fieldKey in imp[profileName]) {
              if (!Object.prototype.hasOwnProperty.call(imp[profileName], fieldKey)) continue;
              if (dangerousKeys.includes(fieldKey)) { delete imp[profileName][fieldKey]; continue; }
              if (typeof imp[profileName][fieldKey] !== 'string') {
                  imp[profileName][fieldKey] = String(imp[profileName][fieldKey]);
              }
          }
      }
      return sanitize(imp);
  };

  const handleFile = (file) => {
      resetUI();
      if (!file) return;

      if (file.size > 1024 * 1024) {
          return showStatus('File is too large. Maximum allowed size is 1 MB.', 'error');
      }
      if (!file.name.toLowerCase().endsWith('.json')) {
          return showStatus('Invalid file type. Please select a .json vault file.', 'error');
      }

      fileInfo.innerHTML = `Selected: <strong></strong> (${(file.size / 1024).toFixed(1)} KB)`;
      fileInfo.querySelector('strong').textContent = file.name;

      const reader = new FileReader();
      reader.onerror = () => showStatus('Could not read the file. Please try again.', 'error');
      reader.onload = (event) => {
          try {
              let rawText = event.target.result;
              if (rawText.charCodeAt(0) === 0xFEFF) rawText = rawText.slice(1);

              const raw = JSON.parse(rawText);
              if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
                  throw new Error('Invalid file format.');
              }

              if (!raw._magic_fill_vault) {
                  throw new Error('This file was not created by Magic Fill. Only vault files exported from this extension can be imported.');
              }

              if (typeof raw.data !== 'string' || raw.data.length === 0) {
                  throw new Error('Vault file is corrupted: encrypted data payload is missing.');
              }

              pendingRaw = raw;
              showStatus('Vault file recognized. Enter your passphrase to decrypt.', '');
              passphraseArea.classList.add('show');
              document.getElementById('passphrase').focus();

          } catch (err) {
              showStatus(err.message || 'Failed to parse the file.', 'error');
          }
      };
      reader.readAsText(file, 'UTF-8');
  };

  fileInput.addEventListener('change', () => {
      const file = fileInput.files[0];
      if (file) handleFile(file);
      fileInput.value = '';
  });

  dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.classList.add('drag-over');
  });
  dropZone.addEventListener('dragleave', () => {
      dropZone.classList.remove('drag-over');
  });
  dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
  });

  document.getElementById('decrypt-btn').addEventListener('click', async () => {
      if (!pendingRaw) return showStatus('No vault file loaded.', 'error');

      const passphrase = document.getElementById('passphrase').value;
      if (!passphrase || passphrase.trim().length < 1) {
          return showStatus('Passphrase cannot be empty.', 'error');
      }

      try {
          const decrypted = await decryptVault(pendingRaw, passphrase);
          const validated = validateProfiles(decrypted);
          pendingProfiles = validated;
          passphraseArea.classList.remove('show');

          const count = Object.keys(validated).length;
          showStatus(`✅ Decrypted successfully! Found ${count} profile(s).`, 'success');

          chrome.storage.local.get(['profiles'], (res) => {
              processWithProfiles(res.profiles || {});

              function processWithProfiles(existing) {
                  const existingNames = Object.keys(existing);
                  const importedNames = Object.keys(validated);
                  const conflicts = importedNames.filter(n => existingNames.includes(n));

                  if (conflicts.length > 0 && existingNames.length > 0) {
                      const names = conflicts.length <= 3
                          ? conflicts.map(n => `"${n}"`).join(', ')
                          : conflicts.slice(0, 3).map(n => `"${n}"`).join(', ') + ` and ${conflicts.length - 3} more`;
                      document.getElementById('conflict-msg').textContent =
                          `${conflicts.length} profile(s) already exist: ${names}. How would you like to handle this?`;
                      conflictArea.classList.add('show');
                  } else {
                      applyImport(validated, existingNames.length === 0 ? 'fresh' : 'merge');
                  }
              }
          });
      } catch (err) {
          console.error(err);
          showStatus('Decryption failed. The passphrase is incorrect or the vault file is corrupted.', 'error');
      }
  });

  document.getElementById('passphrase').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') document.getElementById('decrypt-btn').click();
  });

  const applyImport = (importedProfiles, strategy) => {
      chrome.storage.local.get(['profiles', 'activeProfile'], (res) => {
          const existing = res.profiles || {};
          let activeProfile = res.activeProfile || '';
          let finalProfiles = {};
          const importedCount = Object.keys(importedProfiles).length;

          if (strategy === 'merge') {
              finalProfiles = { ...existing };
              for (const name in importedProfiles) {
                  if (finalProfiles[name]) {
                      finalProfiles[name] = { ...finalProfiles[name], ...importedProfiles[name] };
                  } else {
                      finalProfiles[name] = importedProfiles[name];
                  }
              }
          } else if (strategy === 'duplicate') {
              finalProfiles = { ...existing };
              for (const name in importedProfiles) {
                  if (finalProfiles[name]) {
                      let counter = 1;
                      let newName = `${name} (${counter})`;
                      while (finalProfiles[newName]) { counter++; newName = `${name} (${counter})`; }
                      finalProfiles[newName] = importedProfiles[name];
                  } else {
                      finalProfiles[name] = importedProfiles[name];
                  }
              }
          } else {
              finalProfiles = importedProfiles;
          }

          if (!finalProfiles[activeProfile]) {
              activeProfile = Object.keys(finalProfiles)[0] || 'Default Profile';
          }

          chrome.storage.local.set({ profiles: finalProfiles, activeProfile: activeProfile }, () => {
              if (chrome.runtime.lastError) {
                  const errorMsg = chrome.runtime.lastError.message || '';
                  showStatus('Import Failed: ' + errorMsg, 'error');
                  return;
              }
              conflictArea.classList.remove('show');
              const label = strategy === 'merge' ? 'merged' : strategy === 'duplicate' ? 'duplicated' : 'loaded';
              statusBox.innerHTML = `✅ ${importedCount} profile(s) ${label} successfully!<br><small style="opacity:0.7">Your profiles are ready in the extension. You can now close this tab.</small>`;
              statusBox.className = 'status-box show success';
              dropZone.style.display = 'none';
              fileInfo.innerHTML = '';

              const closeBtn = document.createElement('button');
              closeBtn.textContent = '✕ Close This Tab';
              closeBtn.className = 'btn btn-close-tab';
              closeBtn.addEventListener('click', () => window.close());
              statusBox.parentElement.appendChild(closeBtn);
          });
      });
  };

  document.getElementById('conflict-merge').addEventListener('click', () => {
      if (pendingProfiles) applyImport(pendingProfiles, 'merge');
  });
  document.getElementById('conflict-duplicate').addEventListener('click', () => {
      if (pendingProfiles) applyImport(pendingProfiles, 'duplicate');
  });
  document.getElementById('conflict-cancel').addEventListener('click', () => {
      conflictArea.classList.remove('show');
      showStatus('Import cancelled.', '');
      pendingProfiles = null;
  });

});
