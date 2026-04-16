<div align="center">
  <img src="icons/icon128.png" alt="Magic Fill Logo" width="128">
  <h1>Magic Fill</h1>
  <p><strong>A secure, beautiful, and premium data-fill extension for Chrome and Firefox.</strong></p>
  
  <p>
    <a href="#"><img src="https://img.shields.io/badge/Security-AES--GCM%20%7C%20PBKDF2-success" alt="Security"></a>
  </p>
</div>

## 🚀 Features

- **🔒 Secure Vault**: Protects your data with state-of-the-art AES-GCM encryption and PBKDF2 PIN hashing.
- **🎨 Premium UI/UX**: Features a highly responsive, glassmorphic dark-mode design with smooth micro-animations.
- **⏱️ Auto-Lock Mechanism**: Advanced session management via `chrome.alarms` and `chrome.idle` to secure your vault when you are away.
- **🛡️ Hardened Security**: Built-in mitigations for XSS and robust storage integrity checks.
- **🦊 Cross-Browser Support**: 100% feature parity and stability across both Google Chrome and Mozilla Firefox.

## 🛠️ Installation

### Chrome
1. Navigate to `chrome://extensions/`
2. Enable **Developer mode** in the top right corner.
3. Click **Load unpacked** and select the `builds/chrome/` directory (after compiling via `build.sh`).

### Firefox
1. Navigate to `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on...**
3. Select any file (e.g., `manifest.json`) in the `builds/firefox/` directory (after compiling via `build.sh`).

## 📦 Building from Source

To generate the packaged extensions for both Chrome and Firefox, simply run the included build script:

```bash
chmod +x build.sh
./build.sh
```

The generated `.zip` packages will be placed in the `builds/` directory.
