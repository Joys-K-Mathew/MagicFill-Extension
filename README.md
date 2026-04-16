<div align="center">
  <img src="icons/icon128.png" alt="Magic Fill Logo" width="128">
  <h1>✨ Magic Fill</h1>
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

## 📄 License
MIT License

Copyright (c) 2026 Joys K Mathew

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
