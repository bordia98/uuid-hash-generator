# 🆔 UUID Generator & Cryptographic Hash Calculator

[![GitHub Pages](https://img.shields.io/badge/Hosted%20On-GitHub%20Pages-blue?style=flat-square&logo=github)](https://bordia98.github.io/uuid-hash-generator/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-orange?style=flat-square)](#)
[![Client-Side Privacy](https://img.shields.io/badge/Privacy-100%25%20Client--Side-emerald?style=flat-square)](#)
[![Theme Support](https://img.shields.io/badge/Theme-Light%20%7C%20Dark-purple?style=flat-square)](#)

A high-performance, developer-focused, and 100% client-side **UUID Generator, Validator, and Cryptographic Hash Calculator**. Generate RFC 4122 v4 and modern RFC 9562 v7 time-ordered UUIDs, inspect GUID structures, compute SHA-256, MD5, SHA-512, SHA-1 hashes, and calculate client-side file checksums and HMAC signatures with complete privacy.

🌐 **Live Demo:** [https://bordia98.github.io/uuid-hash-generator/](https://bordia98.github.io/uuid-hash-generator/)

---

## ✨ Features

- 🎲 **Multi-Version UUID Generation:**
  - **UUID v4 (RFC 4122):** Cryptographically secure pseudorandom IDs using browser CSPRNG.
  - **UUID v7 (RFC 9562):** Time-ordered 48-bit Unix millisecond timestamp prefix, ideal for database primary keys and B-Tree indexing.
  - **Bulk Generation:** Produce 1 to 100 UUIDs in one click.
  - **Formatting Options:** Hyphens vs. No Hyphens, Uppercase vs. Lowercase, Braces `{...}` (GUID format).
  - **Export Options:** One-click copy all and direct `.txt` file download.
- 🔍 **UUID Inspector & Validator:**
  - Validates UUID syntax.
  - Detects version (v1, v2, v3, v4, v5, v7) and variant (RFC 4122 / Leach-Salz / Microsoft).
  - Extracts embedded UTC timestamp from v7 and v1 UUIDs.
- 🔒 **Real-Time Cryptographic Text Hashes:**
  - **SHA-256** (256-bit secure hash)
  - **MD5** (128-bit checksums & cache hashing)
  - **SHA-512** (512-bit high-security hashing)
  - **SHA-384** (384-bit hash)
  - **SHA-1** (160-bit legacy/git hash)
- 📁 **Client-Side File Checksum & Integrity:**
  - Drag-and-drop any file to calculate SHA-256, MD5, and SHA-1 checksums directly inside browser memory.
  - **Files are NEVER uploaded to any server.**
- 🔑 **HMAC Generator:**
  - Compute Hash-based Message Authentication Codes with a custom secret key (SHA-256, SHA-512, SHA-384, SHA-1).
  - Returns both Hexadecimal and Base64 outputs.
- 🌓 **Light & Dark Theme:** Sleek modern developer theme with instant switching and persistent local storage.
- 🔒 **Zero Telemetry & 100% Privacy:** Runs entirely in the browser using the W3C Web Crypto API (`crypto.subtle` and `crypto.getRandomValues`).

---

## 🚀 Quick Start / Local Development

Zero build configurations or package managers required.

### Option 1: Open Directly
Open `index.html` in your web browser.

### Option 2: Run with Python 3
```bash
cd uuid-hash-generator
python3 -m http.server 8002
```
Then navigate to `http://localhost:8002`.

---

## 🛠️ Deploying to GitHub Pages

1. Create a GitHub repository named `uuid-hash-generator` under your account (`bordia98/uuid-hash-generator`).
2. Push this directory to the repository `main` branch.
3. In GitHub, open **Settings** > **Pages**.
4. Set **Source** to `Deploy from a branch` with branch `main` and folder `/ (root)`.
5. Your application will be live at:
   ```
   https://bordia98.github.io/uuid-hash-generator/
   ```

---

## 📁 Project Structure

```
uuid-hash-generator/
├── index.html       # Semantic HTML5 markup, meta tags & Schema.org JSON-LD
├── style.css        # Responsive styling with CSS custom properties (Light/Dark)
├── script.js        # Web Crypto API engine + MD5 algorithm + UUID v4/v7 generators
├── robots.txt       # Search engine crawler directives
├── sitemap.xml      # XML sitemap for SEO discovery
├── LICENSE          # MIT Open Source License
└── README.md        # Comprehensive documentation
```

---

## 🔒 Security & Privacy

- **100% In-Browser Execution:** Cryptographic hashing and file parsing occur strictly in your local device memory using native Web Crypto primitives.
- **Zero Network Traffic:** Open browser DevTools Network tab to confirm zero requests are dispatched during hashing or generation.

---

## 📜 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for more information.

Engineered with precision by [bordia98](https://github.com/bordia98).
