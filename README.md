# HoneyGuard

[![CI](https://github.com/midnightat/HoneyGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/midnightat/HoneyGuard/actions/workflows/ci.yml)

**Human Error Protection for Email** — an experimental Chrome extension built with Manifest V3, React, TypeScript, and Vite.

HoneyGuard is intended to help people spot phishing, lookalike domains, and risky links before acting on email. This repository contains the v0.1.0-alpha extension skeleton; it is not a security product yet.

> **Important:** Phishing detection is not implemented. The extension does not inspect email, verify senders or links, or protect against phishing. Do not rely on it for security decisions.

## Current status

- A Manifest V3 extension with a simple HoneyGuard popup.
- The popup displays “Extension running” and notes that protection is not configured. This is a UI status only; it does not mean that any security checks are active.
- A TypeScript contract for future detection modules.
- A local Vite build, with no host permissions, email access, or network communication requested by the extension.

## Planned features

These features are not implemented:

- Lookalike-domain and Unicode homograph detection.
- Email sender analysis in Gmail.
- Inspection of the real destinations behind links in email.
- User-managed trusted contacts and domains.
- Clear, explainable warnings about suspicious messages.

The planned checks should run locally where possible. Email content should not be sent to external servers.

## Requirements

- Node.js 22 or newer and npm.
- Google Chrome to load and run the unpacked extension.

## Local development

Clone the repository, then install dependencies:

```sh
git clone https://github.com/midnightat/HoneyGuard.git
cd HoneyGuard
npm install
```

Start the Vite development server for UI work:

```sh
npm run dev
```

To build and load the extension in Chrome:

```sh
npm run build
```

1. Open `chrome://extensions`.
2. Turn on **Developer mode**.
3. Select **Load unpacked** and choose the generated `dist` directory.
4. Open the HoneyGuard toolbar popup.

After changing source files, run `npm run build` again and reload the extension from `chrome://extensions`.

## Checks

```sh
npm test
npm run typecheck
npm run build
```

## Project layout

```text
public/manifest.json  Chrome Extension Manifest V3
src/popup/            Popup UI and its test
src/detection/        Types for future detection modules
src/main.tsx          Popup entry point
dist/                 Generated extension; load this directory in Chrome
```

HoneyGuard is an early local MVP. Gmail integration, email analysis, a backend, accounts, and payments are outside the scope of this version.

## License

HoneyGuard is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE).

Third-party dependencies remain under their respective licenses.
