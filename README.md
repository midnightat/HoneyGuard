# HoneyGuard

[![CI](https://github.com/midnightat/HoneyGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/midnightat/HoneyGuard/actions/workflows/ci.yml)

**Human Error Protection for Email** — an experimental Chrome extension built with Manifest V3, React, TypeScript, and Vite.

HoneyGuard is an early-stage extension for local, manual hostname checks. It is not a complete security product.

> **Important:** Full phishing protection is not implemented. The popup analyzes only a hostname that you enter; it does not inspect email, verify senders or links, or analyze the current tab. Results are limited signals, not a safety guarantee or confirmed phishing verdict.

## Current status

- A Manifest V3 extension with a popup for manually checking a hostname.
- The popup passes the entered hostname to the local Domain Detection Engine and displays its status, suspicion level, normalized hostname, findings, and explanations.
- Input must be a hostname. URLs and email addresses are not automatically converted or inspected.
- A local Chrome test harness for manually checking browser URL/IDNA behavior against the same cases used by Node.js tests.
- A local Vite build, with no host permissions, email access, or network communication requested by the extension.

## Planned features

These features are not implemented:

- Email sender analysis in Gmail.
- Inspection of the real destinations behind links in email.
- User-managed trusted contacts and domains.
- Clear, explainable warnings about suspicious messages.

The domain engine is used only for manual hostname checks in the popup. It does not inspect actual email, senders, links, or the current tab. Planned email-related checks should run locally where possible; email content should not be sent to external servers.

## Domain Detection Engine

The current engine is an early, limited hostname analyzer. It is not a complete phishing detector:

```ts
import { analyzeHostname } from './src/detection/domain';

const result = analyzeHostname('rnicrosoft.com');
```

The API accepts a hostname only, not a URL or email address. Results are a discriminated union:

- `success` includes `suspicion: none | low | medium | high`, normalized hostname, suffix classification, and explainable findings.
- `invalid` and `unsupported` include a machine-readable `reasonCode` and never have a `suspicion` field.

`none` means that this limited engine found no known signal; it does **not** mean the domain is safe. Even `high` is not a confirmed phishing verdict and never blocks a domain.
`low` is reserved for weak heuristics, `medium` for one strong mechanism, and `high` requires at least two independent strong mechanisms. Multiple algorithms that identify one spoofed label share a mechanism and evidence group and count once.

### Scope and limitations

- Built-in reference domains are only `microsoft.com` and `paypal.com`. Future/custom references can be passed as `trustedDomains`; they do not disable other checks.
- Hostnames use the runtime WHATWG `URL` implementation for IDNA conversion, `punycode` for checked U-label decoding, and `tldts` with ICANN and PRIVATE PSL data. Results can vary with the browser's URL/IDNA version.
- Before IDNA/URL normalization, the API and popup reject input longer than 1,024 UTF-16 code units with `invalid/input_too_long`. This generous pre-normalization ceiling is four times the 253-character canonical DNS hostname limit, leaving headroom for Unicode input and IDNA mapping while bounding synchronous parsing. The normal 63-octet A-label and 253-character canonical hostname checks still apply afterward; input is never silently truncated.
- `.test` is the only special-use suffix analyzed in v0.2, using a clearly marked comparison boundary. Other recognized special-use domains return `unsupported`; unknown suffixes are also `unsupported`, and neither category is suspicious by itself.
- Unicode lookalike mapping is deliberately limited to Latin, Cyrillic, and Greek source characters with Unicode UTS #39 `MA` mappings. This is **not** a UTS #39 skeleton implementation: it does not implement full script resolution, bidi processing, or every Unicode script. Other scripts return `unsupported` rather than an implicit safe result.
- The fixed source snapshot is Unicode 18.0.0 `confusables.txt` from [Unicode security data](https://www.unicode.org/Public/security/latest/confusables.txt), SHA-256 `6ed3ee967c9dfdf6677d563c9985182fbc50a2efb7d6059cd57b2e2ce18f5b92`. The full source is kept under `data/unicode/18.0.0/`; the generated table has 674 mappings (258 multi-code-point outputs, 11,986 bytes raw / about 3.5 KB gzip). The popup bundle includes only this limited table, not the original source. Unicode attribution and source terms are included with the data.
- The analyzer is bundled into the popup. The production JavaScript asset is 374.58 kB raw / 125.99 kB gzip, up from 224.56 kB / 69.90 kB before integration (+150.02 kB raw / +56.09 kB gzip). The CSS asset is 3.13 kB / 1.09 kB gzip, up from 0.94 kB / 0.50 kB (+2.19 kB / +0.59 kB gzip). Figures include the existing engine and can vary with dependency and build-tool versions.
- Similarity is evidence, not proof. The bounded edit-distance signal is weak; correlated methods for one spoofed label share an evidence group. The engine can miss unknown brands or more complex tricks and can flag a legitimate domain that resembles a built-in reference.
- Checks run locally. The analyzer makes no network requests and does not read or send email.

### Local Chrome URL / IDNA harness

The browser harness checks WHATWG `URL` hostname conversion with the same shared fixture file used by the Vitest suite. It makes no external requests and does not access email:

1. Open `chrome://extensions` and enable **Developer mode**.
2. Choose **Load unpacked** and select `tools/domain-test-harness`.
3. Open the **HoneyGuard Domain Test Harness** popup and review the PASS/FAIL results.

The harness exercises Chrome's URL/IDNA behavior only. Browser behavior is not automatically tested in CI, and this manual check does not replace the Node.js engine tests.

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
src/detection/domain/ Standalone hostname parsing and detection engine
data/unicode/         Pinned official Unicode confusables source
scripts/              Offline Unicode table generator
tools/domain-test-harness/ Local Chrome WHATWG URL/IDNA harness
src/main.tsx          Popup entry point
dist/                 Generated extension; load this directory in Chrome
```

HoneyGuard is an early local MVP. Gmail integration, email analysis, a backend, accounts, and payments are outside the scope of this version.

## License

HoneyGuard is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE).

Third-party dependencies remain under their respective licenses.
