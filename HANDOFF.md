# My Life Manager: complete project handoff (give this file to another AI)

Written 2 Nov 2026. Owner: Aditya, a beginner coder (SAP SD consultant). Explain things simply, give exact commands and where to run them.

## 1. What the app is
A private, offline-first, Android-first personal life manager. Free/open-source tools only, no paid hosting, no cloud AI, no analytics, no accounts.
Brand: "Midnight Emerald & Champagne Gold" (bg #090D0B, card #151E18, emerald #16A765, gold #CBAA62, silver #B9C2CA, fonts Fraunces + Manrope bundled). Logo: dark-green circle, gold open ring, emerald dot, white centre dot.

## 2. Owner's rules (must keep following)
* Security first. Never claim "zero vulnerabilities" or "hack-proof". Never claim a test passed unless it really ran. Disclose limitations.
* Never claim an APK was built unless the file exists. Do not hard-code demo figures into real calculations.
* Free/open-source only; explain any cost first and ask before any significant recurring cost.
* Make reasonable technical decisions without repeated questions. Beginner-friendly instructions.
* The owner approved the Phase 1 prototype and asked for the real app with all security in place.

## 3. Owner-approved design decisions
* Modules: Home dashboard; Bills & Expenses; Loans; Insurance; Year plan (next 12 months of dues); Investments/SIPs; Gold; Silver; combined Precious Metals; Documents; Reminders; More; Settings/Backup/Privacy; App lock.
* Investments: invested amount only. NO current value, NO gain/loss, no market prices. Optional nominee field.
* Gold and silver: only weight and total amount paid (no rates or valuation). Weights are never added together.
* Insurance has "Nominee or beneficiary"; insurance and documents have a "Belongs to" family tag (Self, Spouse, Father, Mother, Child, Other family).
* 4-digit PIN. New logo (replaced an earlier one the owner thought might belong to someone else).
* Free plan note: Claude cannot run scheduled tasks or control browsers/computers for this user.

## 4. Stack
Vite 8, TypeScript 7 (strict) for security code, UI kept as plain JavaScript (`src/ui/app.js`, ported from the approved prototype to preserve the design), Capacitor 8 (`@capacitor/core, app, local-notifications, filesystem, share, android`), `@aparajita/capacitor-secure-storage` 8.0.1 (Android Keystore AES-GCM), `@aparajita/capacitor-biometric-auth` 10.0.0, `hash-wasm` (Argon2id), `pdfjs-dist` 6.4.299 (legacy build, bundled), `@fontsource/fraunces` and `manrope`, vitest 5 + fake-indexeddb, Playwright for e2e. App id `app.mylifemanager.personal`, min SDK 24, target 36.

## 5. Project location and files (`/home/claude/build/mylifemanager`, zipped for the owner)
* `index.html`: shell + strict CSP meta. `src/main.ts`: fonts, CSS, calls `start()`.
* `src/ui/app.js` (UI, pages, forms, lock screens, onboarding, reminders, backup UI), `styles.css`, `extra.css`.
* `src/security/`: `bytes.ts, crypto.ts, vault.ts, lockout.ts, store.ts, files.ts, schema.ts, repair.ts, pinPolicy.ts, backup.ts`.
* `src/platform/`: `env.ts, secretStore.ts, biometric.ts, lifecycle.ts, notify.ts, share.ts, testHooks.ts`.
* `test/` (vitest, 64 tests), `e2e/` (`lib.cjs, suite.cjs`, results in `e2e/results.json`).
* `android/` (Capacitor project, hardened), `scripts/` (`copy-pdfjs.mjs`, `make-icons.cjs`), `public/pdfjs/` (fonts/cmaps/wasm for the PDF viewer), `.github/workflows/android.yml`.
* `SECURITY.md` (full security report), `docs/PHONE-TEST-CHECKLIST.md`, `README.md`, this file.
* npm scripts: `dev, typecheck, build, build:test, test, sync, audit:deps`. Test build (`vite build --mode test --outDir dist-test`) exposes `window.__mlm` and `window.__mlmStubs`; the production build contains neither (verified by search).

## 6. Security design (details)
* Data key (DEK): random 256-bit AES-GCM. Encrypts the whole state JSON (AAD `mlm/vault/v1`) and each attached file separately (AAD `mlm/file/v1/<id>`), random 96-bit IV each. Held only as a non-extractable CryptoKey in memory, dropped on lock.
* KEK = HKDF(Argon2id(PIN) || deviceSecret, kekSalt). Argon2id PIN params: 19456 KiB, t=2, p=1. deviceSecret = 32 random bytes in Keystore-backed secure storage. DEK wrapped with the KEK. Biometric: second wrap under a bioSecret in secure storage, released only after the OS strong-biometric prompt (app-level gate, stated limitation).
* PIN rules: exactly 4 digits; weak PINs refused (repeated digit, runs, repeating pairs, 24 common ones).
* Lockout: 3 wrong = 30 s, then 60, 120, 300, 900 s. Counter stored in secure store, increased BEFORE verification, clock-rollback protection, damaged counter treated as hostile.
* Re-auth for: reveal policy number, create backup, restore, change PIN, toggle fingerprint, delete all (PIN-only for change PIN, restore, fingerprint toggle, delete all).
* Locking: on leaving the app (Immediately / 1 min default / 5 min), inactivity (1/5/15/never, default 5), explicit lock button. Locking blanks the DOM first, flushes pending saves, drops the key. 90 s grace when a file picker or share sheet opens. Android Back button closes modal layers, goes Home, then minimises.
* Backup `.mlmbackup`: `MLMBK` + version + header JSON {kdf, salt, ids} + sealed entries (AES-256-GCM, AAD = header prefix + entry index). Argon2id 65536 KiB, t=3. Password >= 10 chars. KDF params in header are bounded. Restore validates, sanitises (prototype-pollution keys dropped, strings capped, depth limits), repairs records (`repair.ts` drops records with missing/invalid required fields, keeps only 32-hex file ids), checks every file by magic bytes, then replaces everything in one transaction.
* Files: PDF/PNG/JPEG only, magic-byte check, name sanitised and must match type, max 10 MB, stored encrypted by 32-hex id, viewed through blob URLs (images) or pdf.js (isEvalSupported false), revoked on close.
* CSP: `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'none'`. All user text is HTML-escaped.
* Android: `allowBackup=false`, empty data-extraction rules, cleartext off, INTERNET + SCHEDULE_EXACT_ALARM + USE_EXACT_ALARM removed via `tools:node="remove"`, only MainActivity exported, FileProvider limited to cache dir, `FLAG_SECURE` set before window creation, recents screenshot off (API 33+), WebView file/content/geolocation access off, debugging off, `loggingBehavior: none`. Notification channel visibility private; reminder text generic ("A payment is due soon") unless the user turns "hide details" off.
* Reminders: local notifications only, up to 60 scheduled, stable hashed ids, approximate timing. Sources: manual reminders (recurring up to 12 occurrences), bills (lead time), insurance renewal -30/-7 days, document expiry (remind days), SIP dates.

## 7. Status: what was done and tested
* Phase 1 interactive prototype: built, approved by owner.
* Real app: built and runs. `npm run build` succeeds; `tsc --noEmit` clean.
* Unit tests: 64 passed. End-to-end (desktop Chromium, test build): 21 passed (see SECURITY.md section 7). `npm audit --omit=dev`: 0 vulnerabilities; full audit has 4 moderate dev-tool findings (glob/minimatch, build tooling only).
* **NOT RUN / NOT DONE**: no APK was built (the work environment has no Android SDK and cannot reach Google/Gradle/Maven servers; do not try to bypass that block). Keystore, real fingerprint, real notifications, FLAG_SECURE, WebView hardening, merged-manifest permissions, MobSF, MASTG dynamic tests, root testing, pen test are all untested. Phone checklist is in `docs/PHONE-TEST-CHECKLIST.md`.

## 8. How to build the APK (for the owner)
Option A, Android Studio (recommended): install Android Studio; in the project folder run `npm install`, `npm run build`, `npx cap sync android`, `npx cap open android`; then Build > Build APK(s).
Option B, GitHub Actions (free): push the project to a GitHub repo, open Actions > "Build Android APK" > Run workflow; download the artifact `my-life-manager-debug-apk`. This makes a debug-signed APK for personal use.
Run the phone checklist afterwards.

## 9. Known limitations (be honest about these)
4-digit PIN is a small space (mitigated by device secret, Argon2id, waits; a compromised/rooted phone can still brute force it; recommend a strong backup password). Fingerprint is an app-level gate. Browser fallback secret store is not hardware-backed (dev/tests only). `style-src 'unsafe-inline'` needed. FLAG_SECURE blocks the owner's own screenshots. Reminders can be late. Forgot PIN = data gone unless backed up. Single device, no sync. Everything in "NOT RUN".

## 10. Process notes / things to disclose
* Early in the work, commands (`npm init`/`npm i`) were run inside two pre-existing folders, `/home/claude/my-life-manager` and `/home/claude/mlm-app`, altering their package.json/lock/node_modules. The real project is the fresh `/home/claude/build/mylifemanager`; the old folders should be treated as untouched-but-modified and can be deleted.
* The owner sent the "go ahead" message several times; it was treated as design approval.

## 11. Suggested next steps
1) Build the APK (section 8) and run the phone checklist; report failures. 2) Fix anything found; update SECURITY.md with real device results. 3) Consider a release-signed build and Play-style hardening (R8). 4) Optional features later: longer alphanumeric app password option, CSV export, widgets.
