# My Life Manager: Security Report

Version 1.0 · written 2 Nov 2026 · everything below states what was actually done.

## 1. Read this first (honest summary)

No software can honestly be called "unhackable" or "zero vulnerabilities", and this report does not claim that.
What it does claim is limited and specific:

* The app was designed security-first, with the protections listed below.
* The parts that run in a normal browser engine were **tested for real** (section 7).
* The parts that only exist on an Android phone (Keystore, fingerprint prompt, real notifications,
  screenshot blocking) were **written but NOT tested here**, because this build environment has no Android SDK, no phone and no
  access to Google's download servers. They are listed as **NOT RUN** in section 7 and have a phone checklist
  (`docs/PHONE-TEST-CHECKLIST.md`).
* **No APK has been built or tested yet.** See `README.md` for how to build it.
* This is a self-review against OWASP MASVS ideas. It is **not** an independent penetration test or a certification.

## 2. What the app protects, and from whom

| Threat | Protection |
|---|---|
| Someone picks up your unlocked phone later | Lock on leaving the app (default 1 min, can be "immediately"), inactivity auto-lock, PIN or fingerprint |
| Someone guesses your PIN | Argon2id key derivation, growing waits (30 s after 3 wrong tries up to 15 min), a counter that survives restarts and is counted *before* the PIN is checked |
| Someone copies the app's files (e.g. a stolen backup of the phone's storage) | Everything stored is AES-256-GCM encrypted; the key needs your PIN **and** a secret held in the Android Keystore; Android backup of app data is switched off |
| Someone steals your backup file | Backup is AES-256-GCM with a key from Argon2id (64 MiB, 3 passes) on a password you choose |
| Malicious or damaged files / backups | Magic-byte file checks, size limit, name checks, sealed backup entries, restored data sanitised and repaired |
| Script injection (XSS) | All user text is escaped, strict Content-Security-Policy, no remote content |
| Shoulder-surfing, screenshots, recent-apps preview | `FLAG_SECURE` (Android, untested here); optional hiding of details in notifications |
| Spying on the network | The app has **no internet permission** and no network code |

**Not** protected against: a phone that is rooted or infected with malware, someone who knows your PIN and holds the unlocked phone,
a forgotten PIN (data is then unrecoverable by design; restore from your backup).

## 3. Architecture

* Web UI (TypeScript/JavaScript) inside the Android WebView via Capacitor 8. All code, fonts and PDF-viewer files are bundled; nothing is loaded from the internet.
* Security code is in `src/security/` (strict TypeScript): `crypto.ts`, `vault.ts`, `lockout.ts`, `backup.ts`, `files.ts`, `schema.ts`, `repair.ts`, `pinPolicy.ts`.
* Data lives in IndexedDB as encrypted blobs only. Small secrets (device secret, biometric secret, attempt counter) live in Android Keystore-backed storage
  (`@aparajita/capacitor-secure-storage`, which wraps values with an AES-GCM key generated inside the Android Keystore).

## 4. Authentication design

* 4-digit PIN (your choice). Obvious PINs are refused (0000, 1234, runs, repeated pairs, a list of 24 very common ones).
* Wrong-PIN schedule: 1-2 wrong = no wait, 3 = 30 s, 4 = 1 min, 5 = 2 min, 6 = 5 min, 7+ = 15 min each.
  The counter is stored in the secure store and **increased before** each check, so killing the app mid-attempt does not give free guesses.
  Moving the clock backwards does not shorten a wait; a damaged counter is treated as hostile (long wait).
* Fingerprint (optional): Android's strong-biometric prompt (no device-PIN fallback). Success releases a second wrapped copy of the data key.
  Limitation: this is an app-level check on a Keystore-held secret (the Keystore key is not itself bound to the fingerprint), so it protects against a person at the phone, not against an attacker who already runs code inside the app.
* Re-authentication is required for: revealing a policy number, creating a backup, restoring, changing the PIN, turning fingerprint on/off, deleting all data.
  PIN-only (no fingerprint) for: changing PIN, restore, fingerprint on/off, delete all.
* The data key is held in memory as a non-extractable CryptoKey and dropped when the app locks; the screen is blanked first.

## 5. Encryption and key management

| Item | Detail |
|---|---|
| Data key (DEK) | Random 256-bit AES-GCM key, created once on first run |
| What it encrypts | The whole data document and each attached file separately, each with its own random 96-bit IV and its own authenticated "AAD" label (so blobs cannot be swapped or moved) |
| Key-wrapping key (KEK) | HKDF-SHA-256 over `Argon2id(PIN)` **plus** a random 32-byte device secret kept in the Keystore-backed store |
| Argon2id (PIN) | 19 MiB memory, 2 passes, 1 lane, random 16-byte salt (about 86 ms per guess on the server CPU used for testing; phones will differ) |
| Argon2id (backup) | 64 MiB, 3 passes, 1 lane, random 16-byte salt; password minimum 10 characters; limits on the header parameters stop a malicious file from demanding huge memory |
| Backup file | `MLMBK` header, then each entry AES-256-GCM sealed with the header and the entry number as authenticated data, so reordering, truncation or mixing entries is detected |
| Changing PIN | Re-wraps the same data key under the new PIN (new salts) |
| Wipe | Deletes all stored data, the device secret, the biometric secret and the attempt counter |

Honest note on the 4-digit PIN: there are only 10,000 possible PINs. The device secret stops anyone who has only a copy of the files from guessing offline.
But an attacker who can **run code as the app on the phone** (rooted/compromised device) could try all 10,000 PINs at Argon2 speed, minutes to hours depending on the phone,
because the wait timer can be bypassed by someone who controls the app. This is inherent to short PINs. The strongest protection for your data there is a **long backup password** and a locked, updated, un-rooted phone.

## 6. Android permissions and hardening

| Permission / setting | Status | Reason |
|---|---|---|
| `POST_NOTIFICATIONS` | Requested only if you turn reminders on | Show reminders |
| `RECEIVE_BOOT_COMPLETED` | Declared by the notifications plugin | Put reminders back after a phone restart |
| `WAKE_LOCK` | Declared by the notifications plugin | Deliver a reminder while the phone is asleep |
| `USE_BIOMETRIC` | Added by the biometric library when merged (expected) | Fingerprint unlock |
| `INTERNET` | **Removed** (`tools:node="remove"`) | The app never uses the network |
| `SCHEDULE_EXACT_ALARM`, `USE_EXACT_ALARM` | **Removed** | Not needed; reminders can be a few minutes late |
| Camera, storage, contacts, location, microphone | Not requested | Files are chosen through Android's own picker |

Other settings: `allowBackup=false`, empty data-extraction rules (no cloud or device-transfer copy), cleartext traffic off, only `MainActivity` is exported,
the notification receivers and fingerprint activity have no exported entry points, share-sheet file provider limited to the app's cache folder,
`FLAG_SECURE` set before the window is created, recents screenshot disabled (Android 13+), WebView file/content/geolocation access off, WebView remote debugging off,
no analytics, ads, crash reporters or accounts.
Caveat: the final merged manifest could not be produced here (no Android build). Please check it after building: `aapt2 dump permissions app-debug.apk`.

## 7. Test results (only things that were actually run)

Environment: Linux container, Node 22-class toolchain, Chromium via Playwright, 2 Nov 2026.

### 7a. Unit tests: `npm test` → **64 passed, 0 failed** (6 files)
Vault create/unlock/wrong PIN/lockout/change PIN/biometric wrap/wipe/tamper detection, lockout schedule and clock handling, encrypted backups
(round trip, wrong password, tampering, truncation, reordering, hostile KDF parameters), file validation (magic bytes, names, size), restored-data sanitising
(prototype-pollution keys, depth/length caps), record repair, PIN policy.

### 7b. End-to-end tests in desktop Chromium (test build): `node e2e/suite.cjs` → **21 passed, 0 failed** (`e2e/results.json`)
Onboarding and weak PIN rejection · lock screen hides all data · wrong PIN · lockout survives reload and blocks even a force-enabled keypad ·
no readable data in IndexedDB or localStorage (marker string search) and attached PDF stored encrypted (`%PDF` absent) ·
tampered vault is detected · upload refusals (fake PDF, .exe, PNG renamed .pdf, 11 MB) with nothing stored ·
PDF and PNG attachments encrypt, store and open in the viewer · script-injection payloads in every text field of every record type across all pages never execute ·
CSP blocks inline script, inline handlers, outside network requests, `eval` and `new Function` ·
policy number needs the PIN to reveal · lock on leaving the app and on inactivity (blank screen) · change PIN ·
encrypted backup round trip including a file, then wipe-all (verified empty), then restore; wrong password, tampered, junk and truncated backups refused ·
totals (home, investments, gold/silver, loans, year plan) match entered figures · notification scheduling with a **stubbed** OS layer (opt-in only, generic text by default, detailed text when chosen, 60 cap, no past or duplicate ids, nothing when permission denied) ·
fingerprint flow with a **stubbed** OS prompt (unlocks only when the prompt succeeds) · "forgot PIN" erase needs typed confirmation · form validation, save, persist, delete.

### 7c. Other checks run
* `tsc --noEmit` (strict TypeScript): clean.
* `npm audit --omit=dev` (what ships in the app): **0 vulnerabilities**.
* `npm audit` (including build tools): 4 moderate findings in `glob`/`minimatch` used only by build tooling (not shipped). Not fixed (the fix is a breaking upgrade of the Capacitor CLI); review before release.
* Production bundle: contains none of the test hooks; the only own-code network APIs are none (no `fetch`, XHR, WebSocket or beacon calls in `src/`); URLs found in the bundle are text inside the PDF library (w3.org, adobe, xfa.org and similar) and are not requested.
* Static secret scan of `src/`: no keys, tokens or passwords hard-coded.
* XML of the manifest and resources parses; manifest reviewed by reading.

### 7d. NOT RUN (no Android SDK or device available here)
* Building the APK. **No APK exists yet.**
* Android Keystore behaviour and hardware backing (the in-app status shows "PIN only (browser test)" outside Android).
* Real fingerprint prompt, real notifications and their timing, notification permission dialog, reboot rescheduling.
* `FLAG_SECURE` (screenshot and recents blocking), WebView hardening, back-button handling, file picker and share-sheet backup on Android.
* Merged-manifest permission review, MobSF/static APK scan, OWASP MASTG dynamic testing, root-device testing, penetration test, performance on a low-end phone.
Each has a step in `docs/PHONE-TEST-CHECKLIST.md`.

## 8. OWASP MASVS self-assessment (design review, not certification)

| Area | Status |
|---|---|
| STORAGE | Encrypted at rest, no plaintext in app storage (tested in browser); Android backup off (configured, untested); no logs of user data (`loggingBehavior: none`) |
| CRYPTO | Standard primitives only (WebCrypto AES-GCM, HKDF, Argon2id via `hash-wasm`); random IVs; keys not hard-coded; Keystore part untested on device |
| AUTH | PIN with throttling (tested), fingerprint (stubbed test only), re-auth for sensitive actions (tested) |
| NETWORK | No network permission or code (verified by search; permission removal untested on device) |
| PLATFORM | Minimal exports, strict CSP (tested), WebView hardening (written, untested) |
| CODE | Typecheck clean, dependency audit run, no test code in production bundle (verified) |
| RESILIENCE | Not in scope: no root detection or obfuscation (those can be bypassed and would add false confidence) |
| PRIVACY | No analytics, no accounts, no uploads; notifications can hide details |

## 9. Known limitations and unresolved items

1. 4-digit PIN is a small space (see section 5). Use a strong backup password.
2. Fingerprint unlock is an app-level gate (see section 4).
3. The in-browser fallback secret store (used only for development and tests) is **not** hardware-protected; the Android app uses the Keystore.
4. Everything marked NOT RUN above.
5. `style-src 'unsafe-inline'` is needed by the UI's inline styles (scripts remain strictly blocked).
6. `FLAG_SECURE` is always on, so you cannot take screenshots of the app yourself.
7. Reminders can arrive a few minutes late (exact-alarm permission deliberately not used). Phone makers' battery savers can delay or drop them.
8. After a successful PIN the data key stays in the WebView's memory until the app locks; a device-level memory attack is out of scope.
9. When you pick a file or share a backup, Android moves to another app; the lock grace period for this is 90 seconds.
10. Forgetting the PIN means the data is gone unless you have a backup. This is deliberate.
11. Dev-tool audit findings (section 7c).
12. Single-user, single-device: no sync, no multi-profile.
