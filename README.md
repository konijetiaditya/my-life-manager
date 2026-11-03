# My Life Manager

Private, offline personal life manager for Android: bills, loans, insurance, investments, gold, silver, documents, reminders. Encrypted on the phone, no internet permission.

**Status:** web build runs and is tested; **no APK has been built yet** (see HANDOFF.md section 8 to build it). Read `SECURITY.md` for what is and is not verified.

## Try it on a computer (test the real app in a browser)
In a terminal inside this folder:
```
npm install
npm run dev
```
Open the address it prints (for example http://localhost:5173).

## Run the tests
```
npm test
npm run build:test
cd dist-test && python3 -m http.server 4173      # leave this running, open a second terminal:
node e2e/suite.cjs
```

## Build the Android app
See HANDOFF.md section 8 (Android Studio, or the free GitHub Actions workflow). Then follow `docs/PHONE-TEST-CHECKLIST.md`.
