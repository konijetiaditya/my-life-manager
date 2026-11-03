# Phone test checklist (the things that could NOT be tested without a real Android phone)

Install the debug APK, then tick each line. If any line fails, do not rely on that protection and tell me what you saw.

## Security
- [ ] First launch asks for your name and a PIN; `1234` and `0000` are refused.
- [ ] Settings → Privacy shows **Key protection: PIN + Android Keystore** (not "PIN only").
- [ ] Take a screenshot while the app is open: Android says it is not allowed (or the screenshot is black).
- [ ] Open the recent-apps screen: the app preview is blank.
- [ ] Press Home, wait for the "lock when I leave" time (try "Immediately" first), return: the PIN screen shows and no data is visible.
- [ ] Enter a wrong PIN 3 times: a 30-second wait appears. Close the app completely, reopen: the wait is still there.
- [ ] Turn on fingerprint in Settings, lock the app, unlock with the fingerprint. Then try a finger that is **not** enrolled: it must not unlock.
- [ ] Settings → Change PIN works; the old PIN stops working.
- [ ] Plug the phone into a computer, enable USB debugging, and try `adb backup` or `adb shell run-as app.mylifemanager.personal`: no readable data should be available (release APK: run-as must be refused).
- [ ] Android Settings → Apps → My Life Manager → Permissions: only **Notifications** may appear (and only after you allowed it). No "Internet" in the permission list.

## Features
- [ ] Add a bill, an insurance policy, an investment, gold, silver, a loan, a document with a PDF and a photo; close and reopen: all still there; Open shows the PDF and photo.
- [ ] Reveal a policy number: asks for PIN (or fingerprint) first.
- [ ] Settings → Notifications: turn on Reminders and allow the permission. Press "Send test": a notification arrives in about 5 seconds.
- [ ] Add a reminder for 3 minutes from now: it arrives (a few minutes late is normal). Restart the phone, add another for 3 minutes later: it still arrives.
- [ ] "Hide details on lock screen" on: lock screen shows "A payment is due soon"; off: shows names.
- [ ] Create encrypted backup: the Android share sheet opens; save it to Drive or email it to yourself.
- [ ] Settings → Delete all data, then Restore from backup with the file and password: everything returns, including the attached files.
- [ ] Press the Android Back button on the home screen: the app goes to the background (it does not crash or skip the lock).

## After building, check the APK (computer, optional)
- [ ] `aapt2 dump permissions app-debug.apk` lists no INTERNET and no SCHEDULE_EXACT_ALARM.
