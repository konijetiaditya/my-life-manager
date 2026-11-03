import { isNative } from './env';
import { stubs } from './testHooks';

/** Is fingerprint / face unlock set up on this phone with strong biometrics? */
export async function biometricAvailable(): Promise<boolean> {
  const st = stubs();
  if (st?.bio) return st.bio.available;
  if (!isNative()) return false;
  try {
    const { BiometricAuth } = await import('@aparajita/capacitor-biometric-auth');
    const r = await BiometricAuth.checkBiometry();
    return r.isAvailable && r.strongBiometryIsAvailable;
  } catch {
    return false;
  }
}

/** Ask Android to check the user's biometrics. Returns false on failure or cancel. */
export async function confirmBiometric(reason: string): Promise<boolean> {
  const st = stubs();
  if (st?.bio) return st.bio.result;
  if (!isNative()) return false;
  try {
    const { BiometricAuth, AndroidBiometryStrength } = await import('@aparajita/capacitor-biometric-auth');
    await BiometricAuth.authenticate({
      reason,
      cancelTitle: 'Use PIN',
      allowDeviceCredential: false,
      androidTitle: 'My Life Manager',
      androidSubtitle: reason,
      androidBiometryStrength: AndroidBiometryStrength.strong,
    });
    return true;
  } catch {
    return false;
  }
}
