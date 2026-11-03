import { Capacitor } from '@capacitor/core';

/** True only inside the installed Android app (not in a normal browser). */
export const isNative = (): boolean => Capacitor.isNativePlatform();
