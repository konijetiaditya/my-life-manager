import { isNative } from './env';

/** Calls back when the app goes to the background / comes back, and on the Android back button. */
export async function watchLifecycle(h: { onBackground: () => void; onForeground: () => void; onBack: () => void }): Promise<void> {
  document.addEventListener('visibilitychange', () => (document.hidden ? h.onBackground() : h.onForeground()));
  if (!isNative()) return;
  const { App } = await import('@capacitor/app');
  await App.addListener('appStateChange', ({ isActive }) => (isActive ? h.onForeground() : h.onBackground()));
  await App.addListener('backButton', () => h.onBack());
}

export async function minimizeApp(): Promise<void> {
  if (!isNative()) return;
  const { App } = await import('@capacitor/app');
  await App.minimizeApp();
}
