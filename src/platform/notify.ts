import { isNative } from './env';
import { stubs } from './testHooks';

export interface PlannedNote {
  key: string;
  at: Date;
  title: string;
  body: string;
}

const CHANNEL = 'reminders';
export const MAX_SCHEDULED = 60;

/** Stable positive 31-bit id from a text key, so the same reminder never gets scheduled twice. */
export function noteId(key: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < key.length; i++) {
    h ^= key.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return (h & 0x7fffffff) || 1;
}

export type PermissionState = 'granted' | 'denied' | 'unavailable';

export async function notificationPermission(ask: boolean): Promise<PermissionState> {
  const st = stubs();
  if (st?.notifications) return st.notifications.permission;
  if (!isNative()) return 'unavailable';
  try {
    const { LocalNotifications } = await import('@capacitor/local-notifications');
    let p = await LocalNotifications.checkPermissions();
    if (p.display !== 'granted' && ask) p = await LocalNotifications.requestPermissions();
    return p.display === 'granted' ? 'granted' : 'denied';
  } catch {
    return 'unavailable';
  }
}

/** Replace everything we scheduled earlier with this list. Safe to call often. */
export async function replaceScheduled(notes: PlannedNote[]): Promise<void> {
  const list = notes
    .filter((n) => n.at.getTime() > Date.now() + 5000)
    .sort((a, b) => a.at.getTime() - b.at.getTime())
    .slice(0, MAX_SCHEDULED);
  const st = stubs();
  if (st?.notifications) {
    st.notifications.scheduled = list.map((n) => ({ id: noteId(n.key), at: n.at.getTime(), title: n.title, body: n.body }));
    return;
  }
  if (!isNative()) return;
  const { LocalNotifications } = await import('@capacitor/local-notifications');
  const pending = await LocalNotifications.getPending();
  if (pending.notifications.length) await LocalNotifications.cancel({ notifications: pending.notifications.map((n) => ({ id: n.id })) });
  if (!list.length) return;
  await LocalNotifications.createChannel({
    id: CHANNEL,
    name: 'Reminders',
    description: 'Bill, insurance, document and SIP reminders',
    importance: 3,
    visibility: 0,
    vibration: true,
  });
  const seen = new Set<number>();
  const notifications = list
    .map((n) => ({
      id: noteId(n.key),
      title: n.title,
      body: n.body,
      channelId: CHANNEL,
      schedule: { at: n.at, allowWhileIdle: true },
    }))
    .filter((n) => (seen.has(n.id) ? false : (seen.add(n.id), true)));
  await LocalNotifications.schedule({ notifications });
}

export async function cancelAllScheduled(): Promise<void> {
  await replaceScheduled([]);
}

/** Lets the user check that notifications really arrive on their phone. */
export async function sendTest(delaySeconds = 5): Promise<void> {
  const st = stubs();
  if (st?.notifications) {
    st.notifications.scheduled.push({ id: 1, at: Date.now() + delaySeconds * 1000, title: 'My Life Manager', body: 'Test notification' });
    return;
  }
  if (!isNative()) return;
  const { LocalNotifications } = await import('@capacitor/local-notifications');
  await LocalNotifications.createChannel({ id: CHANNEL, name: 'Reminders', description: 'Bill, insurance, document and SIP reminders', importance: 3, visibility: 0, vibration: true });
  await LocalNotifications.schedule({
    notifications: [{ id: 2147483000, title: 'My Life Manager', body: 'This is a test reminder.', channelId: CHANNEL, schedule: { at: new Date(Date.now() + delaySeconds * 1000), allowWhileIdle: true } }],
  });
}
