/** Test-only switches. They exist ONLY in builds made with `--mode test`; production builds
 *  contain none of this code (the condition below is a build-time constant). */
export interface Stubs {
  bio?: { available: boolean; result: boolean };
  notifications?: { permission: 'granted' | 'denied'; scheduled: Array<{ id: number; at: number; title: string; body: string }> };
}
export function stubs(): Stubs | null {
  if (import.meta.env.MODE !== 'test') return null;
  return ((window as unknown as { __mlmStubs?: Stubs }).__mlmStubs ??= {});
}
