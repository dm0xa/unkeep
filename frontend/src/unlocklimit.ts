// A wrong passphrase is only tested in this browser, so the server never sees
// the guess and cannot rate-limit it. This module owns the local attempt budget:
// the first two failures are free, then each further failure adds a cooldown
// that is kept per link in sessionStorage and survives a reload.
export interface UnlockAttempts {
  attempts: number;
  lockedUntil: number;
}

const UNLOCK_DELAYS_SECONDS = [0, 0, 0, 5, 15, 60, 180, 300];

export function readUnlockAttempts(storageKey: string): UnlockAttempts {
  try {
    const raw = globalThis.sessionStorage?.getItem(storageKey);
    if (!raw) {
      return { attempts: 0, lockedUntil: 0 };
    }
    const parsed = JSON.parse(raw) as Partial<UnlockAttempts>;
    return {
      attempts: Math.max(0, Math.floor(Number(parsed.attempts) || 0)),
      lockedUntil: Math.max(0, Number(parsed.lockedUntil) || 0),
    };
  } catch {
    return { attempts: 0, lockedUntil: 0 };
  }
}

export function writeUnlockAttempts(
  storageKey: string,
  state: UnlockAttempts,
): void {
  try {
    if (state.attempts === 0) {
      globalThis.sessionStorage?.removeItem(storageKey);
      return;
    }
    globalThis.sessionStorage?.setItem(storageKey, JSON.stringify(state));
  } catch {
    // Storage can be unavailable; the limiter still holds for this page.
  }
}

export function nextUnlockAttempts(
  state: UnlockAttempts,
  now: number,
): UnlockAttempts {
  const attempts = state.attempts + 1;
  return { attempts, lockedUntil: now + unlockDelayMs(attempts) };
}

export function unlockDelayMs(attempts: number): number {
  const index = Math.min(attempts, UNLOCK_DELAYS_SECONDS.length - 1);
  return (UNLOCK_DELAYS_SECONDS[index] ?? 0) * 1000;
}

export function formatWait(seconds: number): string {
  if (seconds < 60) {
    return `${seconds} second${seconds === 1 ? "" : "s"}`;
  }
  const minutes = Math.ceil(seconds / 60);
  return `${minutes} minute${minutes === 1 ? "" : "s"}`;
}
