import assert from "node:assert/strict";
import test from "node:test";
import {
  formatWait,
  nextUnlockAttempts,
  readUnlockAttempts,
  unlockDelayMs,
  writeUnlockAttempts,
} from "../src/unlocklimit.ts";

class MemoryStorage {
  private readonly data = new Map<string, string>();

  getItem(key: string): string | null {
    return this.data.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.data.set(key, value);
  }

  removeItem(key: string): void {
    this.data.delete(key);
  }
}

function withStorage(run: (storage: MemoryStorage) => void): void {
  const storage = new MemoryStorage();
  const globals = globalThis as unknown as { sessionStorage?: Storage };
  const previous = globals.sessionStorage;
  globals.sessionStorage = storage as unknown as Storage;
  try {
    run(storage);
  } finally {
    if (previous === undefined) {
      Reflect.deleteProperty(globals, "sessionStorage");
    } else {
      globals.sessionStorage = previous;
    }
  }
}

test("the first two failures carry no cooldown", () => {
  const now = 1_800_000_000_000;
  const first = nextUnlockAttempts({ attempts: 0, lockedUntil: 0 }, now);
  const second = nextUnlockAttempts(first, now);
  assert.deepEqual(first, { attempts: 1, lockedUntil: now });
  assert.deepEqual(second, { attempts: 2, lockedUntil: now });
});

test("the cooldown ladder grows and caps at five minutes", () => {
  assert.equal(unlockDelayMs(3), 5_000);
  assert.equal(unlockDelayMs(4), 15_000);
  assert.equal(unlockDelayMs(5), 60_000);
  assert.equal(unlockDelayMs(6), 180_000);
  assert.equal(unlockDelayMs(7), 300_000);
  assert.equal(unlockDelayMs(99), 300_000);
});

test("attempt state survives a reload and clears after success", () => {
  withStorage(() => {
    const key = "unkeep-unlock-test";
    writeUnlockAttempts(key, { attempts: 3, lockedUntil: 5_000 });
    assert.deepEqual(readUnlockAttempts(key), { attempts: 3, lockedUntil: 5_000 });
    writeUnlockAttempts(key, { attempts: 0, lockedUntil: 0 });
    assert.deepEqual(readUnlockAttempts(key), { attempts: 0, lockedUntil: 0 });
  });
});

test("unreadable storage falls back to an empty budget", () => {
  withStorage((storage) => {
    storage.setItem("bad", "{not json");
    assert.deepEqual(readUnlockAttempts("bad"), { attempts: 0, lockedUntil: 0 });
    assert.deepEqual(readUnlockAttempts("missing"), { attempts: 0, lockedUntil: 0 });
  });
});

test("wait text switches from seconds to minutes", () => {
  assert.equal(formatWait(1), "1 second");
  assert.equal(formatWait(45), "45 seconds");
  assert.equal(formatWait(60), "1 minute");
  assert.equal(formatWait(300), "5 minutes");
});
