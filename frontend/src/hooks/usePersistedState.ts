import { useCallback, useEffect, useRef, useState } from 'react';

const STORAGE_PREFIX = 'nyx:';

function storageKey(key: string) {
  return `${STORAGE_PREFIX}${key}`;
}

function read<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(storageKey(key));
    if (raw === null) return fallback;
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function write<T>(key: string, value: T): void {
  try {
    window.localStorage.setItem(storageKey(key), JSON.stringify(value));
  } catch {
    // Quota exceeded or storage disabled, so silently degrade.
  }
}

/**
 * `useState` that persists to `localStorage` under `nyx:<key>`.
 *
 * Suitable for view preferences (theme, sidebar collapse, default page size).
 * Not suitable for sensitive data because `localStorage` is not encrypted.
 *
 * Cross-tab sync is not implemented; if the user opens two tabs they get
 * independent state until next load. That's the common-case ergonomic.
 */
export function usePersistedState<T>(
  key: string,
  initial: T,
): [T, (next: T | ((prev: T) => T)) => void] {
  const [state, setState] = useState<T>(() => read(key, initial));

  // Avoid writing back the initial value on first mount when nothing changed.
  const hydrated = useRef(false);
  useEffect(() => {
    if (!hydrated.current) {
      hydrated.current = true;
      return;
    }
    write(key, state);
  }, [key, state]);

  const set = useCallback((next: T | ((prev: T) => T)) => {
    setState((prev) =>
      typeof next === 'function' ? (next as (p: T) => T)(prev) : next,
    );
  }, []);

  return [state, set];
}
