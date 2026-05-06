import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  type ReactNode,
} from 'react';
import { usePersistedState } from '../hooks/usePersistedState';

export type ThemePreference =
  | 'light'
  | 'dark'
  | 'system'
  | 'hc-light'
  | 'hc-dark';
export type ResolvedTheme = 'light' | 'dark' | 'hc-light' | 'hc-dark';

interface ThemeContextValue {
  preference: ThemePreference;
  resolved: ResolvedTheme;
  setPreference: (next: ThemePreference) => void;
  /** Cycle light → dark → system → light. Used by the toolbar toggle. */
  cycle: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

function systemPrefersDark(): boolean {
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? false;
}

function resolve(pref: ThemePreference): ResolvedTheme {
  if (pref === 'system') return systemPrefersDark() ? 'dark' : 'light';
  return pref;
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [preference, setPreference] = usePersistedState<ThemePreference>(
    'theme',
    'light',
  );

  const resolved = useMemo(() => resolve(preference), [preference]);

  // Reflect the resolved theme onto <html> so CSS rules under
  // [data-theme="dark"] take effect.
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', resolved);
  }, [resolved]);

  // When the user picks "system", react to OS-level changes live.
  useEffect(() => {
    if (preference !== 'system') return;
    const mq = window.matchMedia?.('(prefers-color-scheme: dark)');
    if (!mq) return;
    const handler = () => {
      document.documentElement.setAttribute(
        'data-theme',
        systemPrefersDark() ? 'dark' : 'light',
      );
    };
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, [preference]);

  const cycle = useCallback(() => {
    setPreference((prev) => {
      if (prev === 'hc-light') return 'hc-dark';
      if (prev === 'hc-dark') return 'hc-light';
      if (prev === 'light') return 'dark';
      if (prev === 'dark') return 'system';
      return 'light';
    });
  }, [setPreference]);

  const value = useMemo<ThemeContextValue>(
    () => ({ preference, resolved, setPreference, cycle }),
    [preference, resolved, setPreference, cycle],
  );

  return (
    <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useTheme must be used inside <ThemeProvider>');
  return ctx;
}
