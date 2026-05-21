import { useCallback, useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { usePersistedState } from './usePersistedState';

export interface FindingsURLState {
  page: string;
  per_page: string;
  sort_by: string;
  sort_dir: string;
  severity: string;
  category: string;
  confidence: string;
  language: string;
  rule_id: string;
  status: string;
  verification: string;
  search: string;
}

const FINDINGS_DEFAULTS: FindingsURLState = {
  page: '1',
  per_page: '50',
  sort_by: '',
  sort_dir: 'asc',
  severity: '',
  category: '',
  confidence: '',
  language: '',
  rule_id: '',
  status: '',
  verification: '',
  search: '',
};

/** Subset of state we remember across sessions. Filters intentionally are
 * NOT persisted because they're scan-specific and should reset by default, but the
 * URL still reflects them so a shared link reproduces them exactly. */
interface PersistedFindingsPrefs {
  per_page: string;
  sort_by: string;
  sort_dir: string;
}

const DEFAULT_PREFS: PersistedFindingsPrefs = {
  per_page: '50',
  sort_by: '',
  sort_dir: 'asc',
};

const FILTER_KEYS: ReadonlySet<string> = new Set([
  'severity',
  'category',
  'confidence',
  'language',
  'rule_id',
  'status',
  'verification',
  'search',
]);

/** Keys that do NOT trigger a page reset when changed. */
const NON_RESET_KEYS: ReadonlySet<string> = new Set([
  'page',
  'sort_by',
  'sort_dir',
  'per_page',
]);

export function useFindingsURLState() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [prefs, setPrefs] = usePersistedState<PersistedFindingsPrefs>(
    'findings:prefs',
    DEFAULT_PREFS,
  );

  const state: FindingsURLState = useMemo(() => {
    const s = {} as FindingsURLState;
    for (const key of Object.keys(
      FINDINGS_DEFAULTS,
    ) as (keyof FindingsURLState)[]) {
      // URL wins; fall back to remembered prefs for keys we persist;
      // last resort is the global default.
      const fromUrl = searchParams.get(key);
      if (fromUrl) {
        s[key] = fromUrl;
      } else if (
        key === 'per_page' ||
        key === 'sort_by' ||
        key === 'sort_dir'
      ) {
        s[key] = prefs[key] || FINDINGS_DEFAULTS[key];
      } else {
        s[key] = FINDINGS_DEFAULTS[key];
      }
    }
    return s;
  }, [searchParams, prefs]);

  // Persist user-driven changes to per_page / sort_*.
  useEffect(() => {
    setPrefs({
      per_page: state.per_page,
      sort_by: state.sort_by,
      sort_dir: state.sort_dir,
    });
  }, [state.per_page, state.sort_by, state.sort_dir, setPrefs]);

  const updateState = useCallback(
    (updates: Partial<FindingsURLState>) => {
      setSearchParams((prev) => {
        const current = {} as FindingsURLState;
        for (const key of Object.keys(
          FINDINGS_DEFAULTS,
        ) as (keyof FindingsURLState)[]) {
          current[key] = prev.get(key) || FINDINGS_DEFAULTS[key];
        }

        const merged = { ...current, ...updates };

        // Reset page to 1 when any filter/non-pagination field changes
        const hasFilterChange = Object.keys(updates).some(
          (k) => !NON_RESET_KEYS.has(k),
        );
        if (hasFilterChange) {
          merged.page = '1';
        }

        // Build new search params, omitting defaults
        const next = new URLSearchParams();
        for (const [k, v] of Object.entries(merged)) {
          if (v && v !== FINDINGS_DEFAULTS[k as keyof FindingsURLState]) {
            next.set(k, v);
          }
        }
        return next;
      });
    },
    [setSearchParams],
  );

  const resetFilters = useCallback(() => {
    setSearchParams((prev) => {
      const next = new URLSearchParams();
      // Preserve per_page but reset everything else
      const perPage = prev.get('per_page');
      if (perPage && perPage !== FINDINGS_DEFAULTS.per_page) {
        next.set('per_page', perPage);
      }
      return next;
    });
  }, [setSearchParams]);

  const hasActiveFilters = useMemo(
    () =>
      Array.from(FILTER_KEYS).some(
        (k) => state[k as keyof FindingsURLState] !== '',
      ),
    [state],
  );

  return { state, updateState, resetFilters, hasActiveFilters };
}
