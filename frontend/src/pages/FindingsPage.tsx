import { useState, useCallback, useMemo, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import { useFindingsURLState } from '../hooks/useFindingsURLState';
import { useDebounce } from '../hooks/useDebounce';
import { usePageTitle } from '../hooks/usePageTitle';
import { useKeyboardShortcuts } from '../hooks/useKeyboardShortcuts';
import { useToast } from '../contexts/ToastContext';
import {
  useFindings,
  useFindingFilters,
  fetchFindingDetail,
} from '../api/queries/findings';
import { useBulkTriage, useAddSuppression } from '../api/mutations/triage';
import { Pagination } from '../components/ui/Pagination';
import { Dropdown, DropdownItem } from '../components/ui/Dropdown';
import { LoadingState } from '../components/ui/LoadingState';
import { ErrorState } from '../components/ui/ErrorState';
import { CopyMarkdownButton } from '../components/CopyMarkdownButton';
import { VerdictBadge } from '../components/VerdictBadge';
import { truncPath } from '../utils/truncPath';
import { findingsToMarkdown } from '../utils/findingMarkdown';
import { ApiError } from '../api/client';
import type { FindingView, FilterValues } from '../api/types';

// ── Helpers ─────────────────────────────────────────────────────────────────

function formatTriageState(state: string): string {
  return (state || 'open').replace(/_/g, ' ');
}

function formatVerificationStatus(status: string): string {
  if (status === 'NotConfirmed') return 'Not confirmed';
  if (status === 'PartiallyConfirmed') return 'Partially confirmed';
  return status || 'Unverified';
}

// ── Filter Bar ──────────────────────────────────────────────────────────────

interface FilterSelectProps {
  id: string;
  label: string;
  values: string[] | undefined;
  current: string;
  onChange: (value: string) => void;
  formatValue?: (value: string) => string;
}

function FilterSelect({
  id,
  label,
  values,
  current,
  onChange,
  formatValue,
}: FilterSelectProps) {
  if (!values || values.length === 0) return null;
  return (
    <select id={id} value={current} onChange={(e) => onChange(e.target.value)}>
      <option value="">All {label}</option>
      {values.map((v) => (
        <option key={v} value={v}>
          {formatValue ? formatValue(v) : v}
        </option>
      ))}
    </select>
  );
}

// ── Bulk Action Bar ─────────────────────────────────────────────────────────

interface BulkBarProps {
  selectedCount: number;
  sharedStatus: string | null;
  onBulkTriage: (state: string) => void;
  onSuppressByPattern: () => void;
  onBulkCopy: () => Promise<string>;
}

const STATUS_OPTIONS: ReadonlyArray<{ value: string; label: string }> = [
  { value: 'investigating', label: 'Investigating' },
  { value: 'false_positive', label: 'Mark as False Positive' },
  { value: 'accepted_risk', label: 'Accept Risk' },
];

function BulkActionBar({
  selectedCount,
  sharedStatus,
  onBulkTriage,
  onSuppressByPattern,
  onBulkCopy,
}: BulkBarProps) {
  const disabled = selectedCount === 0;

  return (
    <div
      className={`bulk-action-bar${selectedCount > 0 ? ' visible' : ''}`}
      aria-hidden={disabled}
    >
      <span className="bulk-count">{selectedCount} selected</span>

      <div className="bulk-actions">
        <Dropdown
          align="right"
          trigger={({ open }) => (
            <button
              type="button"
              className="btn btn-sm bulk-menu-btn"
              disabled={disabled}
            >
              Status
              <span className={`bulk-caret${open ? ' bulk-caret--open' : ''}`}>
                ▾
              </span>
            </button>
          )}
        >
          {({ close }) =>
            STATUS_OPTIONS.map((opt) => (
              <DropdownItem
                key={opt.value}
                checked={sharedStatus === opt.value}
                onClick={() => {
                  onBulkTriage(opt.value);
                  close();
                }}
              >
                {opt.label}
              </DropdownItem>
            ))
          }
        </Dropdown>

        <Dropdown
          align="right"
          trigger={({ open }) => (
            <button
              type="button"
              className="btn btn-sm bulk-menu-btn bulk-menu-btn--warning"
              disabled={disabled}
            >
              Suppress
              <span className={`bulk-caret${open ? ' bulk-caret--open' : ''}`}>
                ▾
              </span>
            </button>
          )}
        >
          {({ close }) => (
            <>
              <DropdownItem
                tone="warning"
                onClick={() => {
                  onBulkTriage('suppressed');
                  close();
                }}
              >
                Suppress this finding
              </DropdownItem>
              <DropdownItem
                tone="warning"
                hint="advanced"
                onClick={() => {
                  onSuppressByPattern();
                  close();
                }}
              >
                Suppress by pattern
              </DropdownItem>
            </>
          )}
        </Dropdown>

        <div className="bulk-divider" aria-hidden />

        <CopyMarkdownButton
          className="bulk-copy-btn"
          iconOnly
          label="Copy selected as markdown"
          title="Copy selected as markdown"
          getMarkdown={onBulkCopy}
        />
      </div>
    </div>
  );
}

// ── Suppress Modal ──────────────────────────────────────────────────────────

interface SuppressModalProps {
  rules: string[];
  files: string[];
  onSuppress: (by: string, value: string, note: string) => void;
  onClose: () => void;
}

function SuppressModal({
  rules,
  files,
  onSuppress,
  onClose,
}: SuppressModalProps) {
  const [note, setNote] = useState('');

  return (
    <div
      className="suppress-modal-overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="suppress-modal">
        <h3>Suppress by Pattern</h3>
        <div className="suppress-options">
          {rules.map((r) => (
            <button
              key={`rule-${r}`}
              className="btn btn-sm suppress-opt"
              onClick={() => onSuppress('rule', r, note)}
            >
              By rule: {r}
            </button>
          ))}
          {files.map((f) => (
            <button
              key={`file-${f}`}
              className="btn btn-sm suppress-opt"
              onClick={() => onSuppress('file', f, note)}
            >
              By file: {truncPath(f, 40)}
            </button>
          ))}
        </div>
        <textarea
          placeholder="Note (optional)..."
          rows={2}
          style={{ width: '100%', marginTop: 'var(--space-3)' }}
          value={note}
          onChange={(e) => setNote(e.target.value)}
        />
        <div
          style={{
            display: 'flex',
            gap: 'var(--space-2)',
            marginTop: 'var(--space-3)',
          }}
        >
          <button className="btn btn-sm" onClick={onClose}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Sortable Header ─────────────────────────────────────────────────────────

interface SortableThProps {
  column: string;
  label: string;
  currentSort: string;
  currentDir: string;
  onSort: (col: string, dir: string) => void;
}

function SortableTh({
  column,
  label,
  currentSort,
  currentDir,
  onSort,
}: SortableThProps) {
  const isActive = currentSort === column;
  const arrow = isActive ? (currentDir === 'desc' ? '\u2193' : '\u2191') : '';

  const handleClick = () => {
    const newDir =
      currentSort === column && currentDir === 'asc' ? 'desc' : 'asc';
    onSort(column, newDir);
  };

  return (
    <th
      className={`sortable${isActive ? ' active' : ''}`}
      onClick={handleClick}
    >
      {label}
      {arrow && <span className="sort-arrow">{arrow}</span>}
    </th>
  );
}

// ── Main Component ──────────────────────────────────────────────────────────

export function FindingsPage() {
  usePageTitle('Findings');
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const toast = useToast();
  const { state, updateState, resetFilters, hasActiveFilters } =
    useFindingsURLState();

  // Local search input state (debounced before pushing to URL)
  const [searchInput, setSearchInput] = useState(state.search);
  const debouncedSearch = useDebounce(searchInput, 300);

  // Sync debounced search to URL state
  useEffect(() => {
    if (debouncedSearch !== state.search) {
      updateState({ search: debouncedSearch });
    }
  }, [debouncedSearch]); // eslint-disable-line react-hooks/exhaustive-deps

  // Sync URL search back to local input when navigating
  useEffect(() => {
    setSearchInput(state.search);
  }, [state.search]);

  // Build query params for the API
  const queryParams = useMemo(
    () => ({
      page: Number(state.page) || 1,
      per_page: Number(state.per_page) || 50,
      sort_by: state.sort_by || undefined,
      sort_dir: state.sort_dir !== 'asc' ? state.sort_dir : undefined,
      severity: state.severity || undefined,
      category: state.category || undefined,
      confidence: state.confidence || undefined,
      language: state.language || undefined,
      rule_id: state.rule_id || undefined,
      status: state.status || undefined,
      verification: state.verification || undefined,
      search: state.search || undefined,
    }),
    [state],
  );

  const { data, isLoading, isError, error } = useFindings(queryParams);
  const { data: filters } = useFindingFilters();

  // Selection state
  const [selected, setSelected] = useState<Set<number>>(new Set());

  // Clear selection when data changes
  useEffect(() => {
    setSelected(new Set());
  }, [data]);

  const bulkTriage = useBulkTriage();
  const addSuppression = useAddSuppression();

  // Suppress modal
  const [suppressModalOpen, setSuppressModalOpen] = useState(false);

  // ── Selection handlers ──

  const toggleRow = useCallback((index: number) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  }, []);

  const toggleSelectAll = useCallback(
    (checked: boolean) => {
      if (!data) return;
      if (checked) {
        setSelected(new Set(data.findings.map((f) => f.index)));
      } else {
        setSelected(new Set());
      }
    },
    [data],
  );

  const allSelected =
    data != null &&
    data.findings.length > 0 &&
    data.findings.every((f) => selected.has(f.index));

  const sharedStatus = useMemo<string | null>(() => {
    if (!data || selected.size === 0) return null;
    const states = new Set(
      data.findings
        .filter((f) => selected.has(f.index))
        .map((f) => f.triage_state || f.status),
    );
    return states.size === 1 ? [...states][0] : null;
  }, [data, selected]);

  // ── Bulk action handlers ──

  const getSelectedFingerprints = useCallback((): string[] => {
    if (!data) return [];
    return data.findings
      .filter((f) => selected.has(f.index))
      .map((f) => f.fingerprint);
  }, [data, selected]);

  const handleBulkTriage = useCallback(
    (triageState: string) => {
      const fingerprints = getSelectedFingerprints();
      if (fingerprints.length === 0) return;
      bulkTriage.mutate(
        { fingerprints, state: triageState, note: '' },
        {
          onSuccess: () => {
            setSelected(new Set());
            toast.success(
              `Marked ${fingerprints.length} finding${fingerprints.length === 1 ? '' : 's'} as ${triageState.replace('_', ' ')}`,
            );
          },
          onError: (err) =>
            toast.error(
              err instanceof Error ? err.message : 'Bulk triage failed',
              'Could not update findings',
            ),
        },
      );
    },
    [getSelectedFingerprints, bulkTriage, toast],
  );

  const handleSuppressByPattern = useCallback(() => {
    if (selected.size === 0 || !data) return;
    setSuppressModalOpen(true);
  }, [selected.size, data]);

  const handleBulkCopy = useCallback(async (): Promise<string> => {
    const indices =
      data?.findings.filter((f) => selected.has(f.index)).map((f) => f.index) ??
      [];
    const results = await Promise.allSettled(
      indices.map((i) => fetchFindingDetail(queryClient, i)),
    );
    const views = results
      .filter(
        (r): r is PromiseFulfilledResult<FindingView> =>
          r.status === 'fulfilled',
      )
      .map((r) => r.value);
    return findingsToMarkdown(views);
  }, [data, selected, queryClient]);

  const suppressPatternRules = useMemo(() => {
    if (!data) return [];
    const selectedFindings = data.findings.filter((f) => selected.has(f.index));
    return [...new Set(selectedFindings.map((f) => f.rule_id))];
  }, [data, selected]);

  const suppressPatternFiles = useMemo(() => {
    if (!data) return [];
    const selectedFindings = data.findings.filter((f) => selected.has(f.index));
    return [...new Set(selectedFindings.map((f) => f.path))];
  }, [data, selected]);

  const handleSuppress = useCallback(
    (by: string, value: string, note: string) => {
      addSuppression.mutate(
        { by, value, note },
        {
          onSuccess: () => {
            setSuppressModalOpen(false);
            setSelected(new Set());
            toast.success(`Added suppression by ${by}`);
          },
          onError: (err) =>
            toast.error(
              err instanceof Error ? err.message : 'Suppression failed',
              'Could not add suppression',
            ),
        },
      );
    },
    [addSuppression, toast],
  );

  // ── Sort handler ──

  const handleSort = useCallback(
    (col: string, dir: string) => {
      updateState({ sort_by: col, sort_dir: dir });
    },
    [updateState],
  );

  // ── Filter handler ──

  const handleFilterChange = useCallback(
    (key: string, value: string) => {
      updateState({ [key]: value });
    },
    [updateState],
  );

  // ── Row click ──

  const handleRowClick = useCallback(
    (e: React.MouseEvent, finding: FindingView) => {
      if ((e.target as HTMLElement).tagName === 'INPUT') return;
      navigate(`/findings/${finding.index}`);
    },
    [navigate],
  );

  // ── Keyboard navigation: j/k row cursor + / search + Enter to open ──

  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const [cursor, setCursor] = useState(-1);

  // Reset cursor whenever the visible page changes.
  useEffect(() => {
    setCursor(-1);
  }, [data]);

  const shortcuts = useMemo(
    () => [
      {
        key: '/',
        description: 'Focus search',
        handler: () => searchInputRef.current?.focus(),
      },
      {
        key: 'j',
        description: 'Next finding',
        handler: () => {
          if (!data || data.findings.length === 0) return;
          setCursor((c) => Math.min(c + 1, data.findings.length - 1));
        },
      },
      {
        key: 'k',
        description: 'Previous finding',
        handler: () => {
          if (!data || data.findings.length === 0) return;
          setCursor((c) => Math.max(c - 1, 0));
        },
      },
      {
        key: 'Enter',
        description: 'Open highlighted finding',
        handler: () => {
          const f = data?.findings[cursor];
          if (f) navigate(`/findings/${f.index}`);
        },
      },
    ],
    [data, cursor, navigate],
  );

  useKeyboardShortcuts(shortcuts);

  // ── Render ──

  if (isLoading) {
    return <LoadingState message="Loading findings..." />;
  }

  if (isError) {
    if (error instanceof ApiError && error.status === 404) {
      return (
        <div className="empty-state">
          <h3>No scan results yet</h3>
          <p>Run a scan first to see findings.</p>
        </div>
      );
    }
    return <ErrorState title="Error" error={error} />;
  }

  if (!data) return null;

  const page = data.page;
  const totalPages = Math.ceil(data.total / data.per_page) || 1;

  return (
    <div className="findings-page page-shell">
      {/* Filter bar */}
      <div className="filter-bar">
        <input
          type="text"
          ref={searchInputRef}
          placeholder="Search findings... (/)"
          className="search-input"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
        />
        <FilterSelect
          id="filter-severity"
          label="Severities"
          values={filters?.severities}
          current={state.severity}
          onChange={(v) => handleFilterChange('severity', v)}
        />
        <FilterSelect
          id="filter-confidence"
          label="Confidences"
          values={filters?.confidences}
          current={state.confidence}
          onChange={(v) => handleFilterChange('confidence', v)}
        />
        <FilterSelect
          id="filter-category"
          label="Categories"
          values={filters?.categories}
          current={state.category}
          onChange={(v) => handleFilterChange('category', v)}
        />
        <FilterSelect
          id="filter-language"
          label="Languages"
          values={filters?.languages}
          current={state.language}
          onChange={(v) => handleFilterChange('language', v)}
        />
        <FilterSelect
          id="filter-rule"
          label="Rules"
          values={filters?.rules}
          current={state.rule_id}
          onChange={(v) => handleFilterChange('rule_id', v)}
        />
        <FilterSelect
          id="filter-status"
          label="Statuses"
          values={filters?.statuses}
          current={state.status}
          onChange={(v) => handleFilterChange('status', v)}
        />
        <FilterSelect
          id="filter-verification"
          label="Verification"
          values={filters?.verification_statuses}
          current={state.verification}
          onChange={(v) => handleFilterChange('verification', v)}
          formatValue={formatVerificationStatus}
        />
        {hasActiveFilters && (
          <button className="btn btn-sm btn-clear" onClick={resetFilters}>
            Clear All
          </button>
        )}
      </div>

      {/* Bulk action bar */}
      <BulkActionBar
        selectedCount={selected.size}
        sharedStatus={sharedStatus}
        onBulkTriage={handleBulkTriage}
        onSuppressByPattern={handleSuppressByPattern}
        onBulkCopy={handleBulkCopy}
      />

      {/* Findings table */}
      {data.findings.length === 0 ? (
        <div className="empty-state">
          <h3>No findings</h3>
          <p>Run a scan to see results, or adjust your filters.</p>
        </div>
      ) : (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th className="col-checkbox">
                    <input
                      type="checkbox"
                      checked={allSelected}
                      onChange={(e) => toggleSelectAll(e.target.checked)}
                    />
                  </th>
                  <SortableTh
                    column="severity"
                    label="Severity"
                    currentSort={state.sort_by}
                    currentDir={state.sort_dir}
                    onSort={handleSort}
                  />
                  <SortableTh
                    column="confidence"
                    label="Confidence"
                    currentSort={state.sort_by}
                    currentDir={state.sort_dir}
                    onSort={handleSort}
                  />
                  <SortableTh
                    column="rule_id"
                    label="Rule"
                    currentSort={state.sort_by}
                    currentDir={state.sort_dir}
                    onSort={handleSort}
                  />
                  <SortableTh
                    column="category"
                    label="Category"
                    currentSort={state.sort_by}
                    currentDir={state.sort_dir}
                    onSort={handleSort}
                  />
                  <SortableTh
                    column="file"
                    label="File"
                    currentSort={state.sort_by}
                    currentDir={state.sort_dir}
                    onSort={handleSort}
                  />
                  <SortableTh
                    column="line"
                    label="Line"
                    currentSort={state.sort_by}
                    currentDir={state.sort_dir}
                    onSort={handleSort}
                  />
                  <SortableTh
                    column="language"
                    label="Language"
                    currentSort={state.sort_by}
                    currentDir={state.sort_dir}
                    onSort={handleSort}
                  />
                  <SortableTh
                    column="status"
                    label="Status"
                    currentSort={state.sort_by}
                    currentDir={state.sort_dir}
                    onSort={handleSort}
                  />
                  <th>Verified</th>
                </tr>
              </thead>
              <tbody>
                {data.findings.map((f, i) => (
                  <tr
                    key={f.index}
                    className={`clickable${selected.has(f.index) ? ' selected' : ''}${i === cursor ? ' cursor' : ''}`}
                    aria-current={i === cursor ? 'true' : undefined}
                    onClick={(e) => handleRowClick(e, f)}
                  >
                    <td className="col-checkbox">
                      <input
                        type="checkbox"
                        checked={selected.has(f.index)}
                        onChange={() => toggleRow(f.index)}
                      />
                    </td>
                    <td>
                      <span
                        className={`badge badge-${f.severity.toLowerCase()}`}
                      >
                        {f.severity}
                      </span>
                    </td>
                    <td>
                      {f.confidence ? (
                        <span
                          className={`badge badge-conf-${f.confidence.toLowerCase()}`}
                        >
                          {f.confidence}
                        </span>
                      ) : (
                        '-'
                      )}
                    </td>
                    <td title={f.message || ''}>{f.rule_id}</td>
                    <td>{f.category}</td>
                    <td className="cell-path" title={f.path}>
                      {truncPath(f.path)}
                    </td>
                    <td>{f.line}</td>
                    <td>{f.language || '-'}</td>
                    <td>
                      <span
                        className={`badge badge-triage-${f.triage_state || f.status}`}
                      >
                        {formatTriageState(f.triage_state || f.status)}
                      </span>
                    </td>
                    <td>
                      <VerdictBadge
                        verdict={f.dynamic_verdict ?? f.evidence?.dynamic_verdict}
                        compact
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <Pagination
            page={page}
            perPage={data.per_page}
            total={data.total}
            onPageChange={(p) => updateState({ page: String(p) })}
            onPerPageChange={(pp) => updateState({ per_page: String(pp) })}
          />
        </>
      )}

      {/* Suppress by pattern modal */}
      {suppressModalOpen && (
        <SuppressModal
          rules={suppressPatternRules}
          files={suppressPatternFiles}
          onSuppress={handleSuppress}
          onClose={() => setSuppressModalOpen(false)}
        />
      )}
    </div>
  );
}
