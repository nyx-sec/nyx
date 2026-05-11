import { useState, useMemo, useCallback, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { useRules } from '../api/queries/rules';
import { useToggleRule, useCloneRule } from '../api/mutations/rules';
import { LoadingState } from '../components/ui/LoadingState';
import { ErrorState } from '../components/ui/ErrorState';
import { usePageTitle } from '../hooks/usePageTitle';
import type { RuleListItem } from '../api/types';

function useDebounce(value: string, delay: number): string {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}

// ── Rule Detail Panel ────────────────────────────────────────────────────────

function RuleDetail({
  rule,
  onToggle,
  onClone,
}: {
  rule: RuleListItem;
  onToggle: () => void;
  onClone: () => void;
}) {
  return (
    <div className="rule-detail-card">
      <h3>{rule.title}</h3>
      <div className="rule-detail-grid">
        <div className="rule-detail-label">ID</div>
        <div>
          <code style={{ fontSize: 'var(--text-xs)', wordBreak: 'break-all' }}>
            {rule.id}
          </code>
        </div>
        <div className="rule-detail-label">Language</div>
        <div>{rule.language}</div>
        <div className="rule-detail-label">Kind</div>
        <div>
          <span className={`badge badge-${rule.kind}`}>{rule.kind}</span>
        </div>
        <div className="rule-detail-label">Capability</div>
        <div>{rule.cap}</div>
        <div className="rule-detail-label">Case Sensitive</div>
        <div>{rule.case_sensitive ? 'Yes' : 'No'}</div>
        <div className="rule-detail-label">Status</div>
        <div>
          {rule.enabled ? (
            <span style={{ color: 'var(--success)' }}>Enabled</span>
          ) : (
            <span style={{ color: 'var(--text-tertiary)' }}>Disabled</span>
          )}
        </div>
        <div className="rule-detail-label">Findings</div>
        <div>
          {rule.finding_count}
          {rule.suppression_rate > 0
            ? ` (${(rule.suppression_rate * 100).toFixed(0)}% suppressed)`
            : ''}
        </div>
      </div>
      {rule.is_custom && (
        <div style={{ marginTop: 'var(--space-3)' }}>
          <span className="badge-custom">Custom Rule</span>
        </div>
      )}
      {rule.is_gated && (
        <div style={{ marginTop: 'var(--space-3)' }}>
          <span className="badge-builtin">Gated Sink</span>
        </div>
      )}
      <div style={{ marginTop: 'var(--space-4)' }}>
        <div
          className="rule-detail-label"
          style={{ marginBottom: 'var(--space-2)' }}
        >
          Matchers
        </div>
        <div>
          {rule.matchers.map((m) => (
            <code key={m} className="matcher-tag">
              {m}
            </code>
          ))}
        </div>
      </div>
      <div
        style={{
          marginTop: 'var(--space-5)',
          display: 'flex',
          gap: 'var(--space-2)',
        }}
      >
        <button className="btn btn-sm" onClick={onToggle}>
          {rule.enabled ? 'Disable' : 'Enable'}
        </button>
        {!rule.is_custom && (
          <button className="btn btn-primary btn-sm" onClick={onClone}>
            Clone to Custom
          </button>
        )}
      </div>
    </div>
  );
}

// ── Rules Table ──────────────────────────────────────────────────────────────

function RulesTable({
  rules,
  selectedId,
  onSelect,
  onToggle,
}: {
  rules: RuleListItem[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onToggle: (id: string) => void;
}) {
  if (rules.length === 0) {
    return (
      <div className="empty-state" style={{ padding: 20 }}>
        <p>No rules match filters</p>
      </div>
    );
  }

  return (
    <table className="rules-table">
      <colgroup>
        <col className="col-toggle" />
        <col />
        <col className="col-lang" />
        <col className="col-kind" />
        <col className="col-cap" />
        <col className="col-finds" />
      </colgroup>
      <thead>
        <tr>
          <th></th>
          <th>Title</th>
          <th>Lang</th>
          <th>Kind</th>
          <th>Cap</th>
          <th>Finds</th>
        </tr>
      </thead>
      <tbody>
        {rules.map((r) => (
          <tr
            key={r.id}
            className={`rule-row${r.id === selectedId ? ' selected' : ''}${!r.enabled ? ' rule-disabled' : ''}`}
            onClick={() => onSelect(r.id)}
          >
            <td>
              <button
                className={`rule-toggle${r.enabled ? ' toggle-on' : ' toggle-off'}`}
                title={r.enabled ? 'Disable' : 'Enable'}
                onClick={(e) => {
                  e.stopPropagation();
                  onToggle(r.id);
                }}
              >
                {r.enabled ? 'On' : 'Off'}
              </button>
            </td>
            <td className="col-title-cell">
              <span className="rule-title-text">
                {r.title}
                {r.is_custom && (
                  <>
                    {' '}
                    <span className="badge-custom">custom</span>
                  </>
                )}
                {r.is_gated && (
                  <>
                    {' '}
                    <span className="badge-builtin">gated</span>
                  </>
                )}
              </span>
            </td>
            <td>{r.language}</td>
            <td>
              <span className={`badge badge-${r.kind}`}>{r.kind}</span>
            </td>
            <td>{r.cap}</td>
            <td>{r.finding_count}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export function RulesPage() {
  usePageTitle('Rules');
  const params = useParams<{ id?: string }>();
  const { data: rules, isLoading, error } = useRules();
  const toggleRule = useToggleRule();
  const cloneRule = useCloneRule();

  const [selectedId, setSelectedId] = useState<string | null>(
    params.id || null,
  );
  const [langFilter, setLangFilter] = useState('');
  const [kindFilter, setKindFilter] = useState('');
  const [customOnly, setCustomOnly] = useState(false);
  const [searchInput, setSearchInput] = useState('');
  const search = useDebounce(searchInput, 200);

  const langs = useMemo(() => {
    if (!rules) return [];
    return [...new Set(rules.map((r) => r.language))].sort();
  }, [rules]);

  const kinds = ['source', 'sanitizer', 'sink'];

  const filtered = useMemo(() => {
    if (!rules) return [];
    return rules.filter((r) => {
      if (langFilter && r.language !== langFilter) return false;
      if (kindFilter && r.kind !== kindFilter) return false;
      if (customOnly && !r.is_custom) return false;
      if (
        search &&
        !r.matchers.some((m) =>
          m.toLowerCase().includes(search.toLowerCase()),
        ) &&
        !r.title.toLowerCase().includes(search.toLowerCase())
      )
        return false;
      return true;
    });
  }, [rules, langFilter, kindFilter, customOnly, search]);

  const selectedRule = useMemo(
    () => (selectedId && rules ? rules.find((r) => r.id === selectedId) : null),
    [selectedId, rules],
  );

  const handleSelect = useCallback((id: string) => {
    setSelectedId(id);
    history.replaceState(
      null,
      '',
      id ? '/rules/' + encodeURIComponent(id) : '/rules',
    );
  }, []);

  const handleToggle = useCallback(
    (id: string) => {
      toggleRule.mutate(id);
    },
    [toggleRule],
  );

  const handleClone = useCallback(() => {
    if (!selectedId) return;
    cloneRule.mutate({ rule_id: selectedId });
  }, [selectedId, cloneRule]);

  if (isLoading) return <LoadingState message="Loading rules..." />;
  if (error) return <ErrorState message={error.message} />;

  return (
    <div className="rules-page page-shell">
      <div className="rules-layout">
        <div className="rules-list-panel">
          <div className="rules-filters">
            <select
              value={langFilter}
              onChange={(e) => setLangFilter(e.target.value)}
            >
              <option value="">All Languages</option>
              {langs.map((l) => (
                <option key={l} value={l}>
                  {l}
                </option>
              ))}
            </select>
            <select
              value={kindFilter}
              onChange={(e) => setKindFilter(e.target.value)}
            >
              <option value="">All Kinds</option>
              {kinds.map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>
            <label className="rules-custom-toggle">
              <input
                type="checkbox"
                checked={customOnly}
                onChange={(e) => setCustomOnly(e.target.checked)}
              />{' '}
              Custom only
            </label>
            <input
              type="text"
              placeholder="Search matchers..."
              style={{ flex: 1, minWidth: 100 }}
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
            />
          </div>
          <div id="rules-table-wrap">
            <RulesTable
              rules={filtered}
              selectedId={selectedId}
              onSelect={handleSelect}
              onToggle={handleToggle}
            />
          </div>
        </div>

        <div className="rules-detail-panel" id="rules-detail">
          {selectedRule ? (
            <RuleDetail
              rule={selectedRule}
              onToggle={() => handleToggle(selectedRule.id)}
              onClone={handleClone}
            />
          ) : (
            <div className="empty-state" style={{ padding: 40 }}>
              <p>Select a rule to view details</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
