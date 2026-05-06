import {
  useState,
  useMemo,
  useCallback,
  useEffect,
  type ReactNode,
} from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useFindings } from '../api/queries/findings';
import {
  useTriageAudit,
  useSuppressions,
  useSyncStatus,
} from '../api/queries/triage';
import {
  useBulkTriage,
  useDeleteSuppression,
  useTriageExport,
  useTriageImport,
} from '../api/mutations/triage';
import { LoadingState } from '../components/ui/LoadingState';
import { ErrorState } from '../components/ui/ErrorState';
import { Dropdown, DropdownItem } from '../components/ui/Dropdown';
import { usePageTitle } from '../hooks/usePageTitle';
import type { FindingView, AuditEntry, SuppressionRule } from '../api/types';

// ── Helpers ─────────────────────────────────────────────────────────────────

const SEVERITIES = ['High', 'Medium', 'Low'] as const;

const ALL_STATES = [
  'open',
  'investigating',
  'false_positive',
  'accepted_risk',
  'suppressed',
  'fixed',
] as const;

const STATE_FILTERS: { value: string; label: string }[] = [
  { value: 'needs_attention', label: 'Needs attention' },
  { value: 'all', label: 'All findings' },
  { value: 'open', label: 'Open' },
  { value: 'investigating', label: 'Investigating' },
  { value: 'false_positive', label: 'False positive' },
  { value: 'accepted_risk', label: 'Accepted risk' },
  { value: 'suppressed', label: 'Suppressed' },
  { value: 'fixed', label: 'Fixed' },
];

type GroupMode = 'none' | 'rule' | 'file' | 'severity';

const GROUP_MODES: { value: GroupMode; label: string }[] = [
  { value: 'none', label: 'None' },
  { value: 'rule', label: 'Rule' },
  { value: 'file', label: 'File' },
  { value: 'severity', label: 'Severity' },
];

function stateLabel(s: string): string {
  return s.replace(/_/g, ' ');
}

function shortPath(p?: string): string {
  if (!p) return '';
  const parts = p.split('/').filter(Boolean);
  if (parts.length <= 2) return p;
  return parts.slice(-2).join('/');
}

function fileBase(p?: string): string {
  if (!p) return '';
  const parts = p.split('/').filter(Boolean);
  return parts[parts.length - 1] ?? p;
}

function severityRank(s?: string): number {
  const v = (s || '').toLowerCase();
  if (v === 'high') return 0;
  if (v === 'medium') return 1;
  if (v === 'low') return 2;
  return 3;
}

// ── Triage Summary ──────────────────────────────────────────────────────────

interface TriageSummaryProps {
  totalCount: number;
  needsAttention: number;
  stateCounts: Record<string, number>;
  openBySev: Record<string, number>;
  activeFilter: string;
  onFilter: (filter: string) => void;
}

function TriageSummary({
  totalCount,
  needsAttention,
  stateCounts,
  openBySev,
  activeFilter,
  onFilter,
}: TriageSummaryProps) {
  const [expanded, setExpanded] = useState(false);

  const headline = useMemo(() => {
    if (totalCount === 0) return 'No findings';
    if (activeFilter === 'needs_attention') {
      if (needsAttention === 0) {
        return 'Nothing needs attention';
      }
      return `${needsAttention.toLocaleString()} ${needsAttention === 1 ? 'finding needs' : 'findings need'} attention`;
    }
    if (activeFilter === 'all') {
      return `${totalCount.toLocaleString()} ${totalCount === 1 ? 'finding' : 'findings'}`;
    }
    const count = stateCounts[activeFilter] ?? 0;
    const label =
      STATE_FILTERS.find((s) => s.value === activeFilter)?.label ??
      activeFilter;
    return `${count.toLocaleString()} ${label.toLowerCase()}`;
  }, [totalCount, needsAttention, stateCounts, activeFilter]);

  const showSeverity =
    activeFilter === 'needs_attention' ||
    activeFilter === 'all' ||
    activeFilter === 'open';

  return (
    <div className="triage-hero">
      <div className="triage-hero-row">
        <h1 className="triage-hero-title">{headline}</h1>
        {showSeverity && totalCount > 0 && (
          <div className="triage-hero-severity">
            {SEVERITIES.map((sev) => (
              <span
                key={sev}
                className={`triage-sev-stat triage-sev-${sev.toLowerCase()}`}
              >
                <span className="triage-sev-dot" aria-hidden />
                <span className="triage-sev-count">
                  {(openBySev[sev] ?? 0).toLocaleString()}
                </span>
                <span className="triage-sev-name">{sev}</span>
              </span>
            ))}
          </div>
        )}
        {totalCount > 0 && (
          <button
            type="button"
            className="triage-hero-toggle"
            onClick={() => setExpanded((v) => !v)}
            aria-expanded={expanded}
          >
            {expanded ? 'Hide breakdown' : 'Show breakdown'}
            <span className={`triage-caret${expanded ? ' open' : ''}`}>▾</span>
          </button>
        )}
      </div>
      {expanded && (
        <div className="triage-state-row">
          <button
            type="button"
            className={`triage-state-chip${activeFilter === 'all' ? ' active' : ''}`}
            onClick={() => onFilter('all')}
          >
            <span className="triage-state-count">
              {totalCount.toLocaleString()}
            </span>
            <span className="triage-state-label">Total</span>
          </button>
          {ALL_STATES.map((s) => {
            const count = stateCounts[s] ?? 0;
            const muted = count === 0;
            return (
              <button
                key={s}
                type="button"
                className={`triage-state-chip${activeFilter === s ? ' active' : ''}${muted ? ' muted' : ''}`}
                onClick={() => onFilter(s)}
              >
                <span className="triage-state-count">
                  {count.toLocaleString()}
                </span>
                <span className="triage-state-label">{stateLabel(s)}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Rule Filter Chips ───────────────────────────────────────────────────────

interface RuleFilterChipsProps {
  rules: [string, number][];
  selected: Set<string>;
  onToggle: (rule: string) => void;
  onClear: () => void;
}

function RuleFilterChips({
  rules,
  selected,
  onToggle,
  onClear,
}: RuleFilterChipsProps) {
  const [showMore, setShowMore] = useState(false);
  if (rules.length === 0) return null;

  const visibleCount = showMore ? rules.length : Math.min(5, rules.length);
  const visible = rules.slice(0, visibleCount);
  const hasMore = rules.length > 5;

  return (
    <div className="triage-rule-filter">
      <span className="triage-rule-filter-label">Rules:</span>
      {visible.map(([rule, count]) => {
        const active = selected.has(rule);
        return (
          <button
            key={rule}
            type="button"
            className={`rule-chip${active ? ' active' : ''}`}
            onClick={() => onToggle(rule)}
            title={rule}
          >
            <span className="rule-chip-name">{rule}</span>
            <span className="rule-chip-count">{count}</span>
            {active && (
              <span className="rule-chip-x" aria-hidden>
                ×
              </span>
            )}
          </button>
        );
      })}
      {hasMore && (
        <button
          type="button"
          className="triage-rule-more"
          onClick={() => setShowMore((v) => !v)}
        >
          {showMore ? 'Show less' : `+ ${rules.length - 5} more`}
        </button>
      )}
      {selected.size > 0 && (
        <button type="button" className="triage-rule-clear" onClick={onClear}>
          Clear
        </button>
      )}
    </div>
  );
}

// ── Finding Row ─────────────────────────────────────────────────────────────

interface FindingRowProps {
  finding: FindingView;
  selected: boolean;
  expanded: boolean;
  onToggleSelect: () => void;
  onToggleExpand: () => void;
  onTriage: (fingerprint: string, state: string) => void;
}

function FindingRow({
  finding: f,
  selected,
  expanded,
  onToggleSelect,
  onToggleExpand,
  onTriage,
}: FindingRowProps) {
  const navigate = useNavigate();
  const ts = f.triage_state || 'open';
  const sev = (f.severity || 'low').toLowerCase();
  const conf = f.confidence?.toLowerCase();
  const terminal = ts !== 'open' && ts !== 'investigating';

  const handleRowClick = (e: React.MouseEvent<HTMLDivElement>) => {
    // Don't toggle when clicking interactive children
    const tgt = e.target as HTMLElement;
    if (tgt.closest('button, input, a, [role="menu"]')) return;
    onToggleExpand();
  };

  const handleInvestigate = () => {
    navigate(`/findings/${f.index}`);
  };

  return (
    <div
      className={`finding-row${selected ? ' selected' : ''}${expanded ? ' expanded' : ''} finding-row--sev-${sev} finding-row--state-${ts}`}
    >
      <div className="finding-row-main" onClick={handleRowClick}>
        <input
          type="checkbox"
          className="finding-row-check"
          checked={selected}
          onChange={onToggleSelect}
          onClick={(e) => e.stopPropagation()}
          aria-label="Select finding"
        />
        <span className={`finding-row-sev sev-${sev}`}>
          {f.severity || 'Low'}
        </span>
        <div className="finding-row-body">
          <div className="finding-row-title">
            <code className="finding-row-rule">{f.rule_id}</code>
            {ts !== 'open' && (
              <span className={`finding-row-state badge-triage-${ts}`}>
                {stateLabel(ts)}
              </span>
            )}
          </div>
          <div className="finding-row-meta">
            <span className="finding-row-path" title={f.path}>
              {shortPath(f.path)}
              <span className="finding-row-line">:{f.line}</span>
            </span>
            {conf && conf !== 'high' && (
              <span className={`finding-row-conf conf-${conf}`}>
                {conf} conf
              </span>
            )}
            {f.language && (
              <span className="finding-row-lang">{f.language}</span>
            )}
          </div>
        </div>
        <div className="finding-row-actions">
          <button
            type="button"
            className="btn btn-sm btn-primary finding-row-investigate"
            onClick={handleInvestigate}
          >
            Investigate
          </button>
          <Dropdown
            align="right"
            trigger={() => (
              <button
                type="button"
                className="btn btn-sm finding-row-kebab"
                aria-label="More actions"
              >
                ⋯
              </button>
            )}
          >
            {({ close }) => (
              <>
                {!terminal && (
                  <DropdownItem
                    onClick={() => {
                      onTriage(f.fingerprint, 'investigating');
                      close();
                    }}
                  >
                    Mark as investigating
                  </DropdownItem>
                )}
                <DropdownItem
                  tone="warning"
                  onClick={() => {
                    onTriage(f.fingerprint, 'false_positive');
                    close();
                  }}
                >
                  Mark false positive
                </DropdownItem>
                <DropdownItem
                  tone="warning"
                  onClick={() => {
                    onTriage(f.fingerprint, 'suppressed');
                    close();
                  }}
                >
                  Suppress
                </DropdownItem>
                <DropdownItem
                  tone="warning"
                  onClick={() => {
                    onTriage(f.fingerprint, 'accepted_risk');
                    close();
                  }}
                >
                  Accept risk
                </DropdownItem>
                {ts === 'investigating' && (
                  <DropdownItem
                    onClick={() => {
                      onTriage(f.fingerprint, 'fixed');
                      close();
                    }}
                  >
                    Mark fixed
                  </DropdownItem>
                )}
                {terminal && (
                  <DropdownItem
                    onClick={() => {
                      onTriage(f.fingerprint, 'open');
                      close();
                    }}
                  >
                    Reopen
                  </DropdownItem>
                )}
              </>
            )}
          </Dropdown>
          <button
            type="button"
            className="finding-row-chevron"
            onClick={onToggleExpand}
            aria-label={expanded ? 'Collapse details' : 'Expand details'}
            aria-expanded={expanded}
          >
            <span className={`chev${expanded ? ' open' : ''}`}>▾</span>
          </button>
        </div>
      </div>
      {expanded && <FindingRowDetails finding={f} />}
    </div>
  );
}

function FindingRowDetails({ finding: f }: { finding: FindingView }) {
  const sourceLabels = f.labels.filter(
    ([k]) => k === 'source' || k === 'sink' || k === 'sanitizer',
  );
  return (
    <div className="finding-row-details">
      <div className="finding-row-details-grid">
        <div className="finding-row-details-item">
          <div className="finding-row-details-label">Path</div>
          <code className="finding-row-details-path">
            {f.path}:{f.line}
          </code>
        </div>
        {f.message && (
          <div className="finding-row-details-item">
            <div className="finding-row-details-label">Message</div>
            <div className="finding-row-details-text">{f.message}</div>
          </div>
        )}
        {sourceLabels.length > 0 && (
          <div className="finding-row-details-item">
            <div className="finding-row-details-label">Flow</div>
            <div className="finding-row-details-labels">
              {sourceLabels.map(([k, v], i) => (
                <span key={`${k}-${v}-${i}`} className={`cap-badge-${k}`}>
                  <span className="cap-key">{k}</span>
                  <span className="cap-val">{v}</span>
                </span>
              ))}
            </div>
          </div>
        )}
        <div className="finding-row-details-item">
          <div className="finding-row-details-label">Details</div>
          <div className="finding-row-details-actions">
            <Link to={`/findings/${f.index}`} className="btn btn-sm">
              Open full investigation
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Group Header ────────────────────────────────────────────────────────────

interface GroupHeaderProps {
  label: string;
  count: number;
  severityMix: Record<string, number>;
  collapsed: boolean;
  onToggle: () => void;
  allSelected: boolean;
  someSelected: boolean;
  onToggleAll: () => void;
}

function GroupHeader({
  label,
  count,
  severityMix,
  collapsed,
  onToggle,
  allSelected,
  someSelected,
  onToggleAll,
}: GroupHeaderProps) {
  return (
    <div className={`finding-group-header${collapsed ? ' collapsed' : ''}`}>
      <input
        type="checkbox"
        className="finding-group-check"
        checked={allSelected}
        ref={(el) => {
          if (el) el.indeterminate = someSelected && !allSelected;
        }}
        onChange={onToggleAll}
        aria-label="Select all in group"
      />
      <button
        type="button"
        className="finding-group-toggle"
        onClick={onToggle}
        aria-expanded={!collapsed}
      >
        <span className={`chev${collapsed ? '' : ' open'}`}>▾</span>
        <span className="finding-group-label">{label}</span>
        <span className="finding-group-count">{count}</span>
      </button>
      <div className="finding-group-sev">
        {SEVERITIES.map((sev) => {
          const n = severityMix[sev] ?? 0;
          if (n === 0) return null;
          return (
            <span
              key={sev}
              className={`finding-group-sev-pill sev-${sev.toLowerCase()}`}
            >
              {n} {sev}
            </span>
          );
        })}
      </div>
    </div>
  );
}

// ── Findings List ───────────────────────────────────────────────────────────

interface Group {
  key: string;
  label: string;
  findings: FindingView[];
  severityMix: Record<string, number>;
}

function buildGroups(findings: FindingView[], mode: GroupMode): Group[] {
  if (mode === 'none') {
    const mix: Record<string, number> = {};
    findings.forEach((f) => {
      const sev = f.severity || 'Low';
      mix[sev] = (mix[sev] ?? 0) + 1;
    });
    return [{ key: 'all', label: 'All findings', findings, severityMix: mix }];
  }

  const bucket = new Map<string, FindingView[]>();
  const labelFor = (f: FindingView): string => {
    if (mode === 'rule') return f.rule_id || '(unknown rule)';
    if (mode === 'file') return f.path || '(unknown file)';
    if (mode === 'severity') return f.severity || 'Low';
    return 'All';
  };

  for (const f of findings) {
    const k = labelFor(f);
    const arr = bucket.get(k);
    if (arr) arr.push(f);
    else bucket.set(k, [f]);
  }

  const groups: Group[] = Array.from(bucket.entries()).map(([key, items]) => {
    const mix: Record<string, number> = {};
    items.forEach((f) => {
      const sev = f.severity || 'Low';
      mix[sev] = (mix[sev] ?? 0) + 1;
    });
    return {
      key,
      label: mode === 'file' ? shortPath(key) : key,
      findings: items,
      severityMix: mix,
    };
  });

  if (mode === 'severity') {
    groups.sort((a, b) => severityRank(a.key) - severityRank(b.key));
  } else {
    groups.sort((a, b) => b.findings.length - a.findings.length);
  }
  return groups;
}

interface FindingsListProps {
  findings: FindingView[];
  groupMode: GroupMode;
  selected: Set<number>;
  onToggleSelect: (index: number) => void;
  onToggleSelectMany: (indices: number[], select: boolean) => void;
  onTriage: (fingerprint: string, state: string) => void;
}

function FindingsList({
  findings,
  groupMode,
  selected,
  onToggleSelect,
  onToggleSelectMany,
  onTriage,
}: FindingsListProps) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(
    new Set(),
  );
  const [showCount, setShowCount] = useState(200);

  useEffect(() => {
    setShowCount(200);
  }, [groupMode, findings.length]);

  const groups = useMemo(
    () => buildGroups(findings, groupMode),
    [findings, groupMode],
  );

  if (findings.length === 0) {
    return (
      <div className="empty-state">
        <h3>No findings match the current filters</h3>
        <p>Try clearing rule filters or switching state above.</p>
      </div>
    );
  }

  // Apply show-count to the flat list for pagination-like slicing
  let shown = 0;
  const rendered: ReactNode[] = [];

  for (const g of groups) {
    if (shown >= showCount) break;
    const collapsed = collapsedGroups.has(g.key);
    const indices = g.findings.map((f) => f.index);
    const allSel = indices.length > 0 && indices.every((i) => selected.has(i));
    const someSel = indices.some((i) => selected.has(i));

    rendered.push(
      <div key={`g-${g.key}`} className="finding-group">
        {groupMode !== 'none' && (
          <GroupHeader
            label={g.label}
            count={g.findings.length}
            severityMix={g.severityMix}
            collapsed={collapsed}
            onToggle={() => {
              setCollapsedGroups((prev) => {
                const next = new Set(prev);
                if (next.has(g.key)) next.delete(g.key);
                else next.add(g.key);
                return next;
              });
            }}
            allSelected={allSel}
            someSelected={someSel}
            onToggleAll={() => onToggleSelectMany(indices, !allSel)}
          />
        )}
        {!collapsed && (
          <div className="finding-group-body">
            {g.findings.map((f) => {
              if (shown >= showCount) return null;
              shown += 1;
              const key = `${f.fingerprint}-${f.index}`;
              return (
                <FindingRow
                  key={key}
                  finding={f}
                  selected={selected.has(f.index)}
                  expanded={expanded.has(key)}
                  onToggleSelect={() => onToggleSelect(f.index)}
                  onToggleExpand={() => {
                    setExpanded((prev) => {
                      const next = new Set(prev);
                      if (next.has(key)) next.delete(key);
                      else next.add(key);
                      return next;
                    });
                  }}
                  onTriage={onTriage}
                />
              );
            })}
          </div>
        )}
      </div>,
    );
  }

  const total = findings.length;
  const hasMore = showCount < total;

  return (
    <div className="finding-list">
      {rendered}
      {hasMore && (
        <div className="finding-list-more">
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => setShowCount((n) => n + 200)}
          >
            Show 200 more
          </button>
          <span className="finding-list-more-count">
            Showing {Math.min(showCount, total)} of {total.toLocaleString()}
          </span>
        </div>
      )}
    </div>
  );
}

// ── Bulk Action Bar ─────────────────────────────────────────────────────────

interface TriageBulkBarProps {
  selectedCount: number;
  onAction: (state: string) => void;
  onClear: () => void;
}

function TriageBulkBar({
  selectedCount,
  onAction,
  onClear,
}: TriageBulkBarProps) {
  const visible = selectedCount > 0;
  return (
    <div
      className={`bulk-action-bar triage-bulk-bar${visible ? ' visible' : ''}`}
      aria-hidden={!visible}
    >
      <span className="bulk-count">{selectedCount} selected</span>
      <div className="bulk-actions">
        <button
          type="button"
          className="btn btn-sm"
          disabled={!visible}
          onClick={() => onAction('investigating')}
        >
          Investigate
        </button>
        <button
          type="button"
          className="btn btn-sm bulk-menu-btn--warning"
          disabled={!visible}
          onClick={() => onAction('false_positive')}
        >
          False positive
        </button>
        <button
          type="button"
          className="btn btn-sm bulk-menu-btn--warning"
          disabled={!visible}
          onClick={() => onAction('suppressed')}
        >
          Suppress
        </button>
        <button
          type="button"
          className="btn btn-sm bulk-menu-btn--warning"
          disabled={!visible}
          onClick={() => onAction('accepted_risk')}
        >
          Accept risk
        </button>
        <div className="bulk-divider" aria-hidden />
        <button type="button" className="btn btn-sm" onClick={onClear}>
          Clear selection
        </button>
      </div>
    </div>
  );
}

// ── Suppression Rules Tab ───────────────────────────────────────────────────

function SuppressionRulesTab({
  rules,
  onDelete,
}: {
  rules: SuppressionRule[];
  onDelete: (id: number) => void;
}) {
  if (rules.length === 0) {
    return (
      <div className="empty-state">
        <h3>No suppression rules</h3>
        <p>
          Suppress findings by pattern from the Findings page bulk actions, or
          from individual finding detail pages.
        </p>
      </div>
    );
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Type</th>
            <th>Pattern</th>
            <th>State</th>
            <th>Note</th>
            <th>Created</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.id}>
              <td>
                <span className="badge">{r.suppress_by}</span>
              </td>
              <td>
                <code>{r.match_value}</code>
              </td>
              <td>
                <span className={`badge badge-triage-${r.state}`}>
                  {stateLabel(r.state)}
                </span>
              </td>
              <td>{r.note || '-'}</td>
              <td style={{ fontSize: 'var(--text-xs)', whiteSpace: 'nowrap' }}>
                {r.created_at ? r.created_at.substring(0, 10) : '-'}
              </td>
              <td>
                <button
                  className="btn btn-sm btn-danger"
                  onClick={() => onDelete(r.id)}
                >
                  Delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Audit Log Tab ───────────────────────────────────────────────────────────

function AuditLogTab({ entries }: { entries: AuditEntry[] }) {
  if (entries.length === 0) {
    return (
      <div className="empty-state">
        <h3>No audit entries yet</h3>
        <p>
          Every triage action will be logged here with a timestamp and state
          transition.
        </p>
      </div>
    );
  }

  return (
    <div className="table-wrap">
      <table className="triage-audit-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Fingerprint</th>
            <th>Action</th>
            <th>Transition</th>
            <th>Note</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr key={e.id}>
              <td style={{ fontSize: 'var(--text-xs)', whiteSpace: 'nowrap' }}>
                {e.timestamp
                  ? e.timestamp.substring(0, 19).replace('T', ' ')
                  : '-'}
              </td>
              <td style={{ fontSize: 'var(--text-xs)' }}>
                <code title={e.fingerprint}>
                  {e.fingerprint.substring(0, 12)}
                </code>
              </td>
              <td>
                <span className="badge">{e.action}</span>
              </td>
              <td>
                <span className={`badge badge-triage-${e.previous_state}`}>
                  {stateLabel(e.previous_state)}
                </span>
                <span className="triage-arrow">&rarr;</span>
                <span className={`badge badge-triage-${e.new_state}`}>
                  {stateLabel(e.new_state)}
                </span>
              </td>
              <td style={{ fontSize: 'var(--text-xs)' }}>{e.note || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Triage Page ─────────────────────────────────────────────────────────────

type TriageTab = 'findings' | 'rules' | 'audit';

export function TriagePage() {
  usePageTitle('Triage');
  const [triageFilter, setTriageFilter] = useState('needs_attention');
  const [activeTab, setActiveTab] = useState<TriageTab>('findings');
  const [selectedRules, setSelectedRules] = useState<Set<string>>(new Set());
  const [groupMode, setGroupMode] = useState<GroupMode>('none');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<Set<number>>(new Set());

  const {
    data: findingsPage,
    isLoading: findingsLoading,
    error: findingsError,
  } = useFindings({ per_page: 5000 });
  const { data: auditData } = useTriageAudit({ per_page: 100 });
  const { data: suppressionData } = useSuppressions();
  const { data: syncStatus } = useSyncStatus();

  const bulkTriage = useBulkTriage();
  const deleteSuppression = useDeleteSuppression();
  const triageExport = useTriageExport();
  const triageImport = useTriageImport();

  const findings = useMemo(() => findingsPage?.findings ?? [], [findingsPage]);
  const auditEntries = useMemo(() => auditData?.entries ?? [], [auditData]);
  const suppressionRules = useMemo(
    () => suppressionData?.rules ?? [],
    [suppressionData],
  );

  // Summary stats
  const { stateCounts, totalCount, needsAttention, openBySev, topRules } =
    useMemo(() => {
      const counts: Record<string, number> = {};
      ALL_STATES.forEach((s) => (counts[s] = 0));

      findings.forEach((f) => {
        const ts = f.triage_state || 'open';
        counts[ts] = (counts[ts] || 0) + 1;
      });

      const total = findings.length;
      const attention = (counts['open'] || 0) + (counts['investigating'] || 0);

      const bySev: Record<string, number> = {};
      SEVERITIES.forEach((sev) => {
        bySev[sev] = findings.filter(
          (f) => (f.triage_state || 'open') === 'open' && f.severity === sev,
        ).length;
      });

      const ruleCounts: Record<string, number> = {};
      findings
        .filter((f) => (f.triage_state || 'open') === 'open')
        .forEach((f) => {
          ruleCounts[f.rule_id] = (ruleCounts[f.rule_id] || 0) + 1;
        });
      const top = Object.entries(ruleCounts).sort((a, b) => b[1] - a[1]);

      return {
        stateCounts: counts,
        totalCount: total,
        needsAttention: attention,
        openBySev: bySev,
        topRules: top,
      };
    }, [findings]);

  // Filtered findings (applies state + rule chips + search)
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return findings.filter((f) => {
      const ts = f.triage_state || 'open';

      // State filter
      if (triageFilter === 'needs_attention') {
        if (ts !== 'open' && ts !== 'investigating') return false;
      } else if (triageFilter !== 'all' && ts !== triageFilter) {
        return false;
      }

      // Rule filter
      if (selectedRules.size > 0 && !selectedRules.has(f.rule_id)) return false;

      // Search
      if (q.length > 0) {
        const hay = `${f.rule_id} ${f.path} ${f.message ?? ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }

      return true;
    });
  }, [findings, triageFilter, selectedRules, search]);

  // Clear selection when filter changes meaningfully
  useEffect(() => {
    setSelected(new Set());
  }, [triageFilter, selectedRules, search, groupMode]);

  const handleTriage = useCallback(
    (fingerprint: string, state: string) => {
      bulkTriage.mutate({ fingerprints: [fingerprint], state, note: '' });
    },
    [bulkTriage],
  );

  const handleToggleSelect = useCallback((index: number) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  }, []);

  const handleToggleSelectMany = useCallback(
    (indices: number[], select: boolean) => {
      setSelected((prev) => {
        const next = new Set(prev);
        for (const i of indices) {
          if (select) next.add(i);
          else next.delete(i);
        }
        return next;
      });
    },
    [],
  );

  const handleBulkAction = useCallback(
    (state: string) => {
      if (selected.size === 0) return;
      const fingerprints = filtered
        .filter((f) => selected.has(f.index))
        .map((f) => f.fingerprint);
      if (fingerprints.length === 0) return;
      bulkTriage.mutate(
        { fingerprints, state, note: '' },
        { onSuccess: () => setSelected(new Set()) },
      );
    },
    [bulkTriage, filtered, selected],
  );

  const handleToggleRule = useCallback((rule: string) => {
    setSelectedRules((prev) => {
      const next = new Set(prev);
      if (next.has(rule)) next.delete(rule);
      else next.add(rule);
      return next;
    });
  }, []);

  const handleClearRules = useCallback(() => setSelectedRules(new Set()), []);

  const handleDeleteRule = useCallback(
    (id: number) => {
      deleteSuppression.mutate(id);
    },
    [deleteSuppression],
  );

  const handleExport = useCallback(() => {
    triageExport.mutate(undefined, {
      onSuccess: (result) => {
        const r = result as { exported?: number; suppression_rules?: number };
        alert(
          `Exported ${r.exported ?? 0} decisions and ${r.suppression_rules ?? 0} suppression rules to .nyx/triage.json\n\nCommit this file to share triage decisions with your team.`,
        );
      },
      onError: (err) => {
        alert('Export failed: ' + err.message);
      },
    });
  }, [triageExport]);

  const handleImport = useCallback(() => {
    triageImport.mutate(undefined, {
      onSuccess: (result) => {
        const r = result as { imported?: number; total_in_file?: number };
        alert(
          `Imported ${r.imported ?? 0} of ${r.total_in_file ?? 0} decisions from .nyx/triage.json`,
        );
      },
      onError: (err) => {
        alert('Import failed: ' + err.message);
      },
    });
  }, [triageImport]);

  if (findingsLoading) return <LoadingState message="Loading triage data..." />;
  if (findingsError) {
    return (
      <ErrorState
        title="Error loading triage data"
        message={findingsError.message}
      />
    );
  }

  const currentStateLabel =
    STATE_FILTERS.find((s) => s.value === triageFilter)?.label ??
    'Needs attention';
  const currentGroupLabel =
    GROUP_MODES.find((g) => g.value === groupMode)?.label ?? 'None';

  return (
    <div className="triage-page page-shell">
      <TriageSummary
        totalCount={totalCount}
        needsAttention={needsAttention}
        stateCounts={stateCounts}
        openBySev={openBySev}
        activeFilter={triageFilter}
        onFilter={setTriageFilter}
      />

      <div className="triage-tabs-row">
        <div className="triage-tabs">
          <button
            className={`triage-tab${activeTab === 'findings' ? ' active' : ''}`}
            onClick={() => setActiveTab('findings')}
          >
            Findings{' '}
            <span className="triage-tab-count">
              {totalCount.toLocaleString()}
            </span>
          </button>
          <button
            className={`triage-tab${activeTab === 'rules' ? ' active' : ''}${suppressionRules.length === 0 ? ' empty' : ''}`}
            onClick={() => setActiveTab('rules')}
          >
            Suppression rules
            {suppressionRules.length > 0 && (
              <span className="triage-tab-count">
                {suppressionRules.length}
              </span>
            )}
          </button>
          <button
            className={`triage-tab${activeTab === 'audit' ? ' active' : ''}${auditEntries.length === 0 ? ' empty' : ''}`}
            onClick={() => setActiveTab('audit')}
          >
            Audit log
            {auditEntries.length > 0 && (
              <span className="triage-tab-count">{auditEntries.length}</span>
            )}
          </button>
        </div>
        <div className="triage-sync-controls">
          {syncStatus ? (
            syncStatus.sync_enabled ? (
              syncStatus.file_exists ? (
                <span className="triage-sync-status">
                  <span className="triage-sync-dot synced" />
                  <span className="triage-sync-text">
                    {syncStatus.decisions} synced decisions
                  </span>
                </span>
              ) : (
                <span className="triage-sync-status">
                  <span className="triage-sync-dot unsynced" /> No sync file
                </span>
              )
            ) : (
              <span className="triage-sync-status">
                <span className="triage-sync-dot unsynced" /> Sync off
              </span>
            )
          ) : null}
          <button className="btn btn-sm" onClick={handleExport}>
            Export
          </button>
          {syncStatus?.file_exists && (
            <button className="btn btn-sm" onClick={handleImport}>
              Import
            </button>
          )}
        </div>
      </div>

      {activeTab === 'findings' && (
        <>
          <div className="triage-controls">
            <Dropdown
              align="left"
              trigger={({ open }) => (
                <button type="button" className="btn btn-sm triage-control-btn">
                  State: <strong>{currentStateLabel}</strong>
                  <span
                    className={`bulk-caret${open ? ' bulk-caret--open' : ''}`}
                  >
                    ▾
                  </span>
                </button>
              )}
            >
              {({ close }) =>
                STATE_FILTERS.map((opt) => (
                  <DropdownItem
                    key={opt.value}
                    checked={triageFilter === opt.value}
                    onClick={() => {
                      setTriageFilter(opt.value);
                      close();
                    }}
                  >
                    {opt.label}
                  </DropdownItem>
                ))
              }
            </Dropdown>
            <Dropdown
              align="left"
              trigger={({ open }) => (
                <button type="button" className="btn btn-sm triage-control-btn">
                  Group by: <strong>{currentGroupLabel}</strong>
                  <span
                    className={`bulk-caret${open ? ' bulk-caret--open' : ''}`}
                  >
                    ▾
                  </span>
                </button>
              )}
            >
              {({ close }) =>
                GROUP_MODES.map((opt) => (
                  <DropdownItem
                    key={opt.value}
                    checked={groupMode === opt.value}
                    onClick={() => {
                      setGroupMode(opt.value);
                      close();
                    }}
                  >
                    {opt.label}
                  </DropdownItem>
                ))
              }
            </Dropdown>
            <input
              className="triage-search"
              type="search"
              placeholder="Search rule, file, message..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <span className="triage-result-count">
              {filtered.length.toLocaleString()} result
              {filtered.length === 1 ? '' : 's'}
            </span>
          </div>

          <RuleFilterChips
            rules={topRules}
            selected={selectedRules}
            onToggle={handleToggleRule}
            onClear={handleClearRules}
          />

          <TriageBulkBar
            selectedCount={selected.size}
            onAction={handleBulkAction}
            onClear={() => setSelected(new Set())}
          />

          <FindingsList
            findings={filtered}
            groupMode={groupMode}
            selected={selected}
            onToggleSelect={handleToggleSelect}
            onToggleSelectMany={handleToggleSelectMany}
            onTriage={handleTriage}
          />
        </>
      )}

      {activeTab === 'rules' && (
        <SuppressionRulesTab
          rules={suppressionRules}
          onDelete={handleDeleteRule}
        />
      )}

      {activeTab === 'audit' && <AuditLogTab entries={auditEntries} />}
    </div>
  );
}
