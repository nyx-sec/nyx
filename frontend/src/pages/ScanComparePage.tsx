import { useState, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useScanCompare } from '../api/queries/scans';
import { LoadingState } from '../components/ui/LoadingState';
import { ErrorState } from '../components/ui/ErrorState';
import { usePageTitle } from '../hooks/usePageTitle';
import type {
  CompareResponse,
  ComparedFinding,
  ChangedFinding,
  VerdictTransition,
} from '../api/types';

function truncPath(p?: string, max = 50): string {
  if (!p) return '';
  if (p.length <= max) return p;
  return '...' + p.slice(p.length - max + 3);
}

function fmtDate(iso?: string): string {
  return iso ? new Date(iso).toLocaleString() : '-';
}

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

// ── Finding Row ──────────────────────────────────────────────────────────────

function CompareRow({
  f,
  rowCls,
  showChanges,
}: {
  f: ComparedFinding | ChangedFinding;
  rowCls: string;
  showChanges: boolean;
}) {
  const navigate = useNavigate();
  // Both ComparedFinding and ChangedFinding extend FindingView directly
  const severity = f.severity || '';
  const ruleId = f.rule_id || '';
  const path = f.path || '';
  const line = f.line || '-';
  const confidence = f.confidence;
  const index = f.index;

  const changes =
    showChanges && 'changes' in f ? (f as ChangedFinding).changes : [];

  return (
    <div
      className={`compare-finding-row ${rowCls}`}
      onClick={() => index != null && navigate(`/findings/${index}`)}
      style={{ cursor: 'pointer' }}
    >
      <span className={`badge badge-${severity.toLowerCase()}`}>
        {severity}
      </span>
      <span style={{ fontSize: 'var(--text-xs)' }}>{ruleId}</span>
      <span className="finding-path" title={path}>
        {truncPath(path)}
      </span>
      <span
        style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}
      >
        L{line}
      </span>
      {confidence && (
        <span className={`badge badge-conf-${confidence.toLowerCase()}`}>
          {confidence}
        </span>
      )}
      {changes &&
        changes.length > 0 &&
        changes.map((c, i) => (
          <span key={i} className="compare-delta-inline">
            {c.field}: {c.old_value} <span className="delta-arrow">&rarr;</span>{' '}
            {c.new_value}
          </span>
        ))}
    </div>
  );
}

// ── Collapsible Section ──────────────────────────────────────────────────────

function CollapsibleSection({
  sectionKey,
  headerContent,
  defaultCollapsed = false,
  children,
}: {
  sectionKey: string;
  headerContent: React.ReactNode;
  defaultCollapsed?: boolean;
  children: React.ReactNode;
}) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed);

  return (
    <div className="compare-section" data-section={sectionKey}>
      <div
        className="compare-section-header"
        onClick={() => setCollapsed(!collapsed)}
      >
        <span className={`section-toggle ${collapsed ? 'collapsed' : ''}`}>
          &#9660;
        </span>
        {headerContent}
      </div>
      <div
        className="compare-section-body"
        style={{ display: collapsed ? 'none' : undefined }}
      >
        {children}
      </div>
    </div>
  );
}

// ── By Status Tab ────────────────────────────────────────────────────────────

function CompareByStatus({ data }: { data: CompareResponse }) {
  const sections = [
    {
      key: 'new',
      label: 'New Findings',
      badge: 'compare-badge--new',
      rowCls: 'compare-finding-row--new',
      items: data.new_findings,
    },
    {
      key: 'fixed',
      label: 'Fixed Findings',
      badge: 'compare-badge--fixed',
      rowCls: 'compare-finding-row--fixed',
      items: data.fixed_findings,
    },
    {
      key: 'changed',
      label: 'Changed Findings',
      badge: 'compare-badge--changed',
      rowCls: 'compare-finding-row--changed',
      items: data.changed_findings as (ComparedFinding | ChangedFinding)[],
    },
    {
      key: 'unchanged',
      label: 'Unchanged Findings',
      badge: 'compare-badge--unchanged',
      rowCls: 'compare-finding-row--unchanged',
      items: data.unchanged_findings,
    },
  ];

  return (
    <>
      {sections.map((sec) => {
        if (sec.items.length === 0) return null;
        return (
          <CollapsibleSection
            key={sec.key}
            sectionKey={sec.key}
            defaultCollapsed={sec.key === 'unchanged'}
            headerContent={
              <>
                <span className={sec.badge}>{sec.key.toUpperCase()}</span>
                <span>
                  {sec.label} ({sec.items.length})
                </span>
              </>
            }
          >
            {sec.items.map((f, i) => (
              <CompareRow
                key={i}
                f={f}
                rowCls={sec.rowCls}
                showChanges={sec.key === 'changed'}
              />
            ))}
          </CollapsibleSection>
        );
      })}
    </>
  );
}

// ── By Group Tab ─────────────────────────────────────────────────────────────

interface TaggedFinding extends ComparedFinding {
  _status: string;
}

function CompareByGroup({
  data,
  groupField,
}: {
  data: CompareResponse;
  groupField: 'rule_id' | 'path';
}) {
  const groups = useMemo(() => {
    const all: TaggedFinding[] = [];
    data.new_findings.forEach((f) => all.push({ ...f, _status: 'new' }));
    data.fixed_findings.forEach((f) => all.push({ ...f, _status: 'fixed' }));
    data.changed_findings.forEach((f) =>
      all.push({ ...(f as unknown as ComparedFinding), _status: 'changed' }),
    );
    data.unchanged_findings.forEach((f) =>
      all.push({ ...f, _status: 'unchanged' }),
    );

    const grouped: Record<string, TaggedFinding[]> = {};
    all.forEach((f) => {
      // ComparedFinding extends FindingView, so groupField is directly on f
      const key = f[groupField] || '(unknown)';
      if (!grouped[key]) grouped[key] = [];
      grouped[key].push(f);
    });

    return Object.entries(grouped).sort(([a], [b]) => a.localeCompare(b));
  }, [data, groupField]);

  return (
    <div className="scan-compare-page page-shell">
      {groups.map(([key, items]) => {
        const counts = { new: 0, fixed: 0, changed: 0, unchanged: 0 };
        items.forEach(
          (f) =>
            (counts[f._status as keyof typeof counts] =
              (counts[f._status as keyof typeof counts] || 0) + 1),
        );
        const summary =
          [
            counts.new > 0 ? `+${counts.new}` : '',
            counts.fixed > 0 ? `-${counts.fixed}` : '',
            counts.changed > 0 ? `~${counts.changed}` : '',
          ]
            .filter(Boolean)
            .join(' ') || `${counts.unchanged} unchanged`;

        return (
          <CollapsibleSection
            key={key}
            sectionKey={key}
            headerContent={
              <>
                <span
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 'var(--text-xs)',
                  }}
                >
                  {key}
                </span>
                <span className="compare-group-summary">{summary}</span>
              </>
            }
          >
            {items.map((f, i) => (
              <CompareRow
                key={i}
                f={f}
                rowCls={`compare-finding-row--${f._status}`}
                showChanges={f._status === 'changed'}
              />
            ))}
          </CollapsibleSection>
        );
      })}
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

// ── Verdict Diff Tab ─────────────────────────────────────────────────────────

const TRANSITION_ORDER: VerdictTransition[] = [
  'FlippedConfirmed',
  'Regressed',
  'New',
  'FlippedNotConfirmed',
  'Resolved',
  'Unchanged',
];

const TRANSITION_LABELS: Record<VerdictTransition, string> = {
  FlippedConfirmed: 'Flipped Confirmed',
  Regressed: 'Regressed',
  New: 'New',
  FlippedNotConfirmed: 'Flipped Not Confirmed',
  Resolved: 'Resolved',
  Unchanged: 'Unchanged',
};

const TRANSITION_ROW_CLS: Record<VerdictTransition, string> = {
  FlippedConfirmed: 'compare-finding-row--new',
  Regressed: 'compare-finding-row--new',
  New: 'compare-finding-row--new',
  FlippedNotConfirmed: 'compare-finding-row--changed',
  Resolved: 'compare-finding-row--fixed',
  Unchanged: 'compare-finding-row--unchanged',
};

function VerdictDiffSection({ data }: { data: CompareResponse }) {
  const entries = data.verdict_diff;
  if (!entries || entries.length === 0) {
    return (
      <div style={{ color: 'var(--text-secondary)', padding: 'var(--space-4)' }}>
        No verdict-level transitions. Both scans share no findings with stable hashes.
      </div>
    );
  }

  const grouped: Partial<Record<VerdictTransition, typeof entries>> = {};
  for (const e of entries) {
    if (!grouped[e.transition]) grouped[e.transition] = [];
    grouped[e.transition]!.push(e);
  }

  return (
    <>
      {TRANSITION_ORDER.map((t) => {
        const items = grouped[t];
        if (!items || items.length === 0) return null;
        return (
          <CollapsibleSection
            key={t}
            sectionKey={t}
            defaultCollapsed={t === 'Unchanged'}
            headerContent={
              <>
                <span
                  className={`compare-finding-row ${TRANSITION_ROW_CLS[t]}`}
                  style={{ padding: '0 var(--space-2)', borderRadius: 'var(--radius-sm)' }}
                >
                  {TRANSITION_LABELS[t]}
                </span>
                <span style={{ marginLeft: 'var(--space-2)' }}>({items.length})</span>
              </>
            }
          >
            {items.map((e, i) => (
              <div
                key={i}
                className={`compare-finding-row ${TRANSITION_ROW_CLS[t]}`}
                style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}
              >
                <span style={{ color: 'var(--text-tertiary)' }}>
                  {e.path}:{e.line}
                </span>
                <span>{e.rule_id}</span>
                {e.baseline_status && (
                  <span style={{ color: 'var(--text-secondary)' }}>
                    {e.baseline_status}
                  </span>
                )}
                {e.current_status && (
                  <>
                    <span className="delta-arrow">&rarr;</span>
                    <span>{e.current_status}</span>
                  </>
                )}
              </div>
            ))}
          </CollapsibleSection>
        );
      })}
    </>
  );
}

type CompareTab = 'status' | 'rule' | 'file' | 'verdict';

export function ScanComparePage() {
  usePageTitle('Compare scans');
  const { left, right } = useParams<{ left: string; right: string }>();
  const navigate = useNavigate();
  const { data, isLoading, error, refetch } = useScanCompare(
    left || '',
    right || '',
  );
  const [activeTab, setActiveTab] = useState<CompareTab>('status');

  if (isLoading) return <LoadingState message="Loading comparison..." />;
  if (error)
    return (
      <ErrorState
        title="Comparison failed"
        error={error}
        onRetry={() => refetch()}
      />
    );
  if (!data) return <ErrorState message="No comparison data" />;

  const severities = ['HIGH', 'MEDIUM', 'LOW'];

  return (
    <>
      <div className="page-action-row">
        <button className="btn btn-sm" onClick={() => navigate('/scans')}>
          Back to Scans
        </button>
      </div>

      <div className="compare-header">
        <div className="compare-scan-pill">
          <span>Left</span>
          <span className="pill-id">{shortId(data.left_scan.id)}</span>
          <span className="pill-count">
            {data.left_scan.finding_count} findings
          </span>
          <span
            style={{
              color: 'var(--text-tertiary)',
              fontSize: 'var(--text-xs)',
            }}
          >
            {fmtDate(data.left_scan.started_at)}
          </span>
        </div>
        <span className="compare-vs">vs</span>
        <div className="compare-scan-pill">
          <span>Right</span>
          <span className="pill-id">{shortId(data.right_scan.id)}</span>
          <span className="pill-count">
            {data.right_scan.finding_count} findings
          </span>
          <span
            style={{
              color: 'var(--text-tertiary)',
              fontSize: 'var(--text-xs)',
            }}
          >
            {fmtDate(data.right_scan.started_at)}
          </span>
        </div>
      </div>

      <div className="compare-summary-grid">
        <div className="compare-card compare-card--new">
          <div className="compare-card-label">New</div>
          <div className="compare-card-value">{data.summary.new_count}</div>
        </div>
        <div className="compare-card compare-card--fixed">
          <div className="compare-card-label">Fixed</div>
          <div className="compare-card-value">{data.summary.fixed_count}</div>
        </div>
        <div className="compare-card compare-card--changed">
          <div className="compare-card-label">Changed</div>
          <div className="compare-card-value">{data.summary.changed_count}</div>
        </div>
        <div className="compare-card compare-card--unchanged">
          <div className="compare-card-label">Unchanged</div>
          <div className="compare-card-value">
            {data.summary.unchanged_count}
          </div>
        </div>
      </div>

      <div className="severity-delta">
        {severities.map((s) => {
          const d = data.summary.severity_delta[s] || 0;
          let cls = 'delta-zero';
          let prefix = '';
          if (d > 0) {
            cls = 'delta-positive';
            prefix = '+';
          } else if (d < 0) {
            cls = 'delta-negative';
          }
          return (
            <span key={s} className="severity-delta-item">
              <span className={`badge badge-${s.toLowerCase()}`}>{s}</span>
              <span className={cls}>
                {prefix}
                {d}
              </span>
            </span>
          );
        })}
      </div>

      <div className="scan-detail-tabs">
        <button
          className={`scan-detail-tab ${activeTab === 'status' ? 'active' : ''}`}
          onClick={() => setActiveTab('status')}
        >
          By Status
        </button>
        <button
          className={`scan-detail-tab ${activeTab === 'rule' ? 'active' : ''}`}
          onClick={() => setActiveTab('rule')}
        >
          By Rule
        </button>
        <button
          className={`scan-detail-tab ${activeTab === 'file' ? 'active' : ''}`}
          onClick={() => setActiveTab('file')}
        >
          By File
        </button>
        <button
          className={`scan-detail-tab ${activeTab === 'verdict' ? 'active' : ''}`}
          onClick={() => setActiveTab('verdict')}
        >
          Verdict Diff
        </button>
      </div>

      <div id="compare-tab-content">
        {activeTab === 'status' && <CompareByStatus data={data} />}
        {activeTab === 'rule' && (
          <CompareByGroup data={data} groupField="rule_id" />
        )}
        {activeTab === 'file' && (
          <CompareByGroup data={data} groupField="path" />
        )}
        {activeTab === 'verdict' && <VerdictDiffSection data={data} />}
      </div>
    </>
  );
}
