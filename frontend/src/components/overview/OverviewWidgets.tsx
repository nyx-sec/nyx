import React from 'react';
import { useNavigate } from 'react-router-dom';
import type {
  HealthScore,
  PostureSummary,
  BacklogStats,
  ConfidenceDistribution,
  ScannerQuality,
  HotSink,
  OwaspBucket,
  LanguageHealth,
  SuppressionHygiene,
  BaselineInfo,
  WeightedFile,
  OverviewCount,
} from '../../api/types';
import { truncPath } from '../../utils/truncPath';

// ── HealthScoreCard ─────────────────────────────────────────────────────────

export function HealthScoreCard({
  health,
  posture,
}: {
  health: HealthScore;
  posture?: PostureSummary;
}) {
  const gradeClass = `grade-${health.grade.toLowerCase()}`;
  const gradeAccent =
    health.grade === 'A' || health.grade === 'B'
      ? 'var(--green)'
      : health.grade === 'C'
        ? 'var(--amber)'
        : 'var(--red)';
  return (
    <div
      className="card health-card"
      style={{ '--health-accent': gradeAccent } as React.CSSProperties}
    >
      <div className="health-eyebrow">Health Score</div>
      <div className="health-headline">
        <div className={`health-grade-block ${gradeClass}`}>
          <span className="health-grade-letter">{health.grade}</span>
        </div>
        <div className="health-headline-text">
          <div className="health-summary">
            <span className="health-number">{health.score}</span>
            <span className="health-of">/ 100</span>
          </div>
          {posture && (
            <div className={`health-posture posture-${posture.severity}`}>
              {posture.message}
            </div>
          )}
        </div>
        <div className="health-components">
          {health.components.map((c) => {
            const barColor =
              c.score >= 70
                ? 'var(--green)'
                : c.score >= 40
                  ? 'var(--amber)'
                  : 'var(--red)';
            return (
              <div className="health-component" key={c.label} title={c.detail}>
                <div className="health-component-label">{c.label}</div>
                <div className="health-component-bar-track">
                  <div
                    className="health-component-fill"
                    style={{ width: `${c.score}%`, background: barColor }}
                  />
                </div>
                <div className="health-component-score">{c.score}</div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ── PostureBanner ──────────────────────────────────────────────────────────

export function PostureBanner({ posture }: { posture: PostureSummary }) {
  return (
    <div className={`posture-banner posture-${posture.severity}`}>
      <span className="posture-dot" aria-hidden />
      <span className="posture-message">{posture.message}</span>
    </div>
  );
}

// ── BacklogCard ────────────────────────────────────────────────────────────

export function BacklogCard({ backlog }: { backlog: BacklogStats }) {
  const total = backlog.age_buckets.reduce((s, b) => s + b.count, 0);
  const noHistory =
    backlog.oldest_open_days == null && backlog.age_buckets.length === 0;
  if (noHistory) {
    return null;
  }
  return (
    <div className="card backlog-card">
      <div className="card-header">Backlog Age</div>
      <div className="backlog-body">
        <div className="backlog-stat">
          <div className="backlog-stat-value">
            {backlog.oldest_open_days != null
              ? `${backlog.oldest_open_days}d`
              : '–'}
          </div>
          <div className="backlog-stat-label">Oldest open</div>
        </div>
        <div className="backlog-stat">
          <div className="backlog-stat-value">
            {backlog.median_age_days != null
              ? `${backlog.median_age_days}d`
              : '–'}
          </div>
          <div className="backlog-stat-label">Median age</div>
        </div>
        <div className="backlog-stat">
          <div className="backlog-stat-value">{backlog.stale_count}</div>
          <div className="backlog-stat-label">Older than 30 days</div>
        </div>
        {total > 0 && (
          <div className="backlog-bucket">
            <BucketBar buckets={backlog.age_buckets} />
          </div>
        )}
      </div>
    </div>
  );
}

function BucketBar({ buckets }: { buckets: OverviewCount[] }) {
  const total = buckets.reduce((s, b) => s + b.count, 0);
  if (total === 0) return null;
  const colors = [
    'var(--accent)',
    'var(--green)',
    'var(--amber)',
    'var(--red)',
    'var(--muted)',
  ];
  return (
    <div
      className="bucket-bar"
      title={buckets.map((b) => `${b.name}: ${b.count}`).join(' · ')}
    >
      {buckets.map((b, i) => (
        <div
          key={b.name}
          className="bucket-segment"
          style={{
            width: `${(b.count / total) * 100}%`,
            background: colors[i] || 'var(--accent)',
          }}
        />
      ))}
    </div>
  );
}

// ── ConfidenceDistributionChart ────────────────────────────────────────────

export function ConfidenceDistributionChart({
  dist,
}: {
  dist: ConfidenceDistribution;
}) {
  const total = dist.high + dist.medium + dist.low + dist.none;
  if (total === 0) {
    return (
      <div className="empty-state">
        <p>No data</p>
      </div>
    );
  }
  const segments = [
    { label: 'High', value: dist.high, color: 'var(--green)' },
    { label: 'Medium', value: dist.medium, color: 'var(--amber)' },
    { label: 'Low', value: dist.low, color: 'var(--muted)' },
    { label: 'None', value: dist.none, color: 'var(--subtle)' },
  ];
  return (
    <div className="confidence-dist">
      <div className="confidence-bar">
        {segments.map((s) =>
          s.value > 0 ? (
            <div
              key={s.label}
              className="confidence-segment"
              style={{
                width: `${(s.value / total) * 100}%`,
                background: s.color,
              }}
              title={`${s.label}: ${s.value}`}
            />
          ) : null,
        )}
      </div>
      <div className="confidence-legend">
        {segments.map((s) => (
          <div key={s.label} className="confidence-legend-item">
            <span
              className="confidence-swatch"
              style={{ background: s.color }}
            />
            <span>{s.label}</span>
            <span className="confidence-count">{s.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── ScannerQualityPanel ────────────────────────────────────────────────────

export function ScannerQualityPanel({
  quality,
  crossFileRatio,
}: {
  quality: ScannerQuality;
  crossFileRatio?: number;
}) {
  const symexAttempted = Object.entries(quality.symex_breakdown || {})
    .filter(([k]) => k !== 'not_attempted')
    .reduce((s, [, v]) => s + v, 0);
  const symexTotal = Object.values(quality.symex_breakdown || {}).reduce(
    (s, v) => s + v,
    0,
  );
  const totalFiles = quality.files_scanned + quality.files_skipped;
  const filesValue = totalFiles.toLocaleString();
  const filesDetail =
    quality.files_skipped > 0
      ? `${quality.files_scanned.toLocaleString()} fresh · ${quality.files_skipped.toLocaleString()} from cache`
      : quality.files_scanned > 0
        ? `${quality.files_scanned.toLocaleString()} freshly indexed`
        : undefined;
  const dynamic = quality.dynamic_verification ?? {
    total: 0,
    confirmed: 0,
    not_confirmed: 0,
    inconclusive: 0,
    unsupported: 0,
  };
  const dynamicDetail =
    dynamic.total > 0
      ? `${dynamic.total.toLocaleString()} verdicts · ${dynamic.not_confirmed.toLocaleString()} not confirmed · ${dynamic.inconclusive.toLocaleString()} inconclusive · ${dynamic.unsupported.toLocaleString()} unsupported`
      : 'no dynamic verdicts in latest scan';

  const rows: Array<{
    label: string;
    hint: string;
    value: string;
    detail?: string;
  }> = [
    {
      label: 'Files',
      hint: 'Files the scanner saw on this run.',
      value: filesValue,
      detail: filesDetail,
    },
    {
      label: 'Functions analyzed',
      hint: 'Function bodies the call graph saw.',
      value: quality.functions_analyzed.toLocaleString(),
    },
    {
      label: 'Call edges resolved',
      hint: 'Share of call sites that the scanner resolved to a known callee. The remainder are typically external/library calls.',
      value: `${(quality.call_resolution_rate * 100).toFixed(1)}%`,
      detail:
        quality.unresolved_calls > 0
          ? `${quality.unresolved_calls.toLocaleString()} unresolved`
          : undefined,
    },
    {
      label: 'Cross-file flows',
      hint: 'Findings whose taint path crosses a file boundary.',
      value:
        crossFileRatio != null ? `${(crossFileRatio * 100).toFixed(1)}%` : '0%',
      detail: 'of findings',
    },
    {
      label: 'Symbolic verification',
      hint: 'Taint findings the symbolic engine attempted to verify (confirmed, infeasible, or inconclusive).',
      value:
        symexTotal > 0
          ? `${(quality.symex_verified_rate * 100).toFixed(1)}%`
          : 'n/a',
      detail:
        symexTotal > 0
          ? `${symexAttempted} of ${symexTotal} taint findings`
          : 'no taint findings',
    },
    {
      label: 'Dynamic verification',
      hint: 'Findings re-run in generated harnesses against the dynamic payload corpus.',
      value:
        dynamic.total > 0
          ? `${dynamic.confirmed.toLocaleString()} confirmed`
          : 'not run',
      detail: dynamicDetail,
    },
  ];

  return (
    <dl className="kv-list">
      {rows.map((r) => (
        <div className="kv-row" key={r.label}>
          <dt className="kv-label" title={r.hint}>
            {r.label}
          </dt>
          <dd className="kv-value">
            <div className="kv-number">{r.value}</div>
            {r.detail && <div className="kv-detail">{r.detail}</div>}
          </dd>
        </div>
      ))}
    </dl>
  );
}

// ── HotSinksList ───────────────────────────────────────────────────────────

export function HotSinksList({ sinks }: { sinks: HotSink[] }) {
  if (!sinks.length) {
    return (
      <div className="empty-state">
        <p>No data</p>
      </div>
    );
  }
  return (
    <table>
      <thead>
        <tr>
          <th>Sink</th>
          <th>Findings</th>
        </tr>
      </thead>
      <tbody>
        {sinks.map((s) => (
          <tr key={s.callee} title={s.callee}>
            <td className="font-mono">{s.callee}</td>
            <td>{s.count}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ── OwaspChart ─────────────────────────────────────────────────────────────

export function OwaspChart({ buckets }: { buckets: OwaspBucket[] }) {
  if (!buckets.length) {
    return (
      <div className="empty-state">
        <p>No data</p>
      </div>
    );
  }
  const max = Math.max(...buckets.map((b) => b.count), 1);
  return (
    <ul className="owasp-list">
      {buckets.map((b) => (
        <li key={b.code} className="owasp-row" title={b.label}>
          <span className="owasp-code">{b.code}</span>
          <span className="owasp-label">{b.label}</span>
          <div className="owasp-bar">
            <div
              className="owasp-fill"
              style={{ width: `${(b.count / max) * 100}%` }}
            />
          </div>
          <span className="owasp-count">{b.count}</span>
        </li>
      ))}
    </ul>
  );
}

// ── WeightedTopFiles ───────────────────────────────────────────────────────

export function WeightedTopFiles({
  files,
  onRowClick,
}: {
  files: WeightedFile[];
  onRowClick?: (name: string) => void;
}) {
  if (!files.length) {
    return (
      <div className="empty-state">
        <p>No data</p>
      </div>
    );
  }
  return (
    <table>
      <thead>
        <tr>
          <th>File</th>
          <th>Severity</th>
          <th>Score</th>
        </tr>
      </thead>
      <tbody>
        {files.map((f) => (
          <tr
            key={f.name}
            title={f.name}
            className={onRowClick ? 'clickable' : undefined}
            onClick={onRowClick ? () => onRowClick(f.name) : undefined}
          >
            <td>{truncPath(f.name, 45)}</td>
            <td>
              <SeverityStack high={f.high} medium={f.medium} low={f.low} />
            </td>
            <td className="font-mono">{f.score}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function SeverityStack({
  high,
  medium,
  low,
}: {
  high: number;
  medium: number;
  low: number;
}) {
  const total = high + medium + low;
  if (total === 0) return null;
  return (
    <div
      className="severity-stack"
      title={`${high} High · ${medium} Medium · ${low} Low`}
    >
      {high > 0 && (
        <div
          className="sev-segment sev-high"
          style={{ width: `${(high / total) * 100}%` }}
        >
          {high}
        </div>
      )}
      {medium > 0 && (
        <div
          className="sev-segment sev-medium"
          style={{ width: `${(medium / total) * 100}%` }}
        >
          {medium}
        </div>
      )}
      {low > 0 && (
        <div
          className="sev-segment sev-low"
          style={{ width: `${(low / total) * 100}%` }}
        >
          {low}
        </div>
      )}
    </div>
  );
}

// ── LanguageHealthTable ────────────────────────────────────────────────────

export function LanguageHealthTable({ rows }: { rows: LanguageHealth[] }) {
  if (!rows.length) {
    return (
      <div className="empty-state">
        <p>No data</p>
      </div>
    );
  }
  return (
    <table>
      <thead>
        <tr>
          <th>Language</th>
          <th>Findings</th>
          <th>Severity</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.language}>
            <td>{r.language}</td>
            <td>{r.findings}</td>
            <td>
              <SeverityStack high={r.high} medium={r.medium} low={r.low} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ── SuppressionHygieneCard ─────────────────────────────────────────────────

export function SuppressionHygieneCard({
  hygiene,
}: {
  hygiene: SuppressionHygiene;
}) {
  const total =
    hygiene.fingerprint_level +
    hygiene.rule_level +
    hygiene.file_level +
    hygiene.rule_in_file_level;
  const blanket =
    hygiene.rule_level + hygiene.file_level + hygiene.rule_in_file_level;
  const blanketDisplay =
    total > 0 ? `${(hygiene.blanket_rate * 100).toFixed(0)}%` : 'n/a';
  const blanketDetail =
    total > 0
      ? `${blanket} of ${total} suppressions are not pinned to a specific finding`
      : 'No suppressions yet';
  return (
    <dl className="kv-list">
      <div className="kv-row kv-row-emphasis">
        <dt
          className="kv-label"
          title="Share of suppressions that are not pinned to a specific finding fingerprint. Lower is better because triage is decisive rather than blanket-silencing whole rules or files."
        >
          Blanket rate
          <span className="kv-hint">Lower is better</span>
        </dt>
        <dd className="kv-value">
          <div className="kv-number">{blanketDisplay}</div>
          <div className="kv-detail">{blanketDetail}</div>
        </dd>
      </div>
      <div className="kv-row">
        <dt
          className="kv-label"
          title="Suppressions that target one specific finding by its fingerprint. Most precise."
        >
          By fingerprint
          <span className="kv-hint">Most specific</span>
        </dt>
        <dd className="kv-value">
          <div className="kv-number">{hygiene.fingerprint_level}</div>
        </dd>
      </div>
      <div className="kv-row">
        <dt
          className="kv-label"
          title="Suppressions that silence a rule only inside a specific file."
        >
          By rule in a file
        </dt>
        <dd className="kv-value">
          <div className="kv-number">{hygiene.rule_in_file_level}</div>
        </dd>
      </div>
      <div className="kv-row">
        <dt
          className="kv-label"
          title="Suppressions that silence an entire rule across the project."
        >
          By rule
        </dt>
        <dd className="kv-value">
          <div className="kv-number">{hygiene.rule_level}</div>
        </dd>
      </div>
      <div className="kv-row">
        <dt
          className="kv-label"
          title="Suppressions that silence everything in a file."
        >
          By file
          <span className="kv-hint">Least specific</span>
        </dt>
        <dd className="kv-value">
          <div className="kv-number">{hygiene.file_level}</div>
        </dd>
      </div>
    </dl>
  );
}

// ── BaselinePinControl ─────────────────────────────────────────────────────

interface BaselinePinControlProps {
  baseline?: BaselineInfo;
  latestScanId?: string;
  onPin: (scanId: string) => void;
  onUnpin: () => void;
  isPending: boolean;
}

export function BaselinePinControl({
  baseline,
  latestScanId,
  onPin,
  onUnpin,
  isPending,
}: BaselinePinControlProps) {
  const navigate = useNavigate();
  if (baseline) {
    const net = baseline.drift_new - baseline.drift_fixed;
    const driftClass =
      net > 0
        ? 'baseline-drift-bad'
        : net < 0
          ? 'baseline-drift-good'
          : 'baseline-drift-flat';
    return (
      <div className="baseline-strip">
        <span className="baseline-label">Baseline:</span>
        <button
          type="button"
          className="baseline-link"
          onClick={() => navigate(`/scans/${baseline.scan_id}`)}
        >
          {baseline.started_at
            ? new Date(baseline.started_at).toLocaleDateString()
            : baseline.scan_id.slice(0, 8)}
        </button>
        <span className={driftClass}>
          drift: +{baseline.drift_new} new / -{baseline.drift_fixed} fixed (
          {net >= 0 ? '+' : ''}
          {net})
        </span>
        <button
          type="button"
          className="baseline-action"
          onClick={onUnpin}
          disabled={isPending}
        >
          Unpin
        </button>
      </div>
    );
  }
  if (!latestScanId) return null;
  return (
    <div className="baseline-strip baseline-strip-empty">
      <span className="baseline-label">No baseline pinned.</span>
      <button
        type="button"
        className="baseline-action"
        onClick={() => onPin(latestScanId)}
        disabled={isPending}
      >
        Pin latest scan as baseline
      </button>
    </div>
  );
}
