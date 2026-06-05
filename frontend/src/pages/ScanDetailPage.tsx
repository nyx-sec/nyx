import { useState, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  useScan,
  useScans,
  useScanFindings,
  useScanLogs,
  useScanMetrics,
} from '../api/queries/scans';
import { LoadingState } from '../components/ui/LoadingState';
import { ErrorState } from '../components/ui/ErrorState';
import { usePageTitle } from '../hooks/usePageTitle';
import type { ScanView, ScanLogEntry, ScanMetricsSnapshot } from '../api/types';

function truncPath(p?: string, max = 50): string {
  if (!p) return '';
  if (p.length <= max) return p;
  return '...' + p.slice(p.length - max + 3);
}

function fmtDate(iso?: string): string {
  return iso ? new Date(iso).toLocaleString() : '-';
}

function fmtNum(n?: number | null): string {
  return n != null ? n.toLocaleString() : '-';
}

// ── Summary Tab ──────────────────────────────────────────────────────────────

function SummaryTab({ scan }: { scan: ScanView }) {
  const duration =
    scan.duration_secs != null ? scan.duration_secs.toFixed(2) + 's' : '-';
  const langs = (scan.languages || []).join(', ') || '-';

  const timing = scan.timing;
  const dynamicVerifyMs = timing?.dynamic_verify_ms ?? 0;
  let total = 0;
  if (timing) {
    total =
      timing.walk_ms +
      timing.pass1_ms +
      timing.call_graph_ms +
      timing.pass2_ms +
      timing.post_process_ms +
      dynamicVerifyMs;
  }
  const pct = (ms: number) => ((ms / total) * 100).toFixed(1);

  return (
    <>
      <div className="scan-stat-grid">
        <div className="scan-stat-card">
          <div className="scan-stat-label">Files Scanned</div>
          <div className="scan-stat-value">{scan.files_scanned ?? '-'}</div>
        </div>
        <div className="scan-stat-card">
          <div className="scan-stat-label">Findings</div>
          <div className="scan-stat-value">{scan.finding_count ?? '-'}</div>
        </div>
        <div className="scan-stat-card">
          <div className="scan-stat-label">Duration</div>
          <div className="scan-stat-value">{duration}</div>
        </div>
        <div className="scan-stat-card">
          <div className="scan-stat-label">Languages</div>
          <div
            className="scan-stat-value"
            style={{ fontSize: 'var(--text-base)' }}
          >
            {langs}
          </div>
        </div>
      </div>

      <div className="scan-summary-grid">
        <div className="card scan-detail-card">
          <div className="card-header">Details</div>
          <table>
            <tbody>
              <tr>
                <td style={{ color: 'var(--text-secondary)', width: 140 }}>
                  Scan ID
                </td>
                <td
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 'var(--text-xs)',
                  }}
                >
                  {scan.id}
                </td>
              </tr>
              <tr>
                <td style={{ color: 'var(--text-secondary)' }}>Root</td>
                <td
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 'var(--text-sm)',
                  }}
                >
                  {scan.scan_root}
                </td>
              </tr>
              <tr>
                <td style={{ color: 'var(--text-secondary)' }}>Engine</td>
                <td>{scan.engine_version || '-'}</td>
              </tr>
              <tr>
                <td style={{ color: 'var(--text-secondary)' }}>Started</td>
                <td>{fmtDate(scan.started_at)}</td>
              </tr>
              <tr>
                <td style={{ color: 'var(--text-secondary)' }}>Finished</td>
                <td>{fmtDate(scan.finished_at)}</td>
              </tr>
              {scan.error && (
                <tr>
                  <td style={{ color: 'var(--text-secondary)' }}>Error</td>
                  <td style={{ color: 'var(--sev-high)' }}>{scan.error}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {timing && total > 0 && (
          <div className="card scan-timing-card">
            <div className="card-header">Timing Breakdown</div>
            <div className="timing-bar">
              <div
                className="timing-bar-segment walk"
                style={{ width: `${pct(timing.walk_ms)}%` }}
                title={`Walk: ${timing.walk_ms}ms`}
              ></div>
              <div
                className="timing-bar-segment pass1"
                style={{ width: `${pct(timing.pass1_ms)}%` }}
                title={`Pass 1: ${timing.pass1_ms}ms`}
              ></div>
              <div
                className="timing-bar-segment callgraph"
                style={{ width: `${pct(timing.call_graph_ms)}%` }}
                title={`Call Graph: ${timing.call_graph_ms}ms`}
              ></div>
              <div
                className="timing-bar-segment pass2"
                style={{ width: `${pct(timing.pass2_ms)}%` }}
                title={`Pass 2: ${timing.pass2_ms}ms`}
              ></div>
              <div
                className="timing-bar-segment postprocess"
                style={{ width: `${pct(timing.post_process_ms)}%` }}
                title={`Post-process: ${timing.post_process_ms}ms`}
              ></div>
              {dynamicVerifyMs > 0 && (
                <div
                  className="timing-bar-segment postprocess"
                  style={{ width: `${pct(dynamicVerifyMs)}%` }}
                  title={`Dynamic verification: ${dynamicVerifyMs}ms`}
                ></div>
              )}
            </div>
            <div className="timing-legend">
              <span className="timing-legend-item">
                <span
                  className="timing-legend-dot"
                  style={{ background: 'var(--sev-low)' }}
                ></span>{' '}
                Walk {timing.walk_ms}ms
              </span>
              <span className="timing-legend-item">
                <span
                  className="timing-legend-dot"
                  style={{ background: 'var(--accent)' }}
                ></span>{' '}
                Pass 1 {timing.pass1_ms}ms
              </span>
              <span className="timing-legend-item">
                <span
                  className="timing-legend-dot"
                  style={{ background: 'var(--sev-medium)' }}
                ></span>{' '}
                Call Graph {timing.call_graph_ms}ms
              </span>
              <span className="timing-legend-item">
                <span
                  className="timing-legend-dot"
                  style={{ background: 'var(--success)' }}
                ></span>{' '}
                Pass 2 {timing.pass2_ms}ms
              </span>
              <span className="timing-legend-item">
                <span
                  className="timing-legend-dot"
                  style={{ background: 'var(--text-tertiary)' }}
                ></span>{' '}
                Post {timing.post_process_ms}ms
              </span>
              {dynamicVerifyMs > 0 && (
                <span className="timing-legend-item">
                  <span
                    className="timing-legend-dot"
                    style={{ background: 'var(--text-tertiary)' }}
                  ></span>{' '}
                  Dynamic {dynamicVerifyMs}ms
                </span>
              )}
            </div>
          </div>
        )}
      </div>
    </>
  );
}

// ── Findings Tab ─────────────────────────────────────────────────────────────

function FindingsTab({ scanId }: { scanId: string }) {
  const navigate = useNavigate();
  const { data, isLoading, error } = useScanFindings(scanId);

  if (isLoading) return <LoadingState message="Loading findings..." />;
  if (error) return <ErrorState message={error.message} />;
  if (!data?.findings || data.findings.length === 0) {
    return (
      <div className="empty-state">
        <h3>No findings</h3>
        <p>This scan produced no findings.</p>
      </div>
    );
  }

  return (
    <div className="scan-detail-page page-shell">
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Rule</th>
              <th>File</th>
              <th>Line</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {data.findings.map((f) => (
              <tr
                key={f.index}
                className="clickable"
                onClick={() => navigate(`/findings/${f.index}`)}
              >
                <td>
                  <span className={`badge badge-${f.severity.toLowerCase()}`}>
                    {f.severity}
                  </span>
                </td>
                <td>{f.rule_id}</td>
                <td className="cell-path" title={f.path}>
                  {truncPath(f.path)}
                </td>
                <td>{f.line}</td>
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
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div
        style={{
          marginTop: 'var(--space-2)',
          fontSize: 'var(--text-sm)',
          color: 'var(--text-secondary)',
        }}
      >
        Showing {data.findings.length} of {data.total} findings
      </div>
    </div>
  );
}

// ── Logs Tab ─────────────────────────────────────────────────────────────────

function LogsTab({ scanId }: { scanId: string }) {
  const [levelFilter, setLevelFilter] = useState<string | undefined>(undefined);
  const { data: logs, isLoading, error } = useScanLogs(scanId, levelFilter);

  if (isLoading) return <LoadingState message="Loading logs..." />;
  if (error) return <ErrorState message={error.message} />;

  const levels: Array<{ value: string | undefined; label: string }> = [
    { value: undefined, label: 'All' },
    { value: 'info', label: 'Info' },
    { value: 'warn', label: 'Warn' },
    { value: 'error', label: 'Error' },
  ];

  return (
    <>
      <div className="log-filters">
        {levels.map((l) => (
          <button
            key={l.label}
            className={`log-filter-btn ${levelFilter === l.value ? 'active' : ''}`}
            onClick={() => setLevelFilter(l.value)}
          >
            {l.label}
          </button>
        ))}
      </div>
      {!logs || logs.length === 0 ? (
        <div className="empty-state">
          <p>No log entries</p>
        </div>
      ) : (
        <div className="log-viewer">
          {logs.map((l: ScanLogEntry, i: number) => (
            <div key={i} className={`log-entry log-${l.level}`}>
              <span className={`log-level ${l.level}`}>{l.level}</span>
              <span className="log-time">
                {new Date(l.timestamp).toLocaleTimeString()}
              </span>
              <span className="log-message">
                {l.message}
                {l.file_path && (
                  <span style={{ color: 'var(--text-tertiary)' }}>
                    {' '}
                    {l.file_path}
                  </span>
                )}
              </span>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

// ── Metrics Tab ──────────────────────────────────────────────────────────────

function MetricsTab({ scanId, scan }: { scanId: string; scan: ScanView }) {
  const { data: fetchedMetrics } = useScanMetrics(scanId);
  const metrics: ScanMetricsSnapshot | undefined =
    scan.metrics || fetchedMetrics || undefined;

  if (!metrics) {
    return (
      <div className="empty-state">
        <p>No metrics available for this scan.</p>
      </div>
    );
  }

  return (
    <div className="metric-grid">
      <div className="metric-card">
        <div className="metric-card-label">CFG Nodes</div>
        <div className="metric-card-value">{fmtNum(metrics.cfg_nodes)}</div>
      </div>
      <div className="metric-card">
        <div className="metric-card-label">Call Edges</div>
        <div className="metric-card-value">{fmtNum(metrics.call_edges)}</div>
      </div>
      <div className="metric-card">
        <div className="metric-card-label">Functions Analyzed</div>
        <div className="metric-card-value">
          {fmtNum(metrics.functions_analyzed)}
        </div>
      </div>
      <div className="metric-card">
        <div className="metric-card-label">Summaries Reused</div>
        <div className="metric-card-value">
          {fmtNum(metrics.summaries_reused)}
        </div>
      </div>
      <div className="metric-card">
        <div className="metric-card-label">Unresolved Calls</div>
        <div className="metric-card-value">
          {fmtNum(metrics.unresolved_calls)}
        </div>
      </div>
    </div>
  );
}

// ── Scan Detail Page ─────────────────────────────────────────────────────────

type TabId = 'summary' | 'findings' | 'logs' | 'metrics';

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: scan, isLoading, error } = useScan(id || '');
  const { data: allScans } = useScans();
  const [activeTab, setActiveTab] = useState<TabId>('summary');
  usePageTitle(scan ? `Scan ${scan.id.slice(0, 8)}` : 'Scan');

  const prevScanId = useMemo(() => {
    if (!scan || scan.status !== 'completed' || !allScans) return null;
    const completed = allScans
      .filter((s) => s.status === 'completed' && s.started_at)
      .sort((a, b) => (a.started_at || '').localeCompare(b.started_at || ''));
    const myIdx = completed.findIndex((s) => s.id === id);
    if (myIdx > 0) return completed[myIdx - 1].id;
    return null;
  }, [scan, allScans, id]);

  if (isLoading) return <LoadingState message="Loading scan..." />;
  if (error || !scan) {
    return (
      <ErrorState
        title="Scan not found"
        message={error?.message || 'Not found'}
      />
    );
  }

  const tabs: { id: TabId; label: string }[] = [
    { id: 'summary', label: 'Summary' },
    { id: 'findings', label: 'Findings' },
    { id: 'logs', label: 'Logs' },
    { id: 'metrics', label: 'Metrics' },
  ];

  return (
    <>
      <div className="page-action-row">
        <button className="btn btn-sm" onClick={() => navigate('/scans')}>
          Back to Scans
        </button>
        {prevScanId && (
          <button
            className="btn btn-sm page-action-push"
            onClick={() => navigate(`/scans/compare/${prevScanId}/${id}`)}
          >
            Compare with Previous
          </button>
        )}
        <span
          className={`status-badge ${scan.status}`}
          style={{ marginLeft: 'auto' }}
        >
          <span className={`status-dot ${scan.status}`}></span>
          {scan.status}
        </span>
      </div>

      <div className="scan-detail-tabs">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            className={`scan-detail-tab ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div id="scan-tab-content">
        {activeTab === 'summary' && <SummaryTab scan={scan} />}
        {activeTab === 'findings' && <FindingsTab scanId={id!} />}
        {activeTab === 'logs' && <LogsTab scanId={id!} />}
        {activeTab === 'metrics' && <MetricsTab scanId={id!} scan={scan} />}
      </div>
    </>
  );
}
