import { useNavigate } from 'react-router-dom';
import { useOverview, useOverviewTrends } from '../api/queries/overview';
import { usePinBaseline, useUnpinBaseline } from '../api/mutations/baseline';
import { StatCard } from '../components/ui/StatCard';
import { LoadingState } from '../components/ui/LoadingState';
import { ErrorState } from '../components/ui/ErrorState';
import { HorizontalBarChart } from '../components/charts/HorizontalBarChart';
import { LineChart } from '../components/charts/LineChart';
import { OverviewIcon } from '../components/icons/Icons';
import { truncPath } from '../utils/truncPath';
import {
  HealthScoreCard,
  BacklogCard,
  ConfidenceDistributionChart,
  ScannerQualityPanel,
  HotSinksList,
  OwaspChart,
  WeightedTopFiles,
  LanguageHealthTable,
  SuppressionHygieneCard,
  BaselinePinControl,
} from '../components/overview/OverviewWidgets';
import type { OverviewCount, ScanSummary, Insight } from '../api/types';
import { usePageTitle } from '../hooks/usePageTitle';

export function OverviewPage() {
  usePageTitle('Overview');
  const navigate = useNavigate();
  const { data: overview, isLoading, error, refetch } = useOverview();
  const { data: trends } = useOverviewTrends();
  const pinBaseline = usePinBaseline();
  const unpinBaseline = useUnpinBaseline();

  if (isLoading) {
    return <LoadingState message="Loading overview..." />;
  }

  if (error) {
    return (
      <ErrorState
        title="Error loading overview"
        error={error}
        onRetry={() => refetch()}
      />
    );
  }

  if (!overview) {
    return <LoadingState message="Loading overview..." />;
  }

  // Empty state
  if (overview.state === 'empty') {
    return (
      <div className="overview-empty">
        <OverviewIcon size={48} />
        <h2>Welcome to Nyx</h2>
        <p>Run your first scan to see security findings and analytics.</p>
      </div>
    );
  }

  const netDelta = overview.new_since_last - overview.fixed_since_last;

  const categoryItems = (overview.issue_categories || [])
    .slice(0, 8)
    .map((b) => ({ label: b.label, value: b.count, color: '#72f3d7' }));

  const trendData = (trends || []).map((t) => ({
    label: t.timestamp,
    value: t.total,
  }));

  const hotSinks = overview.hot_sinks || [];

  return (
    <>
      <div className="page-header">
        <h2>Overview</h2>
      </div>

      {/* Baseline strip */}
      <BaselinePinControl
        baseline={overview.baseline}
        latestScanId={overview.latest_scan_id}
        onPin={(id) => pinBaseline.mutate(id)}
        onUnpin={() => unpinBaseline.mutate()}
        isPending={pinBaseline.isPending || unpinBaseline.isPending}
      />

      {overview.health && (
        <HealthScoreCard health={overview.health} posture={overview.posture} />
      )}

      {/* Fresh banner */}
      {overview.state === 'fresh' && (
        <div className="overview-fresh-banner">
          <strong>Scan completed</strong>
          <span>
            {overview.total_findings} finding
            {overview.total_findings === 1 ? '' : 's'} detected
            {overview.latest_scan_duration_secs != null
              ? ` in ${overview.latest_scan_duration_secs.toFixed(1)}s`
              : ''}
            .
          </span>
          <a
            href="/findings"
            className="nav-link-internal"
            onClick={(e) => {
              e.preventDefault();
              navigate('/findings');
            }}
          >
            View all findings &rarr;
          </a>
        </div>
      )}

      {/* Stat cards — kept lean: 5 cards, severity stacks live in Top Files
          and Per-Language. Cross-file / Symex moved into Scanner Quality. */}
      <div className="overview-stat-grid overview-stat-grid-5">
        <StatCard
          label="Total Findings"
          value={overview.total_findings}
          delta={netDelta || null}
        />
        <StatCard
          label="New"
          value={overview.new_since_last}
          color={overview.new_since_last > 0 ? 'var(--sev-high)' : undefined}
        />
        <StatCard
          label="Fixed"
          value={overview.fixed_since_last}
          color={overview.fixed_since_last > 0 ? 'var(--success)' : undefined}
        />
        <StatCard
          label="High Confidence"
          value={`${(overview.high_confidence_rate * 100).toFixed(0)}%`}
        />
        <StatCard
          label="Triage Coverage"
          value={`${(overview.triage_coverage * 100).toFixed(0)}%`}
        />
      </div>

      {/* Charts */}
      <div className="overview-chart-grid">
        <div className="card">
          <div className="card-header">Findings Over Time</div>
          {trendData.length >= 2 ? (
            <LineChart points={trendData} />
          ) : (
            <div className="empty-state" style={{ padding: 16 }}>
              <p>Run a second scan to see trends.</p>
            </div>
          )}
        </div>
        <div className="card">
          <div className="card-header">OWASP Top 10 (2021)</div>
          {overview.owasp_buckets && overview.owasp_buckets.length > 0 ? (
            <OwaspChart buckets={overview.owasp_buckets} />
          ) : (
            <div className="empty-state" style={{ padding: 16 }}>
              <p>No OWASP-mapped findings.</p>
            </div>
          )}
        </div>
        <div className="card">
          <div className="card-header">Confidence Distribution</div>
          {overview.confidence_distribution ? (
            <ConfidenceDistributionChart
              dist={overview.confidence_distribution}
            />
          ) : (
            <div className="empty-state" style={{ padding: 16 }}>
              <p>No data</p>
            </div>
          )}
        </div>
        <div className="card">
          <div className="card-header">Issue Categories</div>
          <HorizontalBarChart items={categoryItems} />
        </div>
      </div>

      {/* Per-language + Top Files */}
      <div className="overview-table-grid">
        <div className="card">
          <div className="card-header">Per-Language Posture</div>
          <LanguageHealthTable rows={overview.language_health || []} />
        </div>
        <div className="card">
          <div className="card-header">
            Top Affected Files (severity-weighted)
          </div>
          <WeightedTopFiles
            files={overview.weighted_top_files || []}
            onRowClick={(name) =>
              navigate(`/findings?search=${encodeURIComponent(name)}`)
            }
          />
        </div>
      </div>

      {/* Top Rules + Top Directories (or Hot Sinks when taint findings exist) */}
      <div className="overview-table-grid">
        <div className="card">
          <div className="card-header">Top Rules Triggered</div>
          <CompactTable
            items={overview.top_rules}
            nameLabel="Rule"
            countLabel="Findings"
          />
        </div>
        <div className="card">
          <div className="card-header">Top Directories</div>
          <CompactTable
            items={overview.top_directories}
            nameLabel="Directory"
            countLabel="Findings"
            truncate
          />
        </div>
      </div>

      {hotSinks.length > 0 && (
        <div className="overview-table-grid">
          <div className="card card-full">
            <div className="card-header">Hot Sinks (taint flow)</div>
            <HotSinksList sinks={hotSinks} />
          </div>
        </div>
      )}

      {overview.backlog && <BacklogCard backlog={overview.backlog} />}

      {/* Scanner Quality + Hygiene */}
      <div className="overview-table-grid">
        <div className="card">
          <div className="card-header">Scanner Quality</div>
          {overview.scanner_quality ? (
            <ScannerQualityPanel
              quality={overview.scanner_quality}
              crossFileRatio={overview.cross_file_ratio}
            />
          ) : (
            <div className="empty-state" style={{ padding: 16 }}>
              <p>No engine metrics available</p>
            </div>
          )}
        </div>
        <div className="card">
          <div className="card-header">Suppression Hygiene</div>
          {overview.suppression_hygiene ? (
            <SuppressionHygieneCard hygiene={overview.suppression_hygiene} />
          ) : (
            <div className="empty-state" style={{ padding: 16 }}>
              <p>No suppressions</p>
            </div>
          )}
        </div>
      </div>

      {/* Recent scans */}
      <div className="overview-table-grid">
        <div className="card">
          <div className="card-header">Recent Scans</div>
          <RecentScansTable
            scans={overview.recent_scans}
            currentBaselineId={overview.baseline?.scan_id}
            onRowClick={(scan) => navigate(`/scans/${scan.id}`)}
            onPinBaseline={(scanId) => pinBaseline.mutate(scanId)}
          />
        </div>
        <div className="card">
          <div className="card-header">Insights</div>
          {overview.insights.length > 0 ? (
            <div className="insight-list">
              {overview.insights.map((insight, i) => (
                <InsightCard key={i} insight={insight} />
              ))}
            </div>
          ) : (
            <div className="empty-state" style={{ padding: 16 }}>
              <p>Nothing to flag.</p>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

// ── Sub-components ──────────────────────────────────────────────────────────

interface CompactTableProps {
  items: OverviewCount[];
  nameLabel: string;
  countLabel: string;
  truncate?: boolean;
  onRowClick?: (item: OverviewCount) => void;
}

function CompactTable({
  items,
  nameLabel,
  countLabel,
  truncate,
  onRowClick,
}: CompactTableProps) {
  if (!items || items.length === 0) {
    return (
      <div className="empty-state" style={{ padding: 16 }}>
        <p>No data</p>
      </div>
    );
  }

  return (
    <table>
      <thead>
        <tr>
          <th>{nameLabel}</th>
          <th>{countLabel}</th>
        </tr>
      </thead>
      <tbody>
        {items.map((item) => {
          const displayName = truncate ? truncPath(item.name, 45) : item.name;
          return (
            <tr
              key={item.name}
              className={onRowClick ? 'clickable' : undefined}
              onClick={onRowClick ? () => onRowClick(item) : undefined}
              title={item.name}
            >
              <td>{displayName}</td>
              <td>{item.count}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

interface RecentScansTableProps {
  scans: ScanSummary[];
  currentBaselineId?: string;
  onRowClick: (scan: ScanSummary) => void;
  onPinBaseline?: (scanId: string) => void;
}

function RecentScansTable({
  scans,
  currentBaselineId,
  onRowClick,
  onPinBaseline,
}: RecentScansTableProps) {
  if (!scans || scans.length === 0) {
    return (
      <div className="empty-state" style={{ padding: 16 }}>
        <p>No scans yet</p>
      </div>
    );
  }

  return (
    <table>
      <thead>
        <tr>
          <th>Status</th>
          <th>Duration</th>
          <th>Findings</th>
          <th>Time</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {scans.slice(0, 5).map((scan) => {
          const isBaseline = scan.id === currentBaselineId;
          const canPin =
            !isBaseline && onPinBaseline && scan.status === 'completed';
          return (
            <tr
              key={scan.id}
              className="clickable"
              onClick={() => onRowClick(scan)}
            >
              <td>
                <span className={`status-dot ${scan.status}`} /> {scan.status}
              </td>
              <td>
                {scan.duration_secs != null
                  ? `${scan.duration_secs.toFixed(1)}s`
                  : '-'}
              </td>
              <td>{scan.finding_count ?? '-'}</td>
              <td>
                {scan.started_at
                  ? new Date(scan.started_at).toLocaleString()
                  : '-'}
              </td>
              <td onClick={(e) => e.stopPropagation()}>
                {isBaseline ? (
                  <span className="baseline-label">baseline</span>
                ) : canPin ? (
                  <button
                    type="button"
                    className="baseline-action"
                    onClick={() => onPinBaseline!(scan.id)}
                  >
                    Pin
                  </button>
                ) : null}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

interface InsightCardProps {
  insight: Insight;
}

function InsightCard({ insight }: InsightCardProps) {
  const navigate = useNavigate();

  return (
    <div className={`insight-card insight-${insight.severity}`}>
      <span>{insight.message}</span>
      {insight.action_url && (
        <a
          href={insight.action_url}
          className="nav-link-internal"
          onClick={(e) => {
            e.preventDefault();
            navigate(insight.action_url!);
          }}
        >
          View &rarr;
        </a>
      )}
    </div>
  );
}
