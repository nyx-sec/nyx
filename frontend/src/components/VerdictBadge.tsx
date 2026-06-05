import type { VerifyResult, VerifyStatus } from '../api/types';

const STATUS_LABELS: Record<VerifyStatus, string> = {
  Confirmed: 'Confirmed',
  PartiallyConfirmed: 'Partially confirmed',
  NotConfirmed: 'Not confirmed',
  Inconclusive: 'Inconclusive',
  Unsupported: 'Unsupported',
};

function verdictTooltip(verdict: VerifyResult): string {
  const { status, triggered_payload, reason, inconclusive_reason, detail } =
    verdict;
  switch (status) {
    case 'Confirmed':
      return triggered_payload
        ? `Confirmed via payload: ${triggered_payload}`
        : 'Dynamically confirmed exploitable';
    case 'PartiallyConfirmed':
      return detail
        ? `Partially confirmed (sink reached): ${detail}`
        : 'Partially confirmed: sink reached but exploit chain did not complete';
    case 'NotConfirmed':
      return (verdict.attempts?.length ?? 0) > 0
        ? `Not confirmed after ${verdict.attempts?.length ?? 0} payload attempt(s)`
        : 'Not confirmed';
    case 'Unsupported':
      return reason
        ? `Unsupported: ${reason}`
        : 'Dynamic verification not supported';
    case 'Inconclusive':
      return inconclusive_reason
        ? `Inconclusive: ${inconclusive_reason}${detail ? `: ${detail}` : ''}`
        : detail || 'Inconclusive';
  }
}

interface VerdictBadgeProps {
  verdict: VerifyResult | undefined;
  /** Show full label (default) or compact icon-only mode */
  compact?: boolean;
}

export function VerdictBadge({ verdict, compact = false }: VerdictBadgeProps) {
  if (!verdict) {
    return <span style={{ color: 'var(--text-tertiary)' }}>-</span>;
  }

  const { status } = verdict;
  const label = STATUS_LABELS[status] ?? status;
  const tooltip = verdictTooltip(verdict);

  return (
    <span
      className={`badge badge-dyn-${status.toLowerCase()}`}
      title={tooltip}
      data-testid={`verdict-badge-${status.toLowerCase()}`}
    >
      {compact ? status.charAt(0) : label}
    </span>
  );
}
