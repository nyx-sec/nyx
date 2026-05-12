import type { VerifyResult, VerifyStatus } from '../api/types';

const STATUS_LABELS: Record<VerifyStatus, string> = {
  Confirmed: 'Confirmed',
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
    case 'NotConfirmed':
      return verdict.attempts.length > 0
        ? `Not confirmed after ${verdict.attempts.length} payload attempt(s)`
        : 'Not confirmed';
    case 'Unsupported':
      return reason ? `Unsupported: ${reason}` : 'Dynamic verification not supported';
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
  const flame = status === 'Confirmed' ? '🔥 ' : '';

  return (
    <span
      className={`badge badge-dyn-${status.toLowerCase()}`}
      title={tooltip}
      data-testid={`verdict-badge-${status.toLowerCase()}`}
    >
      {flame}
      {compact ? status.charAt(0) : label}
    </span>
  );
}
