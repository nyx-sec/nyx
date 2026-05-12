import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { VerdictBadge } from '@/components/VerdictBadge';
import type { VerifyResult } from '@/api/types';

function makeVerdict(
  status: VerifyResult['status'],
  extras: Partial<VerifyResult> = {},
): VerifyResult {
  return {
    finding_id: 'test-finding-id',
    status,
    attempts: [],
    ...extras,
  };
}

describe('VerdictBadge', () => {
  it('renders dash when verdict is undefined', () => {
    render(<VerdictBadge verdict={undefined} />);
    expect(screen.getByText('-')).toBeInTheDocument();
  });

  it('renders Confirmed badge with flame and correct class', () => {
    render(
      <VerdictBadge
        verdict={makeVerdict('Confirmed', { triggered_payload: 'sqli-tautology' })}
      />,
    );
    const badge = screen.getByTestId('verdict-badge-confirmed');
    expect(badge).toBeInTheDocument();
    expect(badge.className).toContain('badge-dyn-confirmed');
    expect(badge.textContent).toContain('🔥');
  });

  it('renders NotConfirmed badge with correct class', () => {
    render(<VerdictBadge verdict={makeVerdict('NotConfirmed')} />);
    const badge = screen.getByTestId('verdict-badge-notconfirmed');
    expect(badge).toBeInTheDocument();
    expect(badge.className).toContain('badge-dyn-notconfirmed');
    expect(badge.textContent).not.toContain('🔥');
  });

  it('renders Unsupported badge with correct class', () => {
    render(
      <VerdictBadge
        verdict={makeVerdict('Unsupported', { reason: 'NoPayloadsForCap' })}
      />,
    );
    const badge = screen.getByTestId('verdict-badge-unsupported');
    expect(badge).toBeInTheDocument();
    expect(badge.className).toContain('badge-dyn-unsupported');
  });

  it('renders Inconclusive badge with amber class', () => {
    render(
      <VerdictBadge
        verdict={makeVerdict('Inconclusive', {
          inconclusive_reason: 'BuildFailed',
        })}
      />,
    );
    const badge = screen.getByTestId('verdict-badge-inconclusive');
    expect(badge).toBeInTheDocument();
    expect(badge.className).toContain('badge-dyn-inconclusive');
  });

  it('tooltip contains payload for Confirmed', () => {
    render(
      <VerdictBadge
        verdict={makeVerdict('Confirmed', { triggered_payload: 'sqli-payload' })}
      />,
    );
    const badge = screen.getByTestId('verdict-badge-confirmed');
    expect(badge.getAttribute('title')).toContain('sqli-payload');
  });

  it('tooltip contains reason for Unsupported', () => {
    render(
      <VerdictBadge
        verdict={makeVerdict('Unsupported', { reason: 'ConfidenceTooLow' })}
      />,
    );
    const badge = screen.getByTestId('verdict-badge-unsupported');
    expect(badge.getAttribute('title')).toContain('ConfidenceTooLow');
  });

  it('compact mode renders single character', () => {
    render(<VerdictBadge verdict={makeVerdict('Confirmed')} compact />);
    const badge = screen.getByTestId('verdict-badge-confirmed');
    // Compact: first char of status + flame emoji
    expect(badge.textContent?.replace('🔥 ', '')).toBe('C');
  });

  it('renders all four VerifyStatus variants without crashing', () => {
    const statuses: VerifyResult['status'][] = [
      'Confirmed',
      'NotConfirmed',
      'Unsupported',
      'Inconclusive',
    ];
    for (const status of statuses) {
      const { unmount } = render(<VerdictBadge verdict={makeVerdict(status)} />);
      expect(
        screen.getByTestId(`verdict-badge-${status.toLowerCase()}`),
      ).toBeInTheDocument();
      unmount();
    }
  });
});
