import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { DynamicVerdictSection } from '@/pages/FindingDetailPage';
import type { VerifyResult } from '@/api/types';

function makeVerdict(
  status: VerifyResult['status'],
  extras: Partial<VerifyResult> = {},
): VerifyResult {
  return {
    finding_id: 'test-finding-id-abc',
    status,
    attempts: [],
    ...extras,
  };
}

// Mock navigator.clipboard before each test.
beforeEach(() => {
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
    configurable: true,
    writable: true,
  });
});

describe('DynamicVerdictSection', () => {
  it('renders Confirmed badge', () => {
    render(
      <DynamicVerdictSection
        verdict={makeVerdict('Confirmed', {
          triggered_payload: 'sqli-tautology',
        })}
      />,
    );
    expect(screen.getByTestId('verdict-badge-confirmed')).toBeInTheDocument();
  });

  it('renders NotConfirmed badge', () => {
    render(<DynamicVerdictSection verdict={makeVerdict('NotConfirmed')} />);
    expect(
      screen.getByTestId('verdict-badge-notconfirmed'),
    ).toBeInTheDocument();
  });

  it('renders PartiallyConfirmed badge', () => {
    render(
      <DynamicVerdictSection
        verdict={makeVerdict('PartiallyConfirmed', {
          detail: 'sink reached but exploit chain did not complete',
        })}
      />,
    );
    expect(
      screen.getByTestId('verdict-badge-partiallyconfirmed'),
    ).toBeInTheDocument();
  });

  it('does not crash when the API omits an empty attempts array', () => {
    render(
      <DynamicVerdictSection
        verdict={{ finding_id: 'no-attempts', status: 'Confirmed' }}
      />,
    );
    expect(screen.getByTestId('verdict-badge-confirmed')).toBeInTheDocument();
  });

  it('renders Unsupported badge', () => {
    render(
      <DynamicVerdictSection
        verdict={makeVerdict('Unsupported', { reason: 'NoPayloadsForCap' })}
      />,
    );
    expect(screen.getByTestId('verdict-badge-unsupported')).toBeInTheDocument();
  });

  it('renders Inconclusive badge', () => {
    render(
      <DynamicVerdictSection
        verdict={makeVerdict('Inconclusive', {
          inconclusive_reason: 'BuildFailed',
        })}
      />,
    );
    expect(
      screen.getByTestId('verdict-badge-inconclusive'),
    ).toBeInTheDocument();
  });

  it('shows repro panel only for Confirmed status', () => {
    const { unmount } = render(
      <DynamicVerdictSection verdict={makeVerdict('Confirmed')} />,
    );
    expect(screen.getByTestId('repro-panel')).toBeInTheDocument();
    unmount();

    for (const status of [
      'PartiallyConfirmed',
      'NotConfirmed',
      'Unsupported',
      'Inconclusive',
    ] as const) {
      const { unmount: u } = render(
        <DynamicVerdictSection verdict={makeVerdict(status)} />,
      );
      expect(screen.queryByTestId('repro-panel')).toBeNull();
      u();
    }
  });

  it('repro-panel contains the finding_id in the CLI command', () => {
    render(
      <DynamicVerdictSection
        verdict={makeVerdict('Confirmed', { finding_id: 'cafecafe12345678' })}
      />,
    );
    const panel = screen.getByTestId('repro-panel');
    expect(panel.textContent).toContain('cafecafe12345678');
    expect(panel.textContent).toContain('nyx repro');
  });

  it('Copy button triggers clipboard writeText with the repro command', async () => {
    const findingId = 'test-finding-id-abc';
    render(<DynamicVerdictSection verdict={makeVerdict('Confirmed')} />);

    const copyBtn = screen.getByRole('button', { name: /copy/i });
    fireEvent.click(copyBtn);

    expect(navigator.clipboard.writeText).toHaveBeenCalledOnce();
    const calledWith = (
      navigator.clipboard.writeText as ReturnType<typeof vi.fn>
    ).mock.calls[0][0] as string;
    expect(calledWith).toContain(findingId);
    expect(calledWith).toContain('nyx repro');
  });

  it('shows exact toolchain match label when toolchain_match is exact', () => {
    render(
      <DynamicVerdictSection
        verdict={makeVerdict('Confirmed', { toolchain_match: 'exact' })}
      />,
    );
    expect(screen.getByText('exact toolchain')).toBeInTheDocument();
  });

  it('shows approximate toolchain match label when toolchain_match is drift', () => {
    render(
      <DynamicVerdictSection
        verdict={makeVerdict('Confirmed', { toolchain_match: 'drift' })}
      />,
    );
    expect(screen.getByText('approximate toolchain')).toBeInTheDocument();
  });
});
