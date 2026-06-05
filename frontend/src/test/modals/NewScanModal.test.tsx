import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { NewScanModal } from '@/modals/NewScanModal';

const mockMutateAsync = vi.hoisted(() => vi.fn());
const mockNavigate = vi.hoisted(() => vi.fn());
const mockToastSuccess = vi.hoisted(() => vi.fn());
const mockToastError = vi.hoisted(() => vi.fn());

vi.mock('@/api/queries/health', () => ({
  useHealth: () => ({ data: { scan_root: '/test/project' } }),
}));

vi.mock('@/api/mutations/scans', () => ({
  useStartScan: () => ({
    mutateAsync: mockMutateAsync,
    isPending: false,
  }),
}));

vi.mock('react-router-dom', () => ({
  useNavigate: () => mockNavigate,
}));

vi.mock('@/contexts/ToastContext', () => ({
  useToast: () => ({ success: mockToastSuccess, error: mockToastError }),
}));

vi.mock('@/components/ui/Modal', () => ({
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  Modal: ({ open, children }: { open: boolean; children?: any }) =>
    open ? <>{children}</> : null,
}));

describe('NewScanModal', () => {
  beforeEach(() => {
    mockMutateAsync.mockReset();
    mockMutateAsync.mockResolvedValue(undefined);
    mockNavigate.mockReset();
    mockToastSuccess.mockReset();
    mockToastError.mockReset();
  });

  it('renders when open is true', () => {
    render(<NewScanModal open={true} onClose={vi.fn()} />);
    expect(screen.getByText('Start new scan')).toBeInTheDocument();
  });

  it('calls mutateAsync without verify key when checkbox is untouched', async () => {
    render(<NewScanModal open={true} onClose={vi.fn()} />);
    expect(screen.queryByText('Process Hardening')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Start scan' }));
    await waitFor(() => expect(mockMutateAsync).toHaveBeenCalledOnce());
    const payload = mockMutateAsync.mock.calls[0][0];
    expect(payload).not.toHaveProperty('verify');
    expect(payload).toEqual({
      engine_profile: 'balanced',
      verify_backend: 'auto',
    });
  });

  it('calls mutateAsync with verify: false when checkbox is checked', async () => {
    render(<NewScanModal open={true} onClose={vi.fn()} />);
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: 'Start scan' }));
    await waitFor(() => expect(mockMutateAsync).toHaveBeenCalledOnce());
    const payload = mockMutateAsync.mock.calls[0][0];
    expect(payload).toEqual({ engine_profile: 'balanced', verify: false });
  });

  it('allows selecting the unsafe process verification backend', async () => {
    render(<NewScanModal open={true} onClose={vi.fn()} />);
    const selects = screen.getAllByRole('combobox');
    fireEvent.change(selects[2], { target: { value: 'process' } });
    expect(screen.getByText('Process Hardening')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Start scan' }));
    await waitFor(() => expect(mockMutateAsync).toHaveBeenCalledOnce());
    const payload = mockMutateAsync.mock.calls[0][0];
    expect(payload).toMatchObject({
      verify_backend: 'process',
      harden_profile: 'standard',
    });
  });

  it('hides process hardening when leaving the process backend', () => {
    render(<NewScanModal open={true} onClose={vi.fn()} />);
    const selects = screen.getAllByRole('combobox');
    fireEvent.change(selects[2], { target: { value: 'process' } });
    expect(screen.getByText('Process Hardening')).toBeInTheDocument();

    fireEvent.change(selects[2], { target: { value: 'docker' } });
    expect(screen.queryByText('Process Hardening')).not.toBeInTheDocument();
  });
});
