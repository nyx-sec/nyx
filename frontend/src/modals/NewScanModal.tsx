import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Modal } from '../components/ui/Modal';
import { useHealth } from '../api/queries/health';
import { useToast } from '../contexts/ToastContext';
import { ApiError } from '../api/client';
import {
  useStartScan,
  type ScanMode,
  type EngineProfile,
  type VerifyBackend,
  type HardenProfile,
  type StartScanBody,
} from '../api/mutations/scans';

interface NewScanModalProps {
  open: boolean;
  onClose: () => void;
}

const MODE_HINTS: Record<ScanMode, string> = {
  full: 'AST + CFG + taint (default)',
  ast: 'AST patterns only. Fastest.',
  cfg: 'CFG structural + taint',
  taint: 'Taint flows only',
};

const PROFILE_HINTS: Record<EngineProfile, string> = {
  fast: 'Basic taint. No abstract-interp / context-sensitive / symex / backwards.',
  balanced: 'Default. Adds abstract-interp + context-sensitive inlining.',
  deep: 'Adds symex (cross-file + interproc) and demand-driven backwards taint. About 2 to 3x slower.',
};

const BACKEND_HINTS: Record<VerifyBackend, string> = {
  auto: 'Use Docker when it fits, otherwise fall back to process.',
  docker: 'Require Docker-backed harness execution.',
  process: 'Unsafe local process backend for quick test runs.',
  firecracker: 'Use the Firecracker backend when available.',
};

const HARDEN_HINTS: Record<HardenProfile, string> = {
  standard: 'Baseline process limits.',
  strict: 'Stricter process confinement when supported.',
};

export function NewScanModal({ open, onClose }: NewScanModalProps) {
  const { data: health } = useHealth();
  const startScan = useStartScan();
  const navigate = useNavigate();
  const toast = useToast();
  const defaultRoot = health?.scan_root || '';
  const [scanRoot, setScanRoot] = useState('');
  const [mode, setMode] = useState<ScanMode>('full');
  const [engineProfile, setEngineProfile] = useState<EngineProfile>('balanced');
  const [noVerify, setNoVerify] = useState(false);
  const [verifyBackend, setVerifyBackend] = useState<VerifyBackend>('auto');
  const [hardenProfile, setHardenProfile] = useState<HardenProfile>('standard');

  const handleStart = async () => {
    const root = scanRoot.trim();
    const body: StartScanBody = {};
    if (root && root !== defaultRoot) body.scan_root = root;
    if (mode !== 'full') body.mode = mode;
    body.engine_profile = engineProfile;
    if (noVerify) {
      body.verify = false;
    } else {
      body.verify_backend = verifyBackend;
      body.harden_profile = hardenProfile;
    }
    const payload = Object.keys(body).length ? body : undefined;
    try {
      await startScan.mutateAsync(payload);
      toast.success('Scan started', 'Started');
      onClose();
      navigate('/scans');
    } catch (e) {
      const msg =
        e instanceof ApiError && e.status === 409
          ? 'A scan is already running'
          : e instanceof Error
            ? e.message
            : 'Failed to start scan';
      toast.error(msg, 'Could not start scan');
    }
  };

  if (!open) return null;

  return (
    <Modal open={open} onClose={onClose} className="scan-modal-overlay">
      <div className="scan-modal">
        <h3>Start new scan</h3>
        <div className="scan-modal-form">
          <div className="form-group">
            <label>Scan Root</label>
            <input
              type="text"
              value={scanRoot || defaultRoot}
              onChange={(e) => setScanRoot(e.target.value)}
              placeholder="/path/to/project"
            />
          </div>
          <div className="form-group">
            <label>Analysis Mode</label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as ScanMode)}
            >
              <option value="full">Full</option>
              <option value="ast">AST only</option>
              <option value="cfg">CFG + taint</option>
              <option value="taint">Taint only</option>
            </select>
            <span className="form-hint">{MODE_HINTS[mode]}</span>
          </div>
          <div className="form-group">
            <label>Engine Profile</label>
            <select
              value={engineProfile}
              onChange={(e) =>
                setEngineProfile(e.target.value as EngineProfile)
              }
            >
              <option value="fast">Fast</option>
              <option value="balanced">Balanced (default)</option>
              <option value="deep">Deep</option>
            </select>
            <span className="form-hint">{PROFILE_HINTS[engineProfile]}</span>
          </div>
          <div className="form-group">
            <label>Dynamic Verification</label>
            <div className="toggle-inline">
              <input
                type="checkbox"
                id="new-scan-no-verify"
                checked={noVerify}
                onChange={(e) => setNoVerify(e.target.checked)}
              />
              <label htmlFor="new-scan-no-verify">
                Skip dynamic verification for this scan.
              </label>
            </div>
            <span className="form-hint">
              Verification runs by default on Medium and High confidence
              findings. Check to skip and get a fast static-only result.
            </span>
          </div>
          <div className="form-group">
            <label>Verification Backend</label>
            <select
              value={verifyBackend}
              disabled={noVerify}
              onChange={(e) =>
                setVerifyBackend(e.target.value as VerifyBackend)
              }
            >
              <option value="auto">Auto</option>
              <option value="docker">Docker</option>
              <option value="process">Process (unsafe)</option>
              <option value="firecracker">Firecracker</option>
            </select>
            <span className="form-hint">{BACKEND_HINTS[verifyBackend]}</span>
          </div>
          <div className="form-group">
            <label>Process Hardening</label>
            <select
              value={hardenProfile}
              disabled={noVerify || verifyBackend !== 'process'}
              onChange={(e) =>
                setHardenProfile(e.target.value as HardenProfile)
              }
            >
              <option value="standard">Standard</option>
              <option value="strict">Strict</option>
            </select>
            <span className="form-hint">{HARDEN_HINTS[hardenProfile]}</span>
          </div>
          <div className="scan-modal-actions">
            <button className="btn btn-sm" onClick={onClose}>
              Cancel
            </button>
            <button
              className="btn btn-primary btn-sm"
              onClick={handleStart}
              disabled={startScan.isPending}
            >
              {startScan.isPending ? 'Starting...' : 'Start scan'}
            </button>
          </div>
        </div>
      </div>
    </Modal>
  );
}
