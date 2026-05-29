import { NavLink } from 'react-router-dom';
import {
  OverviewIcon,
  FindingsIcon,
  ScansIcon,
  RulesIcon,
  TriageIcon,
  ConfigIcon,
  ExplorerIcon,
  DebugIcon,
  TagIcon,
} from '../icons/Icons';
import { useEffect, useRef, useState, type FC, type FormEvent } from 'react';
import type { IconProps } from '../icons/Icons';
import { useHealth } from '../../api/queries/health';
import { useOverview } from '../../api/queries/overview';
import {
  useAddTarget,
  useSelectTarget,
  useTargets,
} from '../../api/queries/targets';
import { useSSE } from '../../contexts/SSEContext';

interface NavItem {
  id: string;
  label: string;
  path: string;
  Icon: FC<IconProps>;
  group: 'primary' | 'secondary' | 'footer';
}

const NAV_SECTIONS: NavItem[] = [
  {
    id: 'overview',
    label: 'Overview',
    path: '/',
    Icon: OverviewIcon,
    group: 'primary',
  },
  {
    id: 'findings',
    label: 'Findings',
    path: '/findings',
    Icon: FindingsIcon,
    group: 'primary',
  },
  {
    id: 'scans',
    label: 'Scans',
    path: '/scans',
    Icon: ScansIcon,
    group: 'primary',
  },
  {
    id: 'rules',
    label: 'Rules',
    path: '/rules',
    Icon: RulesIcon,
    group: 'primary',
  },
  {
    id: 'triage',
    label: 'Triage',
    path: '/triage',
    Icon: TriageIcon,
    group: 'primary',
  },
  {
    id: 'explorer',
    label: 'Explorer',
    path: '/explorer',
    Icon: ExplorerIcon,
    group: 'secondary',
  },
  {
    id: 'surface',
    label: 'Surface',
    path: '/surface',
    Icon: ExplorerIcon,
    group: 'secondary',
  },
  {
    id: 'debug',
    label: 'Debug',
    path: '/debug',
    Icon: DebugIcon,
    group: 'secondary',
  },
  {
    id: 'config',
    label: 'Config',
    path: '/config',
    Icon: ConfigIcon,
    group: 'footer',
  },
];

function navLinkClass({ isActive }: { isActive: boolean }) {
  return `nav-link${isActive ? ' active' : ''}`;
}

function targetNameFromPath(path: string) {
  const parts = path.split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] || path || 'Project';
}

function targetInitial(name: string) {
  return name.trim().charAt(0).toUpperCase() || '?';
}

function compactPath(path: string) {
  return path.replace(/^\/Users\/[^/]+/, '~');
}

function TargetSwitcher({ scanRoot }: { scanRoot?: string }) {
  const { data: targets = [] } = useTargets();
  const addTarget = useAddTarget();
  const selectTarget = useSelectTarget();
  const [open, setOpen] = useState(false);
  const [newPath, setNewPath] = useState('');
  const menuRef = useRef<HTMLDivElement | null>(null);

  const activeTarget =
    targets.find((target) => target.active) ??
    (scanRoot
      ? {
          id: '__active__',
          name: targetNameFromPath(scanRoot),
          path: scanRoot,
          active: true,
          exists: true,
        }
      : undefined);

  useEffect(() => {
    if (!open) return;
    function handlePointerDown(event: MouseEvent) {
      if (
        menuRef.current &&
        event.target instanceof Node &&
        !menuRef.current.contains(event.target)
      ) {
        setOpen(false);
      }
    }
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') setOpen(false);
    }
    document.addEventListener('mousedown', handlePointerDown);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handlePointerDown);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [open]);

  function handleSelect(id: string) {
    selectTarget.mutate(
      { id },
      {
        onSuccess: () => setOpen(false),
      },
    );
  }

  function handleAddSubmit(event: FormEvent) {
    event.preventDefault();
    const path = newPath.trim();
    if (!path || addTarget.isPending) return;
    addTarget.mutate(
      { path },
      {
        onSuccess: (target) => {
          setNewPath('');
          selectTarget.mutate(
            { id: target.id },
            {
              onSuccess: () => setOpen(false),
            },
          );
        },
      },
    );
  }

  const isBusy = addTarget.isPending || selectTarget.isPending;
  const errorMessage =
    addTarget.error instanceof Error ? addTarget.error.message : null;

  return (
    <div className="target-switcher" ref={menuRef}>
      <button
        type="button"
        className="target-trigger"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-label="Select project target"
        title={activeTarget?.path}
      >
        <span className="target-avatar">
          {targetInitial(activeTarget?.name ?? 'Project')}
        </span>
        <span className="target-trigger-copy">
          <span className="target-name">
            {activeTarget?.name ?? 'Select target'}
          </span>
          <span className="target-path">
            {activeTarget?.path ? compactPath(activeTarget.path) : 'No target'}
          </span>
        </span>
        <span className={`target-caret${open ? ' open' : ''}`} />
      </button>

      {open && (
        <div className="target-menu" role="menu">
          <div className="target-options">
            {targets.map((target) => (
              <button
                key={target.id}
                type="button"
                className={`target-option${target.active ? ' active' : ''}`}
                onClick={() => handleSelect(target.id)}
                disabled={target.active || !target.exists || isBusy}
                title={target.path}
              >
                <span className="target-option-avatar">
                  {targetInitial(target.name)}
                </span>
                <span className="target-option-copy">
                  <span className="target-option-name">{target.name}</span>
                  <span className="target-option-path">
                    {target.exists ? compactPath(target.path) : 'Missing path'}
                  </span>
                </span>
              </button>
            ))}
          </div>

          <form className="target-add-form" onSubmit={handleAddSubmit}>
            <input
              value={newPath}
              onChange={(event) => setNewPath(event.target.value)}
              placeholder="/path/to/project"
              aria-label="Project path"
            />
            <button
              type="submit"
              className="target-add-button"
              disabled={!newPath.trim() || addTarget.isPending}
              title="Add target"
              aria-label="Add target"
            >
              +
            </button>
          </form>
          {errorMessage && <div className="target-error">{errorMessage}</div>}
        </div>
      )}
    </div>
  );
}

export function Sidebar() {
  const { data: health } = useHealth();
  const { data: overview } = useOverview();
  const { isScanRunning } = useSSE();

  const primary = NAV_SECTIONS.filter((n) => n.group === 'primary');
  const secondary = NAV_SECTIONS.filter((n) => n.group === 'secondary');
  const footer = NAV_SECTIONS.filter((n) => n.group === 'footer');
  const findingsCount =
    overview && overview.state !== 'empty' ? overview.total_findings : null;

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <img src="/logo.png" alt="Nyx" className="sidebar-logo-img" />
      </div>

      <TargetSwitcher scanRoot={health?.scan_root} />

      <ul className="nav-list">
        {primary.map((item) => (
          <li key={item.id}>
            <NavLink
              to={item.path}
              end={item.path === '/'}
              className={navLinkClass}
            >
              <span className="nav-icon">
                <item.Icon />
              </span>
              <span className="nav-label">{item.label}</span>
              {item.id === 'findings' && findingsCount != null && (
                <span className="nav-badge">{findingsCount}</span>
              )}
            </NavLink>
          </li>
        ))}

        <li className="nav-section-header">Tools</li>

        {secondary.map((item) => (
          <li key={item.id}>
            <NavLink to={item.path} className={navLinkClass}>
              <span className="nav-icon">
                <item.Icon />
              </span>
              <span className="nav-label">{item.label}</span>
            </NavLink>
          </li>
        ))}
      </ul>

      <div className="sidebar-footer">
        <ul className="nav-list" style={{ flex: 'none' }}>
          {footer.map((item) => (
            <li key={item.id}>
              <NavLink to={item.path} className={navLinkClass}>
                <span className="nav-icon">
                  <item.Icon />
                </span>
                <span className="nav-label">{item.label}</span>
              </NavLink>
            </li>
          ))}
        </ul>
      </div>

      <div className="sidebar-meta">
        {health?.version && (
          <div className="sidebar-meta-item">
            <TagIcon />
            <span>v{health.version}</span>
          </div>
        )}
        <div className={`scan-indicator${isScanRunning ? ' visible' : ''}`}>
          <span className="status-dot running" />
          Scanning...
        </div>
      </div>
    </aside>
  );
}
