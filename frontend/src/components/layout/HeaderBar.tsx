import { Link, useLocation } from 'react-router-dom';
import { CommandIcon } from '../icons/Icons';

const SECTION_TITLES: Record<string, string> = {
  overview: 'Overview',
  findings: 'Findings',
  scans: 'Scans',
  rules: 'Rules',
  triage: 'Triage',
  config: 'Config',
  explorer: 'Explorer',
  debug: 'Debug',
};

const ROUTE_TITLES: Record<string, string> = {
  '/debug/cfg': 'CFG Viewer',
  '/debug/ssa': 'SSA Viewer',
  '/debug/call-graph': 'Call Graph',
  '/debug/taint': 'Taint Debugger',
  '/debug/summaries': 'Summaries',
};

function pathToSection(pathname: string): string {
  if (pathname === '/') return 'overview';
  const first = pathname.split('/')[1];
  return first || 'overview';
}

function buildBreadcrumbs(pathname: string) {
  const section = pathToSection(pathname);
  const sectionTitle = SECTION_TITLES[section] ?? section;
  const crumbs: Array<{ label: string; path?: string }> = [];

  const sectionPath = section === 'overview' ? '/' : `/${section}`;
  crumbs.push({ label: sectionTitle, path: sectionPath });

  if (ROUTE_TITLES[pathname]) {
    crumbs.push({ label: ROUTE_TITLES[pathname] });
  } else {
    const parts = pathname.split('/').filter(Boolean);
    if (parts.length > 1) {
      const sub = parts.slice(1).join('/');
      crumbs.push({ label: sub });
    }
  }

  return crumbs;
}

interface HeaderBarProps {
  onStartScan?: () => void;
  onOpenPalette?: () => void;
}

const PALETTE_HINT =
  typeof navigator !== 'undefined' && /Mac/i.test(navigator.platform)
    ? '⌘K'
    : 'Ctrl K';

export function HeaderBar({ onStartScan, onOpenPalette }: HeaderBarProps) {
  const { pathname } = useLocation();
  const crumbs = buildBreadcrumbs(pathname);

  return (
    <header className="header-bar">
      <div className="header-left">
        <nav className="breadcrumbs" aria-label="Breadcrumb">
          {crumbs.map((crumb, i) => {
            const isLast = i === crumbs.length - 1;
            return (
              <span key={i}>
                {i > 0 && (
                  <span className="breadcrumb-sep" aria-hidden="true">
                    /
                  </span>
                )}
                {isLast || !crumb.path ? (
                  <span
                    className="breadcrumb-current"
                    aria-current={isLast ? 'page' : undefined}
                  >
                    {crumb.label}
                  </span>
                ) : (
                  <Link to={crumb.path} className="breadcrumb-link">
                    {crumb.label}
                  </Link>
                )}
              </span>
            );
          })}
        </nav>
      </div>
      <div className="header-right">
        {onOpenPalette && (
          <button
            type="button"
            className="btn btn-ghost btn-sm palette-trigger"
            onClick={onOpenPalette}
            aria-label="Open command palette"
            title={`Command palette (${PALETTE_HINT})`}
          >
            <CommandIcon size={12} />
            <span>Search</span>
            <kbd>{PALETTE_HINT}</kbd>
          </button>
        )}
        {onStartScan && (
          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={onStartScan}
          >
            Start scan
          </button>
        )}
      </div>
    </header>
  );
}
