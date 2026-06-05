import type { FC, SVGProps } from 'react';

export interface IconProps {
  className?: string;
  size?: number;
}

type SvgBaseProps = SVGProps<SVGSVGElement> & IconProps;

function svgProps({ className, size = 18 }: IconProps): SvgBaseProps {
  return {
    className,
    width: size,
    height: size,
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.5,
    strokeLinecap: 'round',
    strokeLinejoin: 'round',
  };
}

export function OverviewIcon({ className, size = 18 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 18 18">
      <rect x="2" y="2" width="5.5" height="5.5" rx="1" />
      <rect x="10.5" y="2" width="5.5" height="5.5" rx="1" />
      <rect x="2" y="10.5" width="5.5" height="5.5" rx="1" />
      <rect x="10.5" y="10.5" width="5.5" height="5.5" rx="1" />
    </svg>
  );
}

export function FindingsIcon({ className, size = 18 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 18 18">
      <path d="M9 2L2 6v5c0 3.5 3 6 7 7 4-1 7-3.5 7-7V6L9 2z" />
      <path d="M9 6v4" />
      <circle cx="9" cy="12.5" r="0.5" fill="currentColor" stroke="none" />
    </svg>
  );
}

export function ScansIcon({ className, size = 18 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 18 18">
      <path d="M14.5 9A5.5 5.5 0 1 1 9 3.5" />
      <polyline points="9 5 9 9 12 11" />
    </svg>
  );
}

export function RulesIcon({ className, size = 18 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 18 18">
      <path d="M4 5h10" />
      <path d="M4 9h10" />
      <path d="M4 13h10" />
      <polyline points="2 4.5 2.8 5.5 4 4" />
      <polyline points="2 8.5 2.8 9.5 4 8" />
      <polyline points="2 12.5 2.8 13.5 4 12" />
    </svg>
  );
}

export function TriageIcon({ className, size = 18 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 18 18">
      <path d="M10 2L4 3v9l6 4 6-4V3l-6-1z" />
      <path d="M10 6v4" />
      <circle cx="10" cy="12.5" r="0.5" fill="currentColor" stroke="none" />
    </svg>
  );
}

export function ConfigIcon({ className, size = 18 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 18 18">
      <line x1="3" y1="5" x2="15" y2="5" />
      <line x1="3" y1="9" x2="15" y2="9" />
      <line x1="3" y1="13" x2="15" y2="13" />
      <circle cx="6" cy="5" r="1.5" fill="var(--bg-secondary)" />
      <circle cx="11" cy="9" r="1.5" fill="var(--bg-secondary)" />
      <circle cx="7" cy="13" r="1.5" fill="var(--bg-secondary)" />
    </svg>
  );
}

export function ExplorerIcon({ className, size = 18 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 18 18">
      <path d="M3 3v12h12" />
      <path d="M7 3v4h4V3" />
      <path d="M7 11v4h4v-4" />
      <path d="M11 7h4v4h-4" />
    </svg>
  );
}

export function DebugIcon({ className, size = 18 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 18 18">
      <polyline points="4 5 2 5 2 16 13 16 13 14" />
      <polyline points="6 2 16 2 16 12 6 12 6 2" />
      <path d="M9 5.5h4" />
      <path d="M9 8h4" />
    </svg>
  );
}

export function FolderIcon({ className, size = 14 }: IconProps) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 14 14"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M2 3.5C2 2.95 2.45 2.5 3 2.5h2.5l1.5 1.5H11c.55 0 1 .45 1 1v5.5c0 .55-.45 1-1 1H3c-.55 0-1-.45-1-1V3.5z" />
    </svg>
  );
}

export function TagIcon({ className, size = 14 }: IconProps) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 14 14"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M1.5 7.8V2.5c0-.6.4-1 1-1h5.3L13 6.7l-5.3 5.3L1.5 7.8z" />
      <circle cx="5" cy="5" r="0.8" fill="currentColor" stroke="none" />
    </svg>
  );
}

export function CloseIcon({ className, size = 14 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 14 14">
      <path d="M3 3l8 8M11 3l-8 8" />
    </svg>
  );
}

export function CheckIcon({ className, size = 14 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 14 14">
      <path d="M2.5 7.5l3 3 6-7" />
    </svg>
  );
}

export function SunIcon({ className, size = 16 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 16 16">
      <circle cx="8" cy="8" r="3" />
      <path d="M8 1.5v1.5M8 13v1.5M1.5 8h1.5M13 8h1.5M3.5 3.5l1 1M11.5 11.5l1 1M3.5 12.5l1-1M11.5 4.5l1-1" />
    </svg>
  );
}

export function MoonIcon({ className, size = 16 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 16 16">
      <path d="M13.5 9.5A6 6 0 0 1 6.5 2.5 6 6 0 1 0 13.5 9.5z" />
    </svg>
  );
}

export function RefreshIcon({ className, size = 16 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 16 16">
      <path d="M14 8a6 6 0 1 1-1.76-4.24" />
      <path d="M14 2v4h-4" />
    </svg>
  );
}

export function CommandIcon({ className, size = 16 }: IconProps) {
  return (
    <svg {...svgProps({ className, size })} viewBox="0 0 16 16">
      <path d="M5 3a2 2 0 1 0 0 4h6a2 2 0 1 0 0-4 2 2 0 0 0-2 2v6a2 2 0 1 0 2 2 2 2 0 0 0-2-2H5a2 2 0 1 0 0 4 2 2 0 0 0 2-2V5a2 2 0 0 0-2-2z" />
    </svg>
  );
}

/** Map of icon name to component, for dynamic lookup */
export const ICONS: Record<string, FC<IconProps>> = {
  overview: OverviewIcon,
  findings: FindingsIcon,
  scans: ScansIcon,
  rules: RulesIcon,
  triage: TriageIcon,
  config: ConfigIcon,
  explorer: ExplorerIcon,
  debug: DebugIcon,
  folder: FolderIcon,
  tag: TagIcon,
  check: CheckIcon,
};
