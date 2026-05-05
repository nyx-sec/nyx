import type { GraphMetadata, GraphThemePalette, GraphViewKind } from './types';

export interface NodeStyle {
  fill: string;
  stroke: string;
  textFill: string;
  secondaryFill: string;
  shape: 'rect' | 'terminal' | 'double';
  strokeWidth: number;
  accentFill: string;
  neighborFill: string;
}

export interface EdgeStyle {
  color: string;
  width: number;
  dash: number[];
}

const FALLBACK_PALETTE: GraphThemePalette = {
  background: '#ffffff',
  backgroundSecondary: '#f7f7f8',
  text: '#1a1a1a',
  textSecondary: '#6b6b76',
  textTertiary: '#9b9ba7',
  border: '#e5e5ea',
  borderLight: '#f0f0f4',
  accent: '#72f3d7',
  accentSoft: 'rgba(114, 243, 215, 0.16)',
  success: '#2ecc71',
  warning: '#e67e22',
  danger: '#e74c3c',
  neutral: '#607187',
  neutralSoft: '#8c99ab',
};

function readVar(name: string, fallback: string): string {
  if (typeof window === 'undefined') return fallback;
  const value = getComputedStyle(document.documentElement)
    .getPropertyValue(name)
    .trim();
  return value || fallback;
}

function hexToRgb(value: string): [number, number, number] | null {
  const normalized = value.replace('#', '').trim();
  if (normalized.length !== 3 && normalized.length !== 6) return null;

  const expanded =
    normalized.length === 3
      ? normalized
          .split('')
          .map((part) => part + part)
          .join('')
      : normalized;

  const intValue = Number.parseInt(expanded, 16);
  if (Number.isNaN(intValue)) return null;

  return [(intValue >> 16) & 255, (intValue >> 8) & 255, intValue & 255];
}

export function withAlpha(color: string, alpha: number): string {
  if (color.startsWith('rgba(')) {
    return color.replace(/rgba\(([^)]+),[^)]+\)/, `rgba($1, ${alpha})`);
  }
  if (color.startsWith('rgb(')) {
    const inner = color.slice(4, -1);
    return `rgba(${inner}, ${alpha})`;
  }

  const rgb = hexToRgb(color);
  if (!rgb) return color;
  return `rgba(${rgb[0]}, ${rgb[1]}, ${rgb[2]}, ${alpha})`;
}

export function readGraphPalette(): GraphThemePalette {
  return {
    background: readVar('--bg', FALLBACK_PALETTE.background),
    backgroundSecondary: readVar(
      '--bg-secondary',
      FALLBACK_PALETTE.backgroundSecondary,
    ),
    text: readVar('--text', FALLBACK_PALETTE.text),
    textSecondary: readVar('--text-secondary', FALLBACK_PALETTE.textSecondary),
    textTertiary: readVar('--text-tertiary', FALLBACK_PALETTE.textTertiary),
    border: readVar('--border', FALLBACK_PALETTE.border),
    borderLight: readVar('--border-light', FALLBACK_PALETTE.borderLight),
    accent: readVar('--accent', FALLBACK_PALETTE.accent),
    accentSoft: readVar('--accent-light', FALLBACK_PALETTE.accentSoft),
    success: readVar('--success', FALLBACK_PALETTE.success),
    warning: readVar('--sev-medium', FALLBACK_PALETTE.warning),
    danger: readVar('--sev-high', FALLBACK_PALETTE.danger),
    neutral: FALLBACK_PALETTE.neutral,
    neutralSoft: FALLBACK_PALETTE.neutralSoft,
  };
}

function cfgNodeStyle(
  type: string,
  palette: GraphThemePalette,
  metadata?: GraphMetadata,
): NodeStyle {
  if (metadata?.isCompound) {
    return {
      fill: withAlpha(palette.borderLight, 0.9),
      stroke: palette.border,
      textFill: palette.text,
      secondaryFill: palette.textSecondary,
      shape: 'rect',
      strokeWidth: 1.25,
      accentFill: palette.accent,
      neighborFill: palette.accentSoft,
    };
  }

  switch (type) {
    case 'Entry':
      return {
        fill: palette.success,
        stroke: withAlpha(palette.success, 0.85),
        textFill: '#ffffff',
        secondaryFill: withAlpha('#ffffff', 0.78),
        shape: 'double',
        strokeWidth: 1.8,
        accentFill: palette.accent,
        neighborFill: withAlpha(palette.success, 0.75),
      };
    case 'Exit':
      return {
        fill: palette.textSecondary,
        stroke: withAlpha(palette.textSecondary, 0.85),
        textFill: '#ffffff',
        secondaryFill: withAlpha('#ffffff', 0.78),
        shape: 'double',
        strokeWidth: 1.6,
        accentFill: palette.accent,
        neighborFill: withAlpha(palette.textSecondary, 0.76),
      };
    case 'If':
      return {
        fill: palette.accent,
        stroke: withAlpha(palette.accent, 0.82),
        textFill: '#ffffff',
        secondaryFill: withAlpha('#ffffff', 0.8),
        shape: 'rect',
        strokeWidth: 2,
        accentFill: palette.accent,
        neighborFill: palette.accentSoft,
      };
    case 'Loop':
      return {
        fill: '#4f78c2',
        stroke: '#3c5f9a',
        textFill: '#ffffff',
        secondaryFill: withAlpha('#ffffff', 0.8),
        shape: 'rect',
        strokeWidth: 2.1,
        accentFill: palette.accent,
        neighborFill: withAlpha('#4f78c2', 0.74),
      };
    case 'Call':
      return {
        fill: palette.warning,
        stroke: withAlpha(palette.warning, 0.85),
        textFill: '#ffffff',
        secondaryFill: withAlpha('#ffffff', 0.8),
        shape: 'rect',
        strokeWidth: 1.5,
        accentFill: palette.accent,
        neighborFill: withAlpha(palette.warning, 0.76),
      };
    case 'Return':
      return {
        fill: palette.danger,
        stroke: withAlpha(palette.danger, 0.86),
        textFill: '#ffffff',
        secondaryFill: withAlpha('#ffffff', 0.8),
        shape: 'terminal',
        strokeWidth: 1.7,
        accentFill: palette.accent,
        neighborFill: withAlpha(palette.danger, 0.75),
      };
    default:
      return {
        fill: withAlpha(palette.neutral, 0.92),
        stroke: withAlpha(palette.neutral, 0.8),
        textFill: '#ffffff',
        secondaryFill: withAlpha('#ffffff', 0.78),
        shape: 'rect',
        strokeWidth: 1.2,
        accentFill: palette.accent,
        neighborFill: withAlpha(palette.neutralSoft, 0.88),
      };
  }
}

function callGraphNodeStyle(
  palette: GraphThemePalette,
  metadata?: GraphMetadata,
): NodeStyle {
  const isRecursive = metadata?.isRecursive === true;
  const fill = isRecursive ? '#7d6450' : palette.neutral;
  const stroke = isRecursive ? '#6a5444' : withAlpha(palette.neutral, 0.84);

  return {
    fill,
    stroke,
    textFill: '#ffffff',
    secondaryFill: withAlpha('#ffffff', 0.74),
    shape: 'rect',
    strokeWidth: isRecursive ? 1.8 : 1.3,
    accentFill: palette.accent,
    neighborFill: isRecursive ? withAlpha(fill, 0.76) : palette.accentSoft,
  };
}

export function getNodeStyle(
  type: string,
  graphKind: GraphViewKind = 'cfg',
  metadata?: GraphMetadata,
  palette = FALLBACK_PALETTE,
): NodeStyle {
  return graphKind === 'callgraph'
    ? callGraphNodeStyle(palette, metadata)
    : cfgNodeStyle(type, palette, metadata);
}

export function getEdgeStyle(
  type: string,
  graphKind: GraphViewKind = 'cfg',
  palette = FALLBACK_PALETTE,
): EdgeStyle {
  if (graphKind === 'callgraph') {
    return {
      color: withAlpha(palette.neutralSoft, 0.72),
      width: 1.2,
      dash: [],
    };
  }

  switch (type) {
    case 'True':
      return { color: palette.success, width: 1.8, dash: [] };
    case 'False':
      return { color: palette.danger, width: 1.8, dash: [] };
    case 'Back':
      return { color: '#4f78c2', width: 1.6, dash: [7, 4] };
    case 'Exception':
      return { color: palette.warning, width: 1.6, dash: [3, 3] };
    default:
      return {
        color: withAlpha(palette.textTertiary, 0.78),
        width: 1.3,
        dash: [],
      };
  }
}
