import type { GraphNodeModel, GraphViewKind } from '../types';

interface TextLayoutConfig {
  primaryChars: number;
  secondaryChars: number;
  maxPrimaryLines: number;
  maxSecondaryLines: number;
  maxSublabelLines: number;
}

export interface NodeTextLayout {
  labelLines: string[];
  detailLines: string[];
  sublabelLines: string[];
  lineCount: number;
  maxChars: number;
}

const CONFIG: Record<GraphViewKind, TextLayoutConfig> = {
  callgraph: {
    primaryChars: 28,
    secondaryChars: 30,
    maxPrimaryLines: 2,
    maxSecondaryLines: 1,
    maxSublabelLines: 1,
  },
  cfg: {
    primaryChars: 30,
    secondaryChars: 34,
    maxPrimaryLines: 3,
    maxSecondaryLines: 2,
    maxSublabelLines: 1,
  },
  surface: {
    primaryChars: 32,
    secondaryChars: 32,
    maxPrimaryLines: 2,
    maxSecondaryLines: 2,
    maxSublabelLines: 1,
  },
};

function normalizeWhitespace(value: string): string {
  return value.replace(/\s+/g, ' ').trim();
}

function chooseBreakIndex(value: string, maxChars: number): number {
  const probe = value.slice(0, maxChars + 1);
  const preferred = Math.max(
    probe.lastIndexOf(' '),
    probe.lastIndexOf('.'),
    probe.lastIndexOf(':'),
    probe.lastIndexOf('/'),
    probe.lastIndexOf('_'),
    probe.lastIndexOf('('),
    probe.lastIndexOf(')'),
    probe.lastIndexOf(','),
  );

  if (preferred >= Math.floor(maxChars * 0.55)) {
    return preferred + 1;
  }

  return maxChars;
}

export function wrapGraphText(
  value: string | undefined,
  maxChars: number,
): string[] {
  if (!value) return [];

  const normalized = normalizeWhitespace(value);
  if (!normalized) return [];

  const lines: string[] = [];
  let remaining = normalized;

  while (remaining.length > maxChars) {
    const breakIndex = chooseBreakIndex(remaining, maxChars);
    lines.push(remaining.slice(0, breakIndex).trim());
    remaining = remaining.slice(breakIndex).trim();
  }

  if (remaining) lines.push(remaining);
  return lines;
}

function clampLines(lines: string[], maxLines: number): string[] {
  if (lines.length <= maxLines) return lines;

  const visible = lines.slice(0, maxLines);
  const last = visible[maxLines - 1];
  if (!last) return visible;

  visible[maxLines - 1] = last.endsWith('…') ? last : `${last.slice(0, -1)}…`;
  return visible;
}

export function getNodeTextLayout(
  node: GraphNodeModel,
  viewKind: GraphViewKind,
): NodeTextLayout {
  const config = CONFIG[viewKind];
  const labelLines = clampLines(
    wrapGraphText(node.label, config.primaryChars),
    config.maxPrimaryLines,
  );
  const detailLines = clampLines(
    wrapGraphText(node.detail, config.secondaryChars),
    config.maxSecondaryLines,
  );
  const sublabelLines = clampLines(
    wrapGraphText(node.sublabel, config.secondaryChars),
    config.maxSublabelLines,
  );
  const allLines = labelLines.concat(detailLines, sublabelLines);

  return {
    labelLines,
    detailLines,
    sublabelLines,
    lineCount: allLines.length,
    maxChars: Math.max(...allLines.map((line) => line.length), 8),
  };
}
