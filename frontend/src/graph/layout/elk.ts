import ELK from 'elkjs/lib/elk.bundled.js';
import type { ElkEdgeSection, ElkNode } from 'elkjs/lib/elk-api';
import { getNodeTextLayout } from './text';
import type {
  ElkLayoutPreset,
  GraphModel,
  GraphNodeModel,
  GraphPoint,
  GraphViewKind,
  LayoutGraphEdge,
  LayoutGraphModel,
  LayoutGraphNode,
} from '../types';

const elk = new ELK();

const CHAR_WIDTH = 7.1;
const LINE_HEIGHT = 16;
const HORIZONTAL_PADDING = 30;
const VERTICAL_PADDING = 18;
const MIN_WIDTH = 112;
const BADGE_HEIGHT = 16;
const MAX_WIDTH = 360;

const PRESETS: Record<GraphViewKind, ElkLayoutPreset> = {
  callgraph: {
    direction: 'DOWN',
    nodeSpacing: 42,
    layerSpacing: 148,
    edgeNodeSpacing: 24,
    padding: 36,
    edgeRouting: 'POLYLINE',
  },
  cfg: {
    direction: 'DOWN',
    nodeSpacing: 36,
    layerSpacing: 128,
    edgeNodeSpacing: 24,
    padding: 32,
    edgeRouting: 'ORTHOGONAL',
  },
  surface: {
    direction: 'RIGHT',
    nodeSpacing: 44,
    layerSpacing: 156,
    edgeNodeSpacing: 28,
    padding: 36,
    edgeRouting: 'POLYLINE',
  },
};

function measureNode(
  node: GraphNodeModel,
  viewKind: GraphViewKind,
): {
  width: number;
  height: number;
  text: ReturnType<typeof getNodeTextLayout>;
} {
  const text = getNodeTextLayout(node, viewKind);
  const width = Math.max(
    MIN_WIDTH,
    Math.min(MAX_WIDTH, text.maxChars * CHAR_WIDTH + HORIZONTAL_PADDING),
  );
  const height =
    Math.max(1, text.lineCount) * LINE_HEIGHT +
    VERTICAL_PADDING +
    (node.badges?.length ? BADGE_HEIGHT : 0);

  return { width, height, text };
}

function estimateSigmaNodeSize(
  node: GraphNodeModel,
  width: number,
  height: number,
): number {
  const base = Math.max(6, Math.min(18, Math.sqrt(width * height) / 8));
  if (node.kind === 'Entry' || node.kind === 'Exit') return base + 1.5;
  if (node.kind === 'If' || node.kind === 'Loop') return base + 0.75;
  return base;
}

function buildLayoutOptions(
  graph: GraphModel,
  overrides?: Partial<ElkLayoutPreset>,
): ElkNode['layoutOptions'] {
  const preset = { ...PRESETS[graph.kind], ...overrides };

  return {
    'elk.algorithm': 'layered',
    'elk.direction': preset.direction,
    'elk.spacing.nodeNode': String(preset.nodeSpacing),
    'elk.layered.spacing.nodeNodeBetweenLayers': String(preset.layerSpacing),
    'elk.spacing.edgeNode': String(preset.edgeNodeSpacing),
    'elk.edgeRouting': preset.edgeRouting,
    'elk.layered.crossingMinimization.strategy': 'LAYER_SWEEP',
    'elk.layered.unnecessaryBendpoints': 'true',
    'elk.layered.thoroughness': graph.kind === 'callgraph' ? '6' : '8',
  };
}

function sortSections(
  sections: ElkEdgeSection[] | undefined,
): ElkEdgeSection[] {
  if (!sections || sections.length <= 1) return sections ?? [];

  const sectionById = new Map(sections.map((section) => [section.id, section]));
  const head =
    sections.find(
      (section) =>
        !section.incomingSections || section.incomingSections.length === 0,
    ) ?? sections[0];

  const ordered: ElkEdgeSection[] = [];
  const seen = new Set<string>();
  let cursor: ElkEdgeSection | undefined = head;

  while (cursor && !seen.has(cursor.id)) {
    ordered.push(cursor);
    seen.add(cursor.id);

    const nextId: string | undefined = cursor.outgoingSections?.[0];
    cursor = nextId ? sectionById.get(nextId) : undefined;
  }

  if (ordered.length === sections.length) return ordered;
  return sections;
}

function dedupePoints(points: GraphPoint[]): GraphPoint[] {
  const deduped: GraphPoint[] = [];
  for (const point of points) {
    const previous = deduped[deduped.length - 1];
    if (previous && previous.x === point.x && previous.y === point.y) continue;
    deduped.push(point);
  }
  return deduped;
}

function extractRoute(sections: ElkEdgeSection[] | undefined): GraphPoint[] {
  const points: GraphPoint[] = [];

  for (const section of sortSections(sections)) {
    points.push(section.startPoint);
    if (section.bendPoints) points.push(...section.bendPoints);
    points.push(section.endPoint);
  }

  return dedupePoints(points);
}

function collectBounds(
  nodes: LayoutGraphNode[],
  edges: LayoutGraphEdge[],
  padding: number,
) {
  let minX = Number.POSITIVE_INFINITY;
  let maxX = Number.NEGATIVE_INFINITY;
  let minY = Number.POSITIVE_INFINITY;
  let maxY = Number.NEGATIVE_INFINITY;

  const includePoint = (x: number, y: number) => {
    if (x < minX) minX = x;
    if (x > maxX) maxX = x;
    if (y < minY) minY = y;
    if (y > maxY) maxY = y;
  };

  for (const node of nodes) {
    includePoint(node.x - node.width / 2, node.y - node.height / 2);
    includePoint(node.x + node.width / 2, node.y + node.height / 2);
  }

  for (const edge of edges) {
    for (const point of edge.route) {
      includePoint(point.x, point.y);
    }
  }

  if (minX === Number.POSITIVE_INFINITY) minX = 0;
  if (maxX === Number.NEGATIVE_INFINITY) maxX = 0;
  if (minY === Number.POSITIVE_INFINITY) minY = 0;
  if (maxY === Number.NEGATIVE_INFINITY) maxY = 0;

  const offsetX = padding - minX;
  const offsetY = padding - minY;

  return {
    offsetX,
    offsetY,
    width: maxX - minX + padding * 2,
    height: maxY - minY + padding * 2,
  };
}

export async function layoutGraphWithElk(
  graph: GraphModel,
  overrides?: Partial<ElkLayoutPreset>,
): Promise<LayoutGraphModel> {
  if (graph.nodes.length === 0) {
    return {
      kind: graph.kind,
      nodes: [],
      edges: [],
      bounds: { width: 0, height: 0 },
    };
  }

  const preset = { ...PRESETS[graph.kind], ...overrides };
  const dimensions = new Map<
    string,
    {
      width: number;
      height: number;
      text: ReturnType<typeof getNodeTextLayout>;
    }
  >();

  const elkGraph: ElkNode = {
    id: 'root',
    layoutOptions: buildLayoutOptions(graph, overrides),
    children: graph.nodes.map((node) => {
      const size = measureNode(node, graph.kind);
      dimensions.set(node.key, size);
      return {
        id: node.key,
        width: size.width,
        height: size.height,
      };
    }),
    edges: graph.edges.map((edge) => ({
      id: edge.key,
      sources: [edge.source],
      targets: [edge.target],
    })),
  };

  const layout = await elk.layout(elkGraph);
  const edgeById = new Map(
    layout.edges?.map((edge) => [edge.id ?? '', edge]) ?? [],
  );
  const layoutNodesById = new Map(
    layout.children?.map((node) => [node.id, node]) ?? [],
  );

  const nodes: LayoutGraphNode[] = graph.nodes.map((node) => {
    const layoutNode = layoutNodesById.get(node.key);
    const size = dimensions.get(node.key) ?? measureNode(node, graph.kind);
    const x = (layoutNode?.x ?? 0) + size.width / 2;
    const y = (layoutNode?.y ?? 0) + size.height / 2;

    return {
      ...node,
      x,
      y,
      width: size.width,
      height: size.height,
      sigmaSize: estimateSigmaNodeSize(node, size.width, size.height),
      labelLines: size.text.labelLines,
      detailLines: size.text.detailLines,
      sublabelLines: size.text.sublabelLines,
    };
  });

  const edges: LayoutGraphEdge[] = graph.edges.map((edge) => {
    const layoutEdge = edgeById.get(edge.key);
    const route = extractRoute(layoutEdge?.sections);
    return {
      ...edge,
      route,
    };
  });

  const bounds = collectBounds(nodes, edges, preset.padding);

  return {
    kind: graph.kind,
    nodes: nodes.map((node) => ({
      ...node,
      x: node.x + bounds.offsetX,
      y: node.y + bounds.offsetY,
    })),
    edges: edges.map((edge) => ({
      ...edge,
      route: edge.route.map((point) => ({
        x: point.x + bounds.offsetX,
        y: point.y + bounds.offsetY,
      })),
    })),
    bounds: {
      width: bounds.width,
      height: bounds.height,
    },
  };
}
