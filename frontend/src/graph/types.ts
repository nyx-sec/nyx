export type GraphViewKind = 'callgraph' | 'cfg' | 'surface';

export interface GraphPoint {
  x: number;
  y: number;
}

export interface GraphMetadata {
  [key: string]: unknown;
}

export interface GraphNodeModel {
  key: string;
  rawId: number;
  label: string;
  kind: string;
  detail?: string;
  sublabel?: string;
  badges?: string[];
  line?: number;
  metadata?: GraphMetadata;
}

export type GraphNode = GraphNodeModel;

export interface GraphEdgeModel {
  key: string;
  source: string;
  target: string;
  kind: string;
  label?: string;
  metadata?: GraphMetadata;
}

export type GraphEdge = GraphEdgeModel;

export interface GraphModel {
  kind: GraphViewKind;
  nodes: GraphNodeModel[];
  edges: GraphEdgeModel[];
}

export interface GraphCompactionResult {
  graph: GraphModel;
  compounds: Map<string, string[]>;
}

export interface LayoutBounds {
  width: number;
  height: number;
}

export interface LayoutGraphNode extends GraphNodeModel {
  x: number;
  y: number;
  width: number;
  height: number;
  sigmaSize: number;
  labelLines: string[];
  detailLines: string[];
  sublabelLines: string[];
}

export interface LayoutGraphEdge extends GraphEdgeModel {
  route: GraphPoint[];
}

export interface LayoutGraphModel {
  kind: GraphViewKind;
  nodes: LayoutGraphNode[];
  edges: LayoutGraphEdge[];
  bounds: LayoutBounds;
}

export interface ElkLayoutPreset {
  direction: 'DOWN' | 'RIGHT';
  nodeSpacing: number;
  layerSpacing: number;
  edgeNodeSpacing: number;
  padding: number;
  edgeRouting: 'POLYLINE' | 'ORTHOGONAL';
}

export interface GraphThemePalette {
  background: string;
  backgroundSecondary: string;
  text: string;
  textSecondary: string;
  textTertiary: string;
  border: string;
  borderLight: string;
  accent: string;
  accentSoft: string;
  success: string;
  warning: string;
  danger: string;
  neutral: string;
  neutralSoft: string;
}

export interface SigmaNodeAttributes extends LayoutGraphNode {
  size: number;
  color: string;
  hidden: boolean;
}

export interface SigmaEdgeAttributes extends LayoutGraphEdge {
  color: string;
  size: number;
  hidden: boolean;
}
