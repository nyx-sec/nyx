import type { SurfaceEdge, SurfaceMap, SurfaceNode } from '@/api/types';
import type { GraphModel } from '../types';

const MAX_LABEL = 44;
const MAX_DETAIL = 48;

function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

export const SURFACE_NODE_KIND: Record<SurfaceNode['node'], string> = {
  entry_point: 'EntryPoint',
  data_store: 'DataStore',
  external_service: 'ExternalService',
  dangerous_local: 'DangerousLocal',
};

function nodeTitle(node: SurfaceNode): string {
  switch (node.node) {
    case 'entry_point':
      return `${node.method} ${node.route}`;
    case 'data_store':
      return `${node.kind}: ${node.label}`;
    case 'external_service':
      return `${node.kind}: ${node.label}`;
    case 'dangerous_local':
      return node.function_name;
  }
}

function nodeDetail(node: SurfaceNode): string {
  switch (node.node) {
    case 'entry_point':
      return `${node.framework} · ${node.handler_name}`;
    case 'data_store':
      return 'data store';
    case 'external_service':
      return 'external service';
    case 'dangerous_local':
      return `cap=0x${node.cap_bits.toString(16)}`;
  }
}

function nodeLocation(node: SurfaceNode): { file: string; line: number } {
  if (node.node === 'entry_point') return node.handler_location;
  return node.location;
}

export function adaptSurfaceMap(data: SurfaceMap): GraphModel {
  return {
    kind: 'surface',
    nodes: data.nodes.map((node, index) => {
      const loc = nodeLocation(node);
      const title = nodeTitle(node);
      const detail = nodeDetail(node);
      const searchText = [title, detail, loc.file].join(' ').toLowerCase();
      const authBadge =
        node.node === 'entry_point' && node.auth_required ? ['auth'] : undefined;
      return {
        key: String(index),
        rawId: index,
        label: truncate(title, MAX_LABEL),
        kind: SURFACE_NODE_KIND[node.node],
        detail: truncate(detail, MAX_DETAIL),
        line: loc.line,
        badges: authBadge,
        metadata: {
          surfaceKind: node.node,
          node,
          searchText,
        },
      };
    }),
    edges: data.edges.map((edge: SurfaceEdge, index) => ({
      key: `surface:${edge.from}:${edge.to}:${edge.kind}:${index}`,
      source: String(edge.from),
      target: String(edge.to),
      kind: edge.kind,
      metadata: { ...edge },
    })),
  };
}
