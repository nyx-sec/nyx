import { describe, expect, it } from 'vitest';
import { adaptSurfaceMap, SURFACE_NODE_KIND } from '@/graph/adapters/surface';
import type { SurfaceMap } from '@/api/types';

const SAMPLE: SurfaceMap = {
  nodes: [
    {
      node: 'entry_point',
      location: { file: 'app.py', line: 10, col: 0 },
      framework: 'flask',
      method: 'POST',
      route: '/api/run',
      handler_name: 'run',
      handler_location: { file: 'app.py', line: 12, col: 2 },
      auth_required: false,
    },
    {
      node: 'data_store',
      location: { file: 'db.py', line: 40, col: 0 },
      kind: 'sql',
      label: 'orders',
    },
    {
      node: 'external_service',
      location: { file: 'client.py', line: 5, col: 0 },
      kind: 'http_api',
      label: 'github.com',
    },
    {
      node: 'dangerous_local',
      location: { file: 'app.py', line: 24, col: 4 },
      function_name: 'run',
      cap_bits: 0x400,
    },
  ],
  edges: [
    { from: 0, to: 3, kind: 'calls' },
    { from: 3, to: 1, kind: 'writes_to' },
    { from: 0, to: 2, kind: 'talks_to' },
  ],
};

describe('adaptSurfaceMap', () => {
  it('produces a surface-kind GraphModel', () => {
    const model = adaptSurfaceMap(SAMPLE);
    expect(model.kind).toBe('surface');
    expect(model.nodes).toHaveLength(4);
    expect(model.edges).toHaveLength(3);
  });

  it('keys nodes by index so SurfaceEdge.from/to map directly', () => {
    const model = adaptSurfaceMap(SAMPLE);
    expect(model.nodes.map((n) => n.key)).toEqual(['0', '1', '2', '3']);
    expect(model.edges[0]?.source).toBe('0');
    expect(model.edges[0]?.target).toBe('3');
  });

  it('maps each SurfaceNode kind to a distinct style discriminator', () => {
    const model = adaptSurfaceMap(SAMPLE);
    expect(model.nodes[0]?.kind).toBe(SURFACE_NODE_KIND.entry_point);
    expect(model.nodes[1]?.kind).toBe(SURFACE_NODE_KIND.data_store);
    expect(model.nodes[2]?.kind).toBe(SURFACE_NODE_KIND.external_service);
    expect(model.nodes[3]?.kind).toBe(SURFACE_NODE_KIND.dangerous_local);
  });

  it('builds entry-point labels from method and route', () => {
    const model = adaptSurfaceMap(SAMPLE);
    expect(model.nodes[0]?.label).toBe('POST /api/run');
    expect(model.nodes[0]?.detail).toBe('flask · run');
  });

  it('renders dangerous_local cap_bits as hex in detail', () => {
    const model = adaptSurfaceMap(SAMPLE);
    expect(model.nodes[3]?.detail).toBe('cap=0x400');
  });

  it('uses handler_location for entry_point line, location for others', () => {
    const model = adaptSurfaceMap(SAMPLE);
    expect(model.nodes[0]?.line).toBe(12);
    expect(model.nodes[1]?.line).toBe(40);
  });

  it('emits an auth badge only for entry_points marked auth_required', () => {
    const protectedEntry = adaptSurfaceMap({
      nodes: [
        {
          ...SAMPLE.nodes[0],
          node: 'entry_point',
          auth_required: true,
        } as SurfaceMap['nodes'][0],
      ],
      edges: [],
    });
    expect(protectedEntry.nodes[0]?.badges).toEqual(['auth']);
    const openEntry = adaptSurfaceMap(SAMPLE);
    expect(openEntry.nodes[0]?.badges).toBeUndefined();
  });

  it('produces unique edge keys even for parallel edges of the same kind', () => {
    const parallel: SurfaceMap = {
      nodes: SAMPLE.nodes,
      edges: [
        { from: 0, to: 1, kind: 'calls' },
        { from: 0, to: 1, kind: 'calls' },
      ],
    };
    const model = adaptSurfaceMap(parallel);
    expect(model.edges[0]?.key).not.toBe(model.edges[1]?.key);
  });
});
