import { useMemo, useState } from 'react';
import { useSurfaceMap } from '../api/queries/surface';
import { LoadingState } from '../components/ui/LoadingState';
import { ErrorState } from '../components/ui/ErrorState';
import { EmptyState } from '../components/ui/EmptyState';
import { usePageTitle } from '../hooks/usePageTitle';
import type {
  SurfaceEdge,
  SurfaceEdgeKind,
  SurfaceMap,
  SurfaceNode,
} from '../api/types';

const EDGE_KIND_LABELS: Record<SurfaceEdgeKind, string> = {
  calls: 'Calls',
  reads_from: 'Reads',
  writes_to: 'Writes',
  talks_to: 'Talks to',
  reaches: 'Reaches',
  triggers: 'Triggers',
  auth_required_on: 'Auth required',
};

const NODE_KIND_COLORS: Record<SurfaceNode['node'], string> = {
  entry_point: 'var(--accent)',
  data_store: 'var(--sev-medium)',
  external_service: 'var(--sev-low)',
  dangerous_local: 'var(--sev-high)',
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

function nodeSubtitle(node: SurfaceNode): string {
  switch (node.node) {
    case 'entry_point':
      return `${node.framework} → ${node.handler_name}`;
    case 'data_store':
      return 'Data store';
    case 'external_service':
      return 'External service';
    case 'dangerous_local':
      return `cap=0x${node.cap_bits.toString(16)}`;
  }
}

function nodeLocation(node: SurfaceNode): string {
  const loc = node.node === 'entry_point' ? node.handler_location : node.location;
  return `${loc.file}:${loc.line}`;
}

function NodeCard({
  node,
  index,
  selected,
  onClick,
}: {
  node: SurfaceNode;
  index: number;
  selected: boolean;
  onClick: () => void;
}) {
  const color = NODE_KIND_COLORS[node.node];
  return (
    <button
      type="button"
      onClick={onClick}
      className={`surface-node-card${selected ? ' selected' : ''}`}
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'flex-start',
        gap: 'var(--space-1)',
        padding: 'var(--space-3)',
        border: `1px solid ${selected ? color : 'var(--border)'}`,
        borderLeft: `4px solid ${color}`,
        borderRadius: 'var(--radius-2)',
        background: selected ? 'var(--surface-2)' : 'var(--surface-1)',
        cursor: 'pointer',
        textAlign: 'left',
        width: '100%',
      }}
    >
      <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-tertiary)' }}>
        #{index} · {node.node.replace('_', ' ')}
        {node.node === 'entry_point' && node.auth_required ? ' · auth' : ''}
      </span>
      <span style={{ fontWeight: 600, fontSize: 'var(--text-sm)' }}>
        {nodeTitle(node)}
      </span>
      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
        {nodeSubtitle(node)}
      </span>
      <code style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-tertiary)' }}>
        {nodeLocation(node)}
      </code>
    </button>
  );
}

function summarize(map: SurfaceMap): {
  entries: number;
  stores: number;
  externals: number;
  dangerous: number;
  edgeKinds: Record<string, number>;
} {
  let entries = 0;
  let stores = 0;
  let externals = 0;
  let dangerous = 0;
  for (const n of map.nodes) {
    if (n.node === 'entry_point') entries++;
    else if (n.node === 'data_store') stores++;
    else if (n.node === 'external_service') externals++;
    else if (n.node === 'dangerous_local') dangerous++;
  }
  const edgeKinds: Record<string, number> = {};
  for (const e of map.edges) {
    edgeKinds[e.kind] = (edgeKinds[e.kind] ?? 0) + 1;
  }
  return { entries, stores, externals, dangerous, edgeKinds };
}

function NeighborList({
  map,
  index,
}: {
  map: SurfaceMap;
  index: number | null;
}) {
  if (index === null) {
    return (
      <p style={{ color: 'var(--text-tertiary)' }}>
        Select a node on the left to see its neighbours.
      </p>
    );
  }
  const node = map.nodes[index];
  if (!node) return null;

  const outgoing: SurfaceEdge[] = map.edges.filter((e) => e.from === index);
  const incoming: SurfaceEdge[] = map.edges.filter((e) => e.to === index);

  const renderEdges = (edges: SurfaceEdge[], direction: 'in' | 'out') => {
    if (edges.length === 0) {
      return (
        <p style={{ color: 'var(--text-tertiary)' }}>
          (no {direction === 'in' ? 'inbound' : 'outbound'} edges)
        </p>
      );
    }
    return (
      <ul
        style={{
          listStyle: 'none',
          padding: 0,
          margin: 0,
          display: 'flex',
          flexDirection: 'column',
          gap: 'var(--space-1)',
        }}
      >
        {edges.map((e, i) => {
          const otherIdx = direction === 'in' ? e.from : e.to;
          const other = map.nodes[otherIdx];
          if (!other) return null;
          return (
            <li
              key={`${direction}-${i}`}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-2)',
                fontSize: 'var(--text-xs)',
              }}
            >
              <span
                style={{
                  padding: '2px 6px',
                  borderRadius: 'var(--radius-1)',
                  background: 'var(--surface-2)',
                  color: 'var(--text-secondary)',
                }}
              >
                {EDGE_KIND_LABELS[e.kind]}
              </span>
              <span>
                {direction === 'in' ? '←' : '→'} <strong>{nodeTitle(other)}</strong>
              </span>
              <code
                style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-tertiary)' }}
              >
                {nodeLocation(other)}
              </code>
            </li>
          );
        })}
      </ul>
    );
  };

  return (
    <div>
      <h3 style={{ marginTop: 0 }}>{nodeTitle(node)}</h3>
      <p style={{ color: 'var(--text-secondary)', marginTop: 0 }}>
        {nodeSubtitle(node)} — <code>{nodeLocation(node)}</code>
      </p>
      <h4>Outbound</h4>
      {renderEdges(outgoing, 'out')}
      <h4>Inbound</h4>
      {renderEdges(incoming, 'in')}
    </div>
  );
}

type NodeKindFilter = 'all' | SurfaceNode['node'];

export function SurfacePage() {
  usePageTitle('Surface');
  const { data, isLoading, error } = useSurfaceMap();
  const [selected, setSelected] = useState<number | null>(null);
  const [filter, setFilter] = useState<NodeKindFilter>('all');
  const [query, setQuery] = useState('');

  const visible = useMemo(() => {
    if (!data) return [] as Array<{ node: SurfaceNode; index: number }>;
    const q = query.trim().toLowerCase();
    return data.nodes
      .map((node, index) => ({ node, index }))
      .filter(({ node }) => filter === 'all' || node.node === filter)
      .filter(({ node }) => {
        if (!q) return true;
        return (
          nodeTitle(node).toLowerCase().includes(q) ||
          nodeSubtitle(node).toLowerCase().includes(q) ||
          nodeLocation(node).toLowerCase().includes(q)
        );
      });
  }, [data, filter, query]);

  if (isLoading) return <LoadingState message="Loading surface map..." />;
  if (error) return <ErrorState message={error.message} />;
  if (!data || data.nodes.length === 0) {
    return (
      <EmptyState message="No surface yet. Run an indexed scan (`nyx scan`) to populate the attack-surface map, or invoke `nyx surface` against the project." />
    );
  }

  const summary = summarize(data);

  return (
    <div className="page-content">
      <header
        style={{
          display: 'flex',
          alignItems: 'baseline',
          gap: 'var(--space-4)',
          marginBottom: 'var(--space-4)',
        }}
      >
        <h1 style={{ margin: 0 }}>Attack surface</h1>
        <span style={{ color: 'var(--text-tertiary)', fontSize: 'var(--text-sm)' }}>
          {summary.entries} entry-points · {summary.stores} stores ·{' '}
          {summary.externals} services · {summary.dangerous} dangerous locals ·{' '}
          {data.edges.length} edges
        </span>
      </header>
      <div
        style={{
          display: 'flex',
          gap: 'var(--space-2)',
          marginBottom: 'var(--space-3)',
          flexWrap: 'wrap',
        }}
      >
        <input
          type="search"
          value={query}
          placeholder="Filter by name, label, or path"
          onChange={(e) => setQuery(e.target.value)}
          style={{
            flex: '1 1 220px',
            padding: 'var(--space-2)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-1)',
            background: 'var(--surface-1)',
            color: 'var(--text-primary)',
          }}
        />
        <select
          value={filter}
          onChange={(e) => setFilter(e.target.value as NodeKindFilter)}
          style={{
            padding: 'var(--space-2)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-1)',
            background: 'var(--surface-1)',
            color: 'var(--text-primary)',
          }}
        >
          <option value="all">All node kinds</option>
          <option value="entry_point">Entry points</option>
          <option value="data_store">Data stores</option>
          <option value="external_service">External services</option>
          <option value="dangerous_local">Dangerous locals</option>
        </select>
      </div>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(280px, 1fr) minmax(320px, 1.4fr)',
          gap: 'var(--space-4)',
          alignItems: 'flex-start',
        }}
      >
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: 'var(--space-2)',
            maxHeight: '70vh',
            overflowY: 'auto',
          }}
        >
          {visible.length === 0 ? (
            <p style={{ color: 'var(--text-tertiary)' }}>No nodes match.</p>
          ) : (
            visible.map(({ node, index }) => (
              <NodeCard
                key={index}
                node={node}
                index={index}
                selected={selected === index}
                onClick={() => setSelected(index)}
              />
            ))
          )}
        </div>
        <aside
          style={{
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-2)',
            padding: 'var(--space-4)',
            background: 'var(--surface-1)',
          }}
        >
          <NeighborList map={data} index={selected} />
        </aside>
      </div>
    </div>
  );
}
