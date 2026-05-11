import { formatShortDate } from '../../utils/formatDate';

export interface LinePoint {
  label: string;
  value: number;
}

interface LineChartProps {
  points: LinePoint[];
  color?: string;
  width?: number;
  height?: number;
}

export function LineChart({
  points,
  color = 'var(--accent)',
  width = 400,
  height = 240,
}: LineChartProps) {
  if (!points || points.length < 2) {
    return (
      <div className="empty-state" style={{ padding: 20 }}>
        <p>Need multiple scans for trends</p>
      </div>
    );
  }

  const pad = { top: 15, right: 15, bottom: 30, left: 40 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;

  const maxVal = Math.max(...points.map((p) => p.value), 1);
  const minVal = 0;
  const yRange = maxVal - minVal || 1;

  const xStep = plotW / Math.max(points.length - 1, 1);
  const coords = points.map((p, i) => ({
    x: pad.left + i * xStep,
    y: pad.top + plotH - ((p.value - minVal) / yRange) * plotH,
    label: p.label,
    value: p.value,
  }));

  const polyPoints = coords.map((c) => `${c.x},${c.y}`).join(' ');
  const areaPoints = `${coords[0].x},${pad.top + plotH} ${polyPoints} ${coords[coords.length - 1].x},${pad.top + plotH}`;

  // Y-axis grid lines
  const yTicks = 4;
  const gridLines = [];
  for (let i = 0; i <= yTicks; i++) {
    const y = pad.top + (i / yTicks) * plotH;
    const val = Math.round(maxVal - (i / yTicks) * yRange);
    gridLines.push({ y, val });
  }

  // X-axis label sampling
  const maxLabels = 6;
  const step = Math.max(1, Math.ceil(coords.length / maxLabels));

  return (
    <div className="chart-container">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        width="100%"
        preserveAspectRatio="xMinYMin meet"
        xmlns="http://www.w3.org/2000/svg"
      >
        {/* Grid lines */}
        {gridLines.map((g, i) => (
          <g key={i}>
            <line
              x1={pad.left}
              y1={g.y}
              x2={pad.left + plotW}
              y2={g.y}
              stroke="var(--border-light)"
              strokeWidth={1}
            />
            <text
              x={pad.left - 6}
              y={g.y + 3}
              textAnchor="end"
              fontSize={9}
              fontFamily="var(--font-mono)"
              fill="var(--text-tertiary)"
            >
              {g.val}
            </text>
          </g>
        ))}

        {/* Area fill */}
        <polygon points={areaPoints} fill={color} opacity={0.08} />

        {/* Line */}
        <polyline
          points={polyPoints}
          fill="none"
          stroke={color}
          strokeWidth={2}
          strokeLinejoin="round"
          strokeLinecap="round"
        />

        {/* Dots */}
        {coords.map((c, i) => (
          <circle
            key={i}
            cx={c.x}
            cy={c.y}
            r={3}
            fill={color}
            stroke="var(--bg)"
            strokeWidth={2}
          />
        ))}

        {/* X-axis labels */}
        {coords.map((c, i) => {
          if (i % step !== 0 && i !== coords.length - 1) return null;
          return (
            <text
              key={i}
              x={c.x}
              y={height - 4}
              textAnchor="middle"
              fontSize={9}
              fontFamily="var(--font)"
              fill="var(--text-tertiary)"
            >
              {formatShortDate(c.label)}
            </text>
          );
        })}
      </svg>
    </div>
  );
}
