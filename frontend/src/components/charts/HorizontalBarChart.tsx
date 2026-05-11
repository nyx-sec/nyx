export interface BarItem {
  label: string;
  value: number;
  color?: string;
}

interface HorizontalBarChartProps {
  items: BarItem[];
  maxValue?: number;
  width?: number;
}

export function HorizontalBarChart({
  items,
  maxValue,
  width = 400,
}: HorizontalBarChartProps) {
  if (!items || items.length === 0) {
    return (
      <div className="empty-state" style={{ padding: 20 }}>
        <p>No data</p>
      </div>
    );
  }

  const barH = 32;
  const gap = 12;
  const labelW = 120;
  const valueW = 48;
  const barAreaW = width - labelW - valueW - 16;
  const totalH = items.length * (barH + gap);
  const maxVal = maxValue ?? Math.max(...items.map((i) => i.value), 1);

  return (
    <div className="chart-container">
      <svg
        viewBox={`0 0 ${width} ${totalH}`}
        width="100%"
        preserveAspectRatio="xMinYMin meet"
        xmlns="http://www.w3.org/2000/svg"
      >
        {items.map((item, i) => {
          const y = i * (barH + gap);
          const w = Math.max((item.value / maxVal) * barAreaW, 2);
          const color = item.color || 'var(--accent)';
          return (
            <g key={item.label}>
              <text
                x={labelW - 8}
                y={y + barH / 2 + 4}
                textAnchor="end"
                fontSize={13}
                fontFamily="var(--font)"
                fill="var(--text-secondary)"
              >
                {item.label}
              </text>
              <rect
                x={labelW}
                y={y + 2}
                width={w}
                height={barH - 4}
                rx={3}
                fill={color}
                opacity={0.85}
              />
              <text
                x={labelW + barAreaW + 8}
                y={y + barH / 2 + 4}
                textAnchor="start"
                fontSize={13}
                fontFamily="var(--font-mono)"
                fontWeight={600}
                fill="var(--text)"
              >
                {item.value}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
