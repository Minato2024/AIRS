import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

function ThreatTimelineChart({ data }) {
  return (
    <ResponsiveContainer width="100%" height={280}>
      <AreaChart data={data}>
        <defs>
          <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="var(--chart-line)" stopOpacity={0.45} />
            <stop offset="95%" stopColor="var(--chart-line)" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
        <XAxis
          dataKey="time"
          axisLine={false}
          tickLine={false}
          tick={{ fill: 'var(--muted)', fontSize: 12 }}
        />
        <YAxis
          axisLine={false}
          tickLine={false}
          tick={{ fill: 'var(--muted)', fontSize: 12 }}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: 'var(--tooltip-bg)',
            border: '1px solid var(--tooltip-border)',
            borderRadius: '16px',
            boxShadow: '0 18px 40px rgba(10, 15, 30, 0.18)',
          }}
          labelFormatter={(label) => `Window: ${label}`}
          formatter={(value) => [value, 'Threat count']}
        />
        <Area
          type="monotone"
          dataKey="threats"
          stroke="var(--chart-line)"
          strokeWidth={3}
          fill="url(#threatGradient)"
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}

export default ThreatTimelineChart
