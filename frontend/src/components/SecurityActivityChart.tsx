
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";

interface ChartDataPoint {
  date: string;
  fullDate: string;
  allowed: number;
  blocked: number;
  approval: number;
}

interface SecurityActivityChartProps {
  data: ChartDataPoint[];
}

function SecurityActivityChart({ data }: SecurityActivityChartProps) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart
        data={data}
        margin={{ top: 12, right: 12, left: -20, bottom: 0 }}
      >
        <defs>
          <linearGradient
            id="allowedGradient"
            x1="0"
            y1="0"
            x2="0"
            y2="1"
          >
            <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.28} />
            <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
          </linearGradient>

          <linearGradient
            id="blockedGradient"
            x1="0"
            y1="0"
            x2="0"
            y2="1"
          >
            <stop offset="0%" stopColor="#fb7185" stopOpacity={0.25} />
            <stop offset="95%" stopColor="#fb7185" stopOpacity={0} />
          </linearGradient>
        </defs>

        <CartesianGrid
          stroke="#263449"
          strokeDasharray="4 5"
          vertical={false}
        />

        <XAxis
          dataKey="date"
          tick={{ fill: "#8292a9", fontSize: 12 }}
          axisLine={false}
          tickLine={false}
        />

        <YAxis
          allowDecimals={false}
          tick={{ fill: "#8292a9", fontSize: 12 }}
          axisLine={false}
          tickLine={false}
        />

        <Tooltip
          contentStyle={{
            background: "#111d30",
            border: "1px solid #293b52",
            borderRadius: "10px",
            color: "#f1f5f9",
          }}
        />

        <Area
          type="monotone"
          dataKey="allowed"
          name="Allowed"
          stroke="#22d3ee"
          fill="url(#allowedGradient)"
          strokeWidth={2}
        />

        <Area
          type="monotone"
          dataKey="blocked"
          name="Blocked"
          stroke="#fb7185"
          fill="url(#blockedGradient)"
          strokeWidth={2}
        />

        <Area
          type="monotone"
          dataKey="approval"
          name="Requires approval"
          stroke="#a78bfa"
          fill="transparent"
          strokeWidth={2}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export default SecurityActivityChart;
