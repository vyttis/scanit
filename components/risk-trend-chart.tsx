interface TrendPoint {
  date: string;
  score: number;
}

interface RiskTrendChartProps {
  points: TrendPoint[];
}

export function RiskTrendChart({ points }: RiskTrendChartProps) {
  if (points.length === 0) {
    return (
      <div className="bg-white rounded-lg shadow-md p-6">
        <h2 className="text-sm font-medium text-gray-500 mb-4">Rizikos balo tendencija</h2>
        <p className="text-gray-400 text-sm text-center py-8">
          Tendencijų diagrama bus rodoma atlikus bent 2 skenavimus.
        </p>
      </div>
    );
  }

  const maxScore = 100;
  const chartHeight = 160;
  const chartWidth = 100; // percentage
  const barWidth = Math.min(60, Math.floor(chartWidth / points.length) - 8);

  function barColor(score: number): string {
    if (score >= 70) return 'bg-red-500';
    if (score >= 41) return 'bg-yellow-500';
    return 'bg-green-500';
  }

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-sm font-medium text-gray-500 mb-4">Rizikos balo tendencija</h2>
      <div className="flex items-end justify-around gap-2" style={{ height: chartHeight }}>
        {points.map((point, i) => {
          const heightPct = Math.max(4, (point.score / maxScore) * 100);
          return (
            <div key={i} className="flex flex-col items-center flex-1">
              <span className="text-xs font-medium text-gray-700 mb-1">{point.score}</span>
              <div
                className={`w-full ${barColor(point.score)} rounded-t-md transition-all`}
                style={{ height: `${heightPct}%`, maxWidth: `${barWidth}px` }}
              />
              <span className="text-xs text-gray-400 mt-2 truncate w-full text-center">
                {point.date}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
