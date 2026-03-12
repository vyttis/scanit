interface RiskScoreBadgeProps {
  score: number | null;
  size?: 'sm' | 'lg';
}

export function RiskScoreBadge({ score, size = 'lg' }: RiskScoreBadgeProps) {
  if (score === null) {
    return (
      <div className="text-center">
        <span className="text-gray-400 text-sm">Nėra duomenų</span>
      </div>
    );
  }

  // RAG: Red >=70, Amber 41-70, Green <=40
  const color = score >= 70 ? 'text-red-600 border-red-400' :
    score >= 41 ? 'text-yellow-600 border-yellow-400' :
    'text-green-600 border-green-400';

  const bgColor = score >= 70 ? 'bg-red-50' :
    score >= 41 ? 'text-yellow-50' :
    'bg-green-50';

  const label = score >= 70 ? 'Kritinis' :
    score >= 41 ? 'Vidutinis' :
    'Saugus';

  const dimensions = size === 'lg'
    ? 'w-28 h-28 text-4xl border-[6px]'
    : 'w-16 h-16 text-xl border-4';

  return (
    <div className="flex flex-col items-center">
      <div className={`${dimensions} ${color} ${bgColor} rounded-full flex items-center justify-center font-bold`}>
        {score}
      </div>
      <span className={`mt-2 text-sm font-medium ${color.split(' ')[0]}`}>{label}</span>
      <span className="text-xs text-gray-400">/ 100</span>
    </div>
  );
}
