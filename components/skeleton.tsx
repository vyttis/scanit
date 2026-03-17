/**
 * Reusable skeleton loading primitives for shimmer effects.
 */

export function SkeletonBox({ className = '', style }: { className?: string; style?: React.CSSProperties }) {
  return <div className={`animate-pulse bg-gray-200 rounded ${className}`} style={style} />;
}

export function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <SkeletonBox className="h-8 w-48" />
        <SkeletonBox className="h-10 w-40" />
      </div>

      {/* Top row cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {[1, 2, 3].map((i) => (
          <div key={i} className="bg-white rounded-lg shadow-md p-6 space-y-4">
            <SkeletonBox className="h-4 w-24" />
            <SkeletonBox className="h-16 w-16 rounded-full mx-auto" />
          </div>
        ))}
      </div>

      {/* Chart */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <SkeletonBox className="h-4 w-32 mb-4" />
        <div className="flex items-end gap-3 h-32">
          {[60, 80, 40, 70, 50].map((h, i) => (
            <SkeletonBox key={i} className="flex-1" style={{ height: `${h}%` }} />
          ))}
        </div>
      </div>

      {/* Findings list */}
      <div className="space-y-4">
        <SkeletonBox className="h-6 w-48" />
        {[1, 2, 3].map((i) => (
          <div key={i} className="bg-white border border-gray-200 rounded-lg p-5 space-y-3">
            <div className="flex gap-2">
              <SkeletonBox className="h-5 w-16" />
              <SkeletonBox className="h-5 w-20" />
            </div>
            <SkeletonBox className="h-5 w-3/4" />
            <SkeletonBox className="h-4 w-full" />
            <SkeletonBox className="h-4 w-2/3" />
          </div>
        ))}
      </div>
    </div>
  );
}

export function ScanTableSkeleton() {
  return (
    <div className="space-y-6">
      <SkeletonBox className="h-8 w-48" />
      <div className="bg-white rounded-lg shadow-md overflow-hidden">
        <div className="p-4 space-y-3">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="flex items-center gap-4">
              <SkeletonBox className="h-4 w-32" />
              <SkeletonBox className="h-4 w-16" />
              <SkeletonBox className="h-6 w-20 rounded-full" />
              <SkeletonBox className="h-4 w-12" />
              <SkeletonBox className="h-4 w-16" />
              <SkeletonBox className="h-4 w-16" />
              <SkeletonBox className="h-8 w-24" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export function ComplianceSkeleton() {
  return (
    <div className="space-y-6">
      <SkeletonBox className="h-8 w-56" />
      <div className="bg-white rounded-lg shadow-md p-8 flex flex-col items-center">
        <SkeletonBox className="h-28 w-28 rounded-full" />
        <SkeletonBox className="h-4 w-48 mt-4" />
      </div>
      <div className="bg-white rounded-lg shadow-md p-6 space-y-3">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="flex items-center gap-4">
            <SkeletonBox className="h-4 w-32" />
            <SkeletonBox className="h-4 w-40 flex-1" />
            <SkeletonBox className="h-6 w-20 rounded-full" />
            <SkeletonBox className="h-4 w-8" />
          </div>
        ))}
      </div>
    </div>
  );
}
