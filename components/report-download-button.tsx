'use client';

import { useState } from 'react';

interface ReportDownloadButtonProps {
  scanId: string;
  hasReport: boolean;
}

export function ReportDownloadButton({ scanId, hasReport }: ReportDownloadButtonProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleDownload() {
    setLoading(true);
    setError(null);

    try {
      if (!hasReport) {
        // Generate report first via POST
        const res = await fetch('/api/reports', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scan_id: scanId }),
        });
        const data = await res.json();
        if (!res.ok) {
          setError(data.error || 'Klaida generuojant ataskaitą.');
          return;
        }
      }

      // Download via fetch + blob to avoid popup blockers
      const res = await fetch(`/api/reports/download?scan_id=${scanId}`);
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setError(data.error || 'Klaida atsisiunčiant ataskaitą.');
        return;
      }

      const blob = await res.blob();
      const contentType = res.headers.get('Content-Type') || '';
      const ext = contentType.includes('pdf') ? 'pdf' : 'html';
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `ataskaita-${scanId.slice(0, 8)}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch {
      setError('Klaida. Bandykite dar kartą.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex items-center gap-2">
      <button
        onClick={handleDownload}
        disabled={loading}
        className="px-3 py-1.5 bg-blue-600 text-white text-xs font-medium rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
        aria-label={loading ? 'Ataskaita generuojama' : 'Atsisiųsti skenavimo ataskaitą'}
      >
        {loading ? 'Kraunama...' : 'Atsisiųsti ataskaitą'}
      </button>
      {error && <span className="text-xs text-red-600">{error}</span>}
    </div>
  );
}
