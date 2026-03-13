'use client';

import { useRef, useState } from 'react';

interface ReportViewerProps {
  scanId: string;
}

/**
 * Renders the report HTML inside an iframe, loaded from our download proxy.
 * Includes a toolbar with print and download buttons.
 */
export function ReportViewer({ scanId }: ReportViewerProps) {
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function handlePrint() {
    try {
      iframeRef.current?.contentWindow?.print();
    } catch {
      // Fallback: open in new tab for printing
      window.open(`/api/reports/download?scan_id=${scanId}`, '_blank');
    }
  }

  async function handleDownload() {
    setGenerating(true);
    setError(null);
    try {
      // Fetch the report as a blob and trigger download
      const res = await fetch(`/api/reports/download?scan_id=${scanId}`);
      if (!res.ok) {
        setError('Klaida atsisiunčiant ataskaitą.');
        return;
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const contentType = res.headers.get('Content-Type') || '';
      const ext = contentType.includes('pdf') ? 'pdf' : 'html';
      a.download = `ataskaita-${scanId.slice(0, 8)}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch {
      setError('Klaida. Bandykite dar kartą.');
    } finally {
      setGenerating(false);
    }
  }

  return (
    <div className="bg-white rounded-lg shadow-md overflow-hidden">
      {/* Toolbar */}
      <div className="flex items-center justify-between border-b border-gray-200 px-4 py-3 bg-gray-50">
        <span className="text-sm font-medium text-gray-600">Ataskaitos peržiūra</span>
        <div className="flex items-center gap-2">
          {error && <span className="text-xs text-red-600">{error}</span>}
          <button
            onClick={handlePrint}
            className="px-3 py-1.5 text-xs font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
          >
            Spausdinti / PDF
          </button>
          <button
            onClick={handleDownload}
            disabled={generating}
            className="px-3 py-1.5 bg-blue-600 text-white text-xs font-medium rounded-md hover:bg-blue-700 disabled:opacity-50"
          >
            {generating ? 'Kraunama...' : 'Atsisiųsti'}
          </button>
        </div>
      </div>

      {/* Report iframe */}
      <iframe
        ref={iframeRef}
        src={`/api/reports/download?scan_id=${scanId}`}
        className="w-full border-0"
        style={{ minHeight: '80vh' }}
        title="Ataskaita"
        onLoad={(e) => {
          // Auto-resize iframe to content height
          try {
            const iframe = e.currentTarget;
            const doc = iframe.contentDocument || iframe.contentWindow?.document;
            if (doc?.body) {
              iframe.style.height = `${Math.max(doc.body.scrollHeight + 100, 800)}px`;
            }
          } catch {
            // Cross-origin — can't access, use default height
          }
        }}
      />
    </div>
  );
}
