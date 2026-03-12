'use client';

import { useState, useEffect, useCallback } from 'react';
import { createClient } from '@/lib/supabase/client';

interface ScanTriggerButtonProps {
  orgVerified: boolean;
  isAdmin: boolean;
}

export function ScanTriggerButton({ orgVerified, isAdmin }: ScanTriggerButtonProps) {
  const [loading, setLoading] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const pollStatus = useCallback(async (id: string) => {
    try {
      const res = await fetch(`/api/scan?id=${id}`);
      if (res.ok) {
        const data = await res.json();
        setScanStatus(data.status);
        if (data.status === 'completed' || data.status === 'failed') {
          setLoading(false);
          // Refresh the page to show new findings
          window.location.reload();
        }
      }
    } catch {
      // Polling error — continue
    }
  }, []);

  useEffect(() => {
    if (!scanId || !loading) return;
    const interval = setInterval(() => pollStatus(scanId), 3000);
    return () => clearInterval(interval);
  }, [scanId, loading, pollStatus]);

  async function handleTriggerScan() {
    setLoading(true);
    setError(null);
    setScanStatus('queued');

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error);
        setLoading(false);
        return;
      }

      setScanId(data.scan_id);
      setScanStatus('queued');
    } catch {
      setError('Klaida paleidžiant skenavimą. Bandykite dar kartą.');
      setLoading(false);
    }
  }

  const statusLabels: Record<string, string> = {
    queued: 'Laukiama eilėje...',
    running: 'Skenavimas vykdomas...',
    completed: 'Skenavimas baigtas',
    failed: 'Skenavimas nepavyko',
  };

  if (!orgVerified) {
    return (
      <button
        disabled
        className="px-4 py-2 bg-gray-300 text-gray-500 text-sm font-medium rounded-md cursor-not-allowed"
        title="Domenas turi būti patvirtintas"
      >
        Pradėti skenavimą
      </button>
    );
  }

  if (!isAdmin) {
    return null;
  }

  return (
    <div className="flex items-center space-x-3">
      <button
        onClick={handleTriggerScan}
        disabled={loading}
        className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {loading ? 'Skenavimas vyksta...' : 'Pradėti skenavimą'}
      </button>

      {scanStatus && loading && (
        <span className="text-sm text-gray-500 animate-pulse">
          {statusLabels[scanStatus] || scanStatus}
        </span>
      )}

      {error && (
        <span className="text-sm text-red-600">{error}</span>
      )}
    </div>
  );
}
