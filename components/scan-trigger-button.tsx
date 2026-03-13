'use client';

import { useState, useEffect, useCallback, useRef } from 'react';

const SCAN_MODULES = [
  { key: 'shodan', label: 'Shodan' },
  { key: 'hibp', label: 'HIBP' },
  { key: 'ssl', label: 'SSL Labs' },
  { key: 'mxtoolbox', label: 'MXToolbox' },
  { key: 'securitytrails', label: 'SecurityTrails' },
  { key: 'virustotal', label: 'VirusTotal' },
  { key: 'abuseipdb', label: 'AbuseIPDB' },
  { key: 'urlscan', label: 'URLScan' },
];

interface ScanTriggerButtonProps {
  orgVerified: boolean;
  isAdmin: boolean;
}

export function ScanTriggerButton({ orgVerified, isAdmin }: ScanTriggerButtonProps) {
  const [loading, setLoading] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const startTimeRef = useRef<number>(0);

  const pollStatus = useCallback(async (id: string) => {
    try {
      const res = await fetch(`/api/scan?id=${id}`);
      if (res.ok) {
        const data = await res.json();
        setScanStatus(data.status);
        if (data.status === 'completed' || data.status === 'failed') {
          setLoading(false);
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

  // Elapsed time counter
  useEffect(() => {
    if (!loading) return;
    startTimeRef.current = Date.now();
    const interval = setInterval(() => {
      setElapsedSeconds(Math.floor((Date.now() - startTimeRef.current) / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, [loading]);

  // Simulated progress based on elapsed time (scans typically take 30-90s)
  const progressPercent = loading
    ? Math.min(95, Math.round((elapsedSeconds / 60) * 90))
    : scanStatus === 'completed' ? 100 : 0;

  async function handleTriggerScan() {
    setLoading(true);
    setError(null);
    setScanStatus('queued');
    setElapsedSeconds(0);

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
    queued: 'Ruošiamasi skenavimui...',
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
    <div className="space-y-3">
      <div className="flex items-center space-x-3">
        <button
          onClick={handleTriggerScan}
          disabled={loading}
          className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {loading ? 'Skenavimas vyksta...' : 'Pradėti skenavimą'}
        </button>

        {error && (
          <span className="text-sm text-red-600">{error}</span>
        )}
      </div>

      {/* Scan progress panel */}
      {loading && scanStatus && (
        <div className="bg-white border border-gray-200 rounded-lg p-4 space-y-3">
          {/* Status + elapsed time */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="inline-block w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
              <span className="text-sm font-medium text-gray-900">
                {statusLabels[scanStatus] || scanStatus}
              </span>
            </div>
            <span className="text-xs text-gray-400 tabular-nums">
              {Math.floor(elapsedSeconds / 60)}:{(elapsedSeconds % 60).toString().padStart(2, '0')}
            </span>
          </div>

          {/* Progress bar */}
          <div className="w-full bg-gray-100 rounded-full h-2.5">
            <div
              className="bg-blue-500 h-2.5 rounded-full transition-all duration-1000"
              style={{ width: `${progressPercent}%` }}
            />
          </div>

          {/* Module indicators */}
          <div className="grid grid-cols-4 gap-2">
            {SCAN_MODULES.map((mod, i) => {
              const moduleActive = scanStatus === 'running' && elapsedSeconds > i * 2;
              const moduleDone = elapsedSeconds > (i + 1) * 8;
              return (
                <div key={mod.key} className="flex items-center gap-1.5">
                  {moduleDone ? (
                    <svg className="w-3.5 h-3.5 text-green-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                  ) : moduleActive ? (
                    <span className="inline-block w-3.5 h-3.5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin flex-shrink-0" />
                  ) : (
                    <span className="inline-block w-3.5 h-3.5 rounded-full bg-gray-200 flex-shrink-0" />
                  )}
                  <span className={`text-xs ${moduleDone ? 'text-green-700' : moduleActive ? 'text-blue-700' : 'text-gray-400'}`}>
                    {mod.label}
                  </span>
                </div>
              );
            })}
          </div>

          {/* Safe to close message */}
          <div className="bg-blue-50 rounded px-3 py-2">
            <p className="text-xs text-blue-700">
              Skenavimas vyksta serveryje. Galite uždaryti šį langą — rezultatai bus matomi grįžus.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
