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

interface ScannerError {
  module: string;
  error: string;
}

interface ScanTriggerButtonProps {
  orgVerified: boolean;
  isAdmin: boolean;
}

export function ScanTriggerButton({ orgVerified, isAdmin }: ScanTriggerButtonProps) {
  const [loading, setLoading] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<string | null>(null);
  const [scannerErrors, setScannerErrors] = useState<ScannerError[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [timedOut, setTimedOut] = useState(false);
  const startTimeRef = useRef<number>(0);

  const CLIENT_TIMEOUT_SECONDS = 300; // 5 minutes

  const pollStatus = useCallback(async (id: string) => {
    // Client-side timeout: if polling for over 5 minutes, stop and show timeout
    const elapsed = Math.floor((Date.now() - startTimeRef.current) / 1000);
    if (elapsed > CLIENT_TIMEOUT_SECONDS) {
      setTimedOut(true);
      setLoading(false);
      setScanStatus('failed');
      setError('Skenavimas užtruko per ilgai. Bandykite dar kartą.');
      return;
    }

    try {
      const res = await fetch(`/api/scan?id=${id}`);
      if (res.ok) {
        const data = await res.json();
        setScanStatus(data.status);
        if (data.scanner_errors) {
          setScannerErrors(data.scanner_errors);
        }
        if (data.status === 'completed' || data.status === 'failed') {
          setLoading(false);
          // Small delay so user can see the final state
          setTimeout(() => window.location.reload(), 1500);
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

  // Progress based on elapsed time (scans typically take 30-90s)
  const progressPercent = loading
    ? Math.min(95, Math.round((elapsedSeconds / 60) * 90))
    : scanStatus === 'completed' ? 100 : 0;

  // Check which modules have errors
  const failedModules = new Set(scannerErrors.map(e => e.module));

  async function handleTriggerScan() {
    setLoading(true);
    setError(null);
    setTimedOut(false);
    setScanStatus('queued');
    setScannerErrors([]);
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
    completed: 'Skenavimas baigtas!',
    failed: 'Skenavimas nepavyko',
  };

  if (!orgVerified) {
    return (
      <button
        disabled
        className="px-4 py-2 bg-gray-300 text-gray-500 text-sm font-medium rounded-md cursor-not-allowed"
        title="Domenas turi būti patvirtintas"
        aria-label="Pradėti skenavimą (neprieinama — domenas nepatvirtintas)"
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
          aria-label={loading ? 'Skenavimas vykdomas' : 'Pradėti domeno skenavimą'}
        >
          {loading ? 'Skenavimas vyksta...' : 'Pradėti skenavimą'}
        </button>

        {error && (
          <span className="text-sm text-red-600">{error}</span>
        )}
        {timedOut && (
          <button
            onClick={handleTriggerScan}
            className="px-3 py-1.5 text-xs font-medium text-blue-700 bg-blue-50 border border-blue-200 rounded-md hover:bg-blue-100 transition-colors"
          >
            Bandyti dar kartą
          </button>
        )}
      </div>

      {/* Scan progress panel */}
      {(loading || scanStatus === 'completed' || scanStatus === 'failed') && scanStatus && (
        <div className={`border rounded-lg p-4 space-y-3 ${
          scanStatus === 'failed' ? 'bg-red-50 border-red-200' :
          scanStatus === 'completed' ? 'bg-green-50 border-green-200' :
          'bg-white border-gray-200'
        }`}>
          {/* Status + elapsed time */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {scanStatus === 'completed' ? (
                <svg className="w-4 h-4 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                </svg>
              ) : scanStatus === 'failed' ? (
                <svg className="w-4 h-4 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              ) : (
                <span className="inline-block w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
              )}
              <span className={`text-sm font-medium ${
                scanStatus === 'failed' ? 'text-red-900' :
                scanStatus === 'completed' ? 'text-green-900' :
                'text-gray-900'
              }`}>
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
              className={`h-2.5 rounded-full transition-all duration-1000 ${
                scanStatus === 'failed' ? 'bg-red-500' :
                scanStatus === 'completed' ? 'bg-green-500' :
                'bg-blue-500'
              }`}
              style={{ width: `${scanStatus === 'completed' ? 100 : scanStatus === 'failed' ? 100 : progressPercent}%` }}
            />
          </div>

          {/* Module indicators */}
          <div className="grid grid-cols-4 gap-2">
            {SCAN_MODULES.map((mod, i) => {
              const hasFailed = failedModules.has(mod.key);
              const moduleActive = scanStatus === 'running' && elapsedSeconds > i * 2 && !hasFailed;
              const moduleDone = (scanStatus === 'completed' || elapsedSeconds > (i + 1) * 8) && !hasFailed;
              return (
                <div key={mod.key} className="flex items-center gap-1.5">
                  {hasFailed ? (
                    <svg className="w-3.5 h-3.5 text-red-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  ) : moduleDone ? (
                    <svg className="w-3.5 h-3.5 text-green-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                  ) : moduleActive ? (
                    <span className="inline-block w-3.5 h-3.5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin flex-shrink-0" />
                  ) : (
                    <span className="inline-block w-3.5 h-3.5 rounded-full bg-gray-200 flex-shrink-0" />
                  )}
                  <span className={`text-xs ${
                    hasFailed ? 'text-red-600' :
                    moduleDone ? 'text-green-700' :
                    moduleActive ? 'text-blue-700' :
                    'text-gray-400'
                  }`}>
                    {mod.label}
                  </span>
                </div>
              );
            })}
          </div>

          {/* Scanner errors detail */}
          {scannerErrors.length > 0 && (
            <div className="bg-yellow-50 border border-yellow-200 rounded px-3 py-2">
              <p className="text-xs font-medium text-yellow-800 mb-1">
                {scannerErrors.length} modulis(-iai) nepavyko:
              </p>
              {scannerErrors.map((err, i) => (
                <p key={i} className="text-xs text-yellow-700">
                  <span className="font-medium">{err.module}</span>: {err.error}
                </p>
              ))}
            </div>
          )}

          {/* Safe to close message */}
          {loading && (
            <div className="bg-blue-50 rounded px-3 py-2">
              <p className="text-xs text-blue-700">
                Skenavimas vyksta serveryje. Galite uždaryti šį langą — rezultatai bus matomi grįžus.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
