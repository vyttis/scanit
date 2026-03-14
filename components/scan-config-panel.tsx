'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import type { PlanType } from '@/types/database';

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

interface ScanConfigPanelProps {
  orgVerified: boolean;
  isAdmin: boolean;
  domain: string;
  plan: PlanType;
}

export function ScanConfigPanel({ orgVerified, isAdmin, domain, plan }: ScanConfigPanelProps) {
  const [showConfig, setShowConfig] = useState(false);
  const [loading, setLoading] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<string | null>(null);
  const [scannerErrors, setScannerErrors] = useState<ScannerError[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [timedOut, setTimedOut] = useState(false);
  const startTimeRef = useRef<number>(0);

  // Professional plan fields
  const [ipRangesText, setIpRangesText] = useState('');
  const [subdomainsText, setSubdomainsText] = useState('');
  const [emailsText, setEmailsText] = useState('');

  const isProfessional = plan === 'professional';

  // Count scannable objects in real-time
  const ipRanges = ipRangesText.split(/[\n,]/).map(s => s.trim()).filter(Boolean);
  const subdomainsList = subdomainsText.split(/[\n,]/).map(s => s.trim()).filter(Boolean);
  const emailsList = emailsText.split(/[\n,]/).map(s => s.trim()).filter(Boolean);
  const totalObjects = 1 + ipRanges.length + subdomainsList.length + emailsList.length; // domain + extras

  const CLIENT_TIMEOUT_SECONDS = 300;

  const pollStatus = useCallback(async (id: string) => {
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

  useEffect(() => {
    if (!loading) return;
    startTimeRef.current = Date.now();
    const interval = setInterval(() => {
      setElapsedSeconds(Math.floor((Date.now() - startTimeRef.current) / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, [loading]);

  const progressPercent = loading
    ? Math.min(95, Math.round((elapsedSeconds / 60) * 90))
    : scanStatus === 'completed' ? 100 : 0;

  const failedModules = new Set(scannerErrors.map(e => e.module));

  async function handleStartScan() {
    setLoading(true);
    setError(null);
    setTimedOut(false);
    setScanStatus('queued');
    setScannerErrors([]);
    setElapsedSeconds(0);

    const requestBody: Record<string, unknown> = {};
    if (isProfessional) {
      if (ipRanges.length > 0) requestBody.ip_ranges = ipRanges;
      if (subdomainsList.length > 0) requestBody.subdomains = subdomainsList;
      if (emailsList.length > 0) requestBody.emails = emailsList;
    }

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error);
        setLoading(false);
        return;
      }

      setScanId(data.scan_id);
      setScanStatus('queued');
      setShowConfig(false);
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
      {/* Trigger button */}
      {!showConfig && !loading && !scanStatus && (
        <button
          onClick={() => setShowConfig(true)}
          className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700 transition-colors"
        >
          Pradėti skenavimą
        </button>
      )}

      {/* Configuration panel */}
      {showConfig && !loading && (
        <div className="bg-white border border-gray-200 rounded-lg shadow-lg p-5 space-y-4 max-w-lg">
          <h3 className="text-sm font-bold text-gray-900 uppercase tracking-wide">
            Skenavimo apimtis
          </h3>

          {/* Domain — always enabled */}
          <div className="flex items-start gap-3 p-3 bg-blue-50 border border-blue-200 rounded-lg">
            <input type="checkbox" checked disabled className="mt-0.5 h-4 w-4 text-blue-600 rounded" />
            <div className="flex-1">
              <div className="text-sm font-medium text-gray-900">
                Domenas ({domain})
              </div>
              <div className="text-xs text-gray-500 mt-0.5">
                SSL, DNS, reputacija, subdomenai, el. pašto sauga
              </div>
            </div>
          </div>

          <hr className="border-gray-200" />

          {/* IP ranges — professional only */}
          {isProfessional ? (
            <div className="space-y-2">
              <label className="flex items-center gap-2 text-sm font-medium text-gray-700">
                IP adresų rangai
              </label>
              <textarea
                value={ipRangesText}
                onChange={(e) => setIpRangesText(e.target.value)}
                rows={2}
                className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm font-mono placeholder-gray-400 focus:ring-blue-500 focus:border-blue-500"
                placeholder="192.168.1.0/24&#10;10.0.0.0/8"
              />
              <p className="text-xs text-gray-400">CIDR formatas, po vieną eilutėje</p>
            </div>
          ) : (
            <LockedFeature
              label="IP adresų rangai"
              planLabel="Profesionalus planas"
            />
          )}

          {/* Subdomains — professional only */}
          {isProfessional ? (
            <div className="space-y-2">
              <label className="flex items-center gap-2 text-sm font-medium text-gray-700">
                Subdomainų sąrašas
              </label>
              <textarea
                value={subdomainsText}
                onChange={(e) => setSubdomainsText(e.target.value)}
                rows={2}
                className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm font-mono placeholder-gray-400 focus:ring-blue-500 focus:border-blue-500"
                placeholder={`mail.${domain}\nvpn.${domain}`}
              />
              <p className="text-xs text-gray-400">Po vieną subdomeną eilutėje</p>
            </div>
          ) : (
            <LockedFeature
              label="Subdomainų sąrašas"
              planLabel="Profesionalus planas"
            />
          )}

          {/* Emails — professional only */}
          {isProfessional ? (
            <div className="space-y-2">
              <label className="flex items-center gap-2 text-sm font-medium text-gray-700">
                Darbuotojų el. paštai
              </label>
              <textarea
                value={emailsText}
                onChange={(e) => setEmailsText(e.target.value)}
                rows={2}
                className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm placeholder-gray-400 focus:ring-blue-500 focus:border-blue-500"
                placeholder={`vardas@${domain}\nkitas@${domain}`}
              />
              <div className="flex items-start gap-1.5">
                <svg className="w-3.5 h-3.5 text-yellow-500 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                </svg>
                <p className="text-xs text-gray-500">
                  El. paštai neišsaugomi — naudojami tik šio skenavimo metu
                </p>
              </div>
            </div>
          ) : (
            <LockedFeature
              label="Darbuotojų el. paštai"
              planLabel="Profesionalus planas"
            />
          )}

          <hr className="border-gray-200" />

          {/* Summary line */}
          <div className="flex items-center justify-between text-xs text-gray-500">
            <span>Moduliai: 8</span>
            <span>Tikrinami objektai: {totalObjects}</span>
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowConfig(false)}
              className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 transition-colors"
            >
              Atšaukti
            </button>
            <button
              onClick={handleStartScan}
              className="px-5 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 transition-colors"
            >
              Pradėti skenavimą →
            </button>
          </div>
        </div>
      )}

      {error && !loading && (
        <span className="text-sm text-red-600">{error}</span>
      )}

      {timedOut && (
        <button
          onClick={() => { setShowConfig(true); setScanStatus(null); setTimedOut(false); }}
          className="px-3 py-1.5 text-xs font-medium text-blue-700 bg-blue-50 border border-blue-200 rounded-md hover:bg-blue-100 transition-colors"
        >
          Bandyti dar kartą
        </button>
      )}

      {/* Scan progress panel */}
      {(loading || scanStatus === 'completed' || scanStatus === 'failed') && scanStatus && (
        <div className={`border rounded-lg p-4 space-y-3 ${
          scanStatus === 'failed' ? 'bg-red-50 border-red-200' :
          scanStatus === 'completed' ? 'bg-green-50 border-green-200' :
          'bg-white border-gray-200'
        }`}>
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

function LockedFeature({ label, planLabel }: { label: string; planLabel: string }) {
  return (
    <div className="flex items-center gap-3 p-3 bg-gray-50 border border-gray-200 rounded-lg opacity-75">
      <svg className="w-4 h-4 text-gray-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
      </svg>
      <div className="flex-1">
        <span className="text-sm text-gray-500">{label}</span>
      </div>
      <a
        href="/settings#plan"
        className="text-xs font-medium text-blue-600 hover:text-blue-800 whitespace-nowrap"
      >
        {planLabel}
      </a>
    </div>
  );
}
