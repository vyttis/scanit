'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import type { PublicScanFinding } from '@/types/database';

interface ScanData {
  id: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  risk_score: number | null;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  results?: {
    findings: PublicScanFinding[];
    modules_run: string[];
  };
}

const SEVERITY_LABEL: Record<string, string> = {
  critical: 'Kritinis',
  high: 'Aukštas',
  medium: 'Vidutinis',
  low: 'Žemas',
  info: 'Informacinis',
};

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-blue-100 text-blue-800 border-blue-200',
  info: 'bg-gray-100 text-gray-800 border-gray-200',
};

function RiskCircle({ score }: { score: number }) {
  const color =
    score >= 70
      ? 'text-red-600 border-red-400 bg-red-50'
      : score >= 41
        ? 'text-yellow-600 border-yellow-400 bg-yellow-50'
        : 'text-green-600 border-green-400 bg-green-50';

  const label =
    score >= 70
      ? 'Aukšta rizika'
      : score >= 41
        ? 'Vidutinė rizika'
        : 'Žema rizika';

  return (
    <div className="flex flex-col items-center">
      <div
        className={`w-32 h-32 rounded-full border-[6px] flex items-center justify-center text-4xl font-bold ${color}`}
      >
        {score}
      </div>
      <span className={`mt-2 text-sm font-semibold ${color.split(' ')[0]}`}>
        {label}
      </span>
      <span className="text-xs text-gray-400">Rizikos balas / 100</span>
    </div>
  );
}

export default function RezultataiPage() {
  const params = useParams();
  const id = params.id as string;
  const [scan, setScan] = useState<ScanData | null>(null);
  const [fullResults, setFullResults] = useState<ScanData['results'] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [polling, setPolling] = useState(true);

  useEffect(() => {
    if (!id) return;

    let timer: ReturnType<typeof setInterval>;

    async function poll() {
      try {
        const res = await fetch(`/api/public-scan?id=${id}`);
        if (!res.ok) {
          setError('Skenavimas nerastas.');
          setPolling(false);
          return;
        }
        const data: ScanData = await res.json();
        setScan(data);

        if (data.status === 'completed' || data.status === 'failed') {
          setPolling(false);
          // Fetch full results once completed
          if (data.status === 'completed') {
            const fullRes = await fetch(`/api/public-scan/results?id=${id}`);
            if (fullRes.ok) {
              const fullData = await fullRes.json();
              setFullResults(fullData.results);
            }
          }
        }
      } catch {
        setError('Tinklo klaida.');
        setPolling(false);
      }
    }

    poll();
    if (polling) {
      timer = setInterval(poll, 3000);
    }

    return () => clearInterval(timer);
  }, [id, polling]);

  // Loading / polling state
  if (polling && (!scan || scan.status === 'queued' || scan.status === 'running')) {
    return (
      <div className="min-h-screen bg-slate-50 flex flex-col">
        <Header />
        <main className="flex-1 flex items-center justify-center px-4">
          <div className="text-center">
            <div className="inline-block mb-6">
              <svg
                className="animate-spin h-16 w-16 text-blue-600"
                viewBox="0 0 24 24"
                fill="none"
              >
                <circle
                  className="opacity-25"
                  cx="12"
                  cy="12"
                  r="10"
                  stroke="currentColor"
                  strokeWidth="4"
                />
                <path
                  className="opacity-75"
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                />
              </svg>
            </div>
            <h1 className="text-2xl font-bold text-gray-900 mb-2">
              Skenuojama...
            </h1>
            <p className="text-gray-500">
              Tikrinami 8 saugumo moduliai. Tai užtrunka apie 30–60 sekundžių.
            </p>
            <div className="mt-6 flex justify-center gap-2">
              {['Shodan', 'SSL', 'HIBP', 'MX', 'DNS', 'VT', 'Abuse', 'URL'].map(
                (m) => (
                  <span
                    key={m}
                    className="inline-block px-2 py-1 bg-blue-100 text-blue-700 text-xs rounded animate-pulse"
                  >
                    {m}
                  </span>
                ),
              )}
            </div>
          </div>
        </main>
      </div>
    );
  }

  // Error state
  if (error || scan?.status === 'failed') {
    return (
      <div className="min-h-screen bg-slate-50 flex flex-col">
        <Header />
        <main className="flex-1 flex items-center justify-center px-4">
          <div className="text-center max-w-md">
            <h1 className="text-2xl font-bold text-gray-900 mb-2">
              Skenavimas nepavyko
            </h1>
            <p className="text-gray-500 mb-6">
              {error || 'Įvyko klaida atliekant skenavimą. Bandykite dar kartą.'}
            </p>
            <Link
              href="/tikrinti"
              className="inline-block px-6 py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700"
            >
              Bandyti dar kartą
            </Link>
          </div>
        </main>
      </div>
    );
  }

  // Results
  const findings = fullResults?.findings ?? [];
  const top3 = findings
    .sort((a, b) => {
      const order = ['critical', 'high', 'medium', 'low', 'info'];
      return order.indexOf(a.severity) - order.indexOf(b.severity);
    })
    .slice(0, 3);

  const hasCritical = (scan?.critical_count ?? 0) > 0;

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col">
      <Header />

      <main className="flex-1 max-w-3xl mx-auto w-full px-4 py-8 space-y-8">
        {/* Critical findings banner */}
        {hasCritical && (
          <div className="bg-red-600 text-white rounded-xl p-5 shadow-lg">
            <p className="text-lg font-bold">
              Rastas {scan!.critical_count} kritinis
              {scan!.critical_count === 1
                ? ' pažeidimas'
                : scan!.critical_count < 10
                  ? ' pažeidimai'
                  : ' pažeidimų'}
              . Registruokitės norėdami sužinoti kaip juos pašalinti.
            </p>
          </div>
        )}

        {/* Risk score */}
        <div className="bg-white rounded-xl shadow-md p-8 flex flex-col items-center">
          <RiskCircle score={scan?.risk_score ?? 0} />
        </div>

        {/* Finding counts */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            {
              label: 'Kritinių',
              count: scan?.critical_count ?? 0,
              color: 'text-red-600',
              bg: 'bg-red-50 border-red-200',
            },
            {
              label: 'Aukšto lygio',
              count: scan?.high_count ?? 0,
              color: 'text-orange-600',
              bg: 'bg-orange-50 border-orange-200',
            },
            {
              label: 'Vidutinio lygio',
              count: scan?.medium_count ?? 0,
              color: 'text-yellow-600',
              bg: 'bg-yellow-50 border-yellow-200',
            },
            {
              label: 'Žemo lygio',
              count: scan?.low_count ?? 0,
              color: 'text-blue-600',
              bg: 'bg-blue-50 border-blue-200',
            },
          ].map((item) => (
            <div
              key={item.label}
              className={`${item.bg} border rounded-xl p-4 text-center`}
            >
              <div className={`text-3xl font-bold ${item.color}`}>
                {item.count}
              </div>
              <div className="text-sm text-gray-600 mt-1">{item.label}</div>
            </div>
          ))}
        </div>

        {/* Top 3 findings (visible) */}
        {top3.length > 0 && (
          <div className="space-y-3">
            <h2 className="text-lg font-bold text-gray-900">
              Pagrindiniai nustatyti trūkumai
            </h2>
            {top3.map((f, i) => (
              <div
                key={i}
                className="bg-white border border-gray-200 rounded-xl p-4 flex items-center justify-between"
              >
                <div>
                  <p className="font-medium text-gray-900">{f.title_lt}</p>
                  {/* Description is blurred for free tier */}
                  <p className="text-sm text-gray-400 mt-1 blur-sm select-none" aria-hidden="true">
                    Detalus aprašymas ir rekomendacijos prieinamos registruotiems
                    vartotojams...
                  </p>
                </div>
                <span
                  className={`inline-flex px-3 py-1 text-xs font-semibold rounded-full border ${SEVERITY_COLOR[f.severity]}`}
                >
                  {SEVERITY_LABEL[f.severity]}
                </span>
              </div>
            ))}

            {/* Remaining findings blurred */}
            {findings.length > 3 && (
              <div className="relative">
                <div className="blur-sm pointer-events-none select-none space-y-3" aria-hidden="true">
                  {findings.slice(3, 6).map((f, i) => (
                    <div
                      key={i}
                      className="bg-white border border-gray-200 rounded-xl p-4 flex items-center justify-between"
                    >
                      <p className="font-medium text-gray-900">{f.title_lt}</p>
                      <span
                        className={`inline-flex px-3 py-1 text-xs font-semibold rounded-full border ${SEVERITY_COLOR[f.severity]}`}
                      >
                        {SEVERITY_LABEL[f.severity]}
                      </span>
                    </div>
                  ))}
                </div>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="bg-white/90 px-4 py-2 rounded-lg text-sm font-medium text-gray-700 shadow">
                    Dar {findings.length - 3} trūkumų — registruokitės, kad pamatytumėte
                  </span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Conversion block */}
        <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-xl p-6 sm:p-8 text-white">
          <div className="flex items-start gap-3 mb-4">
            <span className="text-2xl flex-shrink-0">⚠️</span>
            <div>
              <p className="font-bold text-lg mb-3">
                Mes patikrinome tik jūsų domeną. Dar nepatikrinome:
              </p>
              <ul className="space-y-2 text-slate-300">
                <li className="flex items-center gap-2">
                  <span className="text-slate-500">→</span> Jūsų subdomainų
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-slate-500">→</span> Jūsų serverių IP adresų
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-slate-500">→</span> Jūsų darbuotojų el. paštų
                </li>
              </ul>
            </div>
          </div>
          <p className="text-slate-300 mb-6">
            Norėdami gauti pilną PDF ataskaitą su KSĮ reikalavimų žemėlapiu ir NKSC
            audito dokumentu — užsiregistruokite.
          </p>
          <Link
            href="/register"
            className="inline-block w-full sm:w-auto text-center px-8 py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 transition-colors shadow-lg"
          >
            Pradėti 30 dienų nemokamą bandomąjį laikotarpį
          </Link>
        </div>

        {/* Back to scan */}
        <div className="text-center">
          <Link
            href="/tikrinti"
            className="text-sm text-gray-500 hover:text-gray-700 transition-colors"
          >
            ← Skenuoti kitą domeną
          </Link>
        </div>
      </main>

      <footer className="py-6 px-4 text-center text-gray-400 text-sm">
        scanit.lt — Kibernetinio saugumo platforma pagal KSĮ ir NIS2 reikalavimus
      </footer>
    </div>
  );
}

function Header() {
  return (
    <header className="bg-white border-b border-gray-200 py-4 px-4">
      <div className="max-w-3xl mx-auto flex items-center justify-between">
        <a href="/tikrinti" className="text-xl font-bold text-gray-900">
          scanit.lt
        </a>
        <div className="flex items-center gap-4">
          <Link
            href="/tikrinti"
            className="text-sm text-gray-500 hover:text-gray-700"
          >
            Naujas skenavimas
          </Link>
          <Link
            href="/login"
            className="text-sm text-blue-600 hover:text-blue-700 font-medium"
          >
            Prisijungti
          </Link>
        </div>
      </div>
    </header>
  );
}
