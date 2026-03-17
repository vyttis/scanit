'use client';

import { useState, useCallback } from 'react';
import type { Finding, FindingStatusType } from '@/types/database';
import { calculateSla, formatSlaText } from '@/lib/utils/sla';

interface FindingsListProps {
  findings: Finding[];
  findingStatuses?: Record<string, { status: FindingStatusType; note: string | null }>;
  isAdmin?: boolean;
  scanId?: string;
}

const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];

const severityLabels: Record<string, string> = {
  critical: 'Kritinis',
  high: 'Aukštas',
  medium: 'Vidutinis',
  low: 'Žemas',
  info: 'Informacinis',
};

const severityIcons: Record<string, string> = {
  critical: '\u2B24', // ⬤
  high: '\u25B2',     // ▲
  medium: '\u25C6',   // ◆
  low: '\u25CF',      // ●
  info: '\u2139',     // ℹ
};

const severityBadgeColors: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-600 text-white',
  medium: 'bg-yellow-600 text-white',
  low: 'bg-blue-600 text-white',
  info: 'bg-gray-500 text-white',
};

const severityBorderColors: Record<string, string> = {
  critical: 'border-l-red-600',
  high: 'border-l-orange-600',
  medium: 'border-l-yellow-600',
  low: 'border-l-blue-600',
  info: 'border-l-gray-500',
};

const moduleLabels: Record<string, string> = {
  shodan: 'Shodan',
  hibp: 'HaveIBeenPwned',
  ssl: 'SSL/TLS',
  mxtoolbox: 'El. pašto sauga',
  securitytrails: 'Subdomenai / DNS',
  virustotal: 'VirusTotal',
  abuseipdb: 'AbuseIPDB',
  urlscan: 'URLScan',
};

const statusLabels: Record<FindingStatusType, string> = {
  open: 'Atviras',
  in_progress: 'Vykdomas',
  resolved: 'Išspręstas',
  accepted_risk: 'Priimta rizika',
  false_positive: 'Klaidingas teigiamas',
};

const statusColors: Record<FindingStatusType, string> = {
  open: 'bg-red-100 text-red-800 border-red-200',
  in_progress: 'bg-blue-100 text-blue-800 border-blue-200',
  resolved: 'bg-green-100 text-green-800 border-green-200',
  accepted_risk: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  false_positive: 'bg-gray-100 text-gray-600 border-gray-200',
};

function EvidenceBlock({ evidence }: { evidence: Record<string, unknown> | null }) {
  const [open, setOpen] = useState(false);
  if (!evidence) return null;

  return (
    <div className="mt-3">
      <button
        onClick={() => setOpen(!open)}
        className="text-xs text-gray-500 hover:text-gray-700 flex items-center gap-1 cursor-pointer"
        aria-expanded={open}
        aria-label={open ? 'Slėpti techninę informaciją' : 'Rodyti techninę informaciją'}
      >
        <svg
          className={`w-3 h-3 transition-transform ${open ? 'rotate-90' : ''}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
        </svg>
        Techninė informacija
      </button>
      {open && (
        <pre className="mt-2 bg-gray-50 border border-gray-200 rounded-md p-3 text-xs text-gray-600 overflow-x-auto max-h-64 overflow-y-auto">
          {JSON.stringify(evidence, null, 2)}
        </pre>
      )}
    </div>
  );
}

function parseDescriptionSections(description: string): {
  what: string | null;
  why: string | null;
  impact: string | null;
  rest: string;
} {
  const whatMatch = description.match(/(?:KAS TAI[?:]?\s*)([\s\S]*?)(?=KODĖL TAI PAVOJINGA|VERSLO POVEIKIS|$)/i);
  const whyMatch = description.match(/(?:KODĖL TAI PAVOJINGA[?:]?\s*)([\s\S]*?)(?=VERSLO POVEIKIS|$)/i);
  const impactMatch = description.match(/(?:VERSLO POVEIKIS[?:]?\s*)([\s\S]*?)$/i);

  if (whatMatch || whyMatch || impactMatch) {
    return {
      what: whatMatch?.[1]?.trim() || null,
      why: whyMatch?.[1]?.trim() || null,
      impact: impactMatch?.[1]?.trim() || null,
      rest: '',
    };
  }

  return { what: null, why: null, impact: null, rest: description };
}

function RemediationPanel({
  findingId,
  currentStatus,
  currentNote,
  isAdmin,
}: {
  findingId: string;
  currentStatus: FindingStatusType;
  currentNote: string | null;
  isAdmin: boolean;
}) {
  const [status, setStatus] = useState(currentStatus);
  const [note, setNote] = useState(currentNote || '');
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);

  const handleSave = useCallback(async () => {
    setSaving(true);
    setMessage(null);
    try {
      const res = await fetch('/api/findings/status', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding_id: findingId, status, note: note.trim() || null }),
      });
      if (res.ok) {
        setMessage('Išsaugota');
        setTimeout(() => setMessage(null), 3000);
      } else {
        const data = await res.json().catch(() => ({}));
        setMessage(data.error || 'Klaida');
      }
    } catch {
      setMessage('Tinklo klaida');
    }
    setSaving(false);
  }, [findingId, status, note]);

  if (!isAdmin) {
    return (
      <div className="flex items-center gap-2">
        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${statusColors[currentStatus]}`}>
          {statusLabels[currentStatus]}
        </span>
        {currentNote && <span className="text-xs text-gray-500 truncate max-w-[200px]">{currentNote}</span>}
      </div>
    );
  }

  return (
    <div className="border-t border-gray-100 pt-3 mt-3">
      <button
        onClick={() => setExpanded(!expanded)}
        className="text-xs text-gray-500 hover:text-gray-700 flex items-center gap-1 cursor-pointer"
        aria-expanded={expanded}
      >
        <svg className={`w-3 h-3 transition-transform ${expanded ? 'rotate-90' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
        </svg>
        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${statusColors[status]}`}>
          {statusLabels[status]}
        </span>
        <span className="text-xs text-gray-400 ml-1">Pažeidimo šalinimas</span>
      </button>
      {expanded && (
        <div className="mt-2 space-y-2 pl-4">
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value as FindingStatusType)}
            className="block w-full max-w-xs px-2 py-1.5 border border-gray-300 rounded-md text-xs text-gray-900 focus:ring-blue-500 focus:border-blue-500"
          >
            <option value="open">Atviras</option>
            <option value="in_progress">Vykdomas</option>
            <option value="resolved">Išspręstas</option>
            <option value="accepted_risk">Priimta rizika</option>
            <option value="false_positive">Klaidingas teigiamas</option>
          </select>
          <textarea
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Pastaba (pvz., JIRA-123 priskirta tinklo komandai)"
            maxLength={1000}
            rows={2}
            className="block w-full px-2 py-1.5 border border-gray-300 rounded-md text-xs text-gray-900 placeholder-gray-400 focus:ring-blue-500 focus:border-blue-500"
          />
          <div className="flex items-center gap-2">
            <button
              onClick={handleSave}
              disabled={saving}
              className="px-3 py-1 bg-blue-600 text-white text-xs font-medium rounded-md hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {saving ? 'Saugoma...' : 'Išsaugoti'}
            </button>
            {message && (
              <span className={`text-xs ${message === 'Išsaugota' ? 'text-green-600' : 'text-red-600'}`}>
                {message}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function SlaIndicator({ severity, createdAt }: { severity: string; createdAt: string }) {
  const sla = calculateSla(severity as Finding['severity'], createdAt);
  if (!sla) return null;

  const text = formatSlaText(sla);
  const colorClass = sla.isOverdue
    ? 'text-red-600 bg-red-50'
    : sla.isExpiringSoon
    ? 'text-yellow-700 bg-yellow-50'
    : 'text-gray-500 bg-gray-50';

  return (
    <span
      className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs ${colorClass}`}
      title={`SLA: ${sla.deadlineDays} dienų terminas`}
      aria-label={`SLA terminas: ${text}`}
    >
      {text}
    </span>
  );
}

function FindingCard({
  finding,
  isAdmin,
  remediationStatus,
  remediationNote,
}: {
  finding: Finding;
  isAdmin: boolean;
  remediationStatus?: FindingStatusType;
  remediationNote?: string | null;
}) {
  const severity = finding.severity;
  const sections = parseDescriptionSections(finding.description_lt);
  const hasSections = sections.what || sections.why || sections.impact;
  const isPositive = severity === 'info';
  const effectiveStatus = remediationStatus || 'open';
  const isResolved = effectiveStatus === 'resolved' || effectiveStatus === 'false_positive';

  return (
    <div className={`bg-white border border-gray-200 border-l-4 ${severityBorderColors[severity]} rounded-lg shadow-sm overflow-hidden ${isResolved ? 'opacity-60' : ''}`}>
      {/* Header bar */}
      <div className="px-5 py-3 bg-gray-50 border-b border-gray-100 flex items-center gap-2 flex-wrap">
        <span
          className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold ${severityBadgeColors[severity]}`}
          aria-label={`Sunkumo lygis: ${severityLabels[severity]}`}
        >
          <span className="mr-1" aria-hidden="true">{severityIcons[severity]}</span>
          {severityLabels[severity]}
        </span>
        <span className="text-xs font-medium text-gray-500 px-2 py-0.5 bg-white rounded border border-gray-200">
          {moduleLabels[finding.module] || finding.module}
        </span>
        {finding.nis2_article && (
          <span className="text-xs font-medium text-purple-700 px-2 py-0.5 bg-purple-50 rounded border border-purple-200">
            KSĮ {finding.nis2_article}
          </span>
        )}
        {/* SLA indicator for non-info, non-resolved findings */}
        {severity !== 'info' && !isResolved && (
          <SlaIndicator severity={severity} createdAt={finding.created_at} />
        )}
      </div>

      {/* Body */}
      <div className="px-5 py-4 space-y-4">
        {/* Title */}
        <h3 className={`font-semibold text-gray-900 text-base leading-tight ${isResolved ? 'line-through' : ''}`}>
          {finding.title_lt}
        </h3>

        {/* Structured sections */}
        {hasSections ? (
          <>
            {sections.what && (
              <div>
                <div className="flex items-center gap-1.5 mb-1">
                  <span className="text-sm">📋</span>
                  <span className="text-xs font-bold text-gray-700 uppercase tracking-wide">Kas tai?</span>
                </div>
                <p className="text-sm text-gray-700 leading-relaxed pl-5">{sections.what}</p>
              </div>
            )}
            {sections.why && (
              <div>
                <div className="flex items-center gap-1.5 mb-1">
                  <span className="text-sm">⚠️</span>
                  <span className="text-xs font-bold text-gray-700 uppercase tracking-wide">Kodėl tai pavojinga?</span>
                </div>
                <p className="text-sm text-gray-700 leading-relaxed pl-5">{sections.why}</p>
              </div>
            )}
            {sections.impact && (
              <div>
                <div className="flex items-center gap-1.5 mb-1">
                  <span className="text-sm">💼</span>
                  <span className="text-xs font-bold text-gray-700 uppercase tracking-wide">Verslo poveikis</span>
                </div>
                <p className="text-sm text-gray-700 leading-relaxed pl-5">{sections.impact}</p>
              </div>
            )}
          </>
        ) : (
          <div>
            <div className="flex items-center gap-1.5 mb-1">
              <span className="text-sm">{isPositive ? '✅' : '📋'}</span>
              <span className="text-xs font-bold text-gray-700 uppercase tracking-wide">
                {isPositive ? 'Aprašymas' : 'Kas tai?'}
              </span>
            </div>
            <p className="text-sm text-gray-700 leading-relaxed pl-5 whitespace-pre-line">{finding.description_lt}</p>
          </div>
        )}

        {/* Recommendations */}
        <div className="pt-2 border-t border-gray-100">
          <div className="flex items-center gap-1.5 mb-1">
            <span className="text-sm">✅</span>
            <span className="text-xs font-bold text-gray-700 uppercase tracking-wide">Rekomenduojami veiksmai</span>
          </div>
          <p className="text-sm text-gray-700 leading-relaxed pl-5 whitespace-pre-line">{finding.recommendation_lt}</p>
        </div>

        {/* Collapsible evidence */}
        <EvidenceBlock evidence={finding.evidence as Record<string, unknown> | null} />

        {/* Remediation tracking panel */}
        {severity !== 'info' && (
          <RemediationPanel
            findingId={finding.id}
            currentStatus={effectiveStatus}
            currentNote={remediationNote || null}
            isAdmin={isAdmin}
          />
        )}
      </div>
    </div>
  );
}

export function FindingsList({ findings, findingStatuses, isAdmin, scanId }: FindingsListProps) {
  if (findings.length === 0) {
    return (
      <div className="bg-white rounded-lg shadow-md p-8 text-center">
        <p className="text-gray-500">Nustatytų trūkumų nėra. Pradėkite skenavimą, kad patikrintumėte savo domeną.</p>
      </div>
    );
  }

  // Group by severity
  const grouped = severityOrder.reduce((acc, severity) => {
    const items = findings.filter((f) => f.severity === severity);
    if (items.length > 0) {
      acc[severity] = items;
    }
    return acc;
  }, {} as Record<string, Finding[]>);

  // Remediation progress stats
  const nonInfoFindings = findings.filter((f) => f.severity !== 'info');
  const addressedCount = nonInfoFindings.filter((f) => {
    const s = findingStatuses?.[f.id]?.status;
    return s === 'resolved' || s === 'accepted_risk' || s === 'false_positive';
  }).length;
  const progressPercent = nonInfoFindings.length > 0
    ? Math.round((addressedCount / nonInfoFindings.length) * 100)
    : 0;

  return (
    <div className="space-y-6">
      {/* Export + remediation progress bar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        {nonInfoFindings.length > 0 && findingStatuses && (
          <div className="flex items-center gap-3 flex-1">
            <span className="text-sm text-gray-600">
              Pažeidimai šalinami: {addressedCount}/{nonInfoFindings.length}
            </span>
            <div className="flex-1 max-w-xs bg-gray-200 rounded-full h-2.5">
              <div
                className={`h-2.5 rounded-full transition-all ${
                  progressPercent === 100 ? 'bg-green-500' :
                  progressPercent >= 50 ? 'bg-blue-500' : 'bg-yellow-500'
                }`}
                style={{ width: `${progressPercent}%` }}
              />
            </div>
            <span className="text-xs font-semibold text-gray-500">{progressPercent}%</span>
          </div>
        )}
        {scanId && (
          <div className="flex items-center gap-2">
            <a
              href={`/api/findings/export?scan_id=${scanId}&format=csv`}
              className="inline-flex items-center px-3 py-1.5 border border-gray-300 text-xs font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 transition-colors"
              download
            >
              CSV
            </a>
            <a
              href={`/api/findings/export?scan_id=${scanId}&format=json`}
              className="inline-flex items-center px-3 py-1.5 border border-gray-300 text-xs font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 transition-colors"
              download
            >
              JSON
            </a>
          </div>
        )}
      </div>

      {/* Findings grouped by severity */}
      {Object.entries(grouped).map(([severity, items]) => (
        <div key={severity}>
          <div className="flex items-center space-x-2 mb-4">
            <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold ${severityBadgeColors[severity]}`}>
              <span className="mr-1" aria-hidden="true">{severityIcons[severity]}</span>
              {severityLabels[severity]}
            </span>
            <span className="text-sm text-gray-500 font-medium">
              {items.length} {items.length === 1 ? 'trūkumas' : 'trūkumai'}
            </span>
          </div>

          <div className="space-y-4">
            {items.map((finding) => (
              <FindingCard
                key={finding.id}
                finding={finding}
                isAdmin={isAdmin ?? false}
                remediationStatus={findingStatuses?.[finding.id]?.status}
                remediationNote={findingStatuses?.[finding.id]?.note}
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
