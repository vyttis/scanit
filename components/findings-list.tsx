'use client';

import { useState } from 'react';
import type { Finding } from '@/types/database';

interface FindingsListProps {
  findings: Finding[];
}

const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];

const severityLabels: Record<string, string> = {
  critical: 'Kritinis',
  high: 'Aukštas',
  medium: 'Vidutinis',
  low: 'Žemas',
  info: 'Informacinis',
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

/**
 * Split description_lt into structured sections if they exist.
 * Looks for patterns like "KAS TAI:", "KODĖL TAI PAVOJINGA:", "VERSLO POVEIKIS:"
 */
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

function FindingCard({ finding }: { finding: Finding }) {
  const severity = finding.severity;
  const sections = parseDescriptionSections(finding.description_lt);
  const hasSections = sections.what || sections.why || sections.impact;
  const isPositive = severity === 'info';

  return (
    <div className={`bg-white border border-gray-200 border-l-4 ${severityBorderColors[severity]} rounded-lg shadow-sm overflow-hidden`}>
      {/* Header bar */}
      <div className="px-5 py-3 bg-gray-50 border-b border-gray-100 flex items-center gap-2 flex-wrap">
        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold ${severityBadgeColors[severity]}`}>
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
      </div>

      {/* Body */}
      <div className="px-5 py-4 space-y-4">
        {/* Title */}
        <h3 className="font-semibold text-gray-900 text-base leading-tight">{finding.title_lt}</h3>

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
      </div>
    </div>
  );
}

export function FindingsList({ findings }: FindingsListProps) {
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

  return (
    <div className="space-y-8">
      {Object.entries(grouped).map(([severity, items]) => (
        <div key={severity}>
          <div className="flex items-center space-x-2 mb-4">
            <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold ${severityBadgeColors[severity]}`}>
              {severityLabels[severity]}
            </span>
            <span className="text-sm text-gray-500 font-medium">
              {items.length} {items.length === 1 ? 'trūkumas' : 'trūkumai'}
            </span>
          </div>

          <div className="space-y-4">
            {items.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
