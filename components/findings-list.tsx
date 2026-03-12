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

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-blue-100 text-blue-800 border-blue-200',
  info: 'bg-gray-100 text-gray-800 border-gray-200',
};

const severityBadgeColors: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-white',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-400 text-white',
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
    <div className="space-y-6">
      {Object.entries(grouped).map(([severity, items]) => (
        <div key={severity}>
          <div className="flex items-center space-x-2 mb-3">
            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${severityBadgeColors[severity]}`}>
              {severityLabels[severity]}
            </span>
            <span className="text-sm text-gray-500">
              {items.length} {items.length === 1 ? 'trūkumas' : 'trūkumai'}
            </span>
          </div>

          <div className="space-y-3">
            {items.map((finding) => (
              <div
                key={finding.id}
                className={`border rounded-lg p-4 ${severityColors[severity]}`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-1">
                      <span className="text-xs font-medium px-2 py-0.5 bg-white/50 rounded">
                        {moduleLabels[finding.module] || finding.module}
                      </span>
                      {finding.nis2_article && (
                        <span className="text-xs px-2 py-0.5 bg-white/50 rounded">
                          KSĮ {finding.nis2_article}
                        </span>
                      )}
                    </div>
                    <h3 className="font-medium text-sm mb-2">{finding.title_lt}</h3>
                    <p className="text-sm opacity-90 mb-2">{finding.description_lt}</p>
                    <div className="mt-2 pt-2 border-t border-current/10">
                      <p className="text-xs font-medium">Rekomenduojami veiksmai:</p>
                      <p className="text-xs opacity-80 mt-1">{finding.recommendation_lt}</p>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
