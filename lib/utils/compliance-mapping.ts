import type { Finding, FindingSeverity, ScanModule } from '@/types/database';

/**
 * KSĮ article mapping — which scanner modules and finding types
 * relate to which legal article.
 */

export interface KsiArticle {
  id: string;           // e.g., "11(2)(1)"
  title: string;        // Lithuanian title
  requirement: string;  // Short requirement description
  citation: string;     // Legal citation text
  modules: ScanModule[];
}

export const KSI_ARTICLES: KsiArticle[] = [
  {
    id: '11 str. 2 d. 1 p.',
    title: 'Rizikų valdymas',
    requirement: 'Rizikos valdymo politikos',
    citation: '„rizikos valdymo politikos"',
    modules: ['securitytrails'],
  },
  {
    id: '11 str. 2 d. 2 p.',
    title: 'Incidentų valdymas',
    requirement: 'Incidentų valdymo procedūros',
    citation: '„incidentų valdymo procedūros"',
    modules: ['virustotal', 'urlscan'],
  },
  {
    id: '11 str. 2 d. 5 p.',
    title: 'Tinklų saugumas',
    requirement: 'Tinklų ir informacinių sistemų saugumo priemonės',
    citation: '„tinklų ir informacinių sistemų saugumo priemonės"',
    modules: ['shodan', 'ssl', 'abuseipdb'],
  },
  {
    id: '11 str. 2 d. 9 p.',
    title: 'Prieigos kontrolė ir MFA',
    requirement: 'Prieigos kontrolės ir tapatybės valdymo priemonės',
    citation: '„prieigos kontrolės ir tapatybės valdymo priemonės, įskaitant kelių veiksnių autentifikavimą"',
    modules: ['hibp', 'mxtoolbox'],
  },
];

export type ComplianceStatus = 'pass' | 'partial' | 'fail' | 'not_checked';

export interface ArticleComplianceResult {
  article: KsiArticle;
  status: ComplianceStatus;
  findingCount: number;
  worstSeverity: FindingSeverity | null;
  findings: Finding[];
}

/**
 * Evaluate compliance status for each KSĮ article based on findings.
 */
export function evaluateCompliance(findings: Finding[]): ArticleComplianceResult[] {
  return KSI_ARTICLES.map((article) => {
    const articleFindings = findings.filter((f) =>
      article.modules.includes(f.module) && f.severity !== 'info'
    );

    let status: ComplianceStatus;
    let worstSeverity: FindingSeverity | null = null;

    if (articleFindings.length === 0) {
      // Check if any module was actually run (info findings indicate module ran)
      const hasModuleData = findings.some((f) => article.modules.includes(f.module));
      status = hasModuleData ? 'pass' : 'not_checked';
    } else {
      const hasCritical = articleFindings.some((f) => f.severity === 'critical');
      const hasHigh = articleFindings.some((f) => f.severity === 'high');

      if (hasCritical) {
        status = 'fail';
        worstSeverity = 'critical';
      } else if (hasHigh) {
        status = 'fail';
        worstSeverity = 'high';
      } else {
        status = 'partial';
        worstSeverity = articleFindings.some((f) => f.severity === 'medium') ? 'medium' : 'low';
      }
    }

    return {
      article,
      status,
      findingCount: articleFindings.length,
      worstSeverity,
      findings: articleFindings,
    };
  });
}

/**
 * Calculate overall compliance percentage.
 * pass=100%, partial=50%, fail=0%, not_checked=excluded
 */
export function calculateCompliancePercentage(results: ArticleComplianceResult[]): number {
  const checked = results.filter((r) => r.status !== 'not_checked');
  if (checked.length === 0) return 0;

  const score = checked.reduce((sum, r) => {
    if (r.status === 'pass') return sum + 100;
    if (r.status === 'partial') return sum + 50;
    return sum;
  }, 0);

  return Math.round(score / checked.length);
}
