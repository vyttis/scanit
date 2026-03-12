interface ScanCompletedProps {
  firstName: string;
  organizationName: string;
  domain: string;
  scanDate: string;
  riskScore: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

export function scanCompletedHtml({ firstName, organizationName, domain, scanDate, riskScore, criticalCount, highCount, mediumCount, lowCount }: ScanCompletedProps): string {
  const appUrl = process.env.NEXT_PUBLIC_APP_URL || 'https://platform.scanit.lt';

  const riskColor = riskScore >= 70 ? '#dc2626' : riskScore >= 40 ? '#f59e0b' : '#16a34a';
  const riskLabel = riskScore >= 70 ? 'Aukšta rizika' : riskScore >= 40 ? 'Vidutinė rizika' : 'Žema rizika';

  return `<!DOCTYPE html>
<html lang="lt">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#f9fafb;font-family:Arial,sans-serif;">
  <div style="max-width:600px;margin:0 auto;padding:40px 20px;">
    <div style="background-color:#ffffff;border-radius:8px;padding:40px;box-shadow:0 1px 3px rgba(0,0,0,0.1);">
      <h1 style="font-size:24px;color:#111827;margin:0 0 8px;">scanit.lt</h1>
      <hr style="border:none;border-top:1px solid #e5e7eb;margin:16px 0 24px;">

      <p style="font-size:16px;color:#111827;margin:0 0 16px;">
        Gerb. ${firstName},
      </p>

      <p style="font-size:14px;color:#374151;line-height:1.6;margin:0 0 16px;">
        Organizacijos <strong>${organizationName}</strong> (${domain}) skenavimas baigtas.
      </p>

      <div style="background-color:#f9fafb;border-radius:8px;padding:20px;margin:0 0 24px;">
        <div style="text-align:center;margin:0 0 16px;">
          <span style="font-size:36px;font-weight:700;color:${riskColor};">${riskScore}</span>
          <span style="font-size:14px;color:${riskColor};display:block;">${riskLabel}</span>
        </div>
        <table style="width:100%;border-collapse:collapse;">
          <tr>
            <td style="padding:4px 8px;font-size:13px;color:#dc2626;text-align:center;"><strong>${criticalCount}</strong> Kritinių</td>
            <td style="padding:4px 8px;font-size:13px;color:#f59e0b;text-align:center;"><strong>${highCount}</strong> Aukštų</td>
            <td style="padding:4px 8px;font-size:13px;color:#eab308;text-align:center;"><strong>${mediumCount}</strong> Vidutinių</td>
            <td style="padding:4px 8px;font-size:13px;color:#16a34a;text-align:center;"><strong>${lowCount}</strong> Žemų</td>
          </tr>
        </table>
      </div>

      <p style="font-size:14px;color:#374151;line-height:1.6;margin:0 0 16px;">
        Skenavimo data: ${scanDate}
      </p>

      <a href="${appUrl}/reports" style="display:inline-block;background-color:#2563eb;color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;font-size:14px;font-weight:500;">
        Peržiūrėti ataskaitą
      </a>

      <hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0 16px;">
      <p style="font-size:12px;color:#9ca3af;line-height:1.5;margin:0;">
        Ši žinutė išsiųsta automatiškai platformos scanit.lt. Jei negavote šios žinutės tyčia — ignoruokite ją.
      </p>
    </div>
  </div>
</body>
</html>`;
}
