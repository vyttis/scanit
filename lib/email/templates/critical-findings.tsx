interface CriticalFindingsProps {
  firstName: string;
  organizationName: string;
  domain: string;
  criticalCount: number;
  findings: Array<{ title: string; module: string }>;
}

export function criticalFindingsHtml({ firstName, organizationName, domain, criticalCount, findings }: CriticalFindingsProps): string {
  const appUrl = process.env.NEXT_PUBLIC_APP_URL || 'https://platform.scanit.lt';

  const findingsList = findings
    .map(f => `<tr><td style="padding:8px 12px;font-size:14px;color:#111827;border-bottom:1px solid #fee2e2;">${f.title}</td><td style="padding:8px 12px;font-size:14px;color:#6b7280;border-bottom:1px solid #fee2e2;">${f.module}</td></tr>`)
    .join('');

  return `<!DOCTYPE html>
<html lang="lt">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#f9fafb;font-family:Arial,sans-serif;">
  <div style="max-width:600px;margin:0 auto;padding:40px 20px;">
    <div style="background-color:#ffffff;border-radius:8px;padding:40px;box-shadow:0 1px 3px rgba(0,0,0,0.1);border-top:4px solid #dc2626;">
      <h1 style="font-size:24px;color:#111827;margin:0 0 8px;">scanit.lt</h1>
      <hr style="border:none;border-top:1px solid #e5e7eb;margin:16px 0 24px;">

      <div style="background-color:#fef2f2;border-radius:6px;padding:12px 16px;margin:0 0 20px;">
        <p style="font-size:14px;color:#991b1b;margin:0;font-weight:600;">
          Rasta ${criticalCount} kritinių pažeidžiamumų
        </p>
      </div>

      <p style="font-size:16px;color:#111827;margin:0 0 16px;">
        Gerb. ${firstName},
      </p>

      <p style="font-size:14px;color:#374151;line-height:1.6;margin:0 0 16px;">
        Organizacijos <strong>${organizationName}</strong> (${domain}) skenavimo metu nustatyti kritinio lygio pažeidžiamumai,
        reikalaujantys skubaus dėmesio.
      </p>

      <table style="width:100%;border-collapse:collapse;margin:0 0 24px;">
        <tr style="background-color:#fef2f2;">
          <th style="padding:10px 12px;font-size:13px;color:#991b1b;text-align:left;font-weight:600;">Pažeidžiamumas</th>
          <th style="padding:10px 12px;font-size:13px;color:#991b1b;text-align:left;font-weight:600;">Modulis</th>
        </tr>
        ${findingsList}
      </table>

      <a href="${appUrl}/reports" style="display:inline-block;background-color:#dc2626;color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;font-size:14px;font-weight:500;">
        Peržiūrėti išsamią ataskaitą
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
