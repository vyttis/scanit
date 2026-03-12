interface ScanStartedProps {
  firstName: string;
  organizationName: string;
  domain: string;
  scanDate: string;
}

export function scanStartedHtml({ firstName, organizationName, domain, scanDate }: ScanStartedProps): string {
  const appUrl = process.env.NEXT_PUBLIC_APP_URL || 'https://platform.scanit.lt';

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
        Pradėtas organizacijos <strong>${organizationName}</strong> pažeidžiamumų skenavimas.
      </p>

      <table style="width:100%;border-collapse:collapse;margin:0 0 24px;">
        <tr><td style="padding:8px 0;font-size:14px;color:#6b7280;width:140px;">Domenas:</td><td style="padding:8px 0;font-size:14px;color:#111827;">${domain}</td></tr>
        <tr><td style="padding:8px 0;font-size:14px;color:#6b7280;">Pradžios laikas:</td><td style="padding:8px 0;font-size:14px;color:#111827;">${scanDate}</td></tr>
      </table>

      <p style="font-size:14px;color:#374151;line-height:1.6;margin:0 0 16px;">
        Skenavimas gali užtrukti iki 15 minučių. Kai bus baigta, gausite pranešimą su rezultatais.
      </p>

      <a href="${appUrl}/scans" style="display:inline-block;background-color:#2563eb;color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;font-size:14px;font-weight:500;">
        Stebėti skenavimo eigą
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
