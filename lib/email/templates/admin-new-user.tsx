interface AdminNewUserProps {
  firstName: string;
  lastName: string;
  email: string;
  organizationName: string;
  organizationWebsite: string;
  registeredAt: string;
}

export function adminNewUserHtml({ firstName, lastName, email, organizationName, organizationWebsite, registeredAt }: AdminNewUserProps): string {
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
        Naujas vartotojas laukia patvirtinimo
      </p>

      <table style="width:100%;border-collapse:collapse;margin:0 0 24px;">
        <tr><td style="padding:8px 0;font-size:14px;color:#6b7280;width:140px;">Vardas, pavardė:</td><td style="padding:8px 0;font-size:14px;color:#111827;">${firstName} ${lastName}</td></tr>
        <tr><td style="padding:8px 0;font-size:14px;color:#6b7280;">El. paštas:</td><td style="padding:8px 0;font-size:14px;color:#111827;">${email}</td></tr>
        <tr><td style="padding:8px 0;font-size:14px;color:#6b7280;">Organizacija:</td><td style="padding:8px 0;font-size:14px;color:#111827;">${organizationName}</td></tr>
        <tr><td style="padding:8px 0;font-size:14px;color:#6b7280;">Svetainė:</td><td style="padding:8px 0;font-size:14px;color:#111827;">${organizationWebsite}</td></tr>
        <tr><td style="padding:8px 0;font-size:14px;color:#6b7280;">Registracijos data:</td><td style="padding:8px 0;font-size:14px;color:#111827;">${registeredAt}</td></tr>
      </table>

      <a href="${appUrl}/admin/vartotojai" style="display:inline-block;background-color:#2563eb;color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;font-size:14px;font-weight:500;">
        Peržiūrėti ir patvirtinti
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
