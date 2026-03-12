interface RegistrationApprovedProps {
  firstName: string;
  lastName: string;
}

export function registrationApprovedHtml({ firstName, lastName }: RegistrationApprovedProps): string {
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
        Gerb. ${firstName} ${lastName},
      </p>

      <p style="font-size:14px;color:#374151;line-height:1.6;margin:0 0 16px;">
        Jūsų paskyra platformoje <strong>scanit.lt</strong> buvo patvirtinta.
        Dabar galite prisijungti ir pradėti naudotis platforma.
      </p>

      <a href="${appUrl}/login" style="display:inline-block;background-color:#2563eb;color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;font-size:14px;font-weight:500;">
        Prisijungti prie platformos
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
