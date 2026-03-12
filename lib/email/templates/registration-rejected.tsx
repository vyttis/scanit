interface RegistrationRejectedProps {
  firstName: string;
  lastName: string;
}

export function registrationRejectedHtml({ firstName, lastName }: RegistrationRejectedProps): string {
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
        Deja, Jūsų registracijos prašymas platformoje <strong>scanit.lt</strong> buvo atmestas.
      </p>

      <p style="font-size:14px;color:#374151;line-height:1.6;margin:0 0 24px;">
        Jei manote, kad tai klaida, arba turite klausimų, kreipkitės el. paštu
        <a href="mailto:info@scanit.lt" style="color:#2563eb;">info@scanit.lt</a>.
      </p>

      <hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0 16px;">
      <p style="font-size:12px;color:#9ca3af;line-height:1.5;margin:0;">
        Ši žinutė išsiųsta automatiškai platformos scanit.lt. Jei negavote šios žinutės tyčia — ignoruokite ją.
      </p>
    </div>
  </div>
</body>
</html>`;
}
