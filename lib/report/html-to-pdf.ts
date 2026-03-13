import chromium from '@sparticuz/chromium-min';
import puppeteerCore from 'puppeteer-core';

// Remote Chromium binary for Vercel serverless (not bundled locally)
const CHROMIUM_PACK_URL =
  'https://github.com/Sparticuz/chromium/releases/download/v131.0.1/chromium-v131.0.1-pack.tar';

/**
 * Convert an HTML string to a PDF buffer using headless Chromium.
 * Uses @sparticuz/chromium-min with remote binary for Vercel compatibility.
 */
export async function htmlToPdf(html: string): Promise<Buffer> {
  const browser = await puppeteerCore.launch({
    args: chromium.args,
    executablePath: await chromium.executablePath(CHROMIUM_PACK_URL),
    headless: true,
  });

  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });
    const pdfBuffer = await page.pdf({
      format: 'A4',
      margin: { top: '24mm', right: '16mm', bottom: '24mm', left: '16mm' },
      printBackground: true,
    });
    return Buffer.from(pdfBuffer);
  } finally {
    await browser.close();
  }
}
