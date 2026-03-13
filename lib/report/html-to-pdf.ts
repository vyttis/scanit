import chromium from '@sparticuz/chromium';
import puppeteerCore from 'puppeteer-core';

/**
 * Convert an HTML string to a PDF buffer using headless Chromium.
 * Uses @sparticuz/chromium for Vercel/Lambda compatibility.
 */
export async function htmlToPdf(html: string): Promise<Buffer> {
  const browser = await puppeteerCore.launch({
    args: chromium.args,
    defaultViewport: { width: 1280, height: 720 },
    executablePath: await chromium.executablePath(),
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
