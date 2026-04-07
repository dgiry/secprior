import puppeteer from 'puppeteer';
import { mkdirSync } from 'fs';

const BASE = 'http://localhost:3001/index.html';
const OUT  = new URL('../screenshots/', import.meta.url).pathname;
mkdirSync(OUT, { recursive: true });

const browser = await puppeteer.launch({
  headless: true,
  args: ['--no-sandbox', '--disable-gpu']
});
const page = await browser.newPage();
await page.setViewport({ width: 1280, height: 800 });

async function shot(filename, setup) {
  await page.goto(BASE, { waitUntil: 'networkidle0', timeout: 20000 });
  // Wait for articles to load
  await new Promise(r => setTimeout(r, 3000));
  // Dismiss persona modal and OSS bar
  await page.evaluate(() => {
    // Hide modals
    ['modal-persona','modal-settings','modal-how-it-works'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = 'none';
    });
    const o = document.getElementById('oss-bar');
    if (o) o.style.display = 'none';
    // Click skip link if visible
    const skip = Array.from(document.querySelectorAll('a,button')).find(e => e.textContent.includes('Skip') || e.textContent.includes('explore freely'));
    if (skip) skip.click();
    // Mark persona as chosen in sessionStorage
    try { sessionStorage.setItem('cv_persona_chosen','1'); } catch{}
  });
  await new Promise(r => setTimeout(r, 800));
  // Hide ALL modals and overlays aggressively
  await page.evaluate(() => {
    document.querySelectorAll('[id^="modal-"], .modal, .overlay, .backdrop, [role="dialog"]').forEach(el => {
      el.style.display = 'none';
      el.style.visibility = 'hidden';
    });
    // Also click any "Got it" or "Close" buttons
    const closeBtn = Array.from(document.querySelectorAll('button')).find(b =>
      /got it|close|skip|dismiss|ok$/i.test(b.textContent.trim())
    );
    if (closeBtn) closeBtn.click();
  });
  await new Promise(r => setTimeout(r, 300));
  if (setup) await setup(page);
  await new Promise(r => setTimeout(r, 600));
  await page.screenshot({ path: OUT + filename, clip: { x:0, y:0, width:1280, height:800 } });
  console.log('✓', filename);
}

// 1 — Dashboard: Top Priorities with cards
await shot('01-dashboard.png', async (p) => {
  await p.evaluate(() => {
    document.getElementById('btn-top-priorities')?.click();
    window.scrollTo(0, 250);
  });
});

// 2 — Incidents
await shot('02-incidents.png', async (p) => {
  await p.evaluate(() => {
    document.getElementById('btn-incidents')?.click();
    window.scrollTo(0, 240);
  });
});

// 3 — CVEs
await shot('03-cves.png', async (p) => {
  await p.evaluate(() => {
    document.getElementById('btn-cve')?.click();
    window.scrollTo(0, 240);
  });
});

// 4 — Visibility
await shot('04-visibility.png', async (p) => {
  await p.evaluate(() => {
    document.getElementById('btn-analytics-menu')?.click();
  });
  await new Promise(r => setTimeout(r, 300));
  await p.evaluate(() => {
    document.getElementById('btn-visibility')?.click();
    // Force panel visible
    const vp = document.getElementById('visibility-panel');
    if (vp) { vp.style.display = 'block'; vp.scrollIntoView(); }
    // Hide others
    ['cve-panel','stats-panel','briefing-panel','incidents-panel'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = 'none';
    });
    window.scrollTo(0, 240);
  });
});

// 5 — Morning Brief modal
await shot('05-briefing.png', async (p) => {
  await p.evaluate(() => {
    document.getElementById('btn-morning-brief')?.click();
  });
  await new Promise(r => setTimeout(r, 400));
  await p.evaluate(() => window.scrollTo(0, 0));
});

await browser.close();
console.log('\nAll screenshots saved to', OUT);
