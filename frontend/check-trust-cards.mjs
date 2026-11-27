import { chromium } from 'playwright';

(async () => {
  const browser = await chromium.launch({ headless: true });
  
  // Desktop
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  await page.goto('http://host.docker.internal:8090/', { waitUntil: 'networkidle' });
  const el = await page.$('.trust-grid');
  if (el) {
    await el.screenshot({ path: '/tmp/trust_cards_desktop.png' });
    console.log('Desktop trust cards captured!');
  }
  
  // Mobile
  const pageMobile = await browser.newPage({ viewport: { width: 390, height: 844 } });
  await pageMobile.goto('http://host.docker.internal:8090/', { waitUntil: 'networkidle' });
  const elMob = await pageMobile.$('.trust-grid');
  if (elMob) {
    await elMob.screenshot({ path: '/tmp/trust_cards_mobile.png' });
    console.log('Mobile trust cards captured!');
  }

  // Also full section screenshot
  const sec = await page.$('#technology');
  if (sec) {
    await sec.screenshot({ path: '/tmp/technology_section_desktop.png' });
    console.log('Section captured!');
  }
  
  await browser.close();
})();
