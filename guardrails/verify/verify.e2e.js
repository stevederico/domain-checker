import { after, afterEach, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { REPO, SCREENSHOTS } from './paths.js';
import { BACKEND_BOOT_TIMEOUT_MS, FRONTEND_URL, assertPortsFree, resetArtifacts, startServers, stopServers } from './servers.js';
import { ab, click, drainProblems, expectNoText, expectText, expectUrl, fill, findRole, labelledByText, writeBrowserConfig } from './browser.js';

const constants = JSON.parse(readFileSync(path.join(REPO, 'src/constants.json'), 'utf8'));
const PAGE_TITLES = constants.pages.map((item) => item.title);
const HOME_TITLE = PAGE_TITLES[0];

const TLDS = ['com', 'net', 'org', 'io', 'dev', 'app', 'co', 'xyz', 'ai', 'shop', 'site', 'tech'];
const FREE_NAME = `zqv${Date.now().toString(36)}x`;
const VIEWPORT = ['1280', '720'];
const SETUP_TIMEOUT_MS = BACKEND_BOOT_TIMEOUT_MS + 120_000;
const FLOW_TIMEOUT_MS = 90_000;

const ALLOWED_FAILED_REQUESTS = [
  { status: 404, url: /\/api\/signup\/options$/ },
];

const MAIN = { role: 'main' };
const button = (name) => ({ role: 'button', name });
const heading = (name, level) => ({ role: 'heading', name, level });

let servers = [];
let hasFailed = false;
const problems = [];

const goto = (route) => ab('open', `${FRONTEND_URL}${route}`);

const shot = (name) => ab('screenshot', '--full', path.join(SCREENSHOTS, `${name}.png`));

function flow(name, body) {
  it(name, { timeout: FLOW_TIMEOUT_MS }, async (t) => {
    if (hasFailed) return t.skip('an earlier flow failed; the flows share one browser session');
    try {
      await body();
    } catch (error) {
      hasFailed = true;
      throw error;
    }
  });
}

describe('runtime verify', () => {
  before(async () => {
    await assertPortsFree();
    resetArtifacts();
    writeBrowserConfig();
    servers = await startServers();
    await ab('open');
    await ab('set', 'viewport', ...VIEWPORT);
    await ab('set', 'media', 'light', 'reduced-motion');
  }, { timeout: SETUP_TIMEOUT_MS });

  afterEach(async () => {
    problems.push(...(await drainProblems(ALLOWED_FAILED_REQUESTS)));
  });

  after(async () => {
    try {
      await ab('close');
    } catch (error) {
      console.error(`agent-browser close failed: ${error.message}`);
    }
    stopServers(servers);
  });

  flow('landing route opens the checker with an empty state', async () => {
    await goto('/');
    await expectUrl(/\/app\/home$/);
    await findRole(heading('Find your domain', 1), { within: MAIN });
    await findRole({ role: 'textbox', name: 'Domain name' }, { within: MAIN });
    await expectText('Type a name to check availability across 12 TLDs', { within: MAIN });
    for (const title of [...PAGE_TITLES, 'Settings']) await findRole(button(title));
    await shot('01-home-empty');
  });

  flow('checking a taken name lists every TLD and counts the taken ones', async () => {
    await fill({ role: 'textbox', name: 'Domain name' }, 'google', { within: MAIN });
    await expectText(/^ taken$/, { within: MAIN });
    for (const tld of TLDS) await expectText(`google.${tld}`, { within: MAIN, exact: true });
    await shot('02-results-taken');
  });

  flow('an available name is a button that copies the domain', async () => {
    await goto('/app/home');
    await fill({ role: 'textbox', name: 'Domain name' }, FREE_NAME, { within: MAIN });
    await expectText(/^ available$/, { within: MAIN });
    await click(button(`${FREE_NAME}.com`), { within: MAIN });
    await expectText(/^(Copied|Failed to copy)/);
    await shot('03-results-available');
  });

  flow('command menu opens with Ctrl+K and navigates', async () => {
    await click(button('Settings'));
    await expectUrl(/\/app\/settings$/);
    await ab('press', 'Control+k');
    const menu = { role: 'dialog' };
    await findRole({ role: 'combobox' }, { within: menu });
    assert.equal(await labelledByText(menu), 'Command Menu');
    await shot('04-command-menu');
    await click({ role: 'option', name: HOME_TITLE }, { within: menu });
    await expectUrl(/\/app\/home$/);
    await findRole(heading('Find your domain', 1), { within: MAIN });
  });

  flow('settings shows support and the version without a sign-in', async () => {
    await click(button('Settings'));
    await expectUrl(/\/app\/settings$/);
    await findRole(heading('Settings', 1), { within: MAIN });
    await findRole(button('Contact'), { within: MAIN });
    await expectText(/^v\d+\.\d+\.\d+$/, { within: MAIN });
    await shot('05-settings');
  });

  flow('legal pages render with the company name filled in', async () => {
    await goto('/terms');
    await expectText(`Welcome to the ${constants.companyName} Application.`);
    await expectNoText(/_COMPANY_|_WEBSITE_|_EMAIL_/);
    await shot('06-terms');
    for (const route of ['/privacy', '/eula']) {
      await goto(route);
      await expectText(constants.companyName);
      await expectNoText(/_COMPANY_|_WEBSITE_|_EMAIL_/);
    }
    await shot('07-eula');
  });

  flow('unknown route shows the 404 page', async () => {
    await goto('/this-route-does-not-exist');
    await expectText('404', { exact: true });
    await expectText('Page not found.');
    await shot('08-not-found');
  });

  it('no uncaught exceptions, console errors or unexpected failed requests during the flows', () => {
    assert.deepEqual(problems, []);
  });
});
