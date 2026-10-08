// "Is there a newer connector?" An installed connector never updates itself (replacing code from a download without the
// user knowing is not something it does), but it can notice, and say so where the AI reads it: account_info, the playbook
// tool and --doctor. One small file on kapaweb.gr is read at most once a day; nothing about the user is sent (only the
// User-Agent "kapaweb-connector/<version>"), and any failure is silent. KAPAWEB_CONNECTOR_NO_UPDATE_CHECK=1 turns it off.
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { configDir } from './store.js';
import { VERSION } from './util.js';

export const VERSION_URL = 'https://kapaweb.gr/downloads/kapaweb-connector.version.json';
export const DOWNLOAD_URL = 'https://kapaweb.gr/downloads/kapaweb-connector.mcpb';
export const SETUP_PROMPT_URL = 'https://kapaweb.gr/deploy-with-ai/prompt.md';
const FRESH_MS = 24 * 3600 * 1000; // a good answer is reused for a day
const RETRY_MS = 3600 * 1000; // after a failed attempt, try again in an hour

const SEMVER = /^\d+\.\d+\.\d+$/;

/** true when `latest` is a higher x.y.z than `installed` (anything that is not x.y.z counts as "not newer"). */
export function isNewer(latest, installed) {
  if (!SEMVER.test(String(latest)) || !SEMVER.test(String(installed))) return false;
  const a = latest.split('.').map(Number);
  const b = installed.split('.').map(Number);
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] > b[i];
  return false;
}

async function readCache(file) {
  try {
    const c = JSON.parse(await readFile(file, 'utf8'));
    return c && typeof c === 'object' ? c : null;
  } catch {
    return null;
  }
}

async function fetchLatest(fetchFn, url) {
  const res = await fetchFn(url, { signal: AbortSignal.timeout(4000), redirect: 'error', headers: { 'User-Agent': `kapaweb-connector/${VERSION}`, Accept: 'application/json' } });
  if (!res.ok) return null;
  const j = JSON.parse((await res.text()).slice(0, 4096));
  return typeof j?.version === 'string' && SEMVER.test(j.version) ? j.version : null;
}

/**
 * The newest published version, and what to do about it. Returns null when there is nothing to say: up to date, check switched
 * off, or the file could not be read. Never throws.
 * @param {{now?: number, fetchFn?: typeof fetch, url?: string, installed?: string}} [o] (all for tests)
 */
export async function checkForUpdate({ now = Date.now(), fetchFn = null, url = VERSION_URL, installed = VERSION } = {}) {
  try {
    if (process.env.KAPAWEB_CONNECTOR_NO_UPDATE_CHECK === '1') return null;
    if (!fetchFn && process.env.KAPAWEB_CONNECTOR_TEST === '1') return null; // the tests never go to the network by accident
    const file = join(configDir(), 'update-check.json');
    const cache = await readCache(file);
    let latest = null;
    if (cache && Number.isFinite(cache.checkedAt) && now - cache.checkedAt < (cache.latest ? FRESH_MS : RETRY_MS) && now >= cache.checkedAt) {
      latest = cache.latest || null;
    } else {
      try {
        latest = await fetchLatest(fetchFn || fetch, url);
      } catch {
        latest = null;
      }
      await mkdir(configDir(), { recursive: true }).catch(() => {});
      await writeFile(file, JSON.stringify({ checkedAt: now, latest }), { encoding: 'utf8', mode: 0o600 }).catch(() => {});
    }
    if (!latest || !isNewer(latest, installed)) return null;
    return {
      update_available: true,
      installed,
      latest,
      say_to_user: `A newer kapaweb connector (${latest}) is available; this one is ${installed}. It has fixes and tools that the playbook may rely on. Their saved sign-in is kept.`,
      how: `Update it before anything else, as step 1 of ${SETUP_PROMPT_URL} describes. In the Claude Desktop chat (no commands) the user downloads ${DOWNLOAD_URL} and double-clicks it, like the first time.`,
    };
  } catch {
    return null;
  }
}
