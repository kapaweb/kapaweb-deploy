// Which IP addresses ARE kapaweb's own hosting servers: the single source of truth for "is this a real kapaweb panel"
// (server/da.js resolves a typed address against this list, then pins the connection to the matching IP so DNS cannot be
// changed between the check and the actual request). Read from firewall.kapaweb.gr/servers.txt — the same list kapaweb's
// own firewall uses — every time a panel is connected to, so a newly added server works without a new connector version.
// Cached to disk as a fallback for when that site is down; a small built-in snapshot covers the very first run.
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { join } from 'node:path';
import { configDir } from './store.js';
import { VERSION } from './util.js';

// The `k=` token is a light gate against random scrapers, not real secrecy: it ships in this file, so anyone who reads
// the connector's own (public) source has it too. It only keeps the plain URL from being hit by bots that don't look.
export const SERVERS_URL = 'https://firewall.kapaweb.gr/servers.txt?k=f31cec8a9b0494eb518d0463203bb33a4ef65b0a9617ee35';
const FETCH_TIMEOUT_MS = 8000;

/**
 * Shipped with the connector so the very first run (or one with no cached copy) still works if firewall.kapaweb.gr happens
 * to be unreachable at that moment. Refreshed by `tools/pack_mcpb.py` from a live fetch when the connector is built, so it
 * is never far out of date; the live fetch below still runs on every connect and wins whenever it succeeds.
 */
export const BUILT_IN_SERVER_IPS = [
  '65.21.193.212',
  '65.21.202.42',
  '65.108.110.122',
  '65.109.28.52',
  '85.10.242.200',
  '85.10.242.201',
  '85.10.242.202',
  '85.10.242.203',
  '85.10.242.204',
  '85.10.242.205',
  '85.10.242.207',
  '88.99.96.232',
  '88.99.239.249',
  '94.130.41.14',
  '95.216.161.184',
  '135.181.114.210',
  '135.181.114.246',
  '136.243.201.232',
  '136.243.201.233',
  '136.243.201.235',
  '136.243.201.236',
  '144.76.143.152',
  '144.76.143.153',
  '144.76.143.155',
  '144.76.143.159',
  '144.76.182.187',
  '144.76.182.188',
  '144.76.182.190',
  '168.119.161.54',
  '2a01:4f8:221:cc7::2',
  '2a01:4f9:3b:1b54::2',
  '2a01:4f9:4b:1ac9::2',
  '2a01:4f9:6a:10c8::1111',
  '2a01:4f9:6b:21ce::2',
  '2a01:4f9:c012:9973::1',
];

function parseList(text) {
  const ips = text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .filter((l) => isIP(l));
  return ips.length > 0 ? ips : null; // an empty or unparsable answer is not trusted over a real cache
}

function cacheFile() {
  return join(configDir(), 'known-servers.json');
}

async function readCache() {
  try {
    const c = JSON.parse(await readFile(cacheFile(), 'utf8'));
    return Array.isArray(c?.ips) && c.ips.length > 0 ? c.ips : null;
  } catch {
    return null;
  }
}

async function writeCache(ips) {
  try {
    await mkdir(configDir(), { recursive: true });
    await writeFile(cacheFile(), JSON.stringify({ fetchedAt: new Date().toISOString(), ips }), { encoding: 'utf8', mode: 0o600 });
  } catch {
    // the live answer is still used for this call; only the fallback-for-next-time is lost
  }
}

/**
 * The current list of kapaweb server IPs, as a Set (for a real address; the test suite always injects `fetchFn`, so it
 * never touches the network or this computer's cache). Always tries the live URL first; on any failure it falls back to
 * this computer's last cached copy, then to the snapshot built into the connector. Never throws.
 * @param {{fetchFn?: typeof fetch, url?: string}} [o]
 */
export async function knownServerIps({ fetchFn = fetch, url = SERVERS_URL } = {}) {
  try {
    const res = await fetchFn(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS), redirect: 'error', headers: { 'User-Agent': `kapaweb-connector/${VERSION}`, Accept: 'text/plain' } });
    if (res.ok) {
      const ips = parseList((await res.text()).slice(0, 1_000_000));
      if (ips) {
        await writeCache(ips);
        return new Set(ips);
      }
    }
  } catch {
    // fall through to the cache
  }
  const cached = await readCache();
  return new Set(cached || BUILT_IN_SERVER_IPS);
}
