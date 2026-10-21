// Which control panel sits behind the address a customer typed? kapaweb sells DirectAdmin (login on port 2222) and
// Plesk (login on port 8443). The sign-in page takes ONE address; this module works out which panel answers there so the
// right client is used, and the customer never has to say which one they have.
//
// Two rules keep it safe:
//  * the host is verified ONCE (verifyPanelHost: it must be a kapaweb server) and every probe connects to that pinned
//    address, exactly like the real clients do;
//  * it sends as few requests as possible: ONE small GET per candidate panel, never a retry loop, and the same host is not
//    probed again within MIN_GAP_MS. A firewall reads a burst of requests to panel ports as a scan and bans the sender (it
//    happened: repeated probing of 2222/8443 got a real office IP banned fleet-wide).
import http from 'node:http';
import https from 'node:https';
import { connectTarget, verifyPanelHost } from './da.js';
import { UserError, VERSION } from './util.js';

export const PANELS = Object.freeze({
  directadmin: Object.freeze({ id: 'directadmin', name: 'DirectAdmin', port: 2222, probePath: '/' }),
  plesk: Object.freeze({ id: 'plesk', name: 'Plesk', port: 8443, probePath: '/login_up.php' }),
});

export const PROBE_TIMEOUT_MS = 8000;
export const MIN_GAP_MS = 15000;
export const CACHE_MS = 10 * 60 * 1000; // a panel that WAS recognised is remembered, so a retry after a typo sends nothing
const MAX_PROBE_BYTES = 64 * 1024;

const lastDetection = new Map(); // host -> time of the last probe round
const recognised = new Map(); // "host:port" -> { result, at } of a probe round that found exactly one panel
/** Tests only: forget earlier probe rounds. */
export function resetDetectionThrottle() {
  lastDetection.clear();
  recognised.clear();
}

/**
 * "ssd5.kdns.gr", "https://ns67.kdns.gr:8443/login_up.php" -> { host, port, hint }.
 * Shape only (whether it IS a kapaweb server is verifyPanelHost's job). `port` is null when the customer did not type one.
 * `hint` is the panel the address itself gives away (its standard port, or a path only that panel uses), else null.
 */
export function parsePanelInput(input) {
  let s = String(input || '').trim();
  if (!s) throw new UserError('Enter the address of your hosting panel from your welcome e-mail (for example server1.kdns.gr).');
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  let u;
  try {
    u = new URL(s);
  } catch {
    throw new UserError('That does not look like a hosting panel address.');
  }
  const host = u.hostname.toLowerCase();
  if (!host) throw new UserError('That does not look like a hosting panel address.');
  const port = u.port ? Number(u.port) : null;
  if (port !== null && (!Number.isInteger(port) || port < 1 || port > 65535)) throw new UserError('Invalid port in the hosting panel address.');
  const path = u.pathname.toLowerCase();
  let hint = null;
  if (port === PANELS.directadmin.port || /^\/(evo|login)\b/.test(path) || /\bcmd_/.test(path)) hint = 'directadmin';
  else if (port === PANELS.plesk.port || /^\/(login_up\.php|cp|smb|admin)\b/.test(path)) hint = 'plesk';
  return { host, port, hint };
}

/** Does this answer look like DirectAdmin's login (a redirect into its /evo/ skin, or a page/server that names itself)? */
export function looksLikeDirectAdmin(res) {
  if (!res) return false;
  const server = String(res.headers?.server || '');
  const location = String(res.headers?.location || '');
  if (/directadmin/i.test(server)) return true;
  if (res.status >= 300 && res.status < 400 && /(^|\/)(evo|login)\b|CMD_/i.test(location)) return true;
  return res.status >= 200 && res.status < 300 && /directadmin/i.test(String(res.body || ''));
}

/** Does this answer look like Plesk's login page? */
export function looksLikePlesk(res) {
  if (!res) return false;
  const powered = String(res.headers?.['x-powered-by'] || '');
  const cookies = [].concat(res.headers?.['set-cookie'] || []).join(';');
  if (/plesk/i.test(powered) || /PLESKSESSID/i.test(cookies)) return true;
  if (res.status >= 300 && res.status < 400 && /(^|\/)(cp|login_up\.php|smb)\b/i.test(String(res.headers?.location || ''))) return true;
  const body = String(res.body || '');
  return res.status >= 200 && res.status < 300 && (/name=["']login_name["']/i.test(body) || /plesk/i.test(body));
}

const CLASSIFY = { directadmin: looksLikeDirectAdmin, plesk: looksLikePlesk };

/** One small GET, no redirects followed, at most 64 KB read. Resolves { status, headers, body }; rejects on a network error. */
export function httpProbe(panelId, { host, port, pinnedIp, timeoutMs = PROBE_TIMEOUT_MS }) {
  const t = connectTarget(host, port, pinnedIp);
  const lib = t.https ? https : http;
  const options = {
    method: 'GET',
    host: t.connectHost,
    port: t.connectPort,
    path: PANELS[panelId].probePath,
    headers: { Host: t.hostHeader, 'User-Agent': `kapaweb-connector/${VERSION}`, Accept: 'text/html,*/*;q=0.5' },
    timeout: timeoutMs,
  };
  if (t.https) options.servername = t.servername; // the real certificate is issued for the name, not the pinned IP
  return new Promise((resolve, reject) => {
    const req = lib.request(options, (res) => {
      const chunks = [];
      let size = 0;
      const done = () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') });
      res.on('data', (c) => {
        size += c.length;
        if (size <= MAX_PROBE_BYTES) chunks.push(c);
        else res.destroy(); // enough to recognise a login page; 'close' below still resolves with what was read
      });
      res.on('end', done);
      res.on('close', done);
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}

/**
 * Works out which panel answers at `input`.
 * @param {string} input what the customer typed
 * @param {{verifyOpts?: object, probe?: typeof httpProbe, now?: () => number}} [o] probe/now/verifyOpts are for tests
 * @returns {Promise<{panel: 'directadmin'|'plesk', name: string, host: string, port: number, pinnedIp: string}>}
 */
export async function detectPanel(input, o = {}) {
  const { host, port, hint } = parsePanelInput(input);
  const now = o.now || Date.now;
  const probe = o.probe || httpProbe;

  const pinnedIp = await verifyPanelHost(host, o.verifyOpts); // throws for anything that is not a kapaweb server

  // A panel that was recognised a moment ago is not asked again (the customer retyping a password is not a scan).
  const cacheKey = `${host}:${port ?? ''}`;
  const known = recognised.get(cacheKey);
  if (known && now() - known.at < CACHE_MS) return { ...known.result, pinnedIp };

  const last = lastDetection.get(host);
  if (last !== undefined && now() - last < MIN_GAP_MS) {
    const secs = Math.max(1, Math.ceil((MIN_GAP_MS - (now() - last)) / 1000));
    throw new UserError(`The panel at ${host} was checked a moment ago. Wait about ${secs} second${secs === 1 ? '' : 's'} and try again, or type the address with its panel port (for example ${host}:${PANELS.plesk.port} for Plesk or ${host}:${PANELS.directadmin.port} for DirectAdmin). This keeps the server's firewall from taking repeated checks for a scan.`);
  }
  lastDetection.set(host, now());

  // The customer's own port wins when it is a standard one; an address without a hint is tried on both standard ports.
  const candidates = hint ? [hint] : Object.keys(PANELS);
  const results = await Promise.all(
    candidates.map(async (id) => {
      const p = port ?? PANELS[id].port;
      try {
        const res = await probe(id, { host, port: p, pinnedIp });
        return { id, port: p, match: CLASSIFY[id](res), reached: true };
      } catch {
        return { id, port: p, match: false, reached: false };
      }
    }),
  );
  const hits = results.filter((r) => r.match);
  if (hits.length === 1) {
    const result = { panel: hits[0].id, name: PANELS[hits[0].id].name, host, port: hits[0].port };
    recognised.set(cacheKey, { result, at: now() });
    return { ...result, pinnedIp };
  }
  if (hits.length > 1) {
    throw new UserError(`${host} answers like both DirectAdmin and Plesk. Type the address with its panel port (${PANELS.directadmin.port} for DirectAdmin, ${PANELS.plesk.port} for Plesk), for example ${host}:${PANELS.plesk.port}.`);
  }
  if (results.every((r) => !r.reached)) {
    throw new UserError(`Could not reach a hosting panel at ${host}. Check the address and your internet connection.`);
  }
  throw new UserError(`${host} did not answer like a DirectAdmin or Plesk login page. Check the panel address in your welcome e-mail.`);
}

/**
 * Which panel flow an address calls for, sending NOTHING unless it has to:
 *  - a standard port or a panel-only path names the panel (no request here; the sign-in itself is the first request);
 *  - any other explicit port keeps the DirectAdmin behaviour that existed before Plesk was supported (no request);
 *  - a bare host is probed once per panel (detectPanel).
 * Plesk answers come with the verified, pinned address; DirectAdmin's flow verifies the host itself, as it always did.
 */
export async function choosePanel(input, o = {}) {
  const { host, port, hint } = parsePanelInput(input);
  if (hint === 'plesk') {
    const pinnedIp = await verifyPanelHost(host, o.verifyOpts);
    return { panel: 'plesk', name: PANELS.plesk.name, host, port: port ?? PANELS.plesk.port, pinnedIp };
  }
  if (hint === 'directadmin' || port !== null) return { panel: 'directadmin', name: PANELS.directadmin.name, host, port: port ?? PANELS.directadmin.port };
  return detectPanel(input, o);
}
