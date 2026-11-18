// SSL on a panel that has the classic TLS command (CMD_API_SSL) but NOT the new TLS API (/api/domain-tls).
// kapaweb's ns65 and ssd5 are such panels: their File Manager API is the new one, but /api/domain-tls is not served there
// (anonymous probe, 12/11/2026: GET answers 302 to the login page and POST answers 405, exactly like a path that does not exist,
// while on osotir.org / ns3.backorder.gr the same path answers 401). The classic command is there (401 without a key).
//
// What this file does, for the three SSL tools when the new API is absent:
//   status   what visitors really get on https (checked from this computer), plus what the panel says (private keys withheld)
//   dry run  DNS of the name and of www, the web server's answer for an ACME challenge path, CAA records: from this computer
//   issue    the dry run first; then ONE CMD_API_SSL request for the free Let's Encrypt certificate; then a real TLS handshake
//            to prove that visitors get it. The classic command answers HTTP 200 also when it fails (error=1 in the body),
//            so the body is always read.
// The private key of a certificate never leaves the panel through here: it is dropped from every answer.
import { X509Certificate } from 'node:crypto';
import dns from 'node:dns/promises';
import http from 'node:http';
import tls from 'node:tls';
import { DaError } from './da.js';
import { UserError, randomLower, redactor } from './util.js';
import { isPublicAddress } from './web.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// is the new TLS API missing on this panel?
// ---------------------------------------------------------------------------

/**
 * True when a failed /api/domain-tls call means "this panel does not serve that path": a redirect to the login page (GET) or
 * 405 (POST). Anything else (401 key refused, 403 command not allowed, 404 domain unknown, 5xx) is a real answer and is reported as before.
 */
export function absentTlsApi(err) {
  return err instanceof DaError && String(err.path || '').startsWith('/api/domain-tls/') && (err.status === 405 || err.redirected === true);
}

// ---------------------------------------------------------------------------
// probes (real network; tests replace them)
// ---------------------------------------------------------------------------

async function realResolve(fn, name) {
  try {
    return await fn(name);
  } catch (e) {
    if (e?.code === 'ENODATA' || e?.code === 'ENOTFOUND') return [];
    throw e;
  }
}

const REAL = {
  resolve4: (name) => realResolve(dns.resolve4, name),
  resolve6: (name) => realResolve(dns.resolve6, name),
  resolveCaa: (name) => realResolve(dns.resolveCaa, name),
  /** TLS handshake to ip:443 with SNI = name, certificate NOT enforced (we report what is served). */
  tlsPeer(ip, name, timeoutMs = 10000) {
    return new Promise((resolve) => {
      const socket = tls.connect({ host: ip, port: 443, servername: name, rejectUnauthorized: false, timeout: timeoutMs });
      let done = false;
      const end = (v) => {
        if (done) return;
        done = true;
        try {
          socket.destroy();
        } catch {
          /* already closed */
        }
        resolve(v);
      };
      socket.once('secureConnect', () => {
        const cert = socket.getPeerCertificate(false);
        const err = socket.authorizationError;
        end({ ok: true, cert: cert && Object.keys(cert).length ? cert : null, authorized: Boolean(socket.authorized), error: err ? String(err.code || err.message || err) : undefined });
      });
      socket.once('timeout', () => end({ ok: false, error: 'TIMEOUT' }));
      socket.once('error', (e) => end({ ok: false, error: e?.code || e?.message || 'ERROR' }));
    });
  },
  /** GET http://ip/path with Host: name, no redirect followed. */
  httpProbe(ip, name, path, timeoutMs = 10000) {
    return new Promise((resolve) => {
      const req = http.request({ host: ip, port: 80, path, method: 'GET', headers: { Host: name, 'User-Agent': 'kapaweb-connector-check/1', Accept: '*/*', 'Accept-Encoding': 'identity' }, timeout: timeoutMs }, (res) => {
        res.resume();
        resolve({ ok: true, status: res.statusCode, location: res.headers.location });
        res.destroy();
      });
      req.on('timeout', () => req.destroy(new Error('TIMEOUT')));
      req.on('error', (e) => resolve({ ok: false, error: e?.code || e?.message || 'ERROR' }));
      req.end();
    });
  },
};

let hooks = null;
/** Tests only: replaces the network probes (DNS, TLS handshake, HTTP, CAA). */
export function useProbesForTests(h) {
  if (process.env.KAPAWEB_CONNECTOR_TEST !== '1') throw new Error('useProbesForTests is for the tests only');
  hooks = h;
}
function probes() {
  if (hooks) return { ...REAL, ...hooks };
  // a test that forgot to replace the network must fail loudly, never go to the real internet
  if (process.env.KAPAWEB_CONNECTOR_TEST === '1') throw new Error('the SSL probes need useProbesForTests() in a test');
  return REAL;
}

// ---------------------------------------------------------------------------
// what a visitor gets
// ---------------------------------------------------------------------------

const dnsNames = (cert) =>
  String(cert?.subjectaltname || '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => /^DNS:/i.test(s))
    .map((s) => s.slice(4).toLowerCase());

/** The verdict for what a TLS handshake showed. Pure. */
export function judgeCertificate(name, peer, now = Date.now()) {
  if (!peer || !peer.ok) return { name, https: false, verdict: 'no_https', error: peer?.error || 'no answer' };
  const c = peer.cert;
  if (!c) return { name, https: true, verdict: 'no_certificate', error: peer.error };
  let covers = false;
  try {
    covers = tls.checkServerIdentity(name, c) === undefined;
  } catch {
    covers = false;
  }
  const validTo = c.valid_to ? Date.parse(c.valid_to) : NaN;
  const daysLeft = Number.isFinite(validTo) ? Math.floor((validTo - now) / 86400000) : undefined;
  let verdict;
  if (!covers) verdict = 'wrong_name';
  else if (peer.error === 'CERT_HAS_EXPIRED' || (daysLeft !== undefined && daysLeft < 0)) verdict = 'expired';
  else if (!peer.authorized) verdict = 'untrusted';
  else verdict = 'ok';
  const issuer = c.issuer?.O || c.issuer?.CN;
  return {
    name,
    https: true,
    verdict,
    subject: c.subject?.CN,
    names: dnsNames(c),
    issuer,
    valid_from: c.valid_from,
    valid_to: c.valid_to,
    days_left: daysLeft,
    trusted: verdict === 'ok',
    error: peer.error,
    fingerprint: c.fingerprint256, // internal: tells a new certificate from the old one
  };
}

/** What a visitor of `name` gets on https: the name is looked up in the public DNS, the first public address is asked. */
export async function visitorView(name, p = probes()) {
  let addrs = [];
  try {
    addrs = [...(await p.resolve4(name)), ...(await p.resolve6(name).catch(() => []))];
  } catch (e) {
    return { name, https: false, verdict: 'no_dns', error: e?.code || e?.message };
  }
  const ip = addrs.find((a) => isPublicAddress(a));
  if (!ip) return { name, https: false, verdict: 'no_dns', error: addrs.length ? 'the name resolves only to private addresses' : 'the name has no address' };
  return { ...judgeCertificate(name, await p.tlsPeer(ip, name)), resolves_to: ip };
}

const publicFacts = ({ fingerprint, ...rest }) => rest;

// ---------------------------------------------------------------------------
// dry run: can a free certificate be issued now?
// ---------------------------------------------------------------------------

/** CAA: the nearest record set up the tree decides. Pure on the records. */
export function caaAllowsLetsEncrypt(records) {
  const issue = (records || []).map((r) => r?.issue).filter((v) => typeof v === 'string');
  if (!issue.length) return true; // no `issue` property: any CA may issue
  return issue.some((v) => /^\s*letsencrypt\.org\s*(;|$)/i.test(v));
}

async function caaView(domain, p) {
  let name = domain;
  try {
    while (name.split('.').length >= 2) {
      const records = await p.resolveCaa(name);
      if (records && records.length) return { found_at: name, allows_letsencrypt: caaAllowsLetsEncrypt(records), issuers: records.map((r) => r.issue).filter((v) => typeof v === 'string') };
      name = name.split('.').slice(1).join('.');
    }
    return { found_at: null, allows_letsencrypt: true };
  } catch (e) {
    return { found_at: null, allows_letsencrypt: true, could_not_check: e?.code || e?.message };
  }
}

async function nameView(name, serverIp, p) {
  const out = { name, ok: false, problems: [] };
  let a = [];
  let aaaa = [];
  try {
    a = await p.resolve4(name);
    aaaa = await p.resolve6(name).catch(() => []);
  } catch (e) {
    out.problems.push(`DNS lookup failed (${e?.code || e?.message})`);
    out.dns = { error: e?.code || e?.message };
    return out;
  }
  out.dns = { a, aaaa, points_here: a.length > 0 && a.every((x) => x === serverIp) };
  if (!a.length) out.problems.push('the name has no IPv4 address (A record)');
  else if (!out.dns.points_here) out.problems.push(`DNS points to ${a.filter((x) => x !== serverIp).join(', ')}, not only to this server (${serverIp}): the certificate authority would ask there`);
  if (aaaa.length) out.dns.note = `it also has an IPv6 address (${aaaa.join(', ')}); the certificate authority prefers IPv6, so that address must be this server as well`;
  if (out.dns.points_here) {
    const probe = await p.httpProbe(serverIp, name, `/.well-known/acme-challenge/kw-${randomLower(12)}`);
    out.http = probe.ok ? { status: probe.status, location: probe.location } : { error: probe.error };
    if (!probe.ok) out.problems.push(`this server did not answer on port 80 for ${name} (${probe.error})`);
    else if (probe.status >= 500) out.problems.push(`the web server answered ${probe.status} for the challenge path`);
  }
  out.ok = out.problems.length === 0;
  return out;
}

/** The names a certificate would cover: the domain itself (required) and www.<domain> (when it is ready too). */
export async function classicDryRun({ domain, serverIp, allowed }) {
  const base = ownDomain(domain, allowed);
  // the comparison needs the account's real public server address, and the port-80 probe goes to exactly that address
  if (!serverIp || !isPublicAddress(serverIp)) throw new UserError('The panel did not report a public server address for this account (account_info shows server_ip), so DNS cannot be compared with it. Nothing was checked or changed.');
  const p = probes();
  const names = [base, `www.${base}`];
  const [views, caa] = await Promise.all([Promise.all(names.map((n) => nameView(n, serverIp, p))), caaView(base, p)]);
  const failed = views.filter((v) => !v.ok).map((v) => v.name);
  const problems = [];
  if (!caa.allows_letsencrypt) problems.push(`a CAA record at ${caa.found_at} does not allow letsencrypt.org (${caa.issuers.join(' | ')})`);
  if (!views[0].ok) problems.push(`${base}: ${views[0].problems.join('; ')}`);
  const ready = views[0].ok && caa.allows_letsencrypt;
  return {
    method: 'classic',
    note: 'This panel does not offer the TLS API (/api/domain-tls). The check is made from this computer; the certificate is requested with the classic CMD_API_SSL command.',
    domain: base,
    server_ip: serverIp,
    names: views,
    caa,
    dnsNamesFailedChallenge: failed,
    would_request: ready ? names.filter((n) => !failed.includes(n)) : [],
    ready,
    problems,
    next: ready ? 'ssl_issue requests the free Let\'s Encrypt certificate for would_request.' : 'Fix the problems above first (DNS must point to this server).',
  };
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

const PRIVATE_KEY_BLOCK = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;

function certFacts(pem) {
  try {
    const x = new X509Certificate(pem);
    return { subject: x.subject.replace(/\n/g, ', '), issuer: x.issuer.replace(/\n/g, ', '), valid_to: x.validTo, names: x.subjectAltName };
  } catch {
    return { unreadable: true };
  }
}

/** What the panel's CMD_API_SSL answer says, safe to show: private keys are withheld, certificates are summarised. Pure. */
export function describePanelAnswer(body) {
  let fields = null;
  if (body && typeof body === 'object' && !Array.isArray(body)) fields = body;
  else {
    const s = String(body ?? '');
    if (/^\s*[{[]/.test(s)) {
      try {
        const j = JSON.parse(s);
        if (j && typeof j === 'object' && !Array.isArray(j)) fields = j;
      } catch {
        /* not JSON */
      }
    }
    if (!fields && /^\s*</.test(s)) return { format: 'web page', note: 'The panel answered with a web page, not with certificate data.' };
    if (!fields) fields = Object.fromEntries(new URLSearchParams(s));
  }
  const out = {};
  for (const [k, v] of Object.entries(fields)) {
    const t = typeof v === 'string' ? v : JSON.stringify(v ?? '');
    const stripped = t.replace(PRIVATE_KEY_BLOCK, '');
    const hadKey = stripped !== t;
    if (/PRIVATE KEY/.test(stripped) || /BEGIN (RSA |EC )?KEY/.test(stripped)) {
      out[k] = '(withheld: private key)';
      continue;
    }
    const certs = [...stripped.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)].map((m) => m[0]);
    if (certs.length) {
      out[k] = { ...certFacts(certs[0]), certificates_in_field: certs.length, ...(hadKey ? { private_key: 'withheld' } : {}) };
    } else if (hadKey) {
      out[k] = '(withheld: private key)';
    } else out[k] = stripped.length > 300 ? `(${stripped.length} characters)` : stripped;
  }
  return out;
}

export async function classicStatus({ da, domain, allowed }) {
  const base = ownDomain(domain, allowed);
  const p = probes();
  const names = [base, `www.${base}`];
  const [https, panel] = await Promise.all([
    Promise.all(names.map((n) => visitorView(n, p))),
    (async () => {
      try {
        const r = await da.get(`/CMD_API_SSL?${new URLSearchParams({ domain: base })}`, { text: true });
        return { command: 'CMD_API_SSL', answer: describePanelAnswer(r.body) };
      } catch (e) {
        return { command: 'CMD_API_SSL', available: false, reason: String(e?.message || e).slice(0, 300) };
      }
    })(),
  ]);
  const good = https.every((h) => h.verdict === 'ok');
  return {
    method: 'classic',
    note: 'This panel does not offer the TLS API (/api/domain-tls), so there is no certificate list. https shows what visitors really get, checked from this computer.',
    domain: base,
    https: https.map(publicFacts),
    panel,
    next: good ? 'Both names have a valid certificate.' : 'ssl_dry_run shows whether a free certificate can be requested now; ssl_issue requests it.',
  };
}

// ---------------------------------------------------------------------------
// issue
// ---------------------------------------------------------------------------

/** The classic API's answer: error=0|1&text=…&details=… (url-encoded), or the same as JSON. Pure. */
export function parsePanelReply(body) {
  if (body && typeof body === 'object') {
    const err = body.error !== undefined ? String(body.error) : body.success !== undefined ? '0' : '?';
    return { error: err, text: body.text ?? body.success ?? body.result, details: body.details };
  }
  const s = String(body ?? '').trim();
  if (s.startsWith('{')) {
    try {
      return parsePanelReply(JSON.parse(s));
    } catch {
      /* fall through */
    }
  }
  if (/^\s*</.test(s)) return { error: 'html', text: 'The panel answered with a web page, not with the result of the command.' };
  const q = new URLSearchParams(s);
  return { error: q.has('error') ? q.get('error') : '?', text: q.get('text') || undefined, details: q.get('details') || undefined };
}

function ownDomain(domain, allowed) {
  let d = String(domain || '').toLowerCase();
  if (d.startsWith('www.') && allowed.includes(d.slice(4))) d = d.slice(4);
  if (!allowed.includes(d)) throw new UserError(`${domain} is not one of this account's domains (${allowed.join(', ') || 'none'}), so no certificate is requested or checked for it. Use the main name of the domain, without www.`);
  return d;
}

export async function classicIssue({ da, domain, serverIp, allowed, waitSeconds = 90, progress = () => {} }) {
  const base = ownDomain(domain, allowed);
  const p = probes();
  progress('Checking DNS, the web server and CAA records…');
  const dry = await classicDryRun({ domain: base, serverIp, allowed });
  if (!dry.ready) {
    throw new UserError(`A certificate cannot be requested for ${base} yet: ${dry.problems.join(' | ')}. Nothing was changed. (ssl_dry_run shows the details.)`);
  }
  const before = await visitorView(base, p);
  if (before.verdict === 'ok' && (before.days_left ?? 0) > 30 && dry.would_request.every((n) => before.names?.includes(n))) {
    return { method: 'classic', domain: base, already_valid: true, message: `${base} already has a valid certificate (${before.issuer}, ${before.days_left} days left) that covers ${dry.would_request.join(' and ')}: nothing was requested.`, https: publicFacts(before) };
  }
  const form = {
    domain: base,
    action: 'save',
    type: 'create',
    request: 'letsencrypt',
    name: base,
    keysize: 'secp384r1',
    encryption: 'sha256',
    submit: 'save',
  };
  dry.would_request.forEach((n, i) => {
    form[`le_select${i}`] = n; // the panel's own form: le_select0 = the domain, le_select1 = www.<domain>
  });
  progress(`Asking the panel for a free Let's Encrypt certificate for ${dry.would_request.join(' and ')}…`);
  const r = await da.postForm('/CMD_API_SSL', form, { timeoutMs: 180000 });
  const reply = parsePanelReply(r.body);
  const said = redactor.text([reply.text, reply.details].filter(Boolean).join(' — ')).slice(0, 800);
  if (reply.error !== '0' && reply.error !== '?') {
    throw new UserError(`The panel did not issue the certificate for ${base}: ${said || 'no reason given'}. The panel answers HTTP 200 even when it fails; this is its error text. Nothing else was changed.`);
  }
  // do not believe "saved": a real TLS handshake must show a different, valid certificate that covers the name
  progress('The panel accepted the request; waiting for the new certificate to be served…');
  const until = Date.now() + Math.max(0, waitSeconds) * 1000;
  let after = before;
  for (;;) {
    after = await visitorView(base, p);
    if (after.verdict === 'ok' && after.fingerprint && after.fingerprint !== before.fingerprint) break;
    if (Date.now() >= until) break;
    await sleep(5000);
  }
  const www = dry.would_request.includes(`www.${base}`) ? await visitorView(`www.${base}`, p) : null;
  const served = after.verdict === 'ok' && after.fingerprint !== before.fingerprint;
  return {
    method: 'classic',
    domain: base,
    requested: dry.would_request,
    panel_said: said || (reply.error === '?' ? '(no confirmation text; the check below is what counts)' : undefined),
    visitors_get_it: served,
    https: [publicFacts(after), ...(www ? [publicFacts(www)] : [])],
    next: served ? 'Done: visitors get the new certificate.' : 'The panel accepted the request but visitors do not get a valid certificate yet. Check again with ssl_status in a minute or two; do not request it again before that.',
  };
}
