// DirectAdmin HTTP client. Basic auth (user:login key) for normal use, a session
// cookie only during the one-time setup. Never logs or returns credentials.
import { randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { rename, rm, stat } from 'node:fs/promises';
import { lookup as dnsLookup } from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import { isIP } from 'node:net';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createGzip } from 'node:zlib';
import { knownServerIps } from './servers.js';
import { UserError, VERSION, redactor } from './util.js';

export const DEFAULT_PORT = 2222;

/** Idle limit (no byte in either direction) for the big transfers: a database import is silent while the server loads it. */
export const LONG_TRANSFER_TIMEOUT_MS = 4 * 60 * 60 * 1000;

export class DaError extends Error {
  constructor(status, type, message, reason, path) {
    super(message);
    this.name = 'DaError';
    this.status = status;
    this.type = type;
    this.reason = reason;
    this.path = path;
  }
}

/** A local, explicit opt-in for a host outside kapaweb's own server list (comma separated). Not for customer sites. */
function envAllowedPatterns() {
  return (process.env.KAPAWEB_ALLOWED_HOSTS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

async function dnsAddresses(hostname, lookupFn = dnsLookup) {
  try {
    return (await lookupFn(hostname, { all: true, verbatim: true })).map((a) => a.address);
  } catch {
    return [];
  }
}

function refusalMessage(host) {
  return `This connector only works with kapaweb hosting: ${host} does not currently point to a kapaweb server. Check the address in your welcome e-mail or contact kapaweb support.`;
}

/**
 * Is `host` a kapaweb server right now, and which of its addresses is? Resolves it and checks the result against kapaweb's
 * own server IPs (fetched live from firewall.kapaweb.gr on every call, see servers.js: the same list kapaweb's own
 * firewall uses, so a newly added server works without a new connector version). Returns the address to connect to, so
 * the caller can PIN the actual connection to it: resolving again for the real request would let DNS answer differently
 * the second time (a customer's own domain is not under kapaweb's control the way kdns.gr/kapaweb.gr are).
 * @param {{fetchFn?: typeof fetch, url?: string, lookupFn?: typeof import('node:dns/promises').lookup}} [o] (tests only)
 */
export async function verifyPanelHost(host, o) {
  const h = String(host).toLowerCase();
  if (process.env.KAPAWEB_CONNECTOR_TEST === '1' && (h === '127.0.0.1' || h === 'localhost')) return '127.0.0.1';
  if (envAllowedPatterns().some((p) => h === p || h.endsWith('.' + p))) {
    // trusted by local configuration, not by kapaweb's list: still needs a real address to connect to
    const addr = isIP(h) ? h : (await dnsAddresses(h, o?.lookupFn))[0];
    if (!addr) throw new UserError(`Could not resolve ${host}. Check the address and your internet connection.`);
    return addr;
  }
  const known = await knownServerIps(o);
  if (isIP(h)) {
    if (known.has(h)) return h;
    throw new UserError(refusalMessage(host));
  }
  const addrs = await dnsAddresses(h, o?.lookupFn);
  if (addrs.length === 0) throw new UserError(`Could not resolve ${host}. Check the address and your internet connection.`);
  const hit = addrs.find((a) => known.has(a));
  if (!hit) throw new UserError(refusalMessage(host));
  return hit;
}

/** "https://ssd5.kdns.gr:2222/evo/" or "ssd5.kdns.gr" -> { host, port }. Shape only: whether it IS a kapaweb server is verifyPanelHost's job. */
export function parsePanelAddress(input) {
  let s = String(input || '').trim();
  if (!s) throw new UserError('Enter the DirectAdmin address from your welcome e-mail (for example server1.kdns.gr).');
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  let u;
  try {
    u = new URL(s);
  } catch {
    throw new UserError('That does not look like a DirectAdmin address.');
  }
  const host = u.hostname.toLowerCase();
  const port = u.port ? Number(u.port) : DEFAULT_PORT;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new UserError('Invalid port in the DirectAdmin address.');
  return { host, port };
}

/**
 * Where a DaClient actually connects: the pinned IP normally (never `host` again — that would let DNS answer differently
 * the second time), or the mock panel's own address under test.
 */
export function connectTarget(host, port, pinnedIp) {
  if (process.env.KAPAWEB_CONNECTOR_TEST === '1') {
    if (process.env.KAPAWEB_TEST_BASE_URL) {
      const u = new URL(process.env.KAPAWEB_TEST_BASE_URL);
      const https = u.protocol === 'https:';
      const connectHost = u.hostname;
      const connectPort = Number(u.port) || (https ? 443 : 80);
      return { https, connectHost, connectPort, hostHeader: u.host, servername: undefined, uploadHost: connectHost, uploadPort: connectPort };
    }
    if (host === '127.0.0.1') {
      return { https: false, connectHost: '127.0.0.1', connectPort: port, hostHeader: `127.0.0.1:${port}`, servername: undefined, uploadHost: '127.0.0.1', uploadPort: port };
    }
  }
  // uploadHost/uploadPort are for the multipart fetch() path only: fetch() has no way to set TLS SNI apart from the
  // URL's own host, so connecting it to the pinned IP would make the real certificate (issued for the domain) look
  // invalid. Uploads go through the hostname instead, exactly as before pinning existed (see the note in request()).
  return { https: true, connectHost: pinnedIp, connectPort: port, hostHeader: `${host}:${port}`, servername: host, uploadHost: host, uploadPort: port };
}

/** A small Headers-like read of Node's raw response headers, for the few callers that need it (set-cookie, content-type). */
function headerReader(raw) {
  return {
    get(name) {
      const v = raw[String(name).toLowerCase()];
      return Array.isArray(v) ? v.join(', ') : v ?? null;
    },
    getSetCookie() {
      const v = raw['set-cookie'];
      return Array.isArray(v) ? v : v ? [v] : [];
    },
  };
}

export class DaClient {
  /**
   * @param {{host:string, port?:number, username?:string, key?:string, cookie?:string, timeoutMs?:number, fileApi?:'modern'|'legacy', pinnedIp?:string}} opts
   *   fileApi: 'legacy' for a panel without /api/filemanager-actions (see fm-legacy.js).
   *   pinnedIp: the address `host` was already verified to resolve to (from verifyPanelHost); every request connects to
   *   it directly instead of resolving `host` again. Required unless `host` is itself an IP literal (tests only).
   */
  constructor({ host, port = DEFAULT_PORT, username, key, cookie, timeoutMs = 60000, fileApi = 'modern', pinnedIp }) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new UserError('The saved connection has an invalid panel port. Ask the user to run `connect` again.');
    if (username !== undefined && !/^[a-z0-9_.-]{1,32}$/i.test(String(username))) throw new UserError('The saved connection has an invalid username. Ask the user to run `connect` again.');
    const ip = pinnedIp || (isIP(host) ? host : null);
    if (!ip) throw new UserError('Internal error: no verified kapaweb server address for this connection. Ask the user to run `connect` again.');
    this.host = host;
    this.port = port;
    this.pinnedIp = ip;
    this.target = connectTarget(host, port, ip);
    this.username = username;
    this.fileApi = fileApi === 'legacy' ? 'legacy' : 'modern';
    this.timeoutMs = timeoutMs;
    this.authFailed = false;
    this.redirects = 0; // consecutive 3xx answers
    this.cookie = cookie || null;
    this._auth = key ? 'Basic ' + Buffer.from(`${username}:${key}`, 'utf8').toString('base64') : null;
    if (key) redactor.add(key);
    if (cookie) redactor.add(cookie);
  }

  setCookie(cookie) {
    this.cookie = cookie;
    redactor.add(cookie);
  }

  /**
   * @param {string} method
   * @param {string} path  e.g. "/api/session/user-config" or "/CMD_SHOW_LOG?domain=x&type=error"
   * @param {{json?:any, form?:Record<string,string|string[]>, multipart?:FormData, timeoutMs?:number, raw?:boolean, text?:boolean, maxBytes?:number}} [opts]
   */
  #guard() {
    if (this.authFailed) {
      throw new UserError('The kapaweb login key was rejected earlier in this session. Ask the user to run `connect` again (do not retry: repeated failures can lock their IP).');
    }
    if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0' && process.env.KAPAWEB_CONNECTOR_TEST !== '1') {
      throw new UserError('TLS certificate checking is switched off in this environment (NODE_TLS_REJECT_UNAUTHORIZED=0), so the connector will not send a password or key. Remove that setting and restart the AI app.');
    }
  }

  #baseHeaders() {
    const headers = { Accept: 'application/json, text/plain, */*', 'User-Agent': `kapaweb-connector/${VERSION}` }; // the one thing that tells a panel log or a proxy in front of it that this is the connector
    if (this._auth) headers.Authorization = this._auth;
    else if (this.cookie) headers.Cookie = this.cookie;
    return headers;
  }

  /** What a failed connection means for the user. `req` tells a silent socket (our own idle limit) from a real network error. */
  #networkError(err, path, req) {
    const code = err?.code || '';
    if (err?.message === 'timeout' || req?.kwTimedOut) return new UserError(`The hosting panel did not answer in time (${path.split('?')[0]}). Try again in a moment.`);
    if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS/i.test(String(code))) {
      return new UserError('The hosting panel presented a certificate that could not be verified, so the connection was refused for safety. Check the panel address.');
    }
    return new UserError(`Could not reach the hosting panel (${code || err?.message || 'network error'}). Check the internet connection.`);
  }

  /**
   * Sends one request to the PINNED panel address and resolves as soon as the response headers are in (the body is not read).
   * `writeBody(req)` streams a request body; it must end the request, and it never rejects: a problem while sending is
   * returned through `sent()` so that an early error answer from the panel (413...) is still read and reported as such.
   */
  async #open(method, path, { headers = {}, timeoutMs, writeBody } = {}) {
    const t = this.target;
    const lib = t.https ? https : http;
    const options = { method, host: t.connectHost, port: t.connectPort, path, headers: { ...this.#baseHeaders(), ...headers, Host: t.hostHeader }, timeout: timeoutMs || this.timeoutMs };
    if (t.https) options.servername = t.servername;
    let req;
    const answered = new Promise((resolve, reject) => {
      req = lib.request(options, resolve);
      req.on('timeout', () => {
        req.kwTimedOut = true;
        req.destroy(new Error('timeout'));
      });
      req.on('error', reject);
    });
    let sendError = null;
    const sending = writeBody ? writeBody(req).catch((e) => void (sendError = e)) : void req.end();
    try {
      const res = await answered;
      return { req, res, sent: async () => { await sending; return sendError; } };
    } catch (err) {
      throw this.#networkError(err, path, req);
    }
  }

  /** A response that has been read completely -> the usual { status, headers, body } or the right error. */
  #interpret(res, chunks, opts, path) {
    const ctype = String(res.headers['content-type'] || '');
    if (res.statusCode === 401) {
      this.authFailed = true;
      throw new DaError(401, 'UNAUTHORIZED', 'The panel refused the login key (401): it may be expired, revoked, or locked to another IP address. Ask the user to run `connect` again.', undefined, path);
    }
    if (res.statusCode >= 300 && res.statusCode < 400) {
      // Legacy CMD_* endpoints answer 302 to the login page when the key is not accepted (expired, revoked, another IP)
      // and possibly also for a command outside the key's allow-list, so one redirect must not end the whole session:
      // only a run of them does.
      this.redirects += 1;
      if (this.redirects >= 3) this.authFailed = true;
      throw new DaError(
        401,
        'UNAUTHORIZED',
        'The panel redirected to its login page: it did not accept the login key for this command (the key may have expired or been revoked, or the command is outside what the key may do). If several commands fail like this, ask the user to run `connect` again.',
        undefined,
        path,
      );
    }
    if (res.statusCode < 300) this.redirects = 0;
    const raw = Buffer.concat(chunks);
    let payload;
    if (opts.raw) {
      if (opts.maxBytes && raw.length > opts.maxBytes) throw new UserError('The file is larger than the connector will download.');
      payload = raw;
    } else {
      const text = raw.toString('utf8');
      if (!opts.text && /json/i.test(ctype) && text) {
        try {
          payload = JSON.parse(text);
        } catch {
          payload = text;
        }
      } else {
        payload = text;
      }
    }
    if (res.statusCode >= 400) {
      let errBody = payload;
      if (Buffer.isBuffer(errBody)) {
        // raw downloads still carry a JSON error body (e.g. 409 {"reason":"NOT_FOUND"})
        try {
          errBody = JSON.parse(errBody.toString('utf8'));
        } catch {
          errBody = errBody.toString('utf8').slice(0, 300);
        }
      }
      const p = errBody && typeof errBody === 'object' ? errBody : {};
      const type = p.type || `HTTP_${res.statusCode}`;
      let message = p.message || p.error || (typeof errBody === 'string' ? errBody.slice(0, 300) : '');
      if (res.statusCode === 403) message = message || 'ACCESS_DENIED';
      throw new DaError(res.statusCode, type, redactor.text(`${type}${message ? ': ' + message : ''}`), p.reason, path);
    }
    return { status: res.statusCode, headers: headerReader(res.headers), body: payload };
  }

  /** The whole answer into memory (small bodies only: the big transfers use downloadToFile / uploadFile). */
  async #readAll(res, path, req, limit = Infinity) {
    const chunks = [];
    let n = 0;
    try {
      for await (const c of res) {
        n += c.length;
        if (n <= limit) chunks.push(c);
      }
    } catch (err) {
      throw this.#networkError(err, path, req);
    }
    return chunks;
  }

  /**
   * @param {string} method
   * @param {string} path  e.g. "/api/session/user-config" or "/CMD_SHOW_LOG?domain=x&type=error"
   * @param {{json?:any, form?:Record<string,string|string[]>, multipart?:FormData, timeoutMs?:number, raw?:boolean, text?:boolean, maxBytes?:number}} [opts]
   */
  async request(method, path, opts = {}) {
    this.#guard();
    const headers = this.#baseHeaders();

    // Uploads (multipart) are not yet pinned: they only happen once a login key already exists (never the account
    // password), and building a multipart body by hand invites subtle corruption; kept on plain fetch() for now.
    // (Big files do not come through here at all: uploadFile() below streams them, pinned, with a length that is checked.)
    if (opts.multipart) return this.#requestMultipart(method, path, opts, headers);

    let body;
    const extra = {};
    if (opts.json !== undefined) {
      extra['Content-Type'] = 'application/json';
      body = Buffer.from(JSON.stringify(opts.json), 'utf8');
    } else if (opts.form) {
      extra['Content-Type'] = 'application/x-www-form-urlencoded';
      const usp = new URLSearchParams();
      for (const [k, v] of Object.entries(opts.form)) {
        if (Array.isArray(v)) v.forEach((x) => usp.append(k, String(x)));
        else if (v !== undefined && v !== null) usp.append(k, String(v));
      }
      body = Buffer.from(usp.toString(), 'utf8');
    }
    if (body !== undefined) extra['Content-Length'] = String(body.length);

    const { req, res } = await this.#open(method, path, {
      headers: extra,
      timeoutMs: opts.timeoutMs,
      writeBody: async (r) => {
        if (body !== undefined) r.write(body);
        r.end();
      },
    });
    const chunks = await this.#readAll(res, path, req);
    return this.#interpret(res, chunks, opts, path);
  }

  /**
   * GET a big body straight into a file, never into memory: the answer is written to `<dest>.part` and renamed to `dest`
   * only when it ended cleanly. With gzip the file is stored compressed (a SQL dump shrinks about tenfold).
   * Returns the size of the body, the size of the file, and its last 4 KB (to see that a dump ends where it should).
   * @param {string} path
   * @param {string} dest
   * @param {{gzip?:boolean, timeoutMs?:number, onProgress?:(bytes:number)=>void}} [o]
   */
  async downloadToFile(path, dest, { gzip = false, timeoutMs = LONG_TRANSFER_TIMEOUT_MS, onProgress } = {}) {
    this.#guard();
    const { req, res } = await this.#open('GET', path, { timeoutMs });
    if (res.statusCode >= 300) {
      const chunks = await this.#readAll(res, path, req, 65536); // an error answer is a small JSON/text body
      return this.#interpret(res, chunks, { raw: true }, path); // always throws for a non-2xx status
    }
    this.redirects = 0;
    let bytes = 0;
    let tail = Buffer.alloc(0);
    let lastReport = 0;
    const meter = new Transform({
      transform(chunk, _enc, cb) {
        bytes += chunk.length;
        tail = Buffer.concat([tail, chunk]).subarray(-4096);
        if (onProgress && Date.now() - lastReport > 2000) {
          lastReport = Date.now();
          onProgress(bytes);
        }
        cb(null, chunk);
      },
    });
    const part = `${dest}.part`;
    try {
      await pipeline(res, meter, ...(gzip ? [createGzip({ level: 6 })] : []), createWriteStream(part, { flags: 'w', mode: 0o600 }));
      if (!res.complete) throw new Error('The answer ended before it was complete.');
      await rename(part, dest);
    } catch (err) {
      await rm(part, { force: true });
      if (err?.code === 'ENOSPC') throw new UserError('This computer has no space left for the download.');
      throw err instanceof UserError ? err : this.#networkError(err, path, req);
    }
    return { bytes, storedBytes: (await stat(dest)).size, tail: tail.toString('latin1') };
  }

  /**
   * POST one file as multipart/form-data without reading it into memory. The request is built by hand with an exact
   * Content-Length (fields + file + closing boundary); the file is checked to be the size it had at the start, so a file that
   * changes while it is being sent fails instead of sending a corrupt body.
   * @param {string} method
   * @param {string} path
   * @param {{fields?:Record<string,string>, fileField:string, fileName:string, filePath:string, timeoutMs?:number, onProgress?:(sent:number,total:number)=>void}} o
   */
  async uploadFile(method, path, { fields = {}, fileField, fileName, filePath, timeoutMs = LONG_TRANSFER_TIMEOUT_MS, onProgress }) {
    this.#guard();
    const size = (await stat(filePath)).size;
    const boundary = '----kapaweb-' + randomBytes(16).toString('hex');
    const safe = (v) => String(v).replace(/[^A-Za-z0-9._ -]/g, '_'); // header-safe: no quote, backslash, CR/LF, no non-ASCII
    let head = '';
    for (const [k, v] of Object.entries(fields)) head += `--${boundary}\r\nContent-Disposition: form-data; name="${safe(k)}"\r\n\r\n${String(v).replace(/[\r\n]/g, ' ')}\r\n`;
    head += `--${boundary}\r\nContent-Disposition: form-data; name="${safe(fileField)}"; filename="${safe(fileName)}"\r\nContent-Type: application/octet-stream\r\n\r\n`;
    const headBuf = Buffer.from(head, 'utf8');
    const tailBuf = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8');
    const total = headBuf.length + size + tailBuf.length;
    let sent = 0;
    let lastReport = 0;
    const { req, res, sent: sendDone } = await this.#open(method, path, {
      timeoutMs,
      headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}`, 'Content-Length': String(total) },
      writeBody: async (r) => {
        async function* body() {
          yield headBuf;
          let n = 0;
          for await (const chunk of createReadStream(filePath)) {
            n += chunk.length;
            sent += chunk.length;
            if (onProgress && Date.now() - lastReport > 2000) {
              lastReport = Date.now();
              onProgress(sent, size);
            }
            yield chunk;
          }
          if (n !== size) throw new UserError('The file changed while it was being sent. Nothing was imported; run the tool again.');
          yield tailBuf;
        }
        await pipeline(Readable.from(body(), { objectMode: false }), r);
      },
    });
    const chunks = await this.#readAll(res, path, req);
    const sendError = await sendDone();
    if (sendError && res.statusCode < 400) throw sendError instanceof UserError ? sendError : this.#networkError(sendError, path, req);
    return this.#interpret(res, chunks, {}, path);
  }

  /** The one request kind still made with fetch(): see the note in request(). Same return shape and error mapping. */
  async #requestMultipart(method, path, opts, headers) {
    const t = this.target;
    const base = `${t.https ? 'https' : 'http'}://${t.uploadHost}:${t.uploadPort}`;
    let res;
    try {
      res = await fetch(base + path, {
        method,
        headers: { ...headers, Host: t.hostHeader },
        body: opts.multipart,
        redirect: 'manual',
        signal: AbortSignal.timeout(opts.timeoutMs || this.timeoutMs),
      });
    } catch (err) {
      const code = err?.cause?.code || err?.code || '';
      if (err?.name === 'TimeoutError') throw new UserError(`The hosting panel did not answer in time (${path.split('?')[0]}). Try again in a moment.`);
      if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY/i.test(String(code))) {
        throw new UserError('The hosting panel presented a certificate that could not be verified, so the connection was refused for safety. Check the panel address.');
      }
      throw new UserError(`Could not reach the hosting panel (${code || err?.message || 'network error'}). Check the internet connection.`);
    }
    const ctype = res.headers.get('content-type') || '';
    if (res.status === 401) {
      this.authFailed = true;
      throw new DaError(401, 'UNAUTHORIZED', 'The panel refused the login key (401): it may be expired, revoked, or locked to another IP address. Ask the user to run `connect` again.', undefined, path);
    }
    if (res.status >= 300 && res.status < 400) {
      this.redirects += 1;
      if (this.redirects >= 3) this.authFailed = true;
      throw new DaError(
        401,
        'UNAUTHORIZED',
        'The panel redirected to its login page: it did not accept the login key for this command (the key may have expired or been revoked, or the command is outside what the key may do). If several commands fail like this, ask the user to run `connect` again.',
        undefined,
        path,
      );
    }
    if (res.status < 300) this.redirects = 0;
    const text = await res.text();
    let payload = text;
    if (/json/i.test(ctype) && text) {
      try {
        payload = JSON.parse(text);
      } catch {
        payload = text;
      }
    }
    if (res.status >= 400) {
      const p = payload && typeof payload === 'object' ? payload : {};
      const type = p.type || `HTTP_${res.status}`;
      let message = p.message || p.error || (typeof payload === 'string' ? payload.slice(0, 300) : '');
      if (res.status === 403) message = message || 'ACCESS_DENIED';
      throw new DaError(res.status, type, redactor.text(`${type}${message ? ': ' + message : ''}`), p.reason, path);
    }
    return { status: res.status, headers: res.headers, body: payload };
  }

  get(path, opts) {
    return this.request('GET', path, opts);
  }
  postJson(path, json, opts = {}) {
    return this.request('POST', path, { ...opts, json: json === undefined ? {} : json });
  }
  postForm(path, form, opts = {}) {
    return this.request('POST', path, { ...opts, form });
  }
}

/** Turn any thrown value into a message that is safe and useful for the AI. */
export function describeError(err) {
  if (err instanceof UserError) return err.message;
  if (err instanceof DaError) {
    const r = err.reason ? ` (${err.reason})` : '';
    if (err.status === 403) {
      return `The panel says this is not allowed for the connector's key or for this hosting plan${r}. Do not look for a workaround; tell the user, or ask kapaweb support.`;
    }
    if (err.status === 409) return `The panel refused the operation${r}: ${err.message}`;
    if (err.status === 404) return `Not found${r}: ${err.message}`;
    return `${err.message}${r}`;
  }
  return `Unexpected error: ${redactor.text(err?.message || String(err))}`;
}
