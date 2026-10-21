// A signed-in Plesk web session, for the parts of Plesk that have NO public customer API: the Node.js extension and (later)
// the File Manager. They are the same JSON endpoints the Plesk panel's own pages call, so they need what a browser has: a
// session cookie from the normal login page and the forgery-protection token that Plesk puts in every page.
//
// This is the stored PASSWORD route only (the XML API client in plesk.js is what a secret key can use). The password comes
// from the OS keychain, goes only to the verified, pinned kapaweb panel address, and is never logged.
//
// STATUS: written from how Plesk Obsidian's login page and its Node.js extension client work (read from the panel's own
// JavaScript); the login form field names and token handling are NOT yet proven on a real customer login — the first real
// run decides. Everything else is covered by tests against a fake panel.
import { randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { rename, rm } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import { isIP } from 'node:net';
import { connectTarget } from './da.js';
import { UserError, VERSION, redactor } from './util.js';
import { PleskError } from './plesk.js';

const MAX_BODY_BYTES = 32 * 1024 * 1024;
const LOGIN_PATH = '/login_up.php';

/** The forgery-protection token in a Plesk page: a <meta name="forgery_protection_token"> or the login form's hidden input. */
export function extractForgeryToken(html) {
  const s = String(html);
  const tags = s.match(/<(?:meta|input)\b[^>]*\bforgery_protection_token\b[^>]*>/gi) || [];
  for (const tag of tags) {
    const m = /\b(?:content|value)\s*=\s*"([^"]+)"/i.exec(tag) || /\b(?:content|value)\s*=\s*'([^']+)'/i.exec(tag);
    if (m) return m[1];
  }
  return null;
}

/** "a=b; Path=/; HttpOnly" lines -> [name, value] pairs (attributes are not needed: one panel, one host, one path). */
function cookiePairs(setCookie) {
  return [].concat(setCookie || [])
    .map((line) => /^\s*([^=;\s]+)=([^;]*)/.exec(String(line)))
    .filter(Boolean)
    .map((m) => [m[1], m[2]]);
}

/** An object as an application/x-www-form-urlencoded body; arrays become key[0]=a&key[1]=b (what Plesk's own list pages send). */
export function formEncode(obj) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(obj || {})) {
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) v.forEach((x, i) => p.append(`${k}[${i}]`, String(x)));
    else p.append(k, typeof v === 'boolean' ? (v ? 'true' : 'false') : String(v));
  }
  return p.toString();
}

export class PleskWeb {
  /**
   * @param {{host:string, port?:number, username:string, password:string, pinnedIp?:string, timeoutMs?:number}} opts
   */
  constructor({ host, port = 8443, username, password, pinnedIp, timeoutMs = 60000 }) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new UserError('The saved connection has an invalid panel port. Ask the user to run `connect` again.');
    if (!/^[a-z0-9_.@-]{1,60}$/i.test(String(username || ''))) throw new UserError('The Plesk username contains characters that are not allowed.');
    if (!password) throw new UserError('Internal error: no Plesk password for the web session.');
    const ip = pinnedIp || (isIP(host) ? host : null);
    if (!ip) throw new UserError('Internal error: no verified kapaweb server address for this connection. Ask the user to run `connect` again.');
    this.host = host;
    this.port = port;
    this.username = String(username);
    this.timeoutMs = timeoutMs;
    this.target = connectTarget(host, port, ip);
    this.cookies = new Map();
    this.token = null;
    this.loggedIn = false;
    this._loginPromise = null; // calls that arrive together share one login (two logins would invalidate each other's token)
    this.loginFailed = false; // the password was refused: no further attempts (they can get the address blocked)
    this._password = String(password);
    redactor.add(this._password);
  }

  #guard() {
    if (this.loginFailed) {
      throw new UserError('Plesk refused the saved login earlier in this session. Ask the user to run `connect` again (do not retry: repeated failures can get their IP blocked).');
    }
    if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0' && process.env.KAPAWEB_CONNECTOR_TEST !== '1') {
      throw new UserError('TLS certificate checking is switched off in this environment (NODE_TLS_REJECT_UNAUTHORIZED=0), so the connector will not send a password. Remove that setting and try again.');
    }
  }

  /**
   * One HTTP request to the pinned panel address; redirects are NOT followed. Resolves { status, headers, buffer, text }.
   *  - body: string | Buffer, sent as is
   *  - upload: { path, size, field, filename, fields } a file streamed from disk as one multipart part (constant memory)
   *  - saveTo: a successful non-JSON, non-HTML answer is streamed to this file (constant memory); resolves { saved: bytes }
   */
  #send(method, path, { headers = {}, body, binary = false, upload, saveTo, timeoutMs } = {}) {
    const t = this.target;
    const lib = t.https ? https : http;
    const cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    let buf = body === undefined ? null : Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
    let head = null;
    let tail = null;
    const hdrs = { ...headers };
    if (upload) {
      const boundary = '----kapaweb' + randomBytes(12).toString('hex');
      const fields = Object.entries(upload.fields || {}).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join('');
      const filename = String(upload.filename).replace(/["\r\n\\]/g, '_');
      head = Buffer.from(`${fields}--${boundary}\r\nContent-Disposition: form-data; name="${upload.field}"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`, 'utf8');
      tail = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8');
      hdrs['Content-Type'] = `multipart/form-data; boundary=${boundary}`;
      hdrs['Content-Length'] = head.length + upload.size + tail.length;
      buf = null;
    }
    const options = {
      method,
      host: t.connectHost,
      port: t.connectPort,
      path,
      headers: {
        'User-Agent': `kapaweb-connector/${VERSION}`,
        Accept: 'application/json, text/html;q=0.9, */*;q=0.5',
        ...(cookie ? { Cookie: cookie } : {}),
        ...(buf ? { 'Content-Length': buf.length } : {}),
        ...hdrs,
        Host: t.hostHeader,
      },
      timeout: timeoutMs || this.timeoutMs,
    };
    if (t.https) options.servername = t.servername;
    const part = saveTo ? `${saveTo}.part` : null;
    return new Promise((resolve, reject) => {
      const req = lib.request(options, (res) => {
        const type = String(res.headers['content-type'] || '');
        if (saveTo && res.statusCode === 200 && !/json|text\/html/i.test(type)) {
          // a file: straight to disk
          const out = createWriteStream(part);
          let bytes = 0;
          res.on('data', (c) => (bytes += c.length));
          res.on('error', (e) => out.destroy(e));
          out.on('error', reject);
          out.on('finish', () => resolve({ status: 200, headers: res.headers, saved: bytes, buffer: Buffer.alloc(0), text: '' }));
          res.pipe(out);
          return;
        }
        const chunks = [];
        let size = 0;
        res.on('data', (c) => {
          size += c.length;
          if (size > MAX_BODY_BYTES) return req.destroy(new Error('too_large'));
          chunks.push(c);
        });
        res.on('end', () => {
          const buffer = Buffer.concat(chunks);
          resolve({ status: res.statusCode, headers: res.headers, buffer, text: binary && !/text\/html|json/i.test(type) ? '' : buffer.toString('utf8') });
        });
        res.on('error', reject);
      });
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.on('error', reject);
      if (upload) {
        req.write(head);
        const rs = createReadStream(upload.path);
        rs.on('error', (e) => req.destroy(e));
        rs.on('end', () => req.end(tail));
        rs.pipe(req, { end: false });
      } else {
        req.end(buf || undefined);
      }
    }).then(
      async (res) => {
        if (saveTo && res.saved !== undefined) await rename(part, saveTo);
        return res;
      },
      async (err) => {
        if (part) await rm(part, { force: true }).catch(() => {});
        throw err;
      },
    ).catch((err) => {
      const code = err?.code || '';
      if (err?.message === 'timeout') throw new UserError('Plesk did not answer in time. Try again in a moment.');
      if (err?.message === 'too_large') throw new UserError('Plesk sent an answer that is too large to read.');
      if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS/i.test(String(code))) {
        throw new UserError('Plesk presented a certificate that could not be verified, so the connection was refused for safety. Check the panel address.');
      }
      if (code === 'ENOENT' || code === 'EACCES') throw new UserError(`Could not read or write the local file (${code}).`);
      throw new UserError(`Could not reach Plesk (${code || err?.message || 'network error'}). Check the internet connection.`);
    });
  }

  #remember(res) {
    for (const [k, v] of cookiePairs(res.headers['set-cookie'])) {
      this.cookies.set(k, v);
      redactor.add(v);
    }
  }

  /** login(), but a login that is already under way is joined instead of started a second time. */
  #loginOnce() {
    if (!this._loginPromise) {
      this._loginPromise = this.login().finally(() => {
        this._loginPromise = null;
      });
    }
    return this._loginPromise;
  }

  /** Signs in like a browser does: login page (cookie + token), the form, then a page that carries the session's own token. */
  async login() {
    this.#guard();
    this.cookies.clear();
    this.token = null;
    this.loggedIn = false;
    const page = await this.#send('GET', LOGIN_PATH);
    this.#remember(page);
    const loginToken = extractForgeryToken(page.text);
    const form = new URLSearchParams({ login_name: this.username, passwd: this._password, locale_id: 'default' });
    if (loginToken) form.set('forgery_protection_token', loginToken);
    const post = await this.#send('POST', LOGIN_PATH, { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form.toString() });
    this.#remember(post);
    const where = String(post.headers.location || '');
    // A successful login answers with a redirect to a panel page; a refused one shows the login page again.
    if (!(post.status >= 300 && post.status < 400) || /login_up\.php/i.test(where)) {
      if (/two[- ]?factor|two[- ]?step|multi[- ]?factor|verification code|authenticator/i.test(post.text)) {
        throw new UserError('This Plesk login uses two-step verification, which the connector cannot complete. Ask kapaweb support.');
      }
      this.loginFailed = true;
      throw new PleskError('AUTH', 'Plesk did not accept the saved username and password for the panel login. Ask the user to run `connect` again.', 'login');
    }
    // the redirect target (followed through further redirects) is a panel page; it carries the token every later request must send
    let next = where || '/cp/home';
    let home = null;
    const trail = [];
    for (let hop = 0; hop < 6; hop++) {
      const path = /^https?:\/\//i.test(next) ? new URL(next).pathname + new URL(next).search : next.startsWith('/') ? next : '/' + next;
      home = await this.#send('GET', path);
      this.#remember(home);
      trail.push(`${home.status} ${path.split('?')[0]}`);
      if (home.status >= 300 && home.status < 400 && home.headers.location) {
        next = String(home.headers.location);
        continue;
      }
      break;
    }
    const token = extractForgeryToken(home.text);
    if (!token) {
      if (process.env.KAPAWEB_PLESK_DEBUG === '1') process.stderr.write(`[plesk-web] after login: ${trail.join(' -> ')}; html ${home.text.length} bytes; forgery mentions: ${(home.text.match(/forgery/gi) || []).length}; meta tags: ${(home.text.match(/<meta\b[^>]*>/gi) || []).map((m) => (/name=["']([^"']+)/.exec(m) || [])[1]).filter(Boolean).join(',')}\n`);
      throw new PleskError('PARSE', 'Plesk signed the login in but its page had no forgery-protection token, so requests cannot be sent.', 'login');
    }
    this.token = token;
    redactor.add(token);
    this.loggedIn = true;
  }

  /**
   * An XHR-style request with the session. JSON in (`json`) and out. One automatic fresh login when the session has expired.
   * @returns {Promise<{status:number, body:any}>} body is parsed when Plesk sent JSON, else the text
   */
  async request(method, path, { json, form, multipart, upload, saveTo, timeoutMs, binary = false, retry = true, page = false } = {}) {
    this.#guard();
    if (!this.loggedIn) await this.#loginOnce();
    // `page`: ask for the normal HTML page the way a browser does (no XHR headers), e.g. to read the panel's own script URLs
    const headers = page ? { Accept: 'text/html,*/*;q=0.8' } : { 'X-Requested-With': 'XMLHttpRequest', 'X-Forgery-Protection-Token': this.token, Accept: 'application/json' };
    let body;
    if (json !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(json);
    } else if (form !== undefined) {
      headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8';
      body = formEncode(form);
    } else if (multipart !== undefined) {
      // a FormData serialised by the runtime itself (boundary and file parts included): no hand-made multipart parser to get wrong
      const wrapped = new Response(multipart);
      headers['Content-Type'] = wrapped.headers.get('content-type');
      body = Buffer.from(await wrapped.arrayBuffer());
    }
    const res = await this.#send(method, path, { headers, body, binary, upload, saveTo, timeoutMs });
    this.#remember(res);
    const type = String(res.headers['content-type'] || '');
    // 401, a redirect to the login page, or the login form itself = the session ended. A plain 403 is NOT that: Plesk refuses
    // this login for this page (the panel's rights), and signing in again would only be refused again.
    // (a 400 that is not a JSON answer is Plesk's answer to a stale forgery token: another call has signed in again meanwhile)
    const staleToken = res.status === 400 && !/json/i.test(type);
    const expired = res.status === 401 || staleToken || (res.status >= 300 && res.status < 400 && /login_up\.php|\/login/i.test(String(res.headers.location || ''))) || (/text\/html/i.test(type) && /name=["']login_name["']/i.test(res.text));
    if (expired) {
      if (!retry) throw new PleskError('AUTH', 'Plesk ended the session and would not sign in again.', path);
      this.loggedIn = false;
      return this.request(method, path, { json, form, multipart, upload, saveTo, timeoutMs, binary, retry: false, page });
    }
    if (res.saved !== undefined) return { status: res.status, body: { saved: saveTo, bytes: res.saved }, headers: res.headers };
    if (binary && res.status < 400 && !/json|text\/html/i.test(type)) return { status: res.status, body: res.buffer, headers: res.headers };
    let parsed = res.text;
    if (/json/i.test(type) && res.text) {
      try {
        parsed = JSON.parse(res.text);
      } catch {
        throw new PleskError('PARSE', 'Plesk sent a JSON answer that could not be read.', path);
      }
    }
    if (res.status === 403) {
      throw new PleskError('FORBIDDEN', 'Plesk does not allow this login to use that part of the panel (its permissions come from the hosting plan; an administrator can change them).', path, { status: 403 });
    }
    if (res.status >= 400) {
      const message = (parsed && typeof parsed === 'object' && (parsed.message || parsed.error)) || `Plesk answered with status ${res.status}.`;
      throw new PleskError(String(res.status), String(message).slice(0, 400), path, { status: res.status });
    }
    return { status: res.status, body: parsed, headers: res.headers };
  }
}
