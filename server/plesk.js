// Plesk client: the XML API ("XML-RPC") at /enterprise/control/agent.php, the part of Plesk a CUSTOMER may use.
// Plesk's REST API (/api/v2) is for the administrator only and is deliberately not used here. No dependencies.
//
// Credentials travel in the HTTP_AUTH_LOGIN / HTTP_AUTH_PASSWD headers (or one KEY header for a Plesk secret key).
// Unlike a DirectAdmin login key, a Plesk login or secret key is NOT restricted to a list of commands, so what is
// stored for a Plesk account has the rights of the customer's whole Plesk login (see PLESK_SUPPORT.md).
//
// STATUS: the protocol mechanics (headers, packets, parsing, error mapping, host pinning, redaction) are covered by tests
// against a fake panel (test/mock-plesk.js). The OPERATION packets below were written from Plesk's documentation and have
// NOT yet been run against a real Plesk server with a customer login — do not describe them as proven.
import http from 'node:http';
import https from 'node:https';
import { isIP } from 'node:net';
import { connectTarget } from './da.js';
import { UserError, VERSION, redactor } from './util.js';

export const PLESK_PORT = 8443;
export const ENDPOINT = '/enterprise/control/agent.php';
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const MAX_NODES = 200000;

/** The Plesk XML API said no (an `error` status in a result), or its answer could not be understood. */
export class PleskError extends Error {
  constructor(code, message, operation, details = {}) {
    super(message);
    this.name = 'PleskError';
    this.code = code; // Plesk's numeric errcode as a string, 'AUTH' for a refused login, 'FORBIDDEN' for HTTP 403, 'PARSE' for an unreadable answer
    this.operation = operation;
    this.status = details.status; // the HTTP status, when that is what refused
    this.errcode = details.errcode; // Plesk's own errcode, when it sent one (kept for the journal: not secret)
  }
}

// ---------------------------------------------------------------------------------------------------- building packets

/** Escapes text for use inside an XML element. */
export function esc(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]);
}

/** Already-built XML. tag() returns one, so nesting tag() calls never escapes the inner markup; plain strings are text. */
class Xml {
  constructor(text) {
    this.text = text;
  }
  toString() {
    return this.text;
  }
}
/** Marks a string you built yourself as XML (inserted as is). Never use it for text that came from a user. */
export const raw = (xml) => new Xml(String(xml));

/** <name>children</name>. `children`: tag() results (kept as XML), or a string/number leaf (escaped), or an array of these. */
export function tag(name, children = '') {
  if (!/^[A-Za-z][\w-]*$/.test(name)) throw new UserError(`Internal error: bad XML element name ${JSON.stringify(name)}.`);
  const inner = (Array.isArray(children) ? children : [children]).map((c) => (c instanceof Xml ? c.text : esc(c))).join('');
  return new Xml(inner === '' ? `<${name}/>` : `<${name}>${inner}</${name}>`);
}

/** Wraps operations in a <packet>. The version attribute is left out on purpose: Plesk then uses its newest protocol. */
export function packet(...operations) {
  return `<?xml version="1.0" encoding="UTF-8"?><packet>${operations.map(String).join('')}</packet>`;
}

// ------------------------------------------------------------------------------------------------------------ parsing

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
function decode(text) {
  return text.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (m, e) => {
    if (e[0] === '#') {
      const cp = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isInteger(cp) && cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

/**
 * A small XML reader for Plesk's answers: elements, text, CDATA, attributes (kept, rarely needed), comments and the XML
 * declaration. A DOCTYPE / ENTITY declaration is refused (nothing is ever expanded, and Plesk never sends one).
 * @returns {{name:string, attrs:Record<string,string>, text:string, children:object[]}} the root element
 */
export function parseXml(xml) {
  const src = String(xml);
  if (/<!DOCTYPE|<!ENTITY/i.test(src)) throw new PleskError('PARSE', 'The Plesk answer contained a DOCTYPE or ENTITY declaration, which is not accepted.');
  const tokens = /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!\[CDATA\[([\s\S]*?)\]\]>|<(\/?)([A-Za-z_][\w:.-]*)((?:\s+[\w:.-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>|([^<]+)/g;
  const root = { name: '#root', attrs: {}, text: '', children: [] };
  const stack = [root];
  let nodes = 0;
  let m;
  let last = 0;
  while ((m = tokens.exec(src))) {
    if (m.index !== last) throw new PleskError('PARSE', 'The Plesk answer is not valid XML.');
    last = tokens.lastIndex;
    const top = stack[stack.length - 1];
    if (m[0].startsWith('<!--') || m[0].startsWith('<?')) continue;
    if (m[1] !== undefined) {
      top.text += m[1];
    } else if (m[3] !== undefined) {
      if (m[2] === '/') {
        if (stack.length < 2 || top.name !== m[3]) throw new PleskError('PARSE', 'The Plesk answer is not valid XML (mismatched tags).');
        stack.pop();
      } else {
        if (++nodes > MAX_NODES) throw new PleskError('PARSE', 'The Plesk answer is too large to read.');
        const attrs = {};
        for (const a of m[4].matchAll(/([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) attrs[a[1]] = decode(a[2] ?? a[3]);
        const node = { name: m[3], attrs, text: '', children: [] };
        top.children.push(node);
        if (m[5] !== '/') stack.push(node);
      }
    } else if (m[6] !== undefined) {
      top.text += decode(m[6]);
    }
  }
  if (last !== src.length || stack.length !== 1) throw new PleskError('PARSE', 'The Plesk answer is not valid XML (it ends early).');
  if (root.children.length !== 1) throw new PleskError('PARSE', 'The Plesk answer is not a single XML document.');
  return root.children[0];
}

/** First direct child called `name`, or undefined. */
export const child = (node, name) => node?.children.find((c) => c.name === name);
/** Text of the first direct child called `name` (trimmed), or undefined. */
export const childText = (node, name) => child(node, name)?.text.trim();
/** Every descendant called `name`, in document order. */
export function findAll(node, name, out = []) {
  for (const c of node?.children || []) {
    if (c.name === name) out.push(c);
    findAll(c, name, out);
  }
  return out;
}

/** Throws a PleskError for the first failed result (or a refused login) in an answer packet; returns the packet otherwise. */
export function assertOk(root, operation) {
  if (root.name !== 'packet') throw new PleskError('PARSE', `The Plesk answer is not a <packet> (got <${root.name}>).`, operation);
  const system = child(root, 'system');
  if (system && childText(system, 'status') === 'error') {
    const code = childText(system, 'errcode') || '';
    throw new PleskError(code === '1001' ? 'AUTH' : code || 'ERROR', childText(system, 'errtext') || 'Plesk refused the request.', operation, { errcode: code });
  }
  for (const r of findAll(root, 'result')) {
    if (childText(r, 'status') === 'error') {
      throw new PleskError(childText(r, 'errcode') || 'ERROR', childText(r, 'errtext') || 'Plesk could not do that.', operation);
    }
  }
  return root;
}

// ------------------------------------------------------------------------------------------------------------- client

export class PleskClient {
  /**
   * @param {{host:string, port?:number, username?:string, password?:string, key?:string, pinnedIp?:string, timeoutMs?:number}} opts
   *   Either password (with username) or key (a Plesk secret key). pinnedIp: the address verifyPanelHost approved.
   */
  constructor({ host, port = PLESK_PORT, username, password, key, pinnedIp, timeoutMs = 60000 }) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new UserError('The saved connection has an invalid panel port. Ask the user to run `connect` again.');
    if (username !== undefined && !/^[a-z0-9_.@-]{1,60}$/i.test(String(username))) throw new UserError('The Plesk username contains characters that are not allowed.');
    const ip = pinnedIp || (isIP(host) ? host : null);
    if (!ip) throw new UserError('Internal error: no verified kapaweb server address for this connection. Ask the user to run `connect` again.');
    if (!key && !(username && password)) throw new UserError('A Plesk username and password (or a secret key) are needed.');
    this.host = host;
    this.port = port;
    this.pinnedIp = ip;
    this.target = connectTarget(host, port, ip);
    this.timeoutMs = timeoutMs;
    this.authFailed = false;
    if (key) {
      this._auth = { KEY: String(key) };
      redactor.add(String(key));
    } else {
      this._auth = { HTTP_AUTH_LOGIN: String(username), HTTP_AUTH_PASSWD: String(password) };
      redactor.add(String(password));
    }
  }

  #guard() {
    if (this.authFailed) {
      throw new UserError('Plesk refused the saved login earlier in this session. Ask the user to run `connect` again (do not retry: repeated failures can get their IP blocked).');
    }
    if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0' && process.env.KAPAWEB_CONNECTOR_TEST !== '1') {
      throw new UserError('TLS certificate checking is switched off in this environment (NODE_TLS_REJECT_UNAUTHORIZED=0), so the connector will not send a password or key. Remove that setting and try again.');
    }
  }

  /**
   * Sends one XML packet and returns the parsed, checked answer (the <packet> element). Throws PleskError when Plesk
   * reports an error, UserError for network trouble.
   * @param {string} xml a built packet (see packet())
   * @param {string} [operation] label for error messages, e.g. 'database.get-db'
   */
  async call(xml, operation = 'request') {
    this.#guard();
    const body = Buffer.from(xml, 'utf8');
    const t = this.target;
    const lib = t.https ? https : http;
    const options = {
      method: 'POST',
      host: t.connectHost,
      port: t.connectPort,
      path: ENDPOINT,
      headers: {
        ...this._auth,
        Host: t.hostHeader,
        'Content-Type': 'text/xml',
        'Content-Length': body.length,
        Accept: 'text/xml',
        'User-Agent': `kapaweb-connector/${VERSION}`,
      },
      timeout: this.timeoutMs,
    };
    if (t.https) options.servername = t.servername;
    const { status, text } = await new Promise((resolve, reject) => {
      const req = lib.request(options, (res) => {
        const chunks = [];
        let size = 0;
        res.on('data', (c) => {
          size += c.length;
          if (size > MAX_RESPONSE_BYTES) return req.destroy(new Error('too_large'));
          chunks.push(c);
        });
        res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
        res.on('error', reject);
      });
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.on('error', reject);
      req.end(body);
    }).catch((err) => {
      const code = err?.code || '';
      if (err?.message === 'timeout') throw new UserError('Plesk did not answer in time. Try again in a moment.');
      if (err?.message === 'too_large') throw new UserError('Plesk sent an answer that is too large to read.');
      if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS/i.test(String(code))) {
        throw new UserError('Plesk presented a certificate that could not be verified, so the connection was refused for safety. Check the panel address.');
      }
      throw new UserError(`Could not reach Plesk (${code || err?.message || 'network error'}). Check the internet connection.`);
    });
    if (status === 401) {
      this.authFailed = true;
      throw new PleskError('AUTH', 'Plesk refused the login (HTTP 401): the password or key may be wrong. Ask the user to run `connect` again.', operation, { status });
    }
    if (status === 403) {
      // Not necessarily a wrong password: Plesk's XML API can be switched off, or limited to certain IP addresses.
      this.authFailed = true;
      throw new PleskError('FORBIDDEN', 'Plesk refused the request (HTTP 403). The password is not necessarily wrong: Plesk\'s XML API may be switched off for this login or limited to certain IP addresses.', operation, { status });
    }
    if (status >= 500) throw new UserError(`Plesk answered with an error (status ${status}). Try again in a minute; if it keeps happening, contact kapaweb support.`);
    if (status !== 200) throw new PleskError('HTTP', `Plesk answered with status ${status}.`, operation);
    let root;
    try {
      root = parseXml(text);
    } catch (err) {
      if (err instanceof PleskError) err.operation = operation;
      throw err;
    }
    try {
      return assertOk(root, operation);
    } catch (err) {
      if (err instanceof PleskError && err.code === 'AUTH') this.authFailed = true;
      throw err;
    }
  }

  // -- Packets below follow Plesk's XML API documentation; NOT yet run against a real Plesk server with a customer login. --

  /**
   * Asks Plesk for a new secret key for the login this client signed in with, and returns the key. A secret key has the
   * same rights as the login itself (Plesk cannot restrict it), so it is only ever stored in the OS keychain.
   * @param {string} description shown in Plesk next to the key, so the customer can recognise and delete it
   */
  async createSecretKey(description) {
    const root = await this.call(packet(tag('secret_key', tag('create', [tag('description', String(description).slice(0, 100))]))), 'secret_key.create');
    const key = findAll(root, 'result').map((r) => childText(r, 'key')).find(Boolean);
    if (!key || !/^[A-Za-z0-9._-]{8,128}$/.test(key)) throw new PleskError('PARSE', 'Plesk did not return a usable key.', 'secret_key.create');
    return key;
  }

  /** Deletes the secret key this client uses (or, with `key`, another one). Resolves true when Plesk confirmed it. */
  async revokeSecretKey(key = this._auth.KEY) {
    if (!key) throw new UserError('Internal error: no secret key to revoke.');
    await this.call(packet(tag('secret_key', tag('delete', tag('filter', tag('key', key))))), 'secret_key.delete');
    return true;
  }

  /** True when this login is a Plesk administrator (it may read server information; a customer may not). */
  async isAdministrator() {
    try {
      await this.call(packet(tag('server', tag('get', tag('gen_info')))), 'server.get');
      return true;
    } catch (err) {
      if (err instanceof PleskError && err.code !== 'AUTH') return false; // "no permission" is the answer a customer gets
      throw err;
    }
  }

  // -- read-only operations --

  /** The subscriptions (webspaces) of this login: [{ id, name }]. */
  async webspaces() {
    let root;
    try {
      root = await this.call(packet(tag('webspace', tag('get', [tag('filter'), tag('dataset', tag('gen_info'))]))), 'webspace.get');
    } catch (err) {
      if (err instanceof PleskError && err.code === '1013') return []; // "object not found": a login with no subscription yet
      throw err;
    }
    return findAll(root, 'result')
      .filter((r) => childText(r, 'status') === 'ok' && child(r, 'data'))
      .map((r) => {
        const info = child(child(r, 'data'), 'gen_info');
        const ip = childText(info, 'dns_ip_address');
        return { id: childText(r, 'id'), name: childText(info, 'name'), ...(ip ? { ip } : {}) };
      })
      .filter((w) => w.id);
  }

  /** The databases of one subscription: [{ id, name, type }]. */
  async databases(webspaceId) {
    if (!/^\d{1,12}$/.test(String(webspaceId))) throw new UserError('Internal error: bad subscription id.');
    const root = await this.call(packet(tag('database', tag('get-db', tag('filter', tag('webspace-id', webspaceId))))), 'database.get-db');
    return findAll(root, 'result')
      .filter((r) => childText(r, 'status') === 'ok' && childText(r, 'id'))
      .map((r) => ({ id: childText(r, 'id'), name: childText(r, 'name'), type: childText(r, 'type') }));
  }

  // -- databases (XML API "database" operations; whether a customer may use them depends on the hosting plan) --

  /** Creates a database in a subscription and returns its id. type: 'mysql' | 'postgresql'. */
  async createDatabase({ webspaceId, name, type }) {
    if (!/^\d{1,12}$/.test(String(webspaceId))) throw new UserError('Internal error: bad subscription id.');
    if (!['mysql', 'postgresql'].includes(type)) throw new UserError('Internal error: bad database type.');
    const root = await this.call(packet(tag('database', tag('add-db', [tag('webspace-id', webspaceId), tag('name', name), tag('type', type)]))), 'database.add-db');
    const id = findAll(root, 'result').map((r) => childText(r, 'id')).find(Boolean);
    if (!id) throw new PleskError('PARSE', 'Plesk did not return the id of the new database.', 'database.add-db');
    return id;
  }

  /** Creates a database user (login + password) for a database and returns its id. */
  async createDatabaseUser({ databaseId, login, password }) {
    if (!/^\d{1,12}$/.test(String(databaseId))) throw new UserError('Internal error: bad database id.');
    const root = await this.call(packet(tag('database', tag('add-db-user', [tag('db-id', databaseId), tag('login', login), tag('password', password)]))), 'database.add-db-user');
    const id = findAll(root, 'result').map((r) => childText(r, 'id')).find(Boolean);
    if (!id) throw new PleskError('PARSE', 'Plesk did not return the id of the new database user.', 'database.add-db-user');
    return id;
  }

  /** The users of one database: [{ id, login }]. */
  async databaseUsers(databaseId) {
    if (!/^\d{1,12}$/.test(String(databaseId))) throw new UserError('Internal error: bad database id.');
    let root;
    try {
      root = await this.call(packet(tag('database', tag('get-db-users', tag('filter', tag('db-id', databaseId))))), 'database.get-db-users');
    } catch (err) {
      if (err instanceof PleskError && err.code === '1013') return [];
      throw err;
    }
    return findAll(root, 'result').filter((r) => childText(r, 'status') === 'ok' && childText(r, 'id')).map((r) => ({ id: childText(r, 'id'), login: childText(r, 'login') }));
  }

  async dropDatabaseUser(id) {
    if (!/^\d{1,12}$/.test(String(id))) throw new UserError('Internal error: bad database user id.');
    await this.call(packet(tag('database', tag('del-db-user', tag('filter', tag('id', id))))), 'database.del-db-user');
  }

  async dropDatabase(id) {
    if (!/^\d{1,12}$/.test(String(id))) throw new UserError('Internal error: bad database id.');
    await this.call(packet(tag('database', tag('del-db', tag('filter', tag('id', id))))), 'database.del-db');
  }

  // -- web roots --

  /**
   * The document roots of a subscription: [{ domain, path }], path relative to the subscription's own folder ("/httpdocs").
   * The main domain is proven on a real server; add-on domains ("site") and subdomains use the documented filters and have not been
   * run against one yet. A property of the hosting record that is sensitive (the FTP password) is never read out of it.
   */
  async webRoots(webspaceId) {
    if (!/^\d{1,12}$/.test(String(webspaceId))) throw new UserError('Internal error: bad subscription id.');
    const rel = (www, name) => {
      const v = String(www || '');
      if (!v) return null;
      const stripped = v.replace(/^\/var\/www\/vhosts\/[^/]+/, '');
      const path = stripped.startsWith('/') ? stripped : '/' + stripped;
      return path.replace(/\/+$/, '') || '/';
    };
    const wwwOf = (node) => {
      const hosting = child(node, 'hosting');
      const vrt = hosting && child(hosting, 'vrt_hst');
      if (!vrt) return null;
      for (const p of findAll(vrt, 'property')) if (childText(p, 'name') === 'www_root') return childText(p, 'value');
      return null;
    };
    const out = [];
    const tryCall = async (p, op) => {
      try {
        return await this.call(p, op);
      } catch (err) {
        if (err instanceof PleskError && ['1013', '1014', '1006'].includes(err.code)) return null;
        throw err;
      }
    };
    const main = await this.call(packet(tag('webspace', tag('get', [tag('filter', tag('id', webspaceId)), tag('dataset', [tag('gen_info'), tag('hosting')])]))), 'webspace.get');
    for (const r of findAll(main, 'result')) {
      const data = child(r, 'data');
      const path = data && rel(wwwOf(data));
      const name = data && childText(child(data, 'gen_info'), 'name');
      if (path && name) out.push({ domain: name, path });
    }
    const sites = await tryCall(packet(tag('site', tag('get', [tag('filter', tag('parent-id', webspaceId)), tag('dataset', [tag('gen_info'), tag('hosting')])]))), 'site.get');
    if (sites) {
      for (const r of findAll(sites, 'result')) {
        const data = child(r, 'data');
        const path = data && rel(wwwOf(data));
        const name = data && childText(child(data, 'gen_info'), 'name');
        if (path && name) out.push({ domain: name, path });
      }
    }
    const subs = await tryCall(packet(tag('subdomain', tag('get', tag('filter', tag('parent-id', webspaceId))))), 'subdomain.get');
    if (subs) {
      for (const r of findAll(subs, 'result')) {
        const data = child(r, 'data');
        const name = data && childText(data, 'name');
        let path = null;
        if (data) for (const p of findAll(data, 'property')) if (childText(p, 'name') === 'www_root') path = rel(childText(p, 'value'));
        if (path && name) out.push({ domain: name, path });
      }
    }
    return out;
  }
}
