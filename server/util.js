// Shared helpers: errors, random secrets, redaction, small validators.
import { randomBytes, randomInt } from 'node:crypto';

export const VERSION = '0.7.0';
export const PLAYBOOK_URL = 'https://kapaweb.gr/deploy-with-ai/playbook.md';

/** An error whose message is meant to be read by the AI (and the user) verbatim. */
export class UserError extends Error {
  constructor(message, code = 'USER_ERROR') {
    super(message);
    this.name = 'UserError';
    this.code = code;
  }
}

export class NotConnectedError extends UserError {
  constructor(message) {
    super(
      message ||
        'Not connected to a kapaweb hosting account yet. Call the `connect` tool: it opens a page on the user\'s own computer where they sign in once. Never ask the user for a password in the chat.',
      'NOT_CONNECTED',
    );
  }
}

/** The identity of a hosting account: its DirectAdmin username on its panel ("homeburger@ssd5.kdns.gr"). */
export function accountId(conn) {
  return `${String(conn?.username || '').toLowerCase()}@${String(conn?.panelHost || '').toLowerCase()}`;
}

/**
 * Where an account's secrets live in the protected storage: `kind` is 'key' (its login key), 'db' (a database password) or
 * 'secret' (a secret stored with secret_set). The account that was connected before several accounts were supported keeps
 * its old, unprefixed names (`legacy`): nothing has to be moved, so an upgrade can never lose a key.
 */
export function secretName(conn, kind, name = '') {
  const id = conn.id || accountId(conn);
  if (kind === 'key') return conn.legacy ? 'loginKey' : `loginKey:${id}`;
  return conn.legacy ? `${kind}:${name}` : `${kind}:${id}:${name}`;
}

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const LOWER = 'abcdefghijklmnopqrstuvwxyz0123456789';

export function randomToken(bytes = 24) {
  return randomBytes(bytes).toString('hex');
}

export function randomAlnum(length = 32) {
  let out = '';
  for (let i = 0; i < length; i++) out += ALNUM[randomInt(ALNUM.length)];
  return out;
}

export function randomLower(length = 8) {
  let out = '';
  for (let i = 0; i < length; i++) out += LOWER[randomInt(LOWER.length)];
  return out;
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

export function truncate(text, max) {
  const s = String(text);
  if (s.length <= max) return s;
  return s.slice(0, max) + `\n… [truncated, ${s.length - max} more characters]`;
}

// ---------------------------------------------------------------------------
// Redaction: nothing that looks like a secret may reach the AI or the logs.
// ---------------------------------------------------------------------------

const PEM = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g;
const AUTH_HEADER = /(authorization\s*[:=]\s*)(basic|bearer)\s+[A-Za-z0-9+/=._-]+/gi;
const KEY_VALUE =
  /((?:pass(?:word|wd|phrase)?|pwd|pw|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?key|salt|credential)['"]?\s*(?:=>|[:=,])\s*['"]?)([^\s'",;)]{4,})/gi;
// dotenv style names that end in a secret-ish word: MAIL_PW=..., STRIPE_SK=..., APP_KEY=...
const ENV_STYLE = /(\b[A-Z][A-Z0-9_]*(?:_KEY|_SK|_PW|_PASS|_PASSWORD|_SECRET|_TOKEN|_SALT)\b\s*[=:]\s*['"]?)([^\s'",;)]{4,})/g;
// scheme://user:secret@host (mysql://, https://, redis://...) and mysqldump -pSECRET
// (bounded on purpose: an unbounded scheme makes a long run of "a-a-a-..." cost quadratic time)
const URL_CREDENTIALS = /(\b[a-z][a-z0-9+.-]{0,30}:\/\/[^\s:@/]{1,100}:)([^\s@/]{1,200})(@)/gi;
const DASH_P = /(\bmysql\w*\b[^\n]*?\s-p)(?!id-file|retty)([^\s'"-][^\s'"]{3,})/g;
const SECRET_KEY_NAME = /pass(word|wd|phrase)?$|^pwd$|^pw$|secret|token|api[_-]?key|private[_-]?key|authorization|cookie|session(id)?$|^key$|login[_-]?key|^otp$|credential/i;
// {{KW_DB_PASSWORD:<db>}}, {{KW_SECRET:<name>}} and {{KW_RANDOM:<n>}} are instructions for write_file, not secrets: they
// must reach the AI intact (the key/value rules above would otherwise turn "PASSWORD:mydb}}" into "PASSWORD:[redacted]"
// and break the config). The name charset here must match every placeholder name's own validation (secret_set allows
// dots and hyphens too, for domain-like names such as "example.gr-wp-app").
const PLACEHOLDER = /\{\{KW_[A-Z_]+:[A-Za-z0-9_.-]+\}\}/g;
const MARK = String.fromCharCode(1);

export class Redactor {
  #secrets = new Set();

  /** Register an exact secret value (login key, database password...). */
  add(value) {
    if (typeof value === 'string' && value.length >= 6) this.#secrets.add(value);
  }

  /**
   * Forget an exact value again. The human-chosen account password is registered only while it is being used:
   * kept longer it would work as a guessing oracle (write a guess to a file, read it back, look for "[redacted]").
   */
  remove(value) {
    this.#secrets.delete(value);
  }

  text(input) {
    const kept = [];
    // the sentinel character never occurs in real output; if hostile text contains it, it is dropped
    let out = String(input).split(MARK).join('').replace(PLACEHOLDER, (m) => {
      kept.push(m);
      return MARK + (kept.length - 1) + MARK;
    });
    for (const s of this.#secrets) out = out.split(s).join('[redacted]');
    out = out.replace(PEM, '[redacted private key]');
    out = out.replace(AUTH_HEADER, '$1$2 [redacted]');
    // group 2 is the secret value; a value that is one of the protected placeholders is left alone
    const scrub = (re, tail = '') => {
      out = out.replace(re, (m, before, value, after) => (value.startsWith(MARK) ? m : `${before}[redacted]${tail ? after : ''}`));
    };
    scrub(URL_CREDENTIALS, 'after');
    scrub(KEY_VALUE);
    scrub(ENV_STYLE);
    scrub(DASH_P);
    if (kept.length) out = out.replace(new RegExp(`${MARK}(\\d+)${MARK}`, 'g'), (_m, i) => kept[Number(i)]);
    return out;
  }

  /** Deep copy of a JSON value with secret-looking keys blanked and strings scrubbed. */
  json(value, depth = 0) {
    if (depth > 12) return '[too deep]';
    if (typeof value === 'string') return this.text(value);
    if (Array.isArray(value)) return value.map((v) => this.json(v, depth + 1));
    if (isPlainObject(value)) {
      const out = {};
      for (const [k, v] of Object.entries(value)) {
        if (typeof v === 'string' && v && SECRET_KEY_NAME.test(k)) out[k] = '[redacted]';
        else if (v && typeof v === 'object' && /^(secrets?|credentials?)$/i.test(k)) out[k] = '[redacted]';
        else out[k] = this.json(v, depth + 1);
      }
      return out;
    }
    return value;
  }
}

export const redactor = new Redactor();

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

export function reqString(args, name, { max = 4096, pattern, what } = {}) {
  const v = args?.[name];
  if (typeof v !== 'string' || v.trim() === '') throw new UserError(`Missing or invalid argument "${name}" (expected a non-empty string).`);
  if (v.length > max) throw new UserError(`Argument "${name}" is too long.`);
  if (pattern && !pattern.test(v)) throw new UserError(`Argument "${name}" ${what || 'has an invalid format'}.`);
  return v;
}

export function optString(args, name, opts = {}) {
  const v = args?.[name];
  if (v === undefined || v === null || v === '') return undefined;
  return reqString(args, name, opts);
}

export function optBool(args, name, dflt = false) {
  const v = args?.[name];
  if (v === undefined || v === null) return dflt;
  if (typeof v !== 'boolean') throw new UserError(`Argument "${name}" must be true or false.`);
  return v;
}

export function optInt(args, name, dflt, { min = -Infinity, max = Infinity } = {}) {
  const v = args?.[name];
  if (v === undefined || v === null) return dflt;
  if (!Number.isInteger(v) || v < min || v > max) throw new UserError(`Argument "${name}" must be an integer between ${min} and ${max}.`);
  return v;
}

/** An optional array of strings: absent means [], but a wrong type is an error (a string must not silently become []). */
export function optStringArray(args, name, { max = 200, itemMax = 4096 } = {}) {
  const v = args?.[name];
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) throw new UserError(`Argument "${name}" must be an array of strings.`);
  if (v.length > max) throw new UserError(`Argument "${name}" has too many items (max ${max}).`);
  for (const item of v) {
    if (typeof item !== 'string' || item === '' || item.length > itemMax) throw new UserError(`Argument "${name}" must contain only non-empty strings.`);
  }
  return v;
}

export function reqStringArray(args, name, { max = 200, itemMax = 4096 } = {}) {
  const v = args?.[name];
  if (!Array.isArray(v) || v.length === 0) throw new UserError(`Argument "${name}" must be a non-empty array of strings.`);
  if (v.length > max) throw new UserError(`Argument "${name}" has too many items (max ${max}).`);
  for (const item of v) {
    if (typeof item !== 'string' || item === '' || item.length > itemMax) throw new UserError(`Argument "${name}" must contain only non-empty strings.`);
  }
  return v;
}

/** Domain or subdomain name, lower-cased, punycode. */
export function reqDomain(args, name = 'domain') {
  const raw = reqString(args, name, { max: 253 });
  return normalizeDomain(raw, name);
}

export function normalizeDomain(raw, name = 'domain') {
  let d = String(raw).trim().toLowerCase().replace(/\.$/, '');
  try {
    d = new URL('http://' + d).hostname; // punycode + syntax check
  } catch {
    throw new UserError(`Argument "${name}" is not a valid domain name.`);
  }
  if (!/^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/.test(d) || d.includes('..')) {
    throw new UserError(`Argument "${name}" is not a valid domain name.`);
  }
  return d;
}

export function pretty(value) {
  return JSON.stringify(value, null, 2);
}
