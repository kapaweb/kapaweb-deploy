// A brake for wrong passwords. After LOCK_AFTER refused sign-ins in a row against one kapaweb panel, further sign-ins to that
// panel wait BASE_PAUSE_MS, and every new pause is twice as long as the one before (5, 10, 20, 40 ... minutes, at most 24 hours).
// It keeps the person from being blocked by the server's own brute-force defence, and it stops a runaway AI from asking them to
// retype in a loop. It is a courtesy, not a wall: whoever controls this computer can delete the file, and the real protection
// against password guessing is the firewall on the server. Only the panel host is stored, never a username or a password (people
// sometimes type the password into the username box).
import { appendFileSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { UserError } from './util.js';
import { configDir } from './store.js';

export const LOCK_AFTER = 3;
export const BASE_PAUSE_MS = 5 * 60 * 1000;
export const MAX_PAUSE_MS = 24 * 60 * 60 * 1000;
export const FORGET_AFTER_MS = 24 * 60 * 60 * 1000; // a day without a wrong password (counted from the end of a pause) starts over
const MAX_HOSTS = 20;
const HOST_RE = /^[a-z0-9.-]{1,120}$/;
const JOURNAL_MAX_BYTES = 64 * 1024;
const JOURNAL_KEEP_LINES = 200;

/** Sign-in is paused: the message says for how long. Extends UserError so it reaches the person as plain text. */
export class LockedError extends UserError {
  constructor(message, retryAfterMs) {
    super(message);
    this.name = 'LockedError';
    this.retryAfterMs = retryAfterMs;
  }
}

/** "about 5 minutes", "about 2 hours" (always rounded up, so nobody is told to come back too early). */
export function describeWait(ms) {
  const minutes = Math.max(1, Math.ceil(ms / 60000));
  if (minutes < 90) return `about ${minutes} minute${minutes === 1 ? '' : 's'}`;
  const hours = Math.ceil(minutes / 60);
  return `about ${hours} hour${hours === 1 ? '' : 's'}`;
}

let unsaved = null; // the state when the settings folder cannot be written: the brake then works for this process only

const stateFile = () => join(configDir(), 'lockout.json');

function load() {
  if (unsaved) return structuredClone(unsaved);
  const hosts = {};
  try {
    const raw = JSON.parse(readFileSync(stateFile(), 'utf8'));
    const src = raw && typeof raw === 'object' && raw.hosts && typeof raw.hosts === 'object' ? raw.hosts : {};
    const num = (v, max) => (Number.isFinite(v) && v >= 0 ? Math.min(v, max) : 0);
    for (const [host, e] of Object.entries(src)) {
      if (Object.keys(hosts).length >= MAX_HOSTS) break;
      if (!HOST_RE.test(host) || !e || typeof e !== 'object') continue;
      hosts[host] = { fails: num(e.fails, 1000), level: num(e.level, 64), lastFailAt: num(e.lastFailAt, 8.64e15), pausedUntil: num(e.pausedUntil, 8.64e15) };
    }
  } catch {
    /* no file yet, or a damaged one: start from nothing */
  }
  return hosts;
}

function save(hosts) {
  const body = JSON.stringify({ version: 1, hosts });
  try {
    const dir = configDir();
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tmp = join(dir, `lockout.${process.pid}.tmp`);
    writeFileSync(tmp, body, { mode: 0o600 });
    try {
      renameSync(tmp, stateFile());
    } catch {
      writeFileSync(stateFile(), body, { mode: 0o600 }); // a rename over an open file can fail on Windows
    }
    unsaved = null;
  } catch {
    unsaved = structuredClone(hosts);
  }
}

/** An entry that has been quiet for a day (and whose pause is over) is forgotten. */
function current(entry, now) {
  if (!entry) return null;
  if (now >= entry.pausedUntil && now - Math.max(entry.lastFailAt, entry.pausedUntil) >= FORGET_AFTER_MS) return null;
  return entry;
}

/** Is sign-in to this panel host paused right now? */
export function checkPaused(host, now = Date.now()) {
  const e = current(load()[host], now);
  if (!e || now >= e.pausedUntil) return { paused: false, retryAfterMs: 0 };
  return { paused: true, retryAfterMs: Math.min(e.pausedUntil - now, MAX_PAUSE_MS) }; // (a clock set back cannot lock anyone out for longer than a day)
}

/** Every host that is paused right now. */
export function pausedHosts(now = Date.now()) {
  const list = [];
  for (const [host, e] of Object.entries(load())) {
    if (now < e.pausedUntil) list.push({ host, retryAfterMs: Math.min(e.pausedUntil - now, MAX_PAUSE_MS) });
  }
  return list;
}

/** The panel refused a username/password. Returns { paused, pauseMs }: pauseMs > 0 when this refusal started a pause. */
export function recordRefused(host, now = Date.now()) {
  const hosts = load();
  const e = current(hosts[host], now) || { fails: 0, level: 0, lastFailAt: 0, pausedUntil: 0 };
  if (now < e.pausedUntil) return { paused: true, pauseMs: 0 }; // already paused (for example by a second copy of the connector)
  e.fails += 1;
  e.lastFailAt = now;
  let pauseMs = 0;
  if (e.fails >= LOCK_AFTER) {
    e.level += 1;
    pauseMs = Math.min(BASE_PAUSE_MS * 2 ** (e.level - 1), MAX_PAUSE_MS);
    e.pausedUntil = now + pauseMs;
    e.fails = 0;
  }
  hosts[host] = e;
  save(hosts);
  return { paused: pauseMs > 0, pauseMs };
}

/** The panel accepted the password: the slate is clean. */
export function recordSignedIn(host) {
  const hosts = load();
  if (!(host in hosts)) return;
  delete hosts[host];
  save(hosts);
}

/**
 * A small local journal of sign-in attempts (time, panel host, outcome; no username, no password), kept next to the settings
 * so the person or kapaweb support can see what happened. It stays on this computer; it is not sent anywhere.
 */
export function journal(host, result, extra = {}, now = Date.now()) {
  try {
    const dir = configDir();
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const file = join(dir, 'signin.log');
    appendFileSync(file, JSON.stringify({ t: new Date(now).toISOString(), host: host || null, result, ...extra }) + '\n', { mode: 0o600 });
    if (statSync(file).size > JOURNAL_MAX_BYTES) {
      const lines = readFileSync(file, 'utf8').trim().split('\n');
      writeFileSync(file, lines.slice(-JOURNAL_KEEP_LINES).join('\n') + '\n', { mode: 0o600 });
    }
  } catch {
    /* the journal is a convenience */
  }
}
