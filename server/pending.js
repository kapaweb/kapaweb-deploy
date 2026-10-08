// While `--connect` has a sign-in page open, this small file says so for every other connector process on this computer (the AI's
// next command, the MCP server after the restart): the user is signing in right now, and a second page would only confuse them.
// It holds no secret: the address of the page is never written down.
import { mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { alive } from './lock.js';
import { LIFETIME_MS } from './setup.js';
import { configDir } from './store.js';

const file = () => join(configDir(), 'sign-in-open.json');

/** This process has a sign-in page open. */
export function markSignInOpen() {
  try {
    mkdirSync(configDir(), { recursive: true, mode: 0o700 });
    writeFileSync(file(), JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }), { mode: 0o600 });
  } catch {
    // a convenience: without it a second page can be opened, nothing worse
  }
}

/** The page of this process is finished (signed in, refused, expired). A newer page of another process is left alone. */
export function clearSignInOpen() {
  try {
    if (JSON.parse(readFileSync(file(), 'utf8')).pid === process.pid) unlinkSync(file());
  } catch {
    // already gone
  }
}

/** { startedAt, seconds } while a sign-in page opened by ANOTHER process is still waiting for the user; otherwise null. */
export function signInOpen(now = Date.now()) {
  try {
    const { pid, startedAt } = JSON.parse(readFileSync(file(), 'utf8'));
    const age = now - Date.parse(startedAt);
    if (!Number.isInteger(pid) || pid === process.pid || !(age >= 0) || age > LIFETIME_MS || !alive(pid)) return null;
    return { startedAt, seconds: Math.round(age / 1000) };
  } catch {
    return null;
  }
}

/** "3 minutes ago" for a sign-in page that is still open. */
export function describeAgo(seconds) {
  if (seconds < 90) {
    const s = Math.max(seconds, 1);
    return `${s} second${s === 1 ? '' : 's'} ago`;
  }
  return `${Math.round(seconds / 60)} minutes ago`;
}
