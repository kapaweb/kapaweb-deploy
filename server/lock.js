// One lock file for every connector process on this computer: the MCP server an AI app started, and `--call` run from a shell.
// Two deploys of one account must never interleave, and the in-process queue of the MCP server cannot see another process.
// The lock is a safeguard, not a security boundary: if the settings folder cannot be written the operation runs without it.
import { mkdir, open, readFile, rm, stat, utimes } from 'node:fs/promises';
import { readFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { configDir } from './store.js';
import { UserError, sleep } from './util.js';

const WAIT_MS = 120_000; // how long a second operation waits for the first before it gives up
const HEARTBEAT_MS = 30_000; // the holder touches the file this often ...
const STALE_MS = 10 * 60_000; // ... so a file nobody has touched for this long is a leftover of a killed process
const CONTENTION = new Set(['EEXIST', 'EPERM', 'EBUSY', 'EACCES']); // Windows reports a file that is being deleted as EPERM
const MAX_VANISHED = 5; // "the file is in the way" but it is not there: the folder is not usable, so stop trying
const waitFor = () => (Number(process.env.KAPAWEB_CONNECTOR_LOCK_WAIT_MS) > 0 ? Number(process.env.KAPAWEB_CONNECTOR_LOCK_WAIT_MS) : WAIT_MS); // the variable is for tests

/** Is there a process with this id? (A process id can be reused, so callers also look at how old their file is.) */
export function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err?.code === 'EPERM'; // it exists, it is just not ours
  }
}

/** Reads the lock file. Returns null when it is gone. `stale` is true when its holder cannot be running any more. */
async function inspect(path, now = Date.now()) {
  let st;
  let held = null;
  try {
    st = await stat(path);
    held = JSON.parse(await readFile(path, 'utf8'));
  } catch {
    if (!st) return null;
  }
  const untouchedMs = now - st.mtimeMs;
  const pid = Number.isInteger(held?.pid) ? held.pid : null;
  // a file that is still empty was created a moment ago by a process that is about to write its pid
  const stale = untouchedMs > STALE_MS || (pid !== null && !alive(pid)) || (pid === null && untouchedMs > 10_000);
  return { pid, startedAt: held?.startedAt || null, stale };
}

/** Takes the lock file. Returns true when it is ours, false when someone else holds it; throws for anything else. */
async function tryCreate(path) {
  await mkdir(join(path, '..'), { recursive: true, mode: 0o700 });
  const handle = await open(path, 'wx', 0o600);
  try {
    await handle.writeFile(JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }));
  } catch (err) {
    await handle.close().catch(() => {});
    await rm(path, { force: true }).catch(() => {});
    throw err;
  }
  await handle.close();
}

/** Lets go of the lock, but only if it is still the one this process took (a lock that went stale may have been taken over). */
function release(path) {
  try {
    if (JSON.parse(readFileSync(path, 'utf8')).pid !== process.pid) return;
    unlinkSync(path);
  } catch {
    // already gone
  }
}

/**
 * Runs fn while this process holds the lock. Waits (and says so through onWait) when another process holds it, and gives up
 * with a plain message after two minutes. A lock left behind by a process that was killed is taken over.
 * @param {() => Promise<any>} fn
 * @param {{onWait?: (m:string)=>void, waitMs?: number}} [o]
 */
export async function withFileLock(fn, { onWait = () => {}, waitMs = waitFor() } = {}) {
  const path = join(configDir(), 'exclusive.lock');
  const deadline = Date.now() + waitMs;
  let told = false;
  let vanished = 0;
  for (;;) {
    try {
      await tryCreate(path);
      break;
    } catch (err) {
      if (!CONTENTION.has(err?.code)) return fn(); // the settings folder is not usable: run without the lock
      const held = await inspect(path);
      if (!held) {
        if (++vanished > MAX_VANISHED) return fn();
        await sleep(100); // released a moment ago, or being deleted: try again
        continue;
      }
      vanished = 0;
      if (held.stale) {
        await rm(path, { force: true }).catch(() => {});
        continue;
      }
      if (Date.now() >= deadline) {
        throw new UserError(
          `Another deploy, rollback or import of this account is still running (started ${held.startedAt || 'a moment ago'}, process ${held.pid ?? 'unknown'}). Wait for it to finish, then try again. Never run two at once.`,
        );
      }
      if (!told) {
        told = true;
        onWait('Another deploy, rollback or import is running: waiting for it to finish…');
      }
      await sleep(400);
    }
  }
  const beat = setInterval(() => utimes(path, new Date(), new Date()).catch(() => {}), HEARTBEAT_MS);
  beat.unref();
  const onExit = () => release(path);
  process.once('exit', onExit); // a process that is ended with process.exit() still lets go of the lock
  try {
    return await fn();
  } finally {
    clearInterval(beat);
    process.removeListener('exit', onExit);
    release(path);
  }
}
