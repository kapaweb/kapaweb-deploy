// Checks for the files of THIS computer that the file tools upload or write, shared by the Plesk and DirectAdmin versions.
import { mkdir, realpath } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { homedir, platform } from 'node:os';
import { octalToDecimal } from './fm.js';
import { UserError } from './util.js';
import { configDir } from './store.js';

/**
 * A local file that may be uploaded or written. Refused: hidden folders of the home folder (.ssh, .config, .aws ...), the operating
 * system's own folders and other people's home folders, the program-data folders of the home folder (macOS ~/Library except CloudStorage,
 * Windows AppData: keychains, browser profiles, autostart folders such as LaunchAgents and Startup), and the connector's own folder (it holds
 * the database exports it made). A file name such as "photo.jpg" must not let a credential store through, and a download must not be able to
 * land where the system starts programs from.
 */
export function assertLocalFileAllowed(file) {
  const home = resolve(homedir());
  const norm = (p) => p.replace(/\\/g, '/');
  const f = norm(file);
  const h = norm(home).replace(/\/$/, '');
  const lower = f.toLowerCase();
  const insideHome = lower.startsWith(h.toLowerCase() + '/');
  const all = insideHome ? f.slice(h.length + 1).split('/') : [];
  const rel = all.slice(0, -1);
  if (rel.some((seg) => seg.startsWith('.'))) throw new UserError('That file is inside a hidden folder of the home folder (settings or credentials of this computer), which the connector does not touch.');
  if (norm(dirname(file)) === h) throw new UserError('Files directly in the home folder are not handled by the connector: use the project\'s folder.');
  const top = (all[0] || '').toLowerCase();
  const second = (all[1] || '').toLowerCase();
  if ((top === 'library' && second !== 'cloudstorage') || top === 'appdata' || top === 'application data' || top === 'local settings') {
    throw new UserError('That file is in the program-data folder of this computer (keychains, browser profiles, autostart folders): the connector does not read or write there. Use the project\'s own folder.');
  }
  const own = norm(configDir()).replace(/\/$/, '').toLowerCase();
  if (lower === own || lower.startsWith(own + '/')) throw new UserError('That file is in the connector\'s own folder (its settings and the database exports it made), which it does not upload or overwrite.');
  if (/^(\/(etc|private\/etc|system|library|usr|bin|sbin|root|proc|sys|dev)(\/|$)|[a-z]:\/(windows|programdata|program files( \(x86\))?)(\/|$))/.test(lower)) {
    throw new UserError('That file is in a system folder of this computer, which the connector does not read or write.');
  }
  if (!insideHome && /^(\/users|\/home)\/[^/]+(\/|$)/.test(lower)) throw new UserError('That file is in another user\'s home folder, which the connector does not touch.');
}

/**
 * The real path of `p`: links resolved for the part of it that exists (macOS /Volumes/<startup disk> -> /, /tmp -> /private/tmp, a
 * symbolic link inside a project, Windows 8.3 short names), the part that does not exist yet appended as typed. assertLocalFileAllowed
 * judges a path by its text, so an alias of a refused folder ("/Volumes/Macintosh HD/Users/me/Library/LaunchAgents") must be judged by
 * what it really is.
 */
export async function realLocalPath(p) {
  let cur = resolve(p);
  const rest = [];
  for (;;) {
    try {
      const real = await realpath(cur);
      return rest.length ? join(real, ...[...rest].reverse()) : real;
    } catch {
      const parent = dirname(cur);
      if (parent === cur) return resolve(p);
      rest.push(basename(cur));
      cur = parent;
    }
  }
}

/** assertLocalFileAllowed for the path as typed AND as it really is. Returns the real path. */
export async function assertLocalPathAllowed(p) {
  const typed = resolve(p);
  assertLocalFileAllowed(typed);
  const real = await realLocalPath(typed);
  if (real !== typed) assertLocalFileAllowed(real);
  return real;
}

/**
 * Where a download from the hosting goes: `<folder>/<name>` on this computer, checked as typed and as it really is. Call it before
 * anything is fetched (nothing is created yet); `createLocalTarget` then makes the folder and checks again.
 */
export async function checkLocalTarget(folder, name) {
  if (!isAbsolute(String(folder || ''))) throw new UserError('"folder" must be an absolute path on this computer.');
  if (!name || /[\\/]/.test(name) || name === '.' || name === '..') throw new UserError(`"${name}" is not a plain file name.`);
  return assertLocalPathAllowed(resolve(folder, name));
}

/**
 * Creates the download folder (0700) and returns the REAL path to write to. The check runs again after the folder exists: creating it
 * can itself have gone through a link, and what is written must land where the check said.
 */
export async function createLocalTarget(folder, name) {
  await checkLocalTarget(folder, name);
  await mkdir(resolve(folder), { recursive: true, mode: 0o700 });
  const target = join(await realpath(resolve(folder)), name);
  assertLocalFileAllowed(target);
  return target;
}

/** A local file that is uploaded (sent to the hosting): checked as typed and as it really is. Returns the real path. */
export async function realLocalSource(source) {
  if (!isAbsolute(String(source || ''))) throw new UserError('"source" must be an absolute path on this computer.');
  const typed = resolve(source);
  const real = await realpath(typed).catch(() => typed);
  return { typed, real };
}

const sameDir = (a, b) => (platform() === 'linux' ? a === b : a.toLowerCase() === b.toLowerCase());

/**
 * The dump file db_import sends, as its real path. Like every upload it must pass assertLocalFileAllowed, which refuses the connector's
 * own folder: its exports folder holds the database exports of EVERY connected account (another customer's data). One thing from there is
 * allowed, because it is the way back after `db_import clean`: an export of the very database that is being imported into
 * ("db-<database>-<time>.sql.gz", or ".sql.zip" from Plesk).
 */
export async function checkedDumpFile(file, database) {
  const typed = resolve(String(file));
  const real = await realpath(typed).catch(() => typed);
  const exportsDir = join(configDir(), 'exports');
  const exportsReal = await realpath(exportsDir).catch(() => resolve(exportsDir));
  if (sameDir(dirname(real), exportsReal)) {
    const m = /^db-([A-Za-z0-9_]{1,64})-\d{8}T\d{6}Z\.sql\.(gz|zip)$/.exec(basename(real));
    if (!m || m[1] !== database) {
      throw new UserError(`${basename(real)} is in the connector's own exports folder, which holds the database exports of every connected account. Only an export of ${database} itself can be imported back into ${database} from there. Nothing was imported.`);
    }
    return real;
  }
  assertLocalFileAllowed(typed);
  if (real !== typed) assertLocalFileAllowed(real);
  return real;
}

/** Permissions the way the DirectAdmin tools take them: plain rwx bits, never world-writable. */
export function checkedMode(mode) {
  const decimal = octalToDecimal(mode);
  if (decimal > 0o777) throw new UserError('Set-uid, set-gid and sticky bits are not allowed: use plain permissions such as "0644" or "0755".');
  if ((decimal & 0o002) !== 0) throw new UserError('World-writable permissions are refused: 0644/0755 is enough.');
  return decimal;
}
