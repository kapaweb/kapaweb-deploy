// File Manager on OLDER DirectAdmin panels (for example 1.668, the last release for CentOS 7 / RHEL 7). Those panels have the
// read side of the new JSON API (/api/filemanager/list|download|disk-usage) but not /api/filemanager-actions/*, so every
// change goes through the classic CMD_API_FILE_MANAGER command. Same functions, same results as the new API in fm.js.
//
// What the classic command does, as measured on a real panel (not from the documentation alone):
//   - a folder that is not there: the listing is a 404 "Error listing files" on a newer panel and a 500 with the same text on 1.668
//   - answers {"result":..., "success":...} on success and an HTTP 500 with a short text on failure; the JSON comes as
//     application/json on a newer panel and as text/plain on DirectAdmin 1.668 (seen on a real panel), so it is parsed either way
//   - folder: creates one level; when the folder already exists a newer panel answers "success" but 1.668 fails (500), so an existing
//     folder is checked for before it counts as a failure
//   - upload: multipart with the file in `file1`; an existing file is overwritten; default mode 644
//   - extract: needs an EXISTING target folder, merges and overwrites, keeps modes, hidden files and non-ASCII names
//   - delete: recursive, permanent (no trash), and quietly successful for a path that is not there
//   - rename: the new name is relative to `path`. "sub/x" (down) works everywhere; "../other/x" (up) works on a newer panel but not on
//     1.668, and an absolute name is refused on both. So a move to another folder goes through the clipboard (add, then move into a folder).
//   - compress: on a newer panel it packs the clipboard into "<parent of path>/<name of path>.tar.gz", but on 1.668 every attempt ends in
//     a bare 502 (nothing answers), so it is NOT used. A backup is a copy of the files into a folder instead ("….copy").
//   - copy (clipboard): into a fresh folder it copies files and folders recursively; onto a name that is already there it FAILS on 1.668
//     (no overwrite, no merge), so restoring a copy merges item by item (mergeCopy)
import { posix } from 'node:path';
import { DaError } from './da.js';
import { UserError, randomLower } from './util.js';

const FM = '/CMD_API_FILE_MANAGER?json=yes';
const BATCH = 50;

const dirOf = (p) => posix.dirname(p);
const nameOf = (p) => posix.basename(p);

/** The panel's JSON answer as an object, whatever content type it came with; null when it is not JSON. */
function asObject(body) {
  if (body && typeof body === 'object' && !Buffer.isBuffer(body)) return body;
  if (typeof body !== 'string') return null;
  try {
    const parsed = JSON.parse(body);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

/** A failure the panel reported with a 200 (it normally uses a 500). */
function checkAnswer(body, what) {
  const answer = asObject(body);
  if (answer && answer.error) throw new DaError(500, 'HTTP_500', `${what}: ${String(answer.error).slice(0, 200)}`, undefined, FM);
}

function post(da, form, opts) {
  return da.postForm(FM, form, opts).then((r) => {
    checkAnswer(r.body, form.action);
    return r;
  });
}

/** "select0", "select1" ... for the paths of one request. */
function selects(paths) {
  const form = {};
  paths.forEach((p, i) => {
    form[`select${i}`] = p;
  });
  return form;
}

/** Paths grouped by their folder: the classic command works on "the current folder" plus the entries chosen in it. */
function byFolder(paths) {
  const groups = new Map();
  for (const p of paths) {
    const d = dirOf(p);
    if (!groups.has(d)) groups.set(d, []);
    groups.get(d).push(p);
  }
  return groups;
}

// ---- reading ------------------------------------------------------------------------------------------------------

/** Same shape as normEntry() gives for the new API. */
function entryFrom(name, attrs) {
  const a = new URLSearchParams(String(attrs));
  const type = a.get('type') === 'dir' ? 'dir' : a.get('islink') === '1' ? 'link' : 'file';
  const mtime = Number(a.get('mtime'));
  return {
    name,
    type,
    size: Number(a.get('size')) || 0,
    mode: a.get('permission') || undefined,
    modified: Number.isFinite(mtime) && mtime > 0 ? new Date(mtime * 1000).toISOString() : undefined,
  };
}

export async function legacyList(da, path) {
  const dir = posix.normalize('/' + String(path).replace(/^\/+/, '')).replace(/(.)\/$/, '$1');
  let body;
  try {
    ({ body } = await da.get(`${FM}&${new URLSearchParams({ path: dir })}`));
  } catch (err) {
    if (err instanceof DaError && (err.status === 404 || (err.status === 500 && /Error listing files/i.test(err.message))) && (await isMissing(da, dir))) {
      throw new DaError(404, 'NOT_FOUND', `${dir} does not exist`, 'NOT_FOUND', FM);
    }
    throw err;
  }
  // An answer that cannot be read must never look like an empty folder: a deploy that thinks the target is empty makes no backup.
  const answer = asObject(body);
  if (!answer || Object.keys(answer).length === 0) throw new DaError(502, 'UNEXPECTED_ANSWER', `The panel's file listing of ${dir} is in a form the connector does not understand, so nothing was changed.`, undefined, FM);
  const entries = [];
  for (const [key, attrs] of Object.entries(answer)) {
    if (key === dir || dirOf(key) !== dir) continue; // the listing also holds the folder itself and its parents
    entries.push(entryFrom(nameOf(key), attrs));
  }
  entries.sort((a, b) => (a.name < b.name ? -1 : 1));
  return { path: dir.replace(/^\//, ''), total: entries.length, entries };
}

/**
 * Is a folder whose listing failed really not there? 1.668 answers a 500 for a missing folder, and the same 500 could mean a folder
 * that is there but cannot be read, which must not be mistaken for "empty / not there" (a deploy would then make no backup). So the
 * folder above it is asked: it must be readable and must not hold the name.
 */
async function isMissing(da, dir) {
  if (dir === '/') return false;
  try {
    const { entries } = await legacyList(da, dirOf(dir));
    return !entries.some((e) => e.name === nameOf(dir));
  } catch (err) {
    return err instanceof DaError && err.reason === 'NOT_FOUND'; // the folder above is missing too
  }
}

// ---- changing -----------------------------------------------------------------------------------------------------

async function isFolder(da, path) {
  try {
    await legacyList(da, path);
    return true;
  } catch (err) {
    if (err instanceof DaError && err.reason === 'NOT_FOUND') return false;
    throw err;
  }
}

/**
 * Creates a folder and, when needed, the folders above it (the classic command makes one level at a time). A folder that is already
 * there is fine, like on the new API: a newer panel says "success" for it, 1.668 answers with an error, so after an error the folder
 * is looked for before the levels above it are made from the top.
 */
export async function legacyMkdir(da, path) {
  const target = posix.normalize('/' + String(path).replace(/^\/+/, '')).replace(/(.)\/$/, '$1');
  if (target === '/') return;
  try {
    await post(da, { action: 'folder', path: dirOf(target), name: nameOf(target) });
    return;
  } catch (err) {
    if (!(err instanceof DaError)) throw err;
  }
  if (await isFolder(da, target)) return;
  const parts = target.split('/').filter(Boolean);
  for (let i = 0; i < parts.length; i++) {
    const level = '/' + parts.slice(0, i + 1).join('/');
    if (i < parts.length - 1 && (await isFolder(da, level))) continue;
    await post(da, { action: 'folder', path: '/' + parts.slice(0, i).join('/'), name: parts[i] });
  }
}

export async function legacyUpload(da, dir, name, data, { overwrite = true, perm } = {}) {
  if (/["\r\n/]/.test(name)) throw new UserError('This panel cannot store a file whose name contains a double quote, a slash or a line break.');
  if (!overwrite) {
    const { entries } = await legacyList(da, dir);
    if (entries.some((e) => e.name === name)) throw new DaError(409, 'FILEMANAGER_OP_ERROR', 'ALREADY_EXISTS', 'ALREADY_EXISTS', FM);
  }
  const form = new FormData();
  form.append('action', 'upload');
  form.append('path', dir);
  form.append('file1', new Blob([data]), name);
  const { body } = await da.request('POST', FM, { multipart: form, timeoutMs: 300000 });
  checkAnswer(body, 'upload');
  if (perm !== undefined && perm !== 0o644) await legacyChmod(da, [posix.join(dir, name)], perm);
}

/**
 * Puts the items of the folder `src` into the folder `dst`, like extracting an archive does: what is not there yet is copied, a folder
 * that is there is merged into, and a file (or something of another kind) that is there is replaced. The panel's copy alone would
 * fail on every name that already exists.
 */
async function mergeCopy(da, src, dst) {
  const [from, to] = await Promise.all([legacyList(da, src), legacyList(da, dst)]);
  const there = new Map(to.entries.map((e) => [e.name, e]));
  const fresh = [];
  for (const e of from.entries) {
    const cur = there.get(e.name);
    if (!cur) fresh.push(e.name);
    else if (e.type === 'dir' && cur.type === 'dir') await mergeCopy(da, posix.join(src, e.name), posix.join(dst, e.name));
    else {
      await legacyRemove(da, [posix.join(dst, e.name)]);
      fresh.push(e.name);
    }
  }
  if (fresh.length) await copyThrough(da, src, fresh, dst);
}

/** The target folder must exist (the callers make it first). `source` is an archive, or a ".copy" folder made by legacyCreateArchive. */
export async function legacyExtract(da, source, destinationDir) {
  if (/\.copy$/.test(source)) return mergeCopy(da, source, destinationDir);
  await post(da, { action: 'extract', path: source, directory: destinationDir, page: '2' }, { timeoutMs: 300000 });
}

/** Copies `names` (in the folder `from`) into the folder `to`, through the clipboard, which is emptied before and after. */
async function copyThrough(da, from, names, to) {
  try {
    for (let i = 0; i < names.length; i += BATCH) {
      await post(da, { action: 'multiple', empty: '1' });
      await post(da, { action: 'multiple', add: '1', path: from, ...selects(names.slice(i, i + BATCH).map((n) => posix.join(from, n))) });
      await post(da, { action: 'multiple', copy: '1', path: to }, { timeoutMs: 300000 });
    }
  } finally {
    await post(da, { action: 'multiple', empty: '1' }).catch(() => {});
  }
}

/**
 * Backs `sources` up into the NEW folder `destination` (its name ends in ".copy"): every source is copied into it under its own name,
 * exactly what an archive of them would hold. The panel's classic "compress" cannot be used on every panel (see the top of this file),
 * so a backup here takes as much room as the files themselves. The panel does not say which files it left out, so `skipped` is always
 * empty; what is checked is that every source arrived.
 */
export async function legacyCreateArchive(da, sources, destination) {
  if (!/\.copy$/.test(destination)) throw new UserError('On this panel a backup is a folder whose name ends in .copy.');
  await legacyMkdir(da, destination);
  try {
    for (const [dir, paths] of byFolder(sources)) await copyThrough(da, dir, paths.map(nameOf), destination);
    const { entries } = await legacyList(da, destination);
    const have = new Set(entries.map((e) => e.name));
    const lost = sources.map(nameOf).filter((n) => !have.has(n));
    if (lost.length) throw new UserError(`The backup copy is incomplete (missing: ${lost.slice(0, 5).join(', ')}).`);
  } catch (err) {
    await legacyRemove(da, [destination]).catch(() => {}); // no half a backup is left behind to be mistaken for a whole one
    throw err;
  }
  return { skipped: [] };
}

/**
 * Removes paths (recursively and for good). A newer panel answers "deleted" also for a path that is not there; 1.668 deletes the paths
 * that are there and then answers an error for the one that is not. So after an error the folder is looked at: what is gone counts as
 * removed (it is what was wanted), and only what is still there is tried again, one path at a time. With tolerateMissing what still
 * cannot be removed is reported in `failed`, otherwise it is an error.
 */
export async function legacyRemove(da, paths, { tolerateMissing = false } = {}) {
  let removed = 0;
  const failed = [];
  const run = (dir, list) => post(da, { action: 'multiple', button: 'delete', path: dir, ...selects(list) });
  for (const [dir, group] of byFolder(paths)) {
    for (let i = 0; i < group.length; i += BATCH) {
      const chunk = group.slice(i, i + BATCH);
      try {
        await run(dir, chunk);
        removed += chunk.length;
      } catch (err) {
        if (!(err instanceof DaError)) throw err;
        const still = await legacyList(da, dir).then((l) => new Set(l.entries.map((e) => e.name))).catch((e) => (e instanceof DaError && e.reason === 'NOT_FOUND' ? new Set() : Promise.reject(e)));
        for (const p of chunk) {
          if (!still.has(nameOf(p))) {
            removed += 1;
            continue;
          }
          try {
            await run(dir, [p]);
            removed += 1;
          } catch (one) {
            if (!(one instanceof DaError)) throw one;
            if (!tolerateMissing) throw one;
            failed.push(p);
          }
        }
      }
    }
  }
  return { removed, failed };
}

/** `perm` is the decimal number of the mode (0o644 = 420), like the new API; the classic command wants the octal text. */
export async function legacyChmod(da, paths, perm) {
  const chmod = perm.toString(8);
  for (const [dir, group] of byFolder(paths)) {
    for (let i = 0; i < group.length; i += BATCH) await post(da, { action: 'multiple', button: 'permission', chmod, path: dir, ...selects(group.slice(i, i + BATCH)) });
  }
}

const rename = (da, dir, from, to, overwrite) => post(da, { action: 'rename', path: dir, old: from, filename: to, overwrite: overwrite ? 'yes' : 'no' });

/**
 * Moves (or renames) `source` to the path `destination`. In the same folder, or into a folder below it, that is one rename. To any
 * other folder the item is first renamed to a name nothing can clash with, moved there through the clipboard (which keeps names), and
 * given its final name: a rename cannot go "up" on every panel, and the clipboard alone could overwrite a same-named file there.
 */
export async function legacyMove(da, source, destination, overwrite = false) {
  if (source === destination) return;
  const from = dirOf(source);
  const to = dirOf(destination);
  const newName = nameOf(destination);
  // a refused rename is most often "the new name is taken": say so plainly instead of the panel's generic error
  const direct = async (newPath) => {
    try {
      await rename(da, from, nameOf(source), newPath, overwrite);
    } catch (err) {
      if (!overwrite && err instanceof DaError && (await legacyList(da, to).then((l) => l.entries.some((e) => e.name === newName)).catch(() => false))) {
        throw new DaError(409, 'FILEMANAGER_OP_ERROR', `${destination} already exists`, 'ALREADY_EXISTS', FM);
      }
      throw err;
    }
  };
  if (from === to) return direct(newName);
  if (destination.startsWith(from + '/')) return direct(posix.relative(from, destination));
  // early, clear answers before anything is touched
  const { entries } = await legacyList(da, to); // the destination folder must exist
  if (!overwrite && entries.some((e) => e.name === newName)) throw new DaError(409, 'FILEMANAGER_OP_ERROR', `${destination} already exists`, 'ALREADY_EXISTS', FM);
  const parked = `.kw-move-${randomLower(8)}`;
  await rename(da, from, nameOf(source), parked, false);
  try {
    await post(da, { action: 'multiple', empty: '1' });
    await post(da, { action: 'multiple', add: '1', path: from, select0: posix.join(from, parked) });
    await post(da, { action: 'multiple', move: '1', path: to });
  } catch (err) {
    await rename(da, from, parked, nameOf(source), false).catch(() => {}); // put it back under its own name
    throw err;
  } finally {
    await post(da, { action: 'multiple', empty: '1' }).catch(() => {});
  }
  try {
    await rename(da, to, parked, newName, overwrite);
  } catch (err) {
    throw new UserError(`The item was moved to ${to} but could not be given its final name (${err instanceof DaError ? err.message : 'error'}); it is there as ${posix.join(to, parked)}.`);
  }
}
