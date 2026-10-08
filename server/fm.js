// File Manager helpers. Paths are relative to the account home. A panel with the new JSON API (/api/filemanager-actions/*) is used
// through it; an older panel (`da.fileApi === 'legacy'`, see provision.js) is used through the classic command in fm-legacy.js:
// the same functions, the same results.
import { DaError } from './da.js';
import { legacyChmod, legacyCreateArchive, legacyExtract, legacyList, legacyMkdir, legacyMove, legacyRemove, legacyUpload } from './fm-legacy.js';
import { UserError } from './util.js';

const isLegacy = (da) => da.fileApi === 'legacy';

/** What makeBackup() names its backups with: an archive (zip), or on an older panel a folder holding a copy ("copy"). */
export const archiveExt = (da) => (isLegacy(da) ? 'copy' : 'zip');

/** Only the owner may read a backup (it holds the whole site, config files included). An archive is a file (600); on an older panel a backup is a FOLDER, which needs the search bit to be opened at all (700). */
export const backupMode = (da) => (isLegacy(da) ? 0o700 : 0o600);

const CHUNK = 1000;

export function normEntry(f) {
  const mode = Number.isInteger(f.unixMode) ? f.unixMode : null;
  const isDir = mode !== null ? (mode & 0o170000) === 0o040000 : /dir/i.test(String(f.type));
  return {
    name: f.name,
    type: isDir ? 'dir' : f.symlink ? 'link' : 'file',
    size: f.sizeBytes ?? 0,
    sizeOnDisk: f.sizeOnDiskBytes ?? undefined,
    mode: f.mode,
    modified: f.modifyTime,
  };
}

export function isNotFound(err) {
  return err instanceof DaError && (err.reason === 'NOT_FOUND' || err.status === 404);
}

/** Lists a directory completely (paginates when the panel caps the list). */
export async function fmList(da, path) {
  if (isLegacy(da)) return legacyList(da, path);
  const first = await da.get('/api/filemanager/list?' + new URLSearchParams({ path, limit: '0', offset: '0' }));
  const body = first.body || {};
  let files = Array.isArray(body.files) ? body.files : [];
  const total = Number.isInteger(body.filesTotal) ? body.filesTotal : files.length;
  let offset = files.length;
  while (files.length < total && offset < total) {
    const next = await da.get('/api/filemanager/list?' + new URLSearchParams({ path, limit: String(CHUNK), offset: String(offset) }));
    const more = next.body?.files || [];
    if (more.length === 0) break;
    files = files.concat(more);
    offset += more.length;
  }
  return { path: body.canonicalPath || path, total, entries: files.map(normEntry) };
}

export async function fmExists(da, path) {
  try {
    await fmList(da, path);
    return true;
  } catch (err) {
    if (isNotFound(err)) return false;
    throw err;
  }
}

export async function fmDiskUsage(da, path) {
  const { body } = await da.get('/api/filemanager/disk-usage?' + new URLSearchParams({ path }));
  return body;
}

export async function fmMkdir(da, path) {
  if (isLegacy(da)) return legacyMkdir(da, path);
  try {
    await da.postJson('/api/filemanager-actions/mkdir', { path });
  } catch (err) {
    if (!(err instanceof DaError && err.reason === 'ALREADY_EXISTS')) throw err;
  }
}

/** data: Buffer. */
export async function fmUpload(da, dir, name, data, { overwrite = true, perm } = {}) {
  if (isLegacy(da)) return legacyUpload(da, dir, name, data, { overwrite, perm });
  const form = new FormData();
  form.append('dir', dir);
  form.append('name', name);
  form.append('overwrite', overwrite ? 'true' : 'false');
  if (perm !== undefined) form.append('perm', String(perm));
  form.append('file', new Blob([data]), name);
  await da.request('POST', '/api/filemanager-actions/upload', { multipart: form, timeoutMs: 300000 });
}

export async function fmExtract(da, source, destinationDir) {
  if (isLegacy(da)) return legacyExtract(da, source, destinationDir);
  await da.postJson('/api/filemanager-actions/extract-archive', { source, destinationDir, members: [], mergeAndOverwrite: true }, { timeoutMs: 300000 });
}

export async function fmCreateArchive(da, sources, destination) {
  if (isLegacy(da)) return legacyCreateArchive(da, sources, destination);
  const { body } = await da.postJson('/api/filemanager-actions/create-archive', { sources, destination }, { timeoutMs: 300000 });
  return { skipped: Array.isArray(body?.skippedFiles) ? body.skippedFiles : [] };
}

/**
 * Removes paths in batches of 50. With tolerateMissing, a batch that the panel refuses because something in it is
 * already gone (404 / NOT_FOUND / a 409 multi-operation error) is retried one path at a time, so one missing file does
 * not leave the rest of the batch behind. Returns how many were removed and which paths could not be.
 */
export async function fmRemove(da, paths, { trash = false, tolerateMissing = false } = {}) {
  if (isLegacy(da)) return legacyRemove(da, paths, { tolerateMissing }); // (this panel has no trash: a removal is final)
  let removed = 0;
  const failed = [];
  const post = (list) => da.postJson('/api/filemanager-actions/remove', { paths: list, trash });
  const refused = (err) => err instanceof DaError && (isNotFound(err) || err.status === 409);
  for (let i = 0; i < paths.length; i += 50) {
    const chunk = paths.slice(i, i + 50);
    try {
      await post(chunk);
      removed += chunk.length;
    } catch (err) {
      if (!tolerateMissing || !refused(err)) throw err;
      for (const p of chunk) {
        try {
          await post([p]);
          removed += 1;
        } catch (one) {
          if (!refused(one)) throw one;
          failed.push(p);
        }
      }
    }
  }
  return { removed, failed };
}

export async function fmChmod(da, paths, perm) {
  if (isLegacy(da)) return legacyChmod(da, paths, perm);
  await da.postJson('/api/filemanager-actions/chmod', { paths, perm });
}

export async function fmMove(da, source, destination, overwrite = false) {
  if (isLegacy(da)) return legacyMove(da, source, destination, overwrite);
  await da.postJson('/api/filemanager-actions/move', { source, destination, overwrite });
}

export async function fmDownload(da, path, maxBytes = 10 * 1024 * 1024) {
  const { body } = await da.get('/api/filemanager/download?' + new URLSearchParams({ path }), { raw: true, maxBytes });
  return body; // Buffer
}

/** Reads a text file; returns null when it does not exist. */
export async function fmReadText(da, path, maxBytes = 512 * 1024) {
  try {
    const buf = await fmDownload(da, path, maxBytes);
    return buf.toString('utf8');
  } catch (err) {
    if (isNotFound(err)) return null;
    throw err;
  }
}

/** Octal permission string ("0644", "755") -> decimal number the File Manager API expects. */
export function octalToDecimal(mode) {
  const s = String(mode).trim();
  if (!/^0?[0-7]{3,4}$/.test(s)) throw new UserError('Permissions must be an octal string such as "0644" or "0755".');
  return parseInt(s, 8);
}
