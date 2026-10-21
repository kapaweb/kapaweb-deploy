// The files of a Plesk subscription, through the same JSON endpoints Plesk's own File Manager page uses
// (/smb/file-manager/<action>/domainId/<id>/ ... — names and field names read from the panel's JavaScript and confirmed on a
// real customer login on 2026-10-15). Needs a PleskWeb session (the stored Plesk password route).
//
// Paths are absolute inside the subscription, like the File Manager shows them: /httpdocs/index.html, /logs, ...
//
// Plesk answers HTTP 200 with a message even when it did nothing, or did the wrong thing (a permissions form posted as JSON
// answers "success" and sets mode 000), so every write here checks the answer's own status AND reads the result back.
import { rm, stat as fsStat } from 'node:fs/promises';
import { UserError } from './util.js';

const BASE = '/smb/file-manager';
const MAX_NAME = 255;
const LONG_MS = 15 * 60 * 1000; // archiving, unpacking and removing big trees can take minutes without a byte on the wire

/** A path inside the subscription: absolute, no "..", no control characters. */
export function pleskPath(input) {
  const raw = String(input ?? '').trim().replace(/\\/g, '/');
  if (!raw) throw new UserError('A path is required.');
  if (/[\0-\x1f]/.test(raw)) throw new UserError('That path has control characters in it.');
  const parts = ('/' + raw).split('/').filter(Boolean);
  if (parts.some((p) => p === '..' || p === '.')) throw new UserError('A path may not contain "." or ".." segments.');
  if (parts.some((p) => p.length > MAX_NAME)) throw new UserError('A path segment is too long.');
  return '/' + parts.join('/');
}

export const dirOf = (path) => path.slice(0, path.lastIndexOf('/')) || '/';
export const baseOf = (path) => path.slice(path.lastIndexOf('/') + 1);

function checkName(name) {
  if (!name || name === '.' || name === '..' || /[/\0-\x1f]/.test(name) || name.length > MAX_NAME) throw new UserError(`"${name}" is not a valid file name.`);
  return name;
}

/** "rwx r-x r-x " -> 0o755 (Plesk lists permissions as three letter groups). */
export function modeOfPerms(perms) {
  const s = String(perms || '').replace(/\s+/g, '');
  if (!/^[r-][w-][-xsS][r-][w-][-xsS][r-][w-][-xtT]$/.test(s)) return null;
  let mode = 0;
  for (let i = 0; i < 9; i++) if (s[i] !== '-') mode |= 1 << (8 - i);
  return mode;
}

const octal = (mode) => (mode === null ? undefined : '0' + mode.toString(8).padStart(3, '0'));

const stripHtml = (s) => String(s ?? '').replace(/<[^>]*>/g, '').replace(/%%[a-z]+%%/gi, '').replace(/\s+/g, ' ').trim();

/**
 * What a File Manager answer says: { ok, message }. Shapes seen: { status: 'SUCCESS'|'success'|'FAIL'|'ERROR'|'error', message },
 * { statusMessages: [{ status: 'info'|'error', content }] } and the upload answer, which comes as a JSON *string*.
 */
export function outcome(body) {
  let b = body;
  if (typeof b === 'string') {
    try {
      b = JSON.parse(b);
    } catch {
      return { ok: false, message: 'Plesk sent an answer that could not be read.' };
    }
  }
  if (!b || typeof b !== 'object') return { ok: false, message: 'Plesk sent an empty answer.' };
  if (Array.isArray(b.statusMessages) && b.statusMessages.length) {
    const bad = b.statusMessages.find((m) => /error|warning|fail/i.test(String(m?.status)));
    return bad ? { ok: false, message: stripHtml(bad.content) } : { ok: true, message: stripHtml(b.statusMessages[0]?.content) };
  }
  if (typeof b.status === 'string') {
    return { ok: /^(success|ok)$/i.test(b.status), message: stripHtml(b.message), files: b.files };
  }
  return { ok: false, message: stripHtml(b.message) || 'Plesk did not say whether it worked.' };
}

const shortMessage = (m) => String(m || '').replace(/\/var\/www\/vhosts\/[^/\s]+/g, '').split('filemng')[0].trim().slice(0, 300);

export class PleskFiles {
  /** @param {import('./plesk-web.js').PleskWeb} web  @param {number|string} domainId the subscription's id */
  constructor(web, domainId) {
    if (!Number.isInteger(Number(domainId)) || Number(domainId) < 1) throw new UserError('Internal error: no subscription id for the file operation.');
    this.web = web;
    this.id = Number(domainId);
  }

  #url(action, query = {}, tail = '') {
    const q = new URLSearchParams(query).toString();
    return `${BASE}/${action}/domainId/${this.id}${tail}${q ? '?' + q : ''}`;
  }

  /** POST and demand a success answer. */
  async #do(action, query, opts, what) {
    const { body } = await this.web.request('POST', this.#url(action, query, opts?.tail), opts);
    const o = outcome(body);
    if (!o.ok) throw new UserError(`${what}: ${shortMessage(o.message) || 'Plesk refused it.'}`, 'PLESK_FILES');
    return o;
  }

  /** One directory, completely. Throws NOT_FOUND when it does not exist (or is a file). */
  async list(dir) {
    const want = pleskPath(dir);
    const { body } = await this.web.request('GET', this.#url('list-data', { currentDir: want }));
    if (!body || typeof body !== 'object' || body.status === 'error' || !body.state) {
      throw new UserError(`${want} does not exist.`, 'NOT_FOUND');
    }
    // a path that is a file is answered with a one-row listing whose "name" is the file's full path on the server
    if (pleskPath(body.state.currentDir || '/') !== want || (body.data || []).some((r) => String(r.name).includes('/'))) throw new UserError(`${want} is not a folder.`, 'NOT_FOUND');
    const entries = (body.data || [])
      .filter((r) => r.name !== '..')
      .map((r) => ({
        name: r.name,
        type: r.isDirectory ? 'dir' : 'file',
        size: r.isDirectory ? 0 : Number(r.size) || 0,
        mode: octal(modeOfPerms(r.filePerms)),
        modified: Number.isFinite(r.modificationTimestamp) ? new Date(r.modificationTimestamp * 1000).toISOString() : undefined,
      }));
    return { path: want, total: entries.length, entries };
  }

  async exists(path) {
    const p = pleskPath(path);
    if (p === '/') return true;
    try {
      const { entries } = await this.list(dirOf(p));
      return entries.some((e) => e.name === baseOf(p));
    } catch (err) {
      if (err?.code === 'NOT_FOUND') return false;
      throw err;
    }
  }

  async stat(path) {
    const p = pleskPath(path);
    if (p === '/') return { name: '', type: 'dir', size: 0 };
    try {
      return (await this.list(dirOf(p))).entries.find((e) => e.name === baseOf(p)) || null;
    } catch (err) {
      if (err?.code === 'NOT_FOUND') return null;
      throw err;
    }
  }

  /** The bytes of a file (up to maxBytes). */
  async download(path, maxBytes = 8 * 1024 * 1024) {
    const p = pleskPath(path);
    const info = await this.stat(p);
    if (!info) throw new UserError(`${p} does not exist.`, 'NOT_FOUND');
    if (info.type === 'dir') throw new UserError(`${p} is a folder, not a file.`);
    if (info.size > maxBytes) throw new UserError(`${p} is ${info.size} bytes, more than the ${maxBytes} byte limit for this read.`, 'TOO_LARGE');
    const res = await this.web.request('GET', this.#url('download', { currentDir: dirOf(p) === '/' ? '/' : dirOf(p) + '/', file: baseOf(p) }), { binary: true });
    if (!Buffer.isBuffer(res.body)) throw new UserError(`Plesk would not give ${p}.`, 'NOT_FOUND');
    return res.body;
  }

  /** Streams a file of the server to a file on this computer (constant memory). The size must match what the listing says. */
  async downloadTo(path, localFile, { expectedBytes } = {}) {
    const p = pleskPath(path);
    const info = await this.stat(p);
    if (!info) throw new UserError(`${p} does not exist.`, 'NOT_FOUND');
    if (info.type === 'dir') throw new UserError(`${p} is a folder, not a file.`);
    const url = this.#url('download', { currentDir: dirOf(p) === '/' ? '/' : dirOf(p) + '/', file: baseOf(p) });
    const res = await this.web.request('GET', url, { saveTo: localFile, timeoutMs: 3600000 });
    if (!res.body || res.body.bytes === undefined) throw new UserError(`Plesk would not give ${p}.`, 'NOT_FOUND');
    const want = expectedBytes ?? info.size;
    if (res.body.bytes !== want) {
      await rm(localFile, { force: true }).catch(() => {});
      throw new UserError(`The download of ${p} ended early (${res.body.bytes} of ${want} bytes), so the file was discarded. Try again.`);
    }
    return { bytes: res.body.bytes };
  }

  /** Like upload(), but the data is streamed from a file on this computer (constant memory). */
  async uploadFrom(dir, name, localFile, { overwrite = true, mode } = {}) {
    const d = pleskPath(dir);
    checkName(name);
    const size = (await fsStat(localFile)).size;
    const at = `${d === '/' ? '' : d}/${name}`;
    if (!overwrite && (await this.stat(at))) throw new UserError(`${at} already exists.`, 'EXISTS');
    const { body } = await this.web.request('POST', this.#url('upload', { currentDir: d }, `/overwrite/${overwrite ? 'true' : 'false'}`), {
      upload: { path: localFile, size, field: 'file', filename: name },
      timeoutMs: 3600000,
    });
    const o = outcome(body);
    if (!o.ok) throw new UserError(`Could not write ${name} in ${d}: ${shortMessage(o.message) || 'Plesk refused it.'}`, 'PLESK_FILES');
    const saved = o.files && o.files[0];
    if (saved && saved !== name) {
      await this.remove([`${d === '/' ? '' : d}/${saved}`], { permanent: true }).catch(() => {});
      throw new UserError(`${name} already exists in ${d} and was not replaced.`, 'EXISTS');
    }
    const info = await this.stat(at);
    if (!info || info.size !== size) throw new UserError(`Plesk said ${at} was written, but it does not have ${size} bytes.`);
    if (mode !== undefined && mode !== null && info.mode !== octal(mode & 0o777)) await this.chmod([at], mode);
    return { path: at, bytes: size };
  }

  /** A text file, or null when it does not exist. */
  async readText(path, maxBytes = 512 * 1024) {
    try {
      return (await this.download(path, maxBytes)).toString('utf8');
    } catch (err) {
      if (err?.code === 'NOT_FOUND') return null;
      throw err;
    }
  }

  /** Creates a folder and the missing folders above it. Quiet when it exists already. */
  async mkdir(path) {
    const p = pleskPath(path);
    if (p === '/') return;
    // start at the deepest folder that exists, create the rest in one call
    let base = dirOf(p);
    const missing = [baseOf(p)];
    for (;;) {
      if (await this.exists(base)) break;
      missing.unshift(baseOf(base));
      base = dirOf(base);
    }
    const existing = await this.stat(p);
    if (existing) {
      if (existing.type !== 'dir') throw new UserError(`${p} exists and is a file.`);
      return;
    }
    missing.forEach(checkName);
    await this.#do('create-directory', { currentDir: base }, { json: { newDirectoryName: missing.join('/'), recursively: true } }, `Could not create ${p}`);
    if (!(await this.exists(p))) throw new UserError(`Plesk said it created ${p}, but it is not there.`);
  }

  /**
   * Writes a file. Exact bytes (a file part, no newline conversion). Replaces an existing file when overwrite is true; Plesk
   * would otherwise save it as "name (1).ext", which is detected and undone.
   */
  async upload(dir, name, data, { overwrite = true, mode } = {}) {
    const d = pleskPath(dir);
    checkName(name);
    const bytes = Buffer.isBuffer(data) ? data : Buffer.from(data);
    if (!overwrite && (await this.stat(`${d === '/' ? '' : d}/${name}`))) throw new UserError(`${d}/${name} already exists.`, 'EXISTS');
    const form = new FormData();
    form.append('file', new Blob([bytes]), name);
    const { body } = await this.web.request('POST', this.#url('upload', { currentDir: d }, `/overwrite/${overwrite ? 'true' : 'false'}`), { multipart: form });
    const o = outcome(body);
    if (!o.ok) throw new UserError(`Could not write ${name} in ${d}: ${shortMessage(o.message) || 'Plesk refused it.'}`, 'PLESK_FILES');
    const saved = o.files && o.files[0];
    if (saved && saved !== name) {
      await this.remove([`${d === '/' ? '' : d}/${saved}`], { permanent: true }).catch(() => {});
      throw new UserError(`${name} already exists in ${d} and was not replaced.`, 'EXISTS');
    }
    const at = `${d === '/' ? '' : d}/${name}`;
    const info = await this.stat(at);
    if (!info || info.size !== bytes.length) throw new UserError(`Plesk said ${at} was written, but it does not have ${bytes.length} bytes.`);
    if (mode !== undefined && mode !== null && info.mode !== octal(mode & 0o777)) await this.chmod([at], mode);
    return { path: at, bytes: bytes.length };
  }

  /** Removes files/folders. permanent:false moves them to the subscription's trash (/.trash), which counts against the disk quota. */
  async remove(paths, { permanent = false } = {}) {
    const byDir = new Map();
    for (const raw of paths) {
      const p = pleskPath(raw);
      if (p === '/') throw new UserError('The top folder of the subscription cannot be removed.');
      const list = byDir.get(dirOf(p)) || [];
      list.push(baseOf(p));
      byDir.set(dirOf(p), list);
    }
    let removed = 0;
    for (const [dir, names] of byDir) {
      for (let i = 0; i < names.length; i += 50) {
        const chunk = names.slice(i, i + 50);
        const form = { force: permanent ? 'yes' : 'no' };
        chunk.forEach((n, k) => (form[`ids[${k}]`] = n));
        await this.#do('delete', { currentDir: dir }, { form, timeoutMs: LONG_MS }, `Could not remove from ${dir}`);
        removed += chunk.length;
      }
      const left = await this.list(dir).catch(() => null);
      const still = left && names.filter((n) => left.entries.some((e) => e.name === n));
      if (still && still.length) throw new UserError(`Plesk said it removed ${still.join(', ')} from ${dir}, but they are still there.`);
    }
    return { removed };
  }

  /** Moves or renames. */
  async move(source, destination, { overwrite = false } = {}) {
    const from = pleskPath(source);
    const to = pleskPath(destination);
    if (from === '/' || to === '/') throw new UserError('The top folder of the subscription cannot be moved.');
    if (to === from) return;
    if (to.startsWith(from + '/')) throw new UserError('A folder cannot be moved into itself.');
    const src = await this.stat(from);
    if (!src) throw new UserError(`${from} does not exist.`, 'NOT_FOUND');
    const dst = await this.stat(to);
    if (dst) {
      if (!overwrite) throw new UserError(`${to} already exists. Pass overwrite:true to replace it.`, 'EXISTS');
      await this.remove([to], { permanent: false });
    }
    if (!(await this.exists(dirOf(to)))) throw new UserError(`The folder ${dirOf(to)} does not exist.`, 'NOT_FOUND');
    const sameDir = dirOf(from) === dirOf(to);
    if (sameDir) {
      await this.#do('rename', { currentDir: dirOf(from) }, { json: { ids: baseOf(from), newFileName: checkName(baseOf(to)) } }, `Could not rename ${from}`);
    } else {
      let name = baseOf(from);
      if (baseOf(to) !== name) {
        // two steps: rename in place (the target name must be free there), then move
        if (await this.stat(`${dirOf(from) === '/' ? '' : dirOf(from)}/${baseOf(to)}`)) throw new UserError(`${dirOf(from)} already has a "${baseOf(to)}": move it in two steps.`, 'EXISTS');
        await this.#do('rename', { currentDir: dirOf(from) }, { json: { ids: name, newFileName: checkName(baseOf(to)) } }, `Could not rename ${from}`);
        name = baseOf(to);
      }
      await this.#do('move-files', { currentDir: dirOf(from), destinationDir: dirOf(to), overwrite: 'true' }, { form: { 'ids[0]': name } }, `Could not move ${from}`);
    }
    if (!(await this.exists(to))) throw new UserError(`Plesk said it moved ${from}, but ${to} is not there.`);
  }

  /** Permissions as an octal number or string; verified by reading the listing again. Folders can be done recursively. */
  async chmod(paths, mode, { recursive = false } = {}) {
    const m = typeof mode === 'string' ? parseInt(mode, 8) : mode;
    if (!Number.isInteger(m) || m < 0 || m > 0o777) throw new UserError('Permissions must be an octal value such as "0644" or "0755".');
    const form = {
      ownerRead: Boolean(m & 0o400), ownerWrite: Boolean(m & 0o200), ownerExecute: Boolean(m & 0o100),
      groupRead: Boolean(m & 0o040), groupWrite: Boolean(m & 0o020), groupExecute: Boolean(m & 0o010),
      othersRead: Boolean(m & 0o004), othersWrite: Boolean(m & 0o002), othersExecute: Boolean(m & 0o001),
      changeRecursive: recursive,
    };
    for (const raw of paths) {
      const p = pleskPath(raw);
      if (p === '/') throw new UserError('The top folder of the subscription cannot be changed.');
      // (the form must be sent as a normal form post: sent as JSON, Plesk says "success" and sets 000)
      await this.#do('permissions', { currentDir: dirOf(p) === '/' ? '/' : dirOf(p) + '/', file: baseOf(p) }, { form }, `Could not change the permissions of ${p}`);
      const after = await this.stat(p);
      if (!after || after.mode !== octal(m)) throw new UserError(`Plesk said the permissions of ${p} were changed, but they are ${after?.mode ?? 'unknown'}, not ${octal(m)}.`);
    }
  }

  /** Zips files/folders of one directory into <dir>/<archiveName>.zip. */
  async archive(dir, names, archiveName) {
    const d = pleskPath(dir);
    const base = checkName(String(archiveName).replace(/\.zip$/i, ''));
    if (!names.length) throw new UserError('Nothing to archive.');
    names.forEach(checkName);
    await this.#do('create-archive', { currentDir: d, destinationDir: d }, { json: { ids: names, archiveName: base }, timeoutMs: LONG_MS }, `Could not create ${base}.zip`);
    const path = `${d === '/' ? '' : d}/${base}.zip`;
    if (!(await this.exists(path))) throw new UserError(`Plesk said it created ${base}.zip, but it is not there.`);
    return path;
  }

  /**
   * Zips ONE path (any depth) from the top of the subscription into /<archiveName>.zip. The zip is made at the top, never inside
   * a web root (where it could be downloaded for a moment), and holds the full path (httpdocs/blog/...), so unpacking it at the
   * top puts everything back where it was.
   */
  async archivePath(path, archiveName) {
    const p = pleskPath(path);
    if (p === '/') throw new UserError('The top folder of the subscription cannot be archived this way.');
    const base = checkName(String(archiveName).replace(/\.zip$/i, ''));
    await this.#do('create-archive', { currentDir: '/', destinationDir: '/' }, { json: { ids: [p.slice(1)], archiveName: base }, timeoutMs: LONG_MS }, `Could not create ${base}.zip`);
    const made = `/${base}.zip`;
    if (!(await this.exists(made))) throw new UserError(`Plesk said it created ${base}.zip, but it is not there.`);
    return made;
  }

  /** Unpacks <dir>/<archive> into <dir>. */
  async extract(dir, archive, { overwrite = true } = {}) {
    const d = pleskPath(dir);
    checkName(archive);
    await this.#do('extract-archive', { currentDir: d, overwrite: overwrite ? 'true' : 'false' }, { json: { ids: archive, skipConfirmation: true }, timeoutMs: LONG_MS }, `Could not extract ${archive}`);
  }
}

/** The subscription a tool call is about: by name, or the only one. */
export async function resolveWebspace(xml, domain) {
  const sites = await xml.webspaces();
  if (!sites.length) throw new UserError('This Plesk login has no subscription.');
  if (domain) {
    const hit = sites.find((s) => String(s.name || '').toLowerCase() === String(domain).toLowerCase());
    if (!hit) throw new UserError(`"${domain}" is not a subscription of this Plesk login. Known: ${sites.map((s) => s.name).join(', ')}.`, 'DOMAIN_UNKNOWN');
    return hit;
  }
  if (sites.length > 1) throw new UserError(`This Plesk login has several subscriptions (${sites.map((s) => s.name).join(', ')}): say which with the "domain" argument.`, 'DOMAIN_REQUIRED');
  return sites[0];
}
