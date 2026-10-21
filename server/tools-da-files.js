// files_archive / files_extract / files_upload / files_download for DIRECTADMIN accounts. The tools have the same names and arguments as
// the Plesk ones (tools-plesk-files.js hands a DirectAdmin account over to the functions here). They use only the File Manager commands
// the login key already has (the ones deploy uses for its backups), so a connected account needs no new sign-in.
//
// Where it differs from Plesk: a zip is made in /tmp/kw-archives, never next to the files (a web root is public), and an older panel
// (DirectAdmin 1.668) cannot make a zip at all, so there a FOLDER is downloaded file by file instead.
import { basename, isAbsolute, resolve } from 'node:path';
import { mkdir, readFile, realpath, rename, rm, stat } from 'node:fs/promises';
import { archiveExt, fmChmod, fmCreateArchive, fmExtract, fmList, fmMkdir, fmUpload, isNotFound } from './fm.js';
import { assertNotInternal, assertNotWebRootTarget, assertReadable, assertWritable, docrootInfo, isSecretFileName, isUnreadableName, join, normPath } from './paths.js';
import { assertLocalFileAllowed, checkedMode } from './local-guard.js';
import { looksSecret } from './deploy.js';
import { UserError } from './util.js';

export const ARCHIVE_DIR = '/tmp/kw-archives';
const MAX_TREE_FILES = 20000;
const MB = (n) => `${Math.round((n / 1048576) * 10) / 10} MB`;
const parentOf = (p) => p.slice(0, p.lastIndexOf('/')) || '/';
const nameOf = (p) => p.slice(p.lastIndexOf('/') + 1);

async function entryOf(da, path) {
  try {
    return (await fmList(da, parentOf(path))).entries.find((e) => e.name === nameOf(path)) || null;
  } catch (err) {
    if (isNotFound(err)) return null;
    throw err;
  }
}

/** The tool handlers. `h` is the helper bag of tools.js (reqString, optString, optBool, reqStringArray). */
export function daFileOps(h) {
  const { reqString, optString, optBool, reqStringArray } = h;

  async function archive(args, { session, progress = () => {} }) {
    const folder = normPath(reqString(args, 'folder', { max: 1000 }));
    assertReadable(folder);
    const names = reqStringArray(args, 'names', { max: 200 });
    const name = reqString(args, 'name', { max: 100, pattern: /^[A-Za-z0-9][A-Za-z0-9._ -]*$/, what: 'is not a usable archive name (letters, digits, dot, dash, underscore, space)' });
    const da = await session.da();
    if (archiveExt(da) !== 'zip') {
      throw new UserError('This hosting panel runs an older DirectAdmin that cannot make a zip. Use files_download on the FOLDER instead: it is downloaded file by file.');
    }
    const sources = names.map((n) => {
      if (n.includes('/') || n === '.' || n === '..') throw new UserError(`"${n}" is not a name inside ${folder}: give names, not paths.`);
      if (isUnreadableName(n)) throw new UserError(`${n} is a secret or data file and is not put into a zip through the connector.`);
      const p = join(folder, n);
      assertReadable(p);
      const info = docrootInfo(p);
      if (info && info.rel === '') throw new UserError(`${p} is a whole web root: it holds configuration files with passwords. Zip the folders you need inside it.`);
      return p;
    });
    let listing;
    try {
      listing = await fmList(da, folder);
    } catch (err) {
      if (isNotFound(err)) throw new UserError(`${folder} does not exist.`);
      throw err;
    }
    const have = new Set(listing.entries.map((e) => e.name));
    const missing = names.filter((n) => !have.has(n));
    if (missing.length) throw new UserError(`Not in ${folder}: ${missing.slice(0, 10).join(', ')}.`);
    const dest = `${ARCHIVE_DIR}/${name}.zip`;
    await fmMkdir(da, ARCHIVE_DIR);
    if (await entryOf(da, dest)) throw new UserError(`${dest} already exists: choose another name, or delete it first.`);
    progress(`Zipping ${names.length} item(s) of ${folder}…`);
    const { skipped } = await fmCreateArchive(da, sources, dest);
    // the panel answers "done" for a zip it did not make: look at it
    const made = await entryOf(da, dest);
    if (!made || !(made.size > 0)) throw new UserError(`The panel said the zip was made, but ${dest} is not there (or is empty). Nothing was changed in ${folder}.`);
    await fmChmod(da, [dest], 0o600).catch(() => {});
    return {
      archive: dest,
      bytes: made.size,
      ...(skipped.length ? { skipped_by_panel: skipped.slice(0, 20) } : {}),
      note: 'The zip is in /tmp of the account (not public), and holds EVERYTHING inside the folders, config files included. Download it with files_download, then remove it with delete.',
    };
  }

  async function extract(args, { session }) {
    const folder = normPath(reqString(args, 'folder', { max: 1000 }));
    assertWritable(folder);
    assertNotInternal(folder);
    const info = docrootInfo(folder);
    if (info && info.rel === '') throw new UserError(`${folder} is a web root: unpack into a folder inside it (an archive could replace its .htaccess, which carries the kapaweb firewall block). For a whole site use deploy.`);
    if (args.overwrite === false) throw new UserError('On DirectAdmin an unpack always replaces files of the same name.');
    const archiveName = reqString(args, 'archive', { max: 255 });
    if (archiveName.includes('/')) throw new UserError('"archive" is a file name inside the folder, not a path.');
    const da = await session.da();
    const entry = await entryOf(da, join(folder, archiveName));
    if (!entry || entry.type !== 'file') throw new UserError(`${archiveName} is not a file in ${folder}.`);
    await fmExtract(da, join(folder, archiveName), folder);
    return { extracted: archiveName, into: folder, note: 'Files of the same name were replaced. The panel does not list what it unpacked: look with list_files.' };
  }

  async function upload(args, { session, progress = () => {} }) {
    const source = reqString(args, 'source', { max: 1000 });
    if (!isAbsolute(source)) throw new UserError('"source" must be an absolute path on this computer.');
    const local = await realpath(resolve(source)).catch(() => resolve(source));
    const st = await stat(local).catch(() => null);
    if (!st || !st.isFile()) throw new UserError(`The file ${local} does not exist.`);
    assertLocalFileAllowed(local);
    const name = optString(args, 'name', { max: 255 }) || basename(local);
    if (name.includes('/')) throw new UserError('"name" is a file name, not a path: the folder goes in "folder".');
    if (isSecretFileName(name) || isUnreadableName(name)) throw new UserError(`${name} is a secret or data file: it is not uploaded through the connector.`);
    if (st.size <= 1024 * 1024 && looksSecret((await readFile(local)).toString('latin1'))) {
      throw new UserError(`${basename(local)} looks like it contains a private key or an access token, so it is not uploaded.`);
    }
    const folder = normPath(reqString(args, 'folder', { max: 1000 }));
    const target = join(folder, name);
    assertWritable(target);
    assertNotInternal(target);
    assertNotWebRootTarget(target);
    const perm = args.mode ? checkedMode(args.mode) : 420;
    const overwrite = optBool(args, 'overwrite', true);
    const da = await session.da();
    const before = await entryOf(da, target);
    if (before && !overwrite) throw new UserError(`${target} already exists (overwrite is off).`);
    await fmMkdir(da, folder);
    progress(`Uploading ${name} (${MB(st.size)})…`);
    if (da.fileApi === 'legacy') {
      if (st.size > 200 * 1024 * 1024) throw new UserError('This older panel takes a file only through memory: at most 200 MB. Split it, or use deploy.');
      await fmUpload(da, folder, name, await readFile(local), { overwrite, perm });
    } else {
      await da.uploadFile('POST', '/api/filemanager-actions/upload', {
        fields: { dir: folder, name, overwrite: overwrite ? 'true' : 'false', perm: String(perm) },
        fileField: 'file',
        fileName: name,
        filePath: local,
        onProgress: (sent, total) => progress(`Uploading ${name}: ${Math.round((sent / total) * 100)}%`),
      });
    }
    const after = await entryOf(da, target);
    if (!after || after.size !== st.size) throw new UserError(`The upload of ${name} did not arrive complete (${after ? `${after.size} of ${st.size} bytes` : 'the file is not there'}). Try again.`);
    return { path: target, bytes: st.size, replaced: Boolean(before) };
  }

  async function downloadFile(da, path, target, progress) {
    const entry = await entryOf(da, path);
    if (!entry) throw new UserError(`${path} does not exist.`);
    if (entry.type !== 'file') throw new UserError(`${path} is not a regular file.`);
    progress(`Downloading ${nameOf(path)} (${MB(entry.size)})…`);
    const r = await da.downloadToFile('/api/filemanager/download?' + new URLSearchParams({ path }), target, {
      onProgress: (n) => progress(`Downloading ${nameOf(path)}: ${MB(n)} of ${MB(entry.size)}`),
    });
    if (r.storedBytes !== entry.size) {
      await rm(target, { force: true });
      throw new UserError(`The download of ${nameOf(path)} came to ${r.storedBytes} bytes, the panel lists ${entry.size}. It was removed; try again.`);
    }
    return entry.size;
  }

  /** A folder, file by file (an older panel cannot zip). Secret files and symlinks are left out and counted. */
  async function downloadTree(da, path, target, progress, state) {
    await mkdir(target, { recursive: true, mode: 0o700 });
    const { entries } = await fmList(da, path);
    for (const e of entries) {
      const child = join(path, e.name);
      const local = resolve(target, e.name);
      if (e.type === 'link' || isUnreadableName(e.name) || e.name.startsWith('.')) {
        state.left_out.push(child);
        continue;
      }
      if (e.type === 'dir') {
        await downloadTree(da, child, local, progress, state);
      } else {
        if (state.files >= MAX_TREE_FILES) throw new UserError(`More than ${MAX_TREE_FILES} files: that is too many to fetch one by one. Download part of the folder at a time.`);
        state.bytes += await downloadFile(da, child, local, () => {});
        state.files += 1;
        if (state.files % 50 === 0) progress(`${state.files} files, ${MB(state.bytes)} so far…`);
      }
    }
  }

  async function download(args, { session, progress = () => {} }) {
    const path = normPath(reqString(args, 'path', { max: 1000 }));
    assertReadable(path);
    const name = nameOf(path);
    if (isUnreadableName(name)) throw new UserError(`${name} is a secret or data file and is not downloadable through the connector.`);
    if (name.startsWith('.')) throw new UserError('A file whose name starts with a dot is not downloaded (it could be a settings file).');
    const folder = reqString(args, 'folder', { max: 1000 });
    if (!isAbsolute(folder)) throw new UserError('"folder" must be an absolute path on this computer.');
    const target = resolve(folder, name);
    assertLocalFileAllowed(target);
    if (await stat(target).catch(() => null)) throw new UserError(`${target} already exists on this computer; it is not replaced. Choose another folder.`);
    await mkdir(resolve(folder), { recursive: true, mode: 0o700 });
    const da = await session.da();
    const entry = await entryOf(da, path);
    if (!entry) throw new UserError(`${path} does not exist.`);
    if (entry.type === 'dir') {
      const state = { files: 0, bytes: 0, left_out: [] };
      const part = `${target}.part`;
      await rm(part, { recursive: true, force: true });
      try {
        await downloadTree(da, path, part, progress, state);
        await rename(part, target);
      } catch (err) {
        await rm(part, { recursive: true, force: true });
        throw err;
      }
      return { saved_as: target, files: state.files, bytes: state.bytes, ...(state.left_out.length ? { left_out: state.left_out.slice(0, 30), left_out_count: state.left_out.length } : {}), note: 'Secret files, files starting with a dot and symlinks are not downloaded.' };
    }
    const bytes = await downloadFile(da, path, target, progress);
    return { saved_as: target, bytes };
  }

  return { archive, extract, upload, download };
}
