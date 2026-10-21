// deploy / rollback for PLESK subscriptions: the same promise as the DirectAdmin deploy, on Plesk's File Manager.
//   local folder -> zip (forward slashes) -> backup of the current site -> upload -> unpack (merge)
//   -> prune the files an earlier deploy shipped but this one does not -> verify every file on the server -> clean up.
// Safety copies, manifests and release zips live in /.kapaweb-deploy, in the subscription's own folder but OUTSIDE every web root,
// so nothing there can be fetched from the internet. There is no kapaweb firewall block to keep in .htaccess on Plesk.
//
// STATUS: the File Manager calls under this are proven on a real Plesk (2026-10-15, see PLESK_SUPPORT.md); the flow as a whole is
// covered by tests against a fake Plesk and by a real run on the test subscription.
import { lstat, mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { isAbsolute, join, resolve, parse as parsePath } from 'node:path';
import { readZip } from './zip.js';
import { assertSafeLocalDir, buildArchives, collectFiles, stamp, staleFiles } from './deploy.js';
import { baseOf, dirOf } from './plesk-files.js';
import { UserError } from './util.js';

export const WORK = '/.kapaweb-deploy';
const KEEP_BACKUPS = 3;
const STAMP_RE = '\\d{8}T\\d{9}Z';
const MAX_VERIFY_DIRS = 400;
const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const joinP = (dir, name) => `${dir === '/' ? '' : dir}/${name}`;

function cleanSubfolder(sub) {
  if (!sub) return '';
  const parts = String(sub).split('/').filter(Boolean);
  for (const p of parts) if (!/^[A-Za-z0-9._-]+$/.test(p) || p === '.' || p === '..') throw new UserError('"subfolder" may only contain letters, digits, dot, dash and underscore.');
  return parts.join('/');
}

/** Where a deploy goes, and what its backups and manifest are called (a target is identified by its full path). */
export function pleskTargetPaths(docroot, subfolderInput) {
  const subfolder = cleanSubfolder(subfolderInput);
  const target = subfolder ? `${docroot}/${subfolder}` : docroot;
  const slug = target.replace(/[^A-Za-z0-9]/g, (c) => '_' + c.charCodeAt(0).toString(16));
  return { docroot, subfolder, target, slug, manifest: `${WORK}/manifest${slug}.json`, backupBase: `backup${slug}~` };
}

const backupRe = (t, kind) => new RegExp(`^${escRe(t.backupBase)}${STAMP_RE}${kind === 'safety' ? '\\.before-rollback' : kind === 'any' ? '(?:\\.before-rollback)?' : ''}\\.zip$`);

async function listBackups(files, t, kind = 'backup') {
  try {
    const { entries } = await files.list(WORK);
    const re = backupRe(t, kind);
    return entries.filter((e) => e.type === 'file' && re.test(e.name)).map((e) => e.name).sort();
  } catch (err) {
    if (err?.code === 'NOT_FOUND') return [];
    throw err;
  }
}

async function pruneBackups(files, t) {
  for (const kind of ['backup', 'safety']) {
    const names = await listBackups(files, t, kind);
    const old = names.slice(0, Math.max(0, names.length - KEEP_BACKUPS));
    if (old.length) await files.remove(old.flatMap((n) => [`${WORK}/${n}`, `${WORK}/${n}.manifest.json`]), { permanent: true });
  }
}

async function readManifest(files, path) {
  const text = await files.readText(path, 8 * 1024 * 1024);
  if (!text) return null;
  try {
    const m = JSON.parse(text);
    return Array.isArray(m.files) ? m : null;
  } catch {
    return null;
  }
}

/** Zips <target> as <WORK>/<name>.zip. The archive is made at the top of the subscription (never inside a web root) and holds the full path (httpdocs/blog/...), so it unpacks at the top. */
async function archiveTarget(files, t, name) {
  const made = await files.archivePath(t.target, `kw-bk-${stamp()}`);
  await files.mkdir(WORK);
  await files.chmod([WORK], 0o700).catch(() => {});
  await files.move(made, `${WORK}/${name}`, { overwrite: false }).catch(async (err) => {
    await files.remove([made], { permanent: true }).catch(() => {});
    throw err;
  });
  await files.chmod([`${WORK}/${name}`], 0o600).catch(() => {});
  const info = await files.stat(`${WORK}/${name}`);
  if (!info || info.size <= 0) throw new UserError('The backup archive was not created, so nothing was changed.');
  return { path: `${WORK}/${name}`, bytes: info.size };
}

/** Lists the whole target and compares it with what was uploaded: a file that is missing or has another size stops the deploy. */
async function verifyTree(files, target, expected) {
  const dirs = new Set(['']);
  for (const rel of expected.keys()) {
    const parts = rel.split('/');
    for (let i = 1; i < parts.length; i++) dirs.add(parts.slice(0, i).join('/'));
  }
  if (dirs.size > MAX_VERIFY_DIRS) return { checked: 0, skipped: true };
  let checked = 0;
  const bad = [];
  for (const d of dirs) {
    const listing = await files.list(d ? `${target}/${d}` : target);
    const here = new Map(listing.entries.map((e) => [e.name, e]));
    for (const [rel, size] of expected) {
      const parent = rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/')) : '';
      if (parent !== d) continue;
      const e = here.get(baseOf(rel));
      checked += 1;
      if (!e) bad.push(`${rel} is missing`);
      else if (e.type !== 'file' || e.size !== size) bad.push(`${rel} has ${e.size} bytes instead of ${size}`);
    }
  }
  return { checked, bad, skipped: false };
}

/**
 * @param {{files:import('./plesk-files.js').PleskFiles, progress?:(msg:string)=>void}} ctx
 * @param {{sourceDir:string, domain:string, docroot:string, targetIsDocroot?:boolean, subfolder?:string, mode?:string, confirmReplace?:boolean, keep?:string[],
 *          exclude?:string[], forceInclude?:string[], backup?:'full'|'none', confirmNoBackup?:boolean, dryRun?:boolean}} o
 */
export async function deployPlesk({ files, progress = () => {} }, o) {
  const t = pleskTargetPaths(o.docroot, o.subfolder);
  const mode = o.mode || 'update';
  const backupMode = o.backup || 'full';
  if (!['update', 'replace'].includes(mode)) throw new UserError('mode must be "update" or "replace".');
  if (!['full', 'none'].includes(backupMode)) {
    throw new UserError('On a Plesk account backup is "full" (default) or "none" (with confirm_no_backup). "skip_uploads" is a DirectAdmin option.');
  }
  if (mode === 'replace' && !o.confirmReplace) {
    throw new UserError('mode "replace" deletes everything in the target folder that is not in the new release. Ask the user, and only then call again with confirm_replace: true.');
  }
  if (backupMode === 'none' && !o.confirmNoBackup) throw new UserError('backup "none" needs confirm_no_backup: true, after the user agreed to deploy without a safety copy.');

  if (!isAbsolute(String(o.sourceDir || ''))) {
    throw new UserError('source_dir must be an absolute path on this computer (for example C:\\Users\\me\\project\\dist or /home/me/project/dist): a relative path would be resolved against whatever folder the AI app was started in.');
  }
  let root = resolve(o.sourceDir);
  let st;
  try {
    root = await realpath(root);
    st = await lstat(root);
  } catch {
    throw new UserError(`The folder ${resolve(o.sourceDir)} does not exist on this computer.`);
  }
  if (!st.isDirectory()) throw new UserError(`${root} is not a folder.`);
  if (parsePath(root).root === root || resolve(homedir()) === root) throw new UserError('Pick the project\'s build output folder (for example dist or public), not a drive root or the whole home folder.');
  await assertSafeLocalDir(root);

  progress('Reading the local folder…');
  const local = await collectFiles(root, { exclude: o.exclude || [], forceInclude: o.forceInclude || [] });
  // (.htaccess is kept apart by collectFiles for DirectAdmin's firewall merge; on Plesk it is an ordinary file of the release)
  const all = [...local.files, ...(local.htaccess ? [{ rel: '.htaccess', abs: local.htaccess.abs, size: local.htaccess.size }] : [])];
  if (all.length === 0) throw new UserError('Nothing to deploy: the folder has no files after the default exclusions.');
  const total = all.reduce((s, f) => s + f.size, 0);
  const newSet = new Set(all.map((f) => f.rel));
  const expected = new Map(all.map((f) => [f.rel, f.size]));

  const summary = {
    files: all.length,
    megabytes: Math.round((total / 1048576) * 10) / 10,
    excluded: {
      secrets: local.skipped.secrets.length,
      other_files: local.skipped.soft.length + local.skipped.excluded.length,
      folders: local.skipped.dirs,
      symlinks: local.skipped.symlinks.length,
    },
  };

  let existing = { entries: [] };
  try {
    existing = await files.list(t.target);
  } catch (err) {
    if (err?.code !== 'NOT_FOUND') throw err;
  }
  const prev = await readManifest(files, t.manifest);
  const keepList = (o.keep || []).map((k) => String(k).replace(/^\/+|\/+$/g, ''));
  const rootIsDocroot = !t.subfolder && o.targetIsDocroot !== false;
  const protectedRel = (rel) => rootIsDocroot && (rel === '.well-known' || rel.startsWith('.well-known/') || rel === 'cgi-bin' || rel.startsWith('cgi-bin/'));
  const stale = mode === 'update' && prev ? staleFiles(prev.files, newSet, rootIsDocroot).filter((f) => !protectedRel(f)) : [];
  const isKept = (n) => protectedRel(n) || keepList.some((k) => n === k || k.startsWith(n + '/'));
  const wouldRemove = mode === 'replace' ? existing.entries.map((e) => e.name).filter((n) => !isKept(n)) : stale;

  const warnings = [];
  if (local.skipped.secrets.length) warnings.push(`Not uploaded because they look like secrets: ${local.skipped.secrets.slice(0, 8).join(', ')}. (A Node.js app takes its secrets from environment variables: node_env.)`);
  if (local.skipped.symlinks.length) warnings.push(`${local.skipped.symlinks.length} symbolic link(s) were skipped.`);
  if (!all.some((f) => /^(index\.(html?|php)|package\.json|app\.js|server\.js)$/i.test(f.rel)) && !t.subfolder) {
    warnings.push('There is no index.html, index.php or package.json at the top of this folder. Check that it really is the site\'s or app\'s folder and not a parent folder.');
  }
  if (existing.entries.length && !prev && mode === 'update') warnings.push('The target folder already had files but no earlier connector deploy: existing files were kept and only overlaid, and no stale files were removed.');
  if (rootIsDocroot && existing.entries.some((e) => e.name === 'index.html') && !newSet.has('index.html') && [...newSet].some((n) => /^index\.php$/i.test(n))) {
    warnings.push('The web root has an index.html that is not part of this release; it is served before index.php and hides the new site. If it is only Plesk\'s placeholder page, delete it with files_delete.');
  }

  if (o.dryRun) {
    return {
      dry_run: true,
      target: t.target,
      mode,
      existing_items_in_target: existing.entries.length,
      previous_deploy_known: Boolean(prev),
      would_remove_count: wouldRemove.length,
      would_remove: wouldRemove.slice(0, 20),
      ...summary,
      warnings,
      next: 'Call again without dry_run to deploy.',
    };
  }

  const tmp = await mkdtemp(join(tmpdir(), 'kwdeploy-'));
  let backup = null;
  let step = 'start';
  const uploaded = [];
  try {
    step = 'packing';
    progress('Packing the files…');
    const parts = await buildArchives(local.files.concat(local.htaccess ? [{ rel: '.htaccess', abs: local.htaccess.abs, size: local.htaccess.size, mtime: new Date(), exec: false }] : []), local.emptyDirs, tmp);
    for (const p of parts) {
      const names = readZip(await readFile(p.path)).map((e) => e.name);
      if (names.some((n) => n.includes('\\'))) throw new UserError('Internal check failed: an archive entry contains a backslash.');
    }

    step = 'backup';
    await files.mkdir(WORK);
    if (existing.entries.length && backupMode !== 'none') {
      progress('Making a backup of the current site…');
      const name = `${t.backupBase}${stamp()}.zip`;
      backup = await archiveTarget(files, t, name);
      if (prev) await files.upload(WORK, `${name}.manifest.json`, Buffer.from(JSON.stringify(prev), 'utf8'), { overwrite: true, mode: 0o600 }).catch(() => {});
      await pruneBackups(files, t);
    }

    step = 'clearing';
    if (mode === 'replace' && existing.entries.length) {
      progress('Clearing the old files…');
      const toDelete = existing.entries.map((e) => e.name).filter((n) => !isKept(n));
      if (toDelete.length) await files.remove(toDelete.map((n) => joinP(t.target, n)), { permanent: true });
    }

    step = 'uploading';
    await files.mkdir(t.target);
    const ts = stamp();
    for (let i = 0; i < parts.length; i++) {
      progress(`Uploading part ${i + 1} of ${parts.length}…`);
      const name = `kw-release-${ts}-${i + 1}.zip`;
      await files.uploadFrom(t.target, name, parts[i].path, { overwrite: false });
      uploaded.push(joinP(t.target, name));
    }

    step = 'extracting';
    for (let i = 0; i < uploaded.length; i++) {
      progress(`Unpacking part ${i + 1} of ${uploaded.length}…`);
      await files.extract(t.target, baseOf(uploaded[i]), { overwrite: true });
    }
    await files.remove(uploaded, { permanent: true });
    uploaded.length = 0;

    step = 'pruning';
    let pruned = 0;
    if (stale.length) {
      progress(`Removing ${stale.length} stale file(s)…`);
      const r = await files.remove(stale.map((f) => joinP(t.target, f)), { permanent: true });
      pruned = r.removed;
    }

    step = 'manifest';
    const manifest = { version: 1, deployedAt: new Date().toISOString(), target: t.target, files: [...newSet].sort() };
    await files.upload(WORK, baseOf(t.manifest), Buffer.from(JSON.stringify(manifest), 'utf8'), { overwrite: true, mode: 0o600 });

    step = 'verify';
    progress('Checking every file on the server…');
    const v = await verifyTree(files, t.target, expected);
    if (v.bad && v.bad.length) throw new UserError(`After the upload, ${v.bad.length} file(s) are not as they should be on the server: ${v.bad.slice(0, 6).join('; ')}.`);
    if (v.skipped) warnings.push(`The release has more than ${MAX_VERIFY_DIRS} folders, so only the top level was checked on the server.`);

    return {
      deployed: true,
      target: t.target,
      mode,
      ...summary,
      verified_files: v.checked,
      stale_files_removed: pruned,
      backup: backup?.path ? { path: backup.path, megabytes: Math.round((backup.bytes / 1048576) * 10) / 10 } : backupMode === 'none' ? 'skipped (user agreed)' : 'none needed (target was empty)',
      warnings,
      next: 'Verify with check_url (home page and a deeper page). For a Node.js app: node_configure (application root, startup file), node_install, node_restart. If something is wrong, call rollback.',
    };
  } catch (err) {
    const hint = backup?.path ? ` A backup of the previous state exists at ${backup.path}; call rollback to restore it.` : '';
    if (uploaded.length) await files.remove(uploaded, { permanent: true }).catch(() => {});
    throw new UserError(`Deploy stopped at step "${step}": ${err instanceof UserError ? err.message : String(err?.message || err)}${hint}`);
  } finally {
    await rm(tmp, { recursive: true, force: true }).catch(() => {});
  }
}

/** Restores the newest backup (or a named one) of a target. The current state is saved first (<name>.before-rollback.zip). */
export async function rollbackPlesk({ files, progress = () => {} }, o) {
  const t = pleskTargetPaths(o.docroot, o.subfolder);
  const real = await listBackups(files, t, 'backup');
  const any = await listBackups(files, t, 'any');
  if (real.length === 0 && !o.backup) throw new UserError(`There is no backup for ${t.target} in ${WORK}. Nothing to restore.`);
  let chosen = real[real.length - 1];
  if (o.backup) {
    const wanted = String(o.backup).split('/').pop();
    if (!any.includes(wanted)) throw new UserError(`That backup does not exist for this target. Available: ${any.join(', ') || 'none'}.`);
    chosen = wanted;
  }
  const chosenInfo = await files.stat(`${WORK}/${chosen}`);
  if (!chosenInfo || chosenInfo.size <= 0) throw new UserError(`The backup ${chosen} is missing or empty, so nothing was changed.`);

  let existing = { entries: [] };
  try {
    existing = await files.list(t.target);
  } catch (err) {
    if (err?.code !== 'NOT_FOUND') throw err;
  }
  const rootIsDocroot = !t.subfolder && o.targetIsDocroot !== false;
  const keepAlways = (n) => rootIsDocroot && (n === '.well-known' || n === 'cgi-bin');
  let safety = null;
  const undo = () => (safety ? `The state from before the rollback is saved at ${safety}: call rollback again with backup "${baseOf(safety)}" to put it back.` : 'The target was empty before, so there is nothing else to put back.');
  const warnings = [];

  if (existing.entries.length) {
    progress('Saving the current state before restoring…');
    const name = `${t.backupBase}${stamp()}.before-rollback.zip`;
    const made = await archiveTarget(files, t, name);
    safety = made.path;
    const current = await readManifest(files, t.manifest);
    if (current) await files.upload(WORK, `${name}.manifest.json`, Buffer.from(JSON.stringify(current), 'utf8'), { overwrite: true, mode: 0o600 }).catch(() => {});
    progress('Removing the current files…');
    const del = existing.entries.map((e) => e.name).filter((n) => !keepAlways(n));
    try {
      if (del.length) await files.remove(del.map((n) => joinP(t.target, n)), { permanent: true });
    } catch (err) {
      throw new UserError(`Removing the current files stopped part-way (${err instanceof UserError ? err.message : String(err?.message || err)}); some files may already be gone. ${undo()}`);
    }
  }

  progress('Restoring the backup…');
  const moved = `/${chosen}`;
  try {
    // the archive holds the full path of the target (httpdocs/blog/...): it unpacks at the top of the subscription; it is moved there and back (it stays a backup)
    await files.mkdir(dirOf(t.target));
    await files.move(`${WORK}/${chosen}`, moved, { overwrite: true });
    try {
      await files.extract('/', chosen, { overwrite: true });
    } finally {
      await files.move(moved, `${WORK}/${chosen}`, { overwrite: true }).catch(() => warnings.push(`The backup file could not be moved back to ${WORK}: it is at ${moved}.`));
    }
  } catch (err) {
    throw new UserError(`The restore failed AFTER the current files were removed (${err instanceof UserError ? err.message : String(err?.message || err)}). ${undo()}`);
  }

  let manifest;
  try {
    const old = await readManifest(files, `${WORK}/${chosen}.manifest.json`);
    if (old) {
      await files.upload(WORK, baseOf(t.manifest), Buffer.from(JSON.stringify(old), 'utf8'), { overwrite: true, mode: 0o600 });
      manifest = 'restored together with the backup';
    } else {
      await files.remove([t.manifest], { permanent: true });
      manifest = 'reset: the next deploy treats this target like a first deploy (existing files stay, nothing is pruned)';
    }
  } catch {
    manifest = 'could not be updated: the next deploy may prune files of the release that was rolled back';
  }
  const after = await files.list(t.target);
  return {
    restored: true,
    from: `${WORK}/${chosen}`,
    target: t.target,
    items_in_target: after.entries.length,
    manifest,
    state_before_rollback_saved_as: safety,
    ...(warnings.length ? { warnings } : {}),
    next: 'Verify with check_url.',
  };
}
