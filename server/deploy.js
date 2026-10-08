// deploy / rollback: the playbook's section 5 as one safe operation.
//   local folder -> zip (forward slashes) -> backup -> upload -> extract (merge)
//   -> .htaccess merge (keeps the kapaweb firewall block) -> prune stale files
//   using the previous manifest -> verify -> clean up.
import { lstat, mkdtemp, readdir, readFile, realpath, rm, stat } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { isAbsolute, join, resolve, parse as parsePath } from 'node:path';
import { ZipWriter, readZip, extractEntry } from './zip.js';
import { archiveExt, backupMode, fmChmod, fmCreateArchive, fmExtract, fmList, fmMkdir, fmReadText, fmRemove, fmUpload, fmDiskUsage, isNotFound } from './fm.js';
import { hasFirewallBlock, mergeHtaccess } from './htaccess.js';
import { UserError, normalizeDomain } from './util.js';
import { isSecretFileName, normPath } from './paths.js';
import { describeError } from './da.js';

const MAX_FILES = 60000;
const MAX_FILE_BYTES = 200 * 1024 * 1024;
const PART_BYTES = 30 * 1024 * 1024;
const BIG_BACKUP_BYTES = 300 * 1024 * 1024;
const KEEP_BACKUPS = 3;
const WORK_DIR = '/tmp/kw-deploy';
const STAMP_RE = '\\d{8}T\\d{9}Z'; // what stamp() produces
const DATA_FOLDER = /^(uploads|storage|media|files|cache)$/i;

// lower-case: folder names are compared case-insensitively (".Git" and "Node_Modules" are the same folders on Windows/macOS)
const EXCLUDE_DIRS = new Set(['.git', '.svn', '.hg', 'node_modules', '.idea', '.vscode', '__macosx', '.github', '.ssh', '.claude', '.cursor', 'secrets', 'secret', '.secrets', '.terraform']);
const SOFT_EXCLUDE_FILES = [/^\.DS_Store$/, /^Thumbs\.db$/i, /^desktop\.ini$/i, /~$/, /\.(swp|swo|bak|old|orig|tmp|log)$/i, /^npm-debug\.log/, /\.(sql|sqlite|sqlite3)(\.gz)?$/i];
const STORED_EXT = /\.(jpe?g|png|gif|webp|avif|zip|gz|tgz|bz2|7z|rar|woff2?|mp4|webm|mov|mp3|ogg|pdf)$/i;
// every file below 1 MB is scanned, whatever its name or extension (a key can sit in "logo.png" or "notes.txt")
const SCAN_MAX_BYTES = 1024 * 1024;
// names of web content: judged by their content, not by a name such as "credentials.html" or "id_rsa.pub"
const WEB_CONTENT = /\.(html?|xhtml|css|js|mjs|svg|png|jpe?g|gif|webp|avif|ico|woff2?|ttf|otf|eot|pub)$/i;
const SECRET_CONTENT = [
  // a real PEM key: header, optional "Name: value" lines, then base64 (a bare header in a doc page or a JS library is not a key)
  /-----BEGIN [A-Z ]*PRIVATE KEY-----\r?\n(?:[A-Za-z-]+: [^\r\n]*\r?\n)*[A-Za-z0-9+/=]{20,}/,
  /PuTTY-User-Key-File-\d/,
  /\bAKIA(?![0-9A-Z]{9}EXAMPLE)[0-9A-Z]{16}\b/,
  /\bsk_live_[0-9a-zA-Z]{20,}\b/,
  /\bxox[baprs]-[0-9A-Za-z-]{20,}\b/,
  /\bgh[pousr]_[0-9A-Za-z]{30,}\b/,
  /\bgithub_pat_[0-9A-Za-z_]{40,}\b/,
  /\bsk-ant-[A-Za-z0-9_-]{20,}/,
  /\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}/,
];

// Wildcards are capped: a pattern such as "*a*a*a*a*a*a*a*a*b" would otherwise make the matcher backtrack for seconds.
const MAX_GLOB_LENGTH = 200;
const MAX_GLOB_WILDCARDS = 6;

function globToRegExp(glob) {
  if (glob.length > MAX_GLOB_LENGTH || (glob.match(/[*?]/g) || []).length > MAX_GLOB_WILDCARDS) {
    throw new UserError(`The pattern "${glob.slice(0, 40)}..." is too long or has too many wildcards (max ${MAX_GLOB_LENGTH} characters and ${MAX_GLOB_WILDCARDS} wildcards).`);
  }
  const esc = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '\u0000').replace(/\*/g, '[^/]*').replace(/\u0000/g, '.*').replace(/\?/g, '[^/]');
  return new RegExp('^' + esc + '$', 'i');
}

function matcher(patterns) {
  const res = patterns.map((p) => {
    const anchored = p.includes('/');
    const re = globToRegExp(p.replace(/\/$/, ''));
    return { anchored, re };
  });
  return (rel, name) => res.some((m) => (m.anchored ? m.re.test(rel) || m.re.test(rel + '/x') : m.re.test(name)));
}

/** UTC timestamp that sorts lexicographically, with milliseconds so two backups never collide. */
function stamp() {
  return new Date().toISOString().replace(/[-:.]/g, '');
}

function cleanSubfolder(sub) {
  if (!sub) return '';
  const parts = String(sub).split('/').filter(Boolean);
  for (const p of parts) if (!/^[A-Za-z0-9._-]+$/.test(p) || p === '.' || p === '..') throw new UserError('"subfolder" may only contain letters, digits, dot, dash and underscore.');
  return parts.join('/');
}

export function targetPaths(domainInput, subfolderInput) {
  const domain = normalizeDomain(domainInput);
  const subfolder = cleanSubfolder(subfolderInput);
  const domainRoot = `/domains/${domain}`;
  const docroot = `${domainRoot}/public_html`;
  const target = subfolder ? `${docroot}/${subfolder}` : docroot;
  // The manifest name must identify the target exactly ("a.b", "a-b" and "a/b" are three targets): every character
  // outside [A-Za-z0-9] becomes _<hex>.
  const slug = subfolder ? '-' + subfolder.replace(/[^A-Za-z0-9]/g, (c) => '_' + c.charCodeAt(0).toString(16)) : '';
  // Backup names say exactly which target they belong to: "~" cannot occur in a domain or a subfolder, "," stands for "/".
  const backupBase = `backup-${domain}~${subfolder.split('/').join(',')}~`;
  return { domain, subfolder, domainRoot, docroot, target, manifest: `${domainRoot}/.kw-deploy-manifest${slug}.json`, backupBase };
}

// The folder to deploy is named by the AI and becomes PUBLIC on the web, so keep it away
// from places that hold credentials or personal data.
const SENSITIVE_DIR_NAMES = new Set(['.ssh', '.aws', '.gnupg', '.kube', '.docker', '.azure', '.config', '.claude', '.cursor', '.codex', '.password-store', '.local', '.mozilla', '.thunderbird']);
const PERSONAL_FOLDERS = ['documents', 'downloads', 'desktop', 'pictures', 'videos', 'music', 'movies', 'public', 'library', 'applications'];
const SYSTEM_PREFIXES = ['/etc', '/usr', '/var', '/bin', '/sbin', '/boot', '/proc', '/dev', '/sys', '/root', '/system', '/private', '/library', '/applications'];

/** `rootReal` must already be a canonical path (fs.realpath resolves symlinks and Windows 8.3 short names). */
export async function assertSafeLocalDir(rootReal) {
  const lower = rootReal.replace(/\\/g, '/').toLowerCase();
  const segs = lower.split('/').filter(Boolean);
  if (segs.some((s) => SENSITIVE_DIR_NAMES.has(s))) {
    throw new UserError('That folder is inside a place that holds credentials or settings (for example .ssh or .config). Deploy the project\'s build output folder instead.');
  }
  const canon = async (p) => (await realpath(p).catch(() => p)).replace(/\\/g, '/').toLowerCase();
  const tmp = await canon(tmpdir());
  if (lower === tmp) throw new UserError('That is the whole temporary folder. Pick the project\'s build output folder.');
  if (lower.startsWith(tmp + '/')) return; // a scratch folder below it is fine
  const home = await canon(homedir());
  // macOS keeps the folders of Dropbox, OneDrive, Google Drive ... in ~/Library/CloudStorage: projects live there, so it is not a "settings" folder
  const inCloudMount = lower.startsWith(home + '/library/cloudstorage/');
  if (lower === home || lower.startsWith(home + '/appdata') || (lower.startsWith(home + '/library') && !inCloudMount) || lower.startsWith(home + '/application data')) {
    throw new UserError('Pick the project\'s build output folder, not the home folder or the system settings folders inside it.');
  }
  if (home.startsWith(lower.replace(/\/+$/, '') + '/')) {
    throw new UserError('That folder contains your whole user profile (home folder). Pick the project\'s build output folder.');
  }
  // the personal folders themselves are never a website (a project folder INSIDE Documents is fine, Documents itself is not)
  // (also the redirected ones: "OneDrive/Documents", "Dropbox/Desktop"; a folder deeper inside them is fine)
  const below = lower.startsWith(home + '/') ? lower.slice(home.length + 1).split('/').filter(Boolean) : [];
  const isCloud = (s) => /(dropbox|onedrive|google drive|icloud)/.test(s);
  const mount = inCloudMount ? below.slice(2) : null; // below Library/CloudStorage: [provider folder, ...]
  if (
    (below.length === 1 && (PERSONAL_FOLDERS.includes(below[0]) || isCloud(below[0]))) ||
    (below.length === 2 && isCloud(below[0]) && PERSONAL_FOLDERS.includes(below[1])) ||
    (mount && (mount.length === 1 || (mount.length === 2 && PERSONAL_FOLDERS.includes(mount[1]))))
  ) {
    throw new UserError('That is a personal or cloud-sync folder, not a website. Pick the project\'s build output folder inside it.');
  }
  if (SYSTEM_PREFIXES.some((p) => lower === p || lower.startsWith(p + '/')) || /^[a-z]:\/(windows|windows\.old|program files|program files \(x86\)|programdata|\$recycle\.bin|system volume information)(\/|$)/.test(lower) || /^[a-z]:\/users\/(public|default|all users)$/.test(lower)) {
    throw new UserError('That is a system folder. Pick the project\'s build output folder.');
  }
}

const isProtectedRel = (rel) => rel === '.htaccess' || rel === '.well-known' || rel.startsWith('.well-known/') || rel === 'cgi-bin' || rel.startsWith('cgi-bin/');

// ---------------------------------------------------------------------------
// local side
// ---------------------------------------------------------------------------

export async function collectFiles(root, { exclude = [], forceInclude = [] } = {}) {
  const userExcluded = matcher(exclude);
  const forced = matcher(forceInclude);
  const files = [];
  const emptyDirs = [];
  const skipped = { secrets: [], soft: [], excluded: [], dirs: [], symlinks: [] };
  const flagged = [];
  let htaccess = null;

  async function walk(dirAbs, relDir) {
    const entries = (await readdir(dirAbs, { withFileTypes: true })).sort((a, b) => (a.name < b.name ? -1 : 1));
    if (entries.length === 0 && relDir) emptyDirs.push(relDir);
    for (const ent of entries) {
      const abs = join(dirAbs, ent.name);
      const rel = relDir ? `${relDir}/${ent.name}` : ent.name;
      if (ent.isSymbolicLink()) {
        skipped.symlinks.push(rel);
        continue;
      }
      if (ent.isDirectory()) {
        if (EXCLUDE_DIRS.has(ent.name.toLowerCase()) || SENSITIVE_DIR_NAMES.has(ent.name.toLowerCase()) || userExcluded(rel, ent.name)) {
          skipped.dirs.push(rel);
          continue;
        }
        await walk(abs, rel);
        continue;
      }
      if (!ent.isFile()) continue;
      // a page named "credentials.html" or a public key "id_rsa.pub" is not a secret: web content and public keys are
      // judged by what they contain (below), everything else by its name
      if (isSecretFileName(ent.name) && !WEB_CONTENT.test(ent.name)) {
        skipped.secrets.push(rel);
        continue;
      }
      if (userExcluded(rel, ent.name) && !forced(rel, ent.name)) {
        skipped.excluded.push(rel);
        continue;
      }
      if (SOFT_EXCLUDE_FILES.some((re) => re.test(ent.name)) && !forced(rel, ent.name)) {
        skipped.soft.push(rel);
        continue;
      }
      const st = await stat(abs);
      if (st.size > MAX_FILE_BYTES) throw new UserError(`"${rel}" is ${Math.round(st.size / 1048576)} MB, more than the ${MAX_FILE_BYTES / 1048576} MB the connector uploads in one file. Upload it another way (FTP or the DirectAdmin File Manager).`);
      // every file below 1 MB is scanned for private keys and tokens (in dry runs too, so a dry run predicts the real run)
      if (st.size <= SCAN_MAX_BYTES && looksSecret((await readFile(abs)).toString('latin1'))) {
        flagged.push(rel);
        continue;
      }
      if (rel === '.htaccess') {
        htaccess = { abs, size: st.size };
        continue;
      }
      files.push({ rel, abs, size: st.size, mtime: st.mtime, exec: (st.mode & 0o111) !== 0 && !/\.(php|html?|css|js|json|txt|md|png|jpe?g|gif|svg|webp|ico|woff2?)$/i.test(ent.name) });
      if (files.length > MAX_FILES) throw new UserError(`More than ${MAX_FILES} files: check that you picked the build output folder, not the whole project.`);
    }
  }
  await walk(root, '');
  if (flagged.length) {
    throw new UserError(`These files look like they contain a private key or an access token, so nothing was uploaded: ${flagged.slice(0, 10).join(', ')}. Remove the secret from the file (or from the deploy folder) and try again.`);
  }
  return { files, emptyDirs, skipped, htaccess };
}

/** Private keys and access tokens, judged by content. Samples in documentation (AWS's "...EXAMPLE" keys, a bare PEM header) do not count. */
function looksSecret(text) {
  return SECRET_CONTENT.some((re) => re.test(text));
}

async function buildArchives(files, emptyDirs, tmp) {
  const parts = [];
  let cur = null;
  for (const f of files) {
    const data = await readFile(f.abs);
    if (!cur || cur.bytes > PART_BYTES) {
      cur = new ZipWriter(join(tmp, `part${parts.length + 1}.zip`));
      parts.push(cur);
    }
    await cur.addFile(f.rel, data, { mtime: f.mtime, mode: f.exec ? 0o755 : 0o644, store: STORED_EXT.test(f.rel) });
  }
  if (emptyDirs.length) {
    if (!cur) {
      cur = new ZipWriter(join(tmp, 'part1.zip'));
      parts.push(cur);
    }
    for (const d of emptyDirs) await cur.addDir(d);
  }
  const out = [];
  for (const p of parts) {
    const r = await p.close();
    out.push({ path: p.path, bytes: r.bytes, entries: r.entries });
  }
  return out;
}

// ---------------------------------------------------------------------------
// remote helpers
// ---------------------------------------------------------------------------

const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Exact name patterns of one target's archives, so one target's backups can never be mistaken for another's
 * (a plain prefix match let the main site's rollback pick a subfolder's backup):
 *   real backup    backup-<domain>~<subfolder>~<stamp>.zip   (".partial.zip" when data folders were left out)
 *   safety copy    backup-<domain>~<subfolder>~<stamp>.before-rollback.zip   (made by rollback, never chosen by default)
 * ("zip" on a panel with the new File Manager API, a folder called "....copy" on an older one; see archiveExt in fm.js)
 */
function backupRe(t, kind) {
  const core = `^${escRe(t.backupBase)}${STAMP_RE}`;
  // ".partial" = the archive does not hold the data folders (a rollback to it must leave them alone); it can also
  // mark a safety copy that a rollback of a partial backup made
  const ext = '(?:zip|tar\\.gz|copy)';
  const tail = kind === 'safety' ? `(?:\\.partial)?\\.before-rollback\\.${ext}$` : kind === 'any' ? `(?:\\.partial)?(?:\\.before-rollback)?\\.${ext}$` : `(?:\\.partial)?\\.${ext}$`;
  return new RegExp(core + tail);
}

async function listBackups(da, t, kind = 'backup') {
  const re = backupRe(t, kind);
  try {
    const { entries } = await fmList(da, WORK_DIR);
    return entries.filter((e) => (e.type === 'file' || e.type === 'dir') && re.test(e.name)).map((e) => e.name).sort(); // ("dir": a ".copy" backup of an older panel)
  } catch (err) {
    if (isNotFound(err)) return [];
    throw err;
  }
}

async function pruneBackups(da, t) {
  let removed = 0;
  for (const kind of ['backup', 'safety']) {
    const names = await listBackups(da, t, kind);
    const old = names.slice(0, Math.max(0, names.length - KEEP_BACKUPS));
    // each archive may have a companion "<name>.manifest.json" (the deploy manifest of the state it holds)
    if (old.length) await fmRemove(da, old.flatMap((n) => [`${WORK_DIR}/${n}`, `${WORK_DIR}/${n}.manifest.json`]), { tolerateMissing: true });
    removed += old.length;
  }
  return removed;
}

/**
 * The DirectAdmin archiver stores every source under its base name, so nested folders cannot be archived with
 * their path. "skip_uploads" therefore works on the top level only: data folders (uploads, storage, media, files,
 * cache) and wp-content are left out, and the archive is named ".partial" so a rollback knows to leave them alone.
 */
async function makeBackup(da, t, existing, mode) {
  await fmMkdir(da, WORK_DIR);
  await fmChmod(da, [WORK_DIR], 0o700).catch(() => {}); // backups hold the whole site, config files included
  const partial = mode === 'skip_uploads';
  const leftOut = [];
  const sources = [];
  for (const e of existing.entries) {
    if (partial && isLeftOutOfPartial(e.name)) {
      leftOut.push(e.name);
      continue;
    }
    sources.push(`${t.target}/${e.name}`);
  }
  if (sources.length === 0) return leftOut.length ? { path: null, bytes: 0, skipped: [], leftOut, partial } : null;
  const name = `${t.backupBase}${stamp()}${partial ? '.partial' : ''}.${archiveExt(da)}`;
  const dest = `${WORK_DIR}/${name}`;
  const { skipped } = await fmCreateArchive(da, sources, dest);
  const check = await fmList(da, WORK_DIR);
  const made = check.entries.find((e) => e.name === name);
  if (!made || made.size <= 0) throw new UserError('The backup archive was not created, so nothing was changed.');
  await fmChmod(da, [dest], backupMode(da)).catch(() => {});
  await pruneBackups(da, t);
  return { path: dest, bytes: made.size, skipped, leftOut, partial };
}

const isLeftOutOfPartial = (name) => DATA_FOLDER.test(name) || name === 'wp-content';

/** Manifest entries may be forged (the AI can write that file): only clean relative file paths that are not protected count. */
function staleFiles(listed, newSet, rootIsDocroot = true) {
  const out = [];
  for (const f of listed) {
    if (typeof f !== 'string' || f === '' || f.length > 1024 || newSet.has(f) || (rootIsDocroot && isProtectedRel(f))) continue;
    let clean = false;
    try {
      clean = normPath('/' + f) === '/' + f; // rejects "", ".", "./x", "a//b", "a/", ".." and look-alikes
    } catch {
      clean = false;
    }
    if (clean) out.push(f);
  }
  return out;
}

async function readManifest(da, path) {
  const text = await fmReadText(da, path, 8 * 1024 * 1024);
  if (!text) return null;
  try {
    const m = JSON.parse(text);
    return Array.isArray(m.files) ? m : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// deploy
// ---------------------------------------------------------------------------

/**
 * @param {{da:any, progress?:(msg:string)=>void}} ctx
 * @param {{sourceDir:string, domain:string, subfolder?:string, mode?:'update'|'replace', confirmReplace?:boolean, keep?:string[],
 *          exclude?:string[], forceInclude?:string[], backup?:'full'|'skip_uploads'|'none', confirmNoBackup?:boolean, dryRun?:boolean}} o
 */
export async function deploy({ da, progress = () => {} }, o) {
  const t = targetPaths(o.domain, o.subfolder);
  const mode = o.mode || 'update';
  const backupMode = o.backup || 'full';
  if (!['update', 'replace'].includes(mode)) throw new UserError('mode must be "update" or "replace".');
  if (!['full', 'skip_uploads', 'none'].includes(backupMode)) throw new UserError('backup must be "full", "skip_uploads" or "none".');
  if (mode === 'replace' && !o.confirmReplace) {
    throw new UserError('mode "replace" deletes everything in the web root that is not in the new release. Ask the user, and only then call again with confirm_replace: true.');
  }
  if (backupMode === 'none' && !o.confirmNoBackup) throw new UserError('backup "none" needs confirm_no_backup: true, after the user agreed to deploy without a safety copy.');

  if (!isAbsolute(String(o.sourceDir || ''))) {
    throw new UserError('source_dir must be an absolute path on this computer (for example C:\\Users\\me\\project\\dist or /home/me/project/dist): a relative path would be resolved against whatever folder the AI app was started in.');
  }
  let root = resolve(o.sourceDir);
  let st;
  try {
    root = await realpath(root); // canonical: no symlink or 8.3 short-name tricks past the checks below
    st = await lstat(root);
  } catch {
    throw new UserError(`The folder ${resolve(o.sourceDir)} does not exist on this computer.`);
  }
  if (!st.isDirectory()) throw new UserError(`${root} is not a folder.`);
  if (parsePath(root).root === root || resolve(homedir()) === root) throw new UserError('Pick the project\'s build output folder (for example dist or public), not a drive root or the whole home folder.');
  await assertSafeLocalDir(root);

  // Does the domain exist on this account?
  const domains = await fmList(da, '/domains');
  if (!domains.entries.some((e) => e.type === 'dir' && e.name === t.domain)) {
    throw new UserError(`${t.domain} is not a domain or subdomain of this hosting account. Existing: ${domains.entries.filter((e) => e.type === 'dir').map((e) => e.name).join(', ') || 'none'}.`);
  }

  progress('Reading the local folder…');
  const local = await collectFiles(root, { exclude: o.exclude || [], forceInclude: o.forceInclude || [] });
  const total = local.files.reduce((s, f) => s + f.size, 0);
  if (local.files.length === 0 && !local.htaccess) throw new UserError('Nothing to deploy: the folder has no files after the default exclusions.');
  const rootIsDocroot = !t.subfolder;
  const newSet = new Set([...local.files.map((f) => f.rel), ...(local.htaccess ? ['.htaccess'] : [])]);

  const summary = {
    files: local.files.length + (local.htaccess ? 1 : 0),
    megabytes: Math.round((total / 1048576) * 10) / 10,
    excluded: {
      secrets: local.skipped.secrets.length,
      other_files: local.skipped.soft.length + local.skipped.excluded.length,
      folders: local.skipped.dirs,
      symlinks: local.skipped.symlinks.length,
    },
  };

  // remote state
  let existing = { entries: [] };
  try {
    existing = await fmList(da, t.target);
  } catch (err) {
    if (!isNotFound(err)) throw err;
  }
  const prev = await readManifest(da, t.manifest);
  const keepList = (o.keep || []).map((k) => String(k).replace(/^\/+|\/+$/g, ''));
  const stale = mode === 'update' && prev ? staleFiles(prev.files, newSet, rootIsDocroot) : [];
  // .htaccess, .well-known and cgi-bin of a web root survive a "replace" (kapaweb's firewall block and the certificate
  // challenges live there); a subfolder has no such files, its .htaccess is part of the release like everything else
  const isKept = (n) => (rootIsDocroot && isProtectedRel(n)) || keepList.some((k) => n === k || k.startsWith(n + '/'));
  const wouldRemove = mode === 'replace' ? existing.entries.map((e) => e.name).filter((n) => !isKept(n)) : stale;

  // The release's .htaccess must be acceptable BEFORE anything changes: the merge refuses a "RewriteEngine Off"
  // that would switch the kapaweb firewall block off (dry runs included).
  if (local.htaccess && rootIsDocroot) {
    const current = existing.entries.some((e) => e.name === '.htaccess') ? await fmReadText(da, `${t.target}/.htaccess`, 256 * 1024) : null;
    mergeHtaccess(current, await readFile(local.htaccess.abs, 'utf8'));
  }

  // "skip_uploads" leaves data folders and wp-content out of the backup; "replace" would then delete them with no copy anywhere
  if (mode === 'replace' && backupMode === 'skip_uploads') {
    const unsafe = existing.entries.map((e) => e.name).filter((n) => isLeftOutOfPartial(n) && !keepList.some((k) => n === k || k.startsWith(n + '/')));
    if (unsafe.length) {
      throw new UserError(`Backup "skip_uploads" does not include ${unsafe.join(', ')}, and mode "replace" would delete ${unsafe.length === 1 ? 'it' : 'them'} for good. List ${unsafe.length === 1 ? 'it' : 'them'} in "keep" (untouched) or choose another backup mode.`);
    }
  }

  const warnings = [];
  if (local.skipped.secrets.length) warnings.push(`Not uploaded because they look like secrets: ${local.skipped.secrets.slice(0, 8).join(', ')}.`);
  if (local.skipped.symlinks.length) warnings.push(`${local.skipped.symlinks.length} symbolic link(s) were skipped.`);
  if (!local.files.some((f) => /^index\.(html?|php)$/i.test(f.rel)) && !t.subfolder) warnings.push('There is no index.html or index.php at the top of this folder. Check that it really is the site\'s build output (for example dist or public) and not a parent folder.');
  if (existing.entries.length && !prev && mode === 'update') warnings.push('The web root already had files but no earlier connector deploy: existing files were kept and only overlaid, and no stale files were removed.');

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

  // limits
  const cfg = (await da.get('/api/session/user-config')).body || {};
  const usage = (await da.get('/api/session/user-usage')).body || {};
  const used = (await fmDiskUsage(da, '/').catch(() => null)) || {};
  const quotaBytes = cfg.quotaLim ? Number(cfg.quotaLim) * 1048576 : 0;
  if (quotaBytes && (used.sizeOnDiskBytes || 0) + total * 3 > quotaBytes) {
    throw new UserError(
      `Not enough disk space: the package has ${Math.round(quotaBytes / 1048576)} MB, ${Math.round((used.sizeOnDiskBytes || 0) / 1048576)} MB are used, and this deploy needs about ${Math.round((total * 3) / 1048576)} MB (archive + extracted files + backup). Free space or ask the user about a larger package.`,
    );
  }
  const inode = usage.inode;
  if (inode && !inode.unlimited && inode.limit && inode.usage + local.files.length > inode.limit) {
    throw new UserError(`The package allows ${inode.limit} files and ${inode.usage} are used; this deploy adds about ${local.files.length}.`);
  }
  let existingBytes = 0;
  if (existing.entries.length) existingBytes = (await fmDiskUsage(da, t.target).catch(() => ({}))).sizeOnDiskBytes || 0;
  if (backupMode === 'full' && existingBytes > BIG_BACKUP_BYTES) {
    throw new UserError(`The current site is ${Math.round(existingBytes / 1048576)} MB, too big for an automatic full backup. Call again with backup "skip_uploads" (leaves out wp-content and data folders such as uploads, storage, media, files, cache) or, with the user's agreement, backup "none" and confirm_no_backup: true.`);
  }

  const tmp = await mkdtemp(join(tmpdir(), 'kwdeploy-'));
  let backup = null;
  let step = 'start';
  const uploaded = [];
  try {
    step = 'packing';
    progress('Packing the files…');
    const parts = await buildArchives(local.files, local.emptyDirs, tmp);
    for (const p of parts) {
      const names = readZip(await readFile(p.path)).map((e) => e.name);
      if (names.some((n) => n.includes('\\'))) throw new UserError('Internal check failed: an archive entry contains a backslash.');
    }

    step = 'backup';
    await fmMkdir(da, WORK_DIR);
    let serverHtaccess = null;
    if (rootIsDocroot && existing.entries.some((e) => e.name === '.htaccess')) serverHtaccess = await fmReadText(da, `${t.target}/.htaccess`, 256 * 1024);
    if (existing.entries.length && backupMode !== 'none') {
      progress('Making a backup of the current site…');
      backup = await makeBackup(da, t, existing, backupMode);
      if (backup?.skipped?.length) {
        const list = backup.skipped.slice(0, 5).join(', ');
        if (mode === 'replace') {
          throw new UserError(`The panel could not archive ${backup.skipped.length} file(s) (${list}), and mode "replace" would delete them for good. Nothing was changed. Use mode "update", move those files away first, or ask the user.`);
        }
        warnings.push(`The backup left out ${backup.skipped.length} file(s) that the panel could not archive (${list}).`);
      }
      // the deploy manifest of the state this backup holds travels with it, so a rollback can restore it too
      if (backup?.path && prev) {
        await fmUpload(da, WORK_DIR, `${backup.path.split('/').pop()}.manifest.json`, Buffer.from(JSON.stringify(prev), 'utf8'), { overwrite: true, perm: 384 }).catch(() => {});
      }
    }

    step = 'clearing';
    if (mode === 'replace' && existing.entries.length) {
      progress('Clearing the old files…');
      const toDelete = existing.entries.map((e) => e.name).filter((n) => !isKept(n));
      if (toDelete.length) await fmRemove(da, toDelete.map((n) => `${t.target}/${n}`), { trash: false, tolerateMissing: true });
    }

    step = 'uploading';
    await fmMkdir(da, t.target);
    const ts = stamp();
    for (let i = 0; i < parts.length; i++) {
      progress(`Uploading part ${i + 1} of ${parts.length}…`);
      const name = `release-${t.domain}-${ts}-${i + 1}.zip`;
      await fmUpload(da, WORK_DIR, name, await readFile(parts[i].path));
      uploaded.push(`${WORK_DIR}/${name}`);
    }

    step = 'extracting';
    for (let i = 0; i < uploaded.length; i++) {
      progress(`Unpacking part ${i + 1} of ${uploaded.length}…`);
      await fmExtract(da, uploaded[i], t.target);
    }

    step = 'htaccess';
    let htaccessAction = 'unchanged';
    if (local.htaccess) {
      const incoming = await readFile(local.htaccess.abs, 'utf8');
      if (rootIsDocroot) {
        const current = await fmReadText(da, `${t.target}/.htaccess`, 256 * 1024); // read again now: the panel may have changed it since the first look
        const merged = mergeHtaccess(current, incoming);
        await fmUpload(da, t.target, '.htaccess', Buffer.from(merged.content, 'utf8'), { overwrite: true, perm: 420 });
        htaccessAction = merged.action === 'merged' ? 'merged (kapaweb firewall block kept)' : 'written';
      } else {
        await fmUpload(da, t.target, '.htaccess', Buffer.from(incoming, 'utf8'), { overwrite: true, perm: 420 });
        htaccessAction = 'written (subfolder)';
      }
    }

    step = 'pruning';
    let pruned = 0;
    if (stale.length) {
      progress(`Removing ${stale.length} stale file(s)…`);
      const r = await fmRemove(da, stale.map((f) => `${t.target}/${f}`), { trash: false, tolerateMissing: true });
      pruned = r.removed;
      if (r.failed.length) warnings.push(`${r.failed.length} stale file(s) could not be removed (they may be gone already): ${r.failed.slice(0, 5).map((p) => p.slice(t.target.length + 1)).join(', ')}.`);
    }

    step = 'manifest';
    const manifest = { version: 1, deployedAt: new Date().toISOString(), target: t.target, files: [...newSet].sort() };
    await fmUpload(da, t.domainRoot, t.manifest.split('/').pop(), Buffer.from(JSON.stringify(manifest), 'utf8'), { overwrite: true, perm: 420 });

    step = 'verify';
    const after = await fmList(da, t.target);
    const names = new Set(after.entries.map((e) => e.name));
    const top = [...new Set([...newSet].map((f) => f.split('/')[0]))];
    const missing = top.filter((n) => !names.has(n));
    if (missing.length) throw new UserError(`After extraction these top-level items are missing on the server: ${missing.slice(0, 10).join(', ')}.`);
    if (rootIsDocroot && names.has('index.html') && newSet.has('index.php') && !newSet.has('index.html')) {
      warnings.push('The web root has an index.html that is not part of this release; it is served before index.php and hides the new site. Check it and delete it with the delete tool if it is only a placeholder.');
    }
    if (rootIsDocroot) {
      const finalHt = await fmReadText(da, `${t.target}/.htaccess`, 256 * 1024);
      if (serverHtaccess && hasFirewallBlock(serverHtaccess) && !(finalHt && hasFirewallBlock(finalHt))) {
        warnings.push('The kapaweb firewall block is missing from .htaccess after the deploy. Restore it from the backup before anything else.');
      }
    }

    step = 'cleanup';
    if (uploaded.length) await fmRemove(da, uploaded).catch(() => {});

    return {
      deployed: true,
      target: t.target,
      mode,
      ...summary,
      htaccess: htaccessAction,
      stale_files_removed: pruned,
      backup: backup?.path
        ? { path: backup.path, megabytes: Math.round((backup.bytes / 1048576) * 10) / 10, ...(backup.partial ? { partial: true, left_out: backup.leftOut } : {}) }
        : backupMode === 'none'
          ? 'skipped (user agreed)'
          : backup?.leftOut?.length
            ? { note: `nothing to archive: only ${backup.leftOut.join(', ')} exist${backup.leftOut.length === 1 ? 's' : ''} and skip_uploads leaves them out` }
            : 'none needed (web root was empty)',
      warnings,
      next: 'Verify with check_url (home page and a deeper page) and read the error log with logs. If something is wrong, call rollback.',
    };
  } catch (err) {
    const hint = backup?.path ? ` A backup of the previous state exists at ${backup.path}; call rollback to restore it.` : '';
    if (uploaded.length) await fmRemove(da, uploaded).catch(() => {});
    throw new UserError(`Deploy stopped at step "${step}": ${err instanceof UserError ? err.message : describeError(err)}${hint}`);
  } finally {
    await rm(tmp, { recursive: true, force: true }).catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// rollback
// ---------------------------------------------------------------------------

export async function rollback({ da, progress = () => {} }, o) {
  const t = targetPaths(o.domain, o.subfolder);
  const real = await listBackups(da, t, 'backup');
  const any = await listBackups(da, t, 'any');
  if (real.length === 0 && !o.backup) throw new UserError(`There is no backup for ${t.target} in ${WORK_DIR}. Nothing to restore.`);
  let chosen = real[real.length - 1];
  if (o.backup) {
    const wanted = String(o.backup).split('/').pop();
    if (!any.includes(wanted)) throw new UserError(`That backup does not exist for this target. Available: ${any.join(', ') || 'none'}.`);
    chosen = wanted;
  }
  // nothing is touched before the chosen archive is known to exist and to hold something
  const listing = await fmList(da, WORK_DIR);
  const chosenEntry = listing.entries.find((e) => e.name === chosen);
  if (!chosenEntry || chosenEntry.size <= 0) throw new UserError(`The backup ${chosen} is missing or empty, so nothing was changed.`);
  // a partial archive (a "skip_uploads" backup, or the safety copy of a rollback to one) lacks the data folders: they are left alone
  const partial = /\.partial(?:\.before-rollback)?\.(?:zip|tar\.gz|copy)$/.test(chosen);

  let existing = { entries: [] };
  try {
    existing = await fmList(da, t.target);
  } catch (err) {
    if (!isNotFound(err)) throw err;
  }
  const rootIsDocroot = !t.subfolder;
  // a web root keeps .htaccess (kapaweb's firewall block), .well-known and cgi-bin; a subfolder has no such files
  const keepAlways = (n) => rootIsDocroot && (n === '.well-known' || n === 'cgi-bin' || n === '.htaccess');
  const warnings = [];
  let safety = null;
  let serverHtaccess = null;
  const undo = () =>
    safety
      ? `The state from before the rollback is saved at ${safety}: call rollback again with backup "${safety.split('/').pop()}" to put it back.`
      : 'The web root was empty before, so there is nothing else to put back.';
  if (existing.entries.length) {
    if (rootIsDocroot && existing.entries.some((e) => e.name === '.htaccess')) serverHtaccess = await fmReadText(da, `${t.target}/.htaccess`, 256 * 1024);
    progress('Saving the current state before restoring…');
    await fmMkdir(da, WORK_DIR);
    await fmChmod(da, [WORK_DIR], 0o700).catch(() => {});
    const untouched = partial ? existing.entries.map((e) => e.name).filter(isLeftOutOfPartial) : [];
    const sources = existing.entries.filter((e) => !untouched.includes(e.name)).map((e) => `${t.target}/${e.name}`);
    if (sources.length) {
      const name = `${t.backupBase}${stamp()}${partial ? '.partial' : ''}.before-rollback.${archiveExt(da)}`;
      const { skipped } = await fmCreateArchive(da, sources, `${WORK_DIR}/${name}`);
      const made = (await fmList(da, WORK_DIR)).entries.find((e) => e.name === name);
      if (!made || made.size <= 0) throw new UserError('The safety copy of the current state could not be created, so nothing was changed.');
      if (skipped.length) throw new UserError(`The safety copy would leave out ${skipped.length} file(s) (${skipped.slice(0, 5).join(', ')}), so nothing was changed.`);
      await fmChmod(da, [`${WORK_DIR}/${name}`], backupMode(da)).catch(() => {});
      // the deploy manifest of the state being replaced travels with the safety copy
      const current = await readManifest(da, t.manifest);
      if (current) await fmUpload(da, WORK_DIR, `${name}.manifest.json`, Buffer.from(JSON.stringify(current), 'utf8'), { overwrite: true, perm: 384 }).catch(() => {});
      safety = `${WORK_DIR}/${name}`;
    }
    progress('Removing the current files…');
    const del = existing.entries.map((e) => e.name).filter((n) => !keepAlways(n) && !untouched.includes(n));
    try {
      if (del.length) {
        const r = await fmRemove(da, del.map((n) => `${t.target}/${n}`), { trash: false, tolerateMissing: true });
        if (r.failed.length) warnings.push(`${r.failed.length} current file(s) could not be removed first (${r.failed.slice(0, 5).map((p) => p.slice(t.target.length + 1)).join(', ')}); the restore overwrote what it could.`);
      }
    } catch (err) {
      throw new UserError(`Removing the current files stopped part-way (${err instanceof UserError ? err.message : describeError(err)}); some files may already be gone. ${undo()}`);
    }
  }
  progress('Restoring the backup…');
  try {
    await fmMkdir(da, t.target);
    await fmExtract(da, `${WORK_DIR}/${chosen}`, t.target);
  } catch (err) {
    throw new UserError(`The restore failed AFTER the current files were removed (${err instanceof UserError ? err.message : describeError(err)}). ${undo()}`);
  }
  // the extraction may have replaced .htaccess with the backup's copy: the current firewall block must survive that
  let htaccess = 'unchanged';
  if (rootIsDocroot && serverHtaccess && hasFirewallBlock(serverHtaccess)) {
    try {
      const restored = await fmReadText(da, `${t.target}/.htaccess`, 256 * 1024);
      const merged = mergeHtaccess(serverHtaccess, restored || '');
      await fmUpload(da, t.target, '.htaccess', Buffer.from(merged.content, 'utf8'), { overwrite: true, perm: 420 });
      htaccess = 'merged (kapaweb firewall block kept)';
    } catch (err) {
      htaccess = `WARNING: the kapaweb firewall block could not be merged back (${err instanceof UserError ? err.message : describeError(err)}). Check .htaccess.`;
    }
  }
  // the deploy manifest must describe what is on the server now: the one that came with the backup, or none
  let manifest;
  try {
    const old = await readManifest(da, `${WORK_DIR}/${chosen}.manifest.json`);
    if (old) {
      await fmUpload(da, t.domainRoot, t.manifest.split('/').pop(), Buffer.from(JSON.stringify(old), 'utf8'), { overwrite: true, perm: 420 });
      manifest = 'restored together with the backup';
    } else {
      await fmRemove(da, [t.manifest], { trash: false, tolerateMissing: true });
      manifest = 'reset: the next deploy treats this target like a first deploy (existing files stay, nothing is pruned)';
    }
  } catch {
    manifest = 'could not be updated: the next deploy may prune files of the release that was rolled back';
  }
  const after = await fmList(da, t.target);
  return {
    restored: true,
    from: `${WORK_DIR}/${chosen}`,
    target: t.target,
    items_in_target: after.entries.length,
    htaccess,
    manifest,
    partial_backup: partial || undefined,
    state_before_rollback_saved_as: safety,
    ...(warnings.length ? { warnings } : {}),
    next: 'Verify with check_url and logs.',
  };
}

export { WORK_DIR };
