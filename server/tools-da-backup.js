// backup_list / backup_create / backup_restore for DIRECTADMIN accounts: the panel's own "Backup and Restore" page (user level), done
// from the connector so nobody has to open DirectAdmin for it.
//
// The wire format below was NOT guessed: it is what the panel's own web app sends (observed 5/11/2026 on a real account, DirectAdmin
// Evolution on ssd5.kdns.gr, backup + restore both ran):
//   list     GET  /CMD_SITE_BACKUP?json=yes&domain=<d>   -> ["backup-Nov-05-2026-1.tar.zst", ...]   (names only, newest last)
//   contents POST /CMD_SITE_BACKUP?json=yes  JSON {file, domain, json:'yes', action:'view'}  -> ["domain","email",...]  (what the file holds)
//   create   POST /CMD_SITE_BACKUP?json=yes  JSON {select0..N, domain, json:'yes', action:'backup', form_version:'4', domains0..N}   -> 200, empty body
//   restore  POST /CMD_SITE_BACKUP?json=yes  JSON {file, select0..N, domain, json:'yes', action:'restore', form_version:'3'}          -> 200, empty body
//   upload   POST /api/filemanager-actions/upload (dir '/backups')  -> carries a backup made ELSEWHERE (another server) into this account
//   download GET  /api/filemanager/download?path=/backups/<file>     -> carries a backup of this account to this computer
//   delete   POST /api/filemanager-actions/remove (trash)            -> takes one backup file away again
// Create and restore only QUEUE the job (DirectAdmin's task queue runs it within about a minute): a backup is proven by its name
// appearing in the list, a restore has no completion signal in the panel's API, so the result says "queued" and the caller checks the site.
import { basename, isAbsolute, resolve } from 'node:path';
import { mkdir, open, readFile, realpath, rm, stat } from 'node:fs/promises';
import { UserError, limitOrZero } from './util.js';
import { fmDiskUsage, fmList, fmMkdir, fmRemove, fmUpload, isNotFound } from './fm.js';
import { assertLocalFileAllowed } from './local-guard.js';

const CMD = '/CMD_SITE_BACKUP';
/** Every part of an account the panel can back up (the checkboxes of its "Create Backup" form). */
export const BACKUP_SECTIONS = ['domain', 'subdomain', 'email', 'email_data', 'emailsettings', 'forwarder', 'autoresponder', 'vacation', 'list', 'ftp', 'ftpsettings', 'database', 'database_data', 'trash'];
const SECTION_HELP = {
  domain: 'website files (Domains Directory)',
  subdomain: 'subdomain lists',
  email: 'e-mail accounts',
  email_data: 'e-mail messages',
  emailsettings: 'e-mail filters and catch-all',
  forwarder: 'forwarders',
  autoresponder: 'autoresponders',
  vacation: 'vacation messages',
  list: 'mailing lists',
  ftp: 'FTP accounts',
  ftpsettings: 'FTP settings',
  database: 'database settings (users)',
  database_data: 'database contents',
  trash: 'deleted-trash data',
};
const FILE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$/;
const BACKUPS_DIR = '/backups';
/** A backup that is carried INTO an account: a plain name, and a compressed tar (the two kinds DirectAdmin makes). Its first bytes must say so too. */
const UPLOAD_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.tar\.(gz|zst)$/i;
const MAGIC = { gz: Buffer.from([0x1f, 0x8b]), zst: Buffer.from([0x28, 0xb5, 0x2f, 0xfd]) };
const MB = (n) => (n < 1048576 ? `${Math.max(1, Math.round(n / 1024))} KB` : `${Math.round((n / 1048576) * 10) / 10} MB`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const names = (body) => (Array.isArray(body) ? body.filter((x) => typeof x === 'string') : null);
// a backup list comes from the panel (a hacked site can create files in /backups): only plain backup names are shown or used
const plainBackups = (list) => list.filter((n) => FILE_RE.test(n) && /\.tar(\.[a-z0-9]+)?$/i.test(n));

/** The tool handlers. `h` is the helper bag of tools.js. */
export function daBackupOps(h) {
  const { reqString, optString, optInt, optStringArray, reqDomain } = h;
  const pollMs = () => (Number(process.env.KAPAWEB_CONNECTOR_POLL_MS) > 0 ? Number(process.env.KAPAWEB_CONNECTOR_POLL_MS) : 5000);

  async function mainDomain(args, da) {
    const given = optString(args, 'domain', { max: 253 });
    if (given) return reqDomain(args);
    const cfg = (await da.get('/api/session/user-config')).body || {};
    const d = String(cfg.domain || (Array.isArray(cfg.domains) ? cfg.domains[0] : '') || '').toLowerCase();
    if (!d) throw new UserError('Could not tell the main domain of this account: pass domain=<the account\'s main domain>.');
    return d;
  }

  async function allDomains(da, main) {
    const cfg = (await da.get('/api/session/user-config')).body || {};
    const list = [cfg.domain, ...(Array.isArray(cfg.domains) ? cfg.domains : [])].filter(Boolean).map((d) => String(d).toLowerCase());
    return [...new Set([main, ...list])];
  }

  async function listNames(da, domain) {
    const { body } = await da.get(`${CMD}?` + new URLSearchParams({ json: 'yes', domain }));
    const raw = names(body);
    const n = raw && plainBackups(raw);
    if (!n) {
      throw new UserError('The panel did not answer with a list of backups. Backups of this account may not be allowed for this connection: ask the user to connect the account again (the new sign-in adds the backup permission), or to use Backup and Restore in DirectAdmin.');
    }
    return n;
  }

  async function contents(da, domain, file) {
    const { body } = await da.postJson(`${CMD}?json=yes`, { file, domain, json: 'yes', action: 'view' });
    const n = names(body);
    if (!n) throw new UserError(`The panel could not read ${file}: it may be damaged, or not finished yet.`);
    return n;
  }

  function checkedSections(list, allowed, what) {
    const bad = list.filter((s) => !allowed.includes(s));
    if (bad.length) throw new UserError(`Unknown ${what} section(s): ${bad.join(', ')}. Allowed: ${allowed.join(', ')}.`);
    return [...new Set(list)];
  }

  function selects(sections) {
    return Object.fromEntries(sections.map((s, i) => [`select${i}`, s]));
  }

  /** Queues a backup and waits until its file shows up in the list. Returns { file } or { file: null, ... } when it was not finished in time. */
  async function createAndWait(da, domain, sections, domains, waitSeconds, progress) {
    const before = new Set(await listNames(da, domain));
    const body = { ...selects(sections), domain, json: 'yes', action: 'backup', form_version: '4', ...Object.fromEntries(domains.map((d, i) => [`domains${i}`, d])) };
    await da.postJson(`${CMD}?json=yes`, body);
    const until = Date.now() + waitSeconds * 1000;
    let last = 0;
    while (Date.now() < until) {
      await sleep(Math.min(pollMs(), Math.max(until - Date.now(), 1)));
      const now = await listNames(da, domain);
      const fresh = now.filter((n) => !before.has(n));
      if (fresh.length) return { file: fresh[fresh.length - 1] };
      if (Date.now() - last > 15000) {
        progress?.(`Backup queued, waiting for DirectAdmin to finish it… ${Math.round((until - Date.now()) / 1000)}s left`);
        last = Date.now();
      }
    }
    return { file: null };
  }

  async function list(args, { session }) {
    const da = await session.da();
    const domain = await mainDomain(args, da);
    const all = await listNames(da, domain);
    const file = optString(args, 'file', { max: 220 });
    if (file) {
      if (!FILE_RE.test(file) || !all.includes(file)) throw new UserError(`${file} is not one of this account's backups: ${all.join(', ') || '(none)'}.`);
      const inside = await contents(da, domain, file);
      return { file, contains: inside.map((s) => ({ section: s, what: SECTION_HELP[s] || s })), restore_with: 'backup_restore (needs the user\'s yes naming what will be replaced)' };
    }
    return { domain, backups: all, count: all.length, note: all.length ? 'Newest last. Pass file=<name> to see what a backup holds. Backups are stored in /backups of the account.' : 'No backups yet: backup_create makes one.' };
  }

  async function create(args, { session, progress }) {
    const da = await session.da();
    const domain = await mainDomain(args, da);
    const wanted = optStringArray(args, 'sections', { max: 30, itemMax: 30 });
    const sections = wanted.length ? checkedSections(wanted, BACKUP_SECTIONS, 'backup') : BACKUP_SECTIONS;
    const given = optStringArray(args, 'domains', { max: 100, itemMax: 253 });
    const domains = given.length ? given.map((d) => reqDomain({ d }, 'd')) : await allDomains(da, domain);
    const wait = optInt(args, 'wait_seconds', 120, { min: 0, max: 600 });
    const warning = await roomWarning(da);
    const made = await createAndWait(da, domain, sections, domains, wait, progress);
    if (made.file) {
      return { created: made.file, sections, domains, ...(warning ? { warning } : {}), note: 'The backup is in /backups of the account. backup_list shows it; backup_restore can restore it.' };
    }
    return {
      status: 'queued',
      sections,
      domains,
      ...(warning ? { warning } : {}),
      note: wait === 0
        ? 'The backup was queued. DirectAdmin makes it within about a minute: look again with backup_list.'
        : `The backup was queued but its file is not there yet after ${wait} s (a big account takes longer). Look again with backup_list before relying on it; do not start a second one.`,
    };
  }

  /** The disk quota of the account: null when it is unlimited (or not told). */
  async function spaceInfo(da) {
    const cfg = (await da.get('/api/session/user-config')).body || {};
    const usage = (await da.get('/api/session/user-usage')).body || {};
    if (usage.quotaBytes?.unlimited === true) return null;
    const limit = limitOrZero(cfg.quotaLim) * 1048576;
    if (!limit) return null;
    const used = ((await fmDiskUsage(da, '/').catch(() => null)) || {}).sizeOnDiskBytes || 0;
    return { limit, used, free: limit - used };
  }

  /** A backup is a whole copy of the account: refuse when the disk is nearly full, warn when it may not fit. Returns a warning text or ''. */
  async function roomWarning(da) {
    const info = await spaceInfo(da);
    if (!info) return '';
    const { limit, used, free } = info;
    if (free < 20 * 1048576) {
      throw new UserError(`Only ${Math.max(0, Math.round(free / 1048576))} MB of the ${Math.round(limit / 1048576)} MB disk quota are free: a backup would not fit. Free space first (old backups can be removed with backup_delete), or ask the user about a larger package.`);
    }
    return free < used ? `Free disk space (${Math.round(free / 1048576)} MB) is smaller than the account's content (${Math.round(used / 1048576)} MB): the backup may not fit. Check it exists with backup_list before relying on it.` : '';
  }

  /** The file entry of a backup in /backups (null when there is none). Only a real file counts, never a folder or a link. */
  async function backupEntry(da, file) {
    try {
      const e = (await fmList(da, BACKUPS_DIR)).entries.find((x) => x.name === file);
      return e && e.type === 'file' ? e : null;
    } catch (err) {
      if (isNotFound(err)) return null;
      throw err;
    }
  }

  /** Removes a file this tool made itself (an upload that failed its checks): it must not stay behind on the account. */
  async function dropOwn(da, file) {
    await fmRemove(da, [`${BACKUPS_DIR}/${file}`], { trash: false, tolerateMissing: true }).catch(() => {});
  }

  /**
   * Carries a backup that was made on ANOTHER server (or earlier, and kept on this computer) into /backups of this account, so that
   * backup_restore can use it. It only adds a file: nothing is restored and no existing backup is replaced. The panel itself must be
   * able to read the file as a backup (its own "view"), otherwise the file is removed again and the caller is told.
   */
  async function upload(args, { session, progress = () => {} }) {
    const source = reqString(args, 'source', { max: 1000 });
    if (!isAbsolute(source)) throw new UserError('"source" must be an absolute path on this computer.');
    const local = await realpath(resolve(source)).catch(() => resolve(source));
    const st = await stat(local).catch(() => null);
    if (!st || !st.isFile()) throw new UserError(`The file ${local} does not exist.`);
    assertLocalFileAllowed(local);
    const name = optString(args, 'name', { max: 130 }) || basename(local);
    const m = UPLOAD_NAME_RE.exec(name);
    if (!m) throw new UserError(`"${name}" is not a usable backup name: letters, digits, dot, dash and underscore only, ending in .tar.gz or .tar.zst. Pass name=<new name> to give the file a name like that.`);
    const ext = m[1].toLowerCase();
    const head = Buffer.alloc(4);
    const fh = await open(local, 'r');
    try {
      await fh.read(head, 0, 4, 0);
    } finally {
      await fh.close();
    }
    if (!head.subarray(0, MAGIC[ext].length).equals(MAGIC[ext])) throw new UserError(`${basename(local)} does not look like a .tar.${ext} archive (its first bytes are not those of a ${ext === 'gz' ? 'gzip' : 'zstd'} file). Nothing was uploaded.`);
    if (st.size < 1024) throw new UserError(`${basename(local)} is only ${st.size} bytes: that cannot be a backup. Nothing was uploaded.`);
    const da = await session.da();
    const domain = await mainDomain(args, da);
    if (await backupEntry(da, name) || (await listNames(da, domain)).includes(name)) {
      throw new UserError(`${name} already exists in /backups of this account; it is never replaced. Pass name=<another name>.`);
    }
    const info = await spaceInfo(da);
    let warning = '';
    if (info) {
      if (info.free < st.size + 20 * 1048576) {
        throw new UserError(`The backup is ${MB(st.size)} but only ${Math.max(0, Math.round(info.free / 1048576))} MB of the ${Math.round(info.limit / 1048576)} MB disk quota are free. Free space first (old backups can be removed with backup_delete), or ask the user about a larger package.`);
      }
      const after = info.free - st.size;
      if (after < info.used) warning = `After this upload ${MB(after)} of disk quota are free, less than the account's content (${MB(info.used)}): the safety backup that backup_restore makes first may not fit. Free space before restoring.`;
    }
    if (!(await fmList(da, BACKUPS_DIR).then(() => true, (err) => (isNotFound(err) ? false : Promise.reject(err))))) await fmMkdir(da, BACKUPS_DIR);
    progress(`Uploading ${name} (${MB(st.size)})…`);
    const perm = 0o600; // a backup holds the whole account, mail and database contents included: only the owner may read it
    if (da.fileApi === 'legacy') {
      if (st.size > 200 * 1024 * 1024) throw new UserError('This older panel takes a file only through memory: at most 200 MB. Use Backup and Restore in DirectAdmin for a bigger one.');
      await fmUpload(da, BACKUPS_DIR, name, await readFile(local), { overwrite: false, perm });
    } else {
      await da.uploadFile('POST', '/api/filemanager-actions/upload', {
        fields: { dir: BACKUPS_DIR, name, overwrite: 'false', perm: String(perm) },
        fileField: 'file',
        fileName: name,
        filePath: local,
        onProgress: (sent, total) => progress(`Uploading ${name}: ${Math.round((sent / total) * 100)}%`),
      });
    }
    const got = await backupEntry(da, name);
    if (!got || got.size !== st.size) {
      await dropOwn(da, name);
      throw new UserError(`The upload of ${name} did not arrive complete (${got ? `${got.size} of ${st.size} bytes` : 'the file is not there'}). It was removed; try again.`);
    }
    // the upload's "200" proves nothing about the file: the panel must list it and be able to read it as a backup
    let listed = false;
    const until = Date.now() + (Number(process.env.KAPAWEB_CONNECTOR_LIST_WAIT_MS) > 0 ? Number(process.env.KAPAWEB_CONNECTOR_LIST_WAIT_MS) : 30000);
    while (!listed) {
      listed = (await listNames(da, domain)).includes(name);
      if (listed || Date.now() > until) break;
      await sleep(Math.min(pollMs(), 2000));
    }
    let inside = [];
    if (listed) inside = await contents(da, domain, name).catch(() => []);
    if (!listed || !inside.length) {
      await dropOwn(da, name);
      throw new UserError(listed
        ? `The panel listed ${name} but could not read it as a backup (it may be damaged, made by another kind of DirectAdmin backup, or not for this account). The uploaded file was removed again; nothing was changed.`
        : `The file arrived but DirectAdmin does not list ${name} as one of this account's backups (the panel only lists names it recognises). The uploaded file was removed again; nothing was changed.`);
    }
    return {
      uploaded: name,
      bytes: st.size,
      contains: inside.map((s) => ({ section: s, what: SECTION_HELP[s] || s })),
      ...(warning ? { warning } : {}),
      note: 'Nothing was restored. backup_restore can now use it: tell the user exactly which parts it will REPLACE (e-mail, forwarders... never the website files unless wanted), get a clear yes, then call backup_restore with the sections and confirm:true.',
    };
  }

  /** Carries a backup of this account to this computer (to take it to another server with backup_upload). */
  async function download(args, { session, progress = () => {} }) {
    const file = reqString(args, 'file', { max: 220, pattern: FILE_RE, what: 'is not a backup file name' });
    if (args.confirm !== true) {
      throw new UserError('A backup holds the whole account: website files, e-mail messages and database contents. Tell the user which backup goes to which folder of this computer; only after their clear yes call again with confirm:true.');
    }
    const folder = reqString(args, 'folder', { max: 1000 });
    if (!isAbsolute(folder)) throw new UserError('"folder" must be an absolute path on this computer.');
    const target = resolve(folder, file);
    assertLocalFileAllowed(target);
    if (await stat(target).catch(() => null)) throw new UserError(`${target} already exists on this computer; it is not replaced. Choose another folder.`);
    const da = await session.da();
    const domain = await mainDomain(args, da);
    if (!(await listNames(da, domain)).includes(file)) throw new UserError(`${file} is not one of this account's backups (backup_list shows them).`);
    const entry = await backupEntry(da, file);
    if (!entry) throw new UserError(`${file} is not a regular file in /backups of this account.`);
    await mkdir(resolve(folder), { recursive: true, mode: 0o700 });
    progress(`Downloading ${file} (${MB(entry.size)})…`);
    const r = await da.downloadToFile(`/api/filemanager/download?` + new URLSearchParams({ path: `${BACKUPS_DIR}/${file}` }), target, {
      onProgress: (n) => progress(`Downloading ${file}: ${MB(n)} of ${MB(entry.size)}`),
    });
    if (r.storedBytes !== entry.size) {
      await rm(target, { force: true });
      throw new UserError(`The download of ${file} came to ${r.storedBytes} bytes, the panel lists ${entry.size}. It was removed; try again.`);
    }
    return { saved_as: target, bytes: entry.size, note: 'The file holds the whole account (mail and database contents too): keep it in the project folder, and move it to the Trash when it is no longer needed.' };
  }

  /** Takes one backup file out of /backups. It goes to the account's trash (File Manager), so it can be brought back. */
  async function remove(args, { session }) {
    const file = reqString(args, 'file', { max: 220, pattern: FILE_RE, what: 'is not a backup file name' });
    if (args.confirm !== true) {
      throw new UserError('Deleting a backup can take away the only way back (a safety backup made before a restore is a backup too). Tell the user which backup file will be removed from /backups; only after their clear yes call again with confirm:true.');
    }
    const da = await session.da();
    if (da.fileApi === 'legacy') throw new UserError('This older panel has no trash, so a removal would be final: ask the user to remove the backup in DirectAdmin (Backup and Restore).');
    const domain = await mainDomain(args, da);
    if (!(await listNames(da, domain)).includes(file)) throw new UserError(`${file} is not one of this account's backups (backup_list shows them).`);
    if (!(await backupEntry(da, file))) throw new UserError(`${file} is not a regular file in /backups of this account.`);
    await fmRemove(da, [`${BACKUPS_DIR}/${file}`], { trash: true });
    if (await backupEntry(da, file)) throw new UserError(`The panel said ${file} was removed but it is still in /backups. Look with backup_list.`);
    return { removed: file, note: 'The file was moved to the trash of the account (DirectAdmin File Manager, Trash): it can be brought back from there until the trash is emptied.' };
  }

  async function restore(args, { session, progress }) {
    const file = reqString(args, 'file', { max: 220, pattern: FILE_RE, what: 'is not a backup file name' });
    const wanted = optStringArray(args, 'sections', { max: 30, itemMax: 30 });
    if (!wanted.length) {
      throw new UserError(`Name the parts to restore in "sections" (for example ["domain"] for the website files only). backup_list file=${file} shows what the backup holds. Restoring everything (e-mail, FTP accounts, database settings) must be asked for part by part.`);
    }
    if (args.confirm !== true) {
      throw new UserError('A restore REPLACES the current data of the chosen sections with the ones in the backup. Tell the user exactly what will be replaced (which backup, which sections); only after their clear yes call again with confirm:true.');
    }
    const da = await session.da();
    const domain = await mainDomain(args, da);
    const have = await listNames(da, domain);
    if (!have.includes(file)) throw new UserError(`${file} is not one of this account's backups: ${have.join(', ') || '(none)'}.`);
    const inside = await contents(da, domain, file);
    const missing = wanted.filter((x) => !inside.includes(x));
    if (missing.length) throw new UserError(`${file} does not hold: ${missing.join(', ')}. It holds: ${inside.join(', ')}.`);
    const sections = [...new Set(wanted)];
    // the current state is always saved first: a restore can then always be undone. If that cannot be done, nothing is restored.
    progress?.('Saving the current state first (safety backup)…');
    await roomWarning(da);
    const domains = await allDomains(da, domain);
    const made = await createAndWait(da, domain, BACKUP_SECTIONS, domains, optInt(args, 'safety_wait_seconds', 180, { min: 1, max: 600 }), progress);
    if (!made.file) {
      throw new UserError('The safety backup of the current state was not finished in time, so NOTHING was restored. Look with backup_list; when the new backup is there, call backup_restore again (or give a larger safety_wait_seconds).');
    }
    // the file is looked at again just before it is used (a backup can be replaced while the safety backup runs)
    const again = await contents(da, domain, file);
    const lost = sections.filter((x) => !again.includes(x));
    if (lost.length || !(await listNames(da, domain)).includes(file)) {
      throw new UserError(`${file} changed while the safety backup was made (it no longer holds ${lost.join(', ') || 'what it held'}), so NOTHING was restored. Look at it again with backup_list.`);
    }
    await da.postJson(`${CMD}?json=yes`, { file, ...selects(sections), domain, json: 'yes', action: 'restore', form_version: '3' });
    return {
      status: 'queued',
      restored_from: file,
      sections: sections.map((s) => ({ section: s, what: SECTION_HELP[s] || s })),
      safety_backup: made.file,
      note: `DirectAdmin runs the restore in the background, usually within a minute; its API gives no "finished" signal. Wait about two minutes, then prove the result yourself (check_url, read_file of something that must have come back, logs). To undo, restore ${made.file} the same way.`,
    };
  }

  return { list, create, restore, upload, download, remove };
}
