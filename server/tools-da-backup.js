// backup_list / backup_create / backup_restore for DIRECTADMIN accounts: the panel's own "Backup and Restore" page (user level), done
// from the connector so nobody has to open DirectAdmin for it.
//
// The wire format below was NOT guessed: it is what the panel's own web app sends (observed 5/11/2026 on a real account, DirectAdmin
// Evolution on ssd5.kdns.gr, backup + restore both ran):
//   list     GET  /CMD_SITE_BACKUP?json=yes&domain=<d>   -> ["backup-Nov-05-2026-1.tar.zst", ...]   (names only, newest last)
//   contents POST /CMD_SITE_BACKUP?json=yes  JSON {file, domain, json:'yes', action:'view'}  -> ["domain","email",...]  (what the file holds)
//   create   POST /CMD_SITE_BACKUP?json=yes  JSON {select0..N, domain, json:'yes', action:'backup', form_version:'4', domains0..N}   -> 200, empty body
//   restore  POST /CMD_SITE_BACKUP?json=yes  JSON {file, select0..N, domain, json:'yes', action:'restore', form_version:'3'}          -> 200, empty body
// Create and restore only QUEUE the job (DirectAdmin's task queue runs it within about a minute): a backup is proven by its name
// appearing in the list, a restore has no completion signal in the panel's API, so the result says "queued" and the caller checks the site.
import { UserError, limitOrZero } from './util.js';
import { fmDiskUsage } from './fm.js';

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

  /** A backup is a whole copy of the account: refuse when the disk is nearly full, warn when it may not fit. Returns a warning text or ''. */
  async function roomWarning(da) {
    const cfg = (await da.get('/api/session/user-config')).body || {};
    const usage = (await da.get('/api/session/user-usage')).body || {};
    if (usage.quotaBytes?.unlimited === true) return '';
    const limit = limitOrZero(cfg.quotaLim) * 1048576;
    if (!limit) return '';
    const used = ((await fmDiskUsage(da, '/').catch(() => null)) || {}).sizeOnDiskBytes || 0;
    const free = limit - used;
    if (free < 20 * 1048576) {
      throw new UserError(`Only ${Math.max(0, Math.round(free / 1048576))} MB of the ${Math.round(limit / 1048576)} MB disk quota are free: a backup would not fit. Free space first (old backups in /backups can be removed by the user in DirectAdmin), or ask the user about a larger package.`);
    }
    return free < used ? `Free disk space (${Math.round(free / 1048576)} MB) is smaller than the account's content (${Math.round(used / 1048576)} MB): the backup may not fit. Check it exists with backup_list before relying on it.` : '';
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

  return { list, create, restore };
}
