// Databases of a Plesk subscription (MySQL/MariaDB and PostgreSQL).
//  - create / drop / users: Plesk's XML API ("database" operations), proven on a real customer login (MariaDB, 2026-10-15)
//  - dump import / export: the panel's own database pages (/smb/database/upload-dump/id/<id>, /smb/database/download-dump/id/<id>)
//    plus the panel's task list (/smb/task/task-progress), which is the only place a failed import says why: the answer to the
//    import request itself is an empty "[]" whether the SQL ran or not.
// An export lands as <name>.zip in the subscription (a .sql inside); it is streamed to this computer and removed from the server.
//
// PostgreSQL: the same XML operations and the same dump pages (type 'postgresql'); NOT yet run for real (the PostgreSQL service of
// the test server is switched off by the owner's decision).
import { stat } from 'node:fs/promises';
import { PleskTasks } from './plesk-tasks.js';
import { UserError, randomAlnum } from './util.js';

// real Plesk (2026-10-15): the panel's dump pages run its `dbbackup` tool, which answers "Only '--server-type=mysql' is supported"
const PG_NO_DUMP = 'Plesk\'s own dump pages work for MySQL/MariaDB only, so a PostgreSQL database cannot be imported or exported through the connector. Create the tables from the app itself (a migration that runs when the app starts, with the pg package: node_run does not pass the app\'s environment variables to the command it runs), or use phpPgAdmin in Plesk (Databases → the database → Webadmin).';
const DB_NAME = /^[a-z][a-z0-9_]{0,62}$/;

/** A password that satisfies Plesk's usual strength rules: all of lower case, upper case and digits. */
export function strongPassword(length = 24) {
  for (;;) {
    const pw = randomAlnum(length);
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw) && /[0-9]/.test(pw)) return pw;
  }
}

/** "kkatoudis" -> "kkatoudi": the part of the login that starts the names of this customer's databases. */
export const namePrefix = (login) => String(login).toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 8) || 'db';

export class PleskDb {
  /** @param {import('./plesk-web.js').PleskWeb} web  @param {import('./plesk.js').PleskClient} xml  @param {import('./plesk-files.js').PleskFiles} files  @param {{id:string,name:string}} site */
  constructor(web, xml, files, site) {
    this.web = web;
    this.xml = xml;
    this.files = files;
    this.site = site;
    this.tasks = new PleskTasks(web);
  }

  /** The panel's own list of the subscription's databases (it knows the server, the users and what actions are allowed). */
  async list() {
    const { body } = await this.web.request('GET', `/smb/database/list/domainId/${Number(this.site.id)}`);
    const rows = Array.isArray(body?.data?.data) ? body.data.data : null;
    if (!rows) {
      return (await this.xml.databases(this.site.id)).map((d) => ({ id: Number(d.id), name: d.name, type: d.type }));
    }
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      type: r.type,
      engine: r.typeTitle || r.fork,
      host: r.serverHost,
      port: r.serverPort,
      users: (r.users || []).map((u) => u.login),
      can_dump: Boolean(r.allowDump),
      can_import: Boolean(r.allowImport),
      asks_password_for_dump: Boolean(r.askPasswordForDump),
      asks_password_for_import: Boolean(r.askPasswordForImport),
    }));
  }

  async find(name) {
    const hit = (await this.list()).find((d) => d.name === name);
    if (!hit) throw new UserError(`${name} is not a database of this Plesk subscription.`, 'DB_UNKNOWN');
    return hit;
  }

  /** Creates a database and one user with the given password. Cleans up the database when the user cannot be created. */
  async create({ name, type, login, password }) {
    if (!DB_NAME.test(name)) throw new UserError('Database names are lower case letters, digits and underscore, starting with a letter (max 63).');
    if (type === 'postgresql' && name.length > 63) throw new UserError('PostgreSQL names are at most 63 characters.');
    const id = await this.xml.createDatabase({ webspaceId: this.site.id, name, type });
    try {
      await this.xml.createDatabaseUser({ databaseId: id, login, password });
    } catch (err) {
      await this.xml.dropDatabase(id).catch(() => {});
      throw err;
    }
    return { id, name, user: login };
  }

  /** Drops a database and its users. */
  async drop(name) {
    const db = await this.find(name);
    for (const u of await this.xml.databaseUsers(db.id).catch(() => [])) await this.xml.dropDatabaseUser(u.id).catch(() => {});
    await this.xml.dropDatabase(db.id);
  }

  // -- dumps --------------------------------------------------------------------------------------------------------

  /**
   * Exports a database into <localFile> (a .zip with the .sql inside, as Plesk makes it). The dump file on the server is removed.
   * @returns {Promise<{bytes:number, remote:string}>}
   */
  async exportDump(db, localFile, { progress = () => {}, timeoutMs } = {}) {
    if (db.type === 'postgresql') throw new UserError(PG_NO_DUMP, 'PG_NO_DUMP');
    if (!db.can_dump) throw new UserError(`Plesk does not allow a dump of ${db.name} for this login.`);
    if (db.asks_password_for_dump) throw new UserError(`Plesk asks for the password of the database user before it dumps ${db.name}; databases created with db_create do not need that.`);
    const base = `kw-dump-${db.name}-${Date.now().toString(36)}`;
    const remote = `/${base}.zip`;
    const known = await this.tasks.knownIds();
    await this.web.request('POST', `/smb/database/download-dump/id/${Number(db.id)}`, { json: { relativePath: '', dumpName: base, dbPassword: '' } });
    const task = await this.tasks.wait({ type: 'database-download', known, progress, timeoutMs, label: `Exporting ${db.name}` });
    await this.tasks.forget([task.id]);
    if (task.status !== 'done') {
      await this.files.remove([remote], { permanent: true }).catch(() => {});
      throw new UserError(`Plesk could not export ${db.name}: ${task.errors.join(' ') || task.title || task.status}`);
    }
    try {
      const info = await this.files.stat(remote);
      if (!info) throw new UserError(`Plesk reported the export of ${db.name} as done, but ${remote} is not there.`);
      progress(`Downloading the dump of ${db.name} (${Math.round(info.size / 1048576)} MB)…`);
      const got = await this.files.downloadTo(remote, localFile, { expectedBytes: info.size });
      return { bytes: got.bytes, remote };
    } finally {
      await this.files.remove([remote], { permanent: true }).catch(() => {});
    }
  }

  /**
   * Imports a local .sql, .sql.gz or .zip file into a database. With `recreate`, Plesk empties the database first.
   * Streams the file; constant memory.
   */
  async importDump(db, localFile, { recreate = false, progress = () => {}, timeoutMs } = {}) {
    if (db.type === 'postgresql') throw new UserError(PG_NO_DUMP, 'PG_NO_DUMP');
    if (!db.can_import) throw new UserError(`Plesk does not allow an import into ${db.name} for this login.`);
    if (db.asks_password_for_import) throw new UserError(`Plesk asks for the password of the database user before it imports into ${db.name}; databases created with db_create do not need that.`);
    const st = await stat(localFile);
    const name = localFile.split(/[\\/]/).pop();
    const known = await this.tasks.knownIds();
    progress(`Uploading ${name} (${Math.round(st.size / 1048576)} MB)…`);
    await this.web.request('POST', `/smb/database/upload-dump/id/${Number(db.id)}`, {
      upload: { path: localFile, size: st.size, field: 'file[]', filename: name, fields: recreate ? { recreateDatabase: '1' } : {} },
      timeoutMs: 3600000,
    });
    const task = await this.tasks.wait({ type: 'database-upload', known, progress, timeoutMs, label: `Importing into ${db.name}` });
    await this.tasks.forget([task.id]);
    if (task.status !== 'done') {
      throw new UserError(`The import into ${db.name} failed: ${task.errors.join(' ') || task.title || task.status}. Statements before the failing one may already have been applied.`, 'IMPORT_FAILED');
    }
    return { task: task.title };
  }
}
