// db_list / db_create / db_import / db_export / db_drop for PLESK accounts (the same tool names and results as for DirectAdmin;
// tools.js hands a Plesk account to these). MySQL/MariaDB proven on a real Plesk; PostgreSQL uses the same calls (not yet run for
// real: the test server's PostgreSQL service is off).
import { mkdir, open, stat } from 'node:fs/promises';
import { basename, isAbsolute, join, resolve } from 'node:path';
import { PleskDb, namePrefix, strongPassword } from './plesk-db.js';
import { PleskFiles, resolveWebspace } from './plesk-files.js';
import { UserError } from './util.js';

const TYPES = ['mysql', 'postgresql'];
const PORTS = { mysql: 3306, postgresql: 5432 };

/** The Plesk side of a tool call: the signed-in web session, the XML client, the subscription, and the helpers built on them. */
export async function pleskContext(session, domain) {
  const web = await session.web();
  const xml = await session.plesk();
  const site = await resolveWebspace(xml, domain);
  const files = new PleskFiles(web, site.id);
  return { web, xml, site, files, db: new PleskDb(web, xml, files, site) };
}

/**
 * @param {{S:Function, optString:Function, optBool:Function, reqString:Function, configDir:Function, mb:Function, assertGzipIntact:Function, stamp?:Function}} h helpers from tools.js
 */
export function pleskDbHandlers(h) {
  const { optString, optBool, reqString, configDir, mb, assertGzipIntact } = h;
  const dbName = (args) => reqString(args, 'database', { pattern: /^[A-Za-z0-9_]{1,64}$/, what: 'is not a valid database name' });
  const domainOf = (args) => optString(args, 'domain', { max: 253 });

  async function exportTo(db, row, { folder, progress }) {
    let dir;
    if (folder) {
      if (!isAbsolute(folder)) throw new UserError('"folder" must be an absolute path on this computer.');
      dir = resolve(folder);
    } else {
      dir = join(configDir(), 'exports');
    }
    await mkdir(dir, { recursive: true, mode: 0o700 });
    if (!(await stat(dir)).isDirectory()) throw new UserError(`${dir} is not a folder.`);
    const file = join(dir, `db-${row.name}-${new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z')}.sql.zip`);
    const started = Date.now();
    const r = await db.exportDump(row, file, { progress });
    return {
      path: file,
      location: 'this computer (not on the server)',
      format: 'a zip with the SQL dump inside, as Plesk makes it; db_import takes it as it is',
      file_megabytes: mb(r.bytes),
      seconds: Math.round((Date.now() - started) / 100) / 10,
      complete: true, // Plesk ended its export task successfully and the download has exactly the size the server has
    };
  }

  return {
    async list(args, { session }) {
      const { db, site } = await pleskContext(session, domainOf(args));
      return { subscription: site.name, databases: await db.list(), created_by_connector: session.createdDatabases() };
    },

    async create(args, { session }) {
      const suffix = reqString(args, 'suffix', { pattern: /^[a-z0-9_]{1,30}$/, what: 'may only contain lowercase letters, digits and underscore (max 30)' });
      const type = optString(args, 'type') || 'mysql';
      if (!TYPES.includes(type)) throw new UserError(`type must be one of: ${TYPES.join(', ')}.`);
      const { db, site } = await pleskContext(session, domainOf(args));
      const login = await session.username();
      const name = `${namePrefix(login)}_${suffix}`;
      const existing = await db.list();
      if (existing.some((d) => d.name === name)) throw new UserError(`The database ${name} already exists. Choose another suffix, or reuse it if it is the user's.`);
      const password = strongPassword(24);
      await session.saveDbPassword(name, password); // store first: an unknown password would be useless
      // PostgreSQL (real Plesk, 2026-10-15): a new database already has a role of its own name, so the user needs another name
      const dbUser = type === 'postgresql' ? `${name}_u`.slice(0, 63) : name;
      try {
        await db.create({ name, type, login: dbUser, password });
      } catch (err) {
        await session.discardDbPassword(name);
        throw err;
      }
      await session.recordDatabase(name);
      const row = (await db.list()).find((d) => d.name === name);
      return {
        subscription: site.name,
        database: name,
        user: dbUser,
        type,
        engine: row?.engine,
        host: row?.host || 'localhost',
        port: row?.port || PORTS[type],
        password_storage: 'kept only on this computer and never shown',
        config_placeholder: `{{KW_DB_PASSWORD:${name}}}`,
        next: 'Write the app config with write_file or files_write (outside the web root) using the placeholder, exactly as given.',
      };
    },

    async import(args, { session, progress = () => {} }) {
      const database = dbName(args);
      const clean = optBool(args, 'clean', false);
      if (clean && !optBool(args, 'confirm_clean', false)) {
        throw new UserError('clean:true empties the database first and destroys its current data. Ask the user; only after they agree call again with confirm_clean:true (the connector then saves an export of the current data first).');
      }
      const file = resolve(reqString(args, 'file'));
      if (!/\.(sql(\.gz)?|zip)$/i.test(file)) throw new UserError('The dump must be a .sql, .sql.gz or .zip file.');
      const st = await stat(file).catch(() => null);
      if (!st || !st.isFile()) throw new UserError(`The file ${file} does not exist.`);
      if (st.size === 0) throw new UserError(`${basename(file)} is empty.`);
      const { db } = await pleskContext(session, domainOf(args));
      const row = await db.find(database);
      if (/\.gz$/i.test(file)) {
        progress(`Checking that ${basename(file)} is a complete gzip file…`);
        await assertGzipIntact(file);
      }
      if (/\.sql$/i.test(file)) {
        // Plesk runs the file as it is: a dump that makes or drops databases would act outside the one chosen
        const fd = await open(file, 'r');
        let head = '';
        try {
          const buf = Buffer.alloc(Math.min(st.size, 2 * 1024 * 1024));
          const { bytesRead } = await fd.read(buf, 0, buf.length, 0);
          head = buf.subarray(0, bytesRead).toString('latin1');
        } finally {
          await fd.close();
        }
        if (/^\s*(CREATE\s+DATABASE|DROP\s+DATABASE|USE\s+`?\w)/im.test(head)) {
          throw new UserError('The dump contains CREATE DATABASE / DROP DATABASE / USE lines, which would act on other databases than the chosen one. Remove them and try again.');
        }
      }
      // emptying a database is only done after its current data is safe
      const saved = clean ? await exportTo(db, row, { progress }) : null;
      const started = Date.now();
      try {
        await db.importDump(row, file, { recreate: clean, progress });
      } catch (err) {
        const where = saved ? ` The data from before is saved in ${saved.path} on this computer.` : '';
        throw new UserError(`${String(err.message).replace(/\.$/, '')}.${where}`, err.code);
      }
      return { imported: basename(file), into: database, megabytes: mb(st.size), seconds: Math.round((Date.now() - started) / 100) / 10, ...(saved ? { previous_data_saved_as: saved.path, previous_data_location: 'this computer (not on the server)' } : {}) };
    },

    async export(args, { session, progress = () => {} }) {
      const database = dbName(args);
      const { db } = await pleskContext(session, domainOf(args));
      return exportTo(db, await db.find(database), { folder: optString(args, 'folder'), progress });
    },

    async drop(args, { session }) {
      const database = dbName(args);
      if (args.confirm_name !== database) throw new UserError('confirm_name must repeat the database name exactly.');
      await session.load();
      if (!session.createdDatabases().includes(database)) throw new UserError(`${database} was not created by this connector, so it will not be dropped. The user can remove it in Plesk (Databases).`);
      const { db } = await pleskContext(session, domainOf(args));
      await db.drop(database);
      await session.forgetDatabase(database);
      return { dropped: database };
    },
  };
}
