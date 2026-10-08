// Holds the connection state for this server process: every hosting account the user has connected (a customer can have
// several), and hands out one of them for a call. `Session` is the whole set; `forAccount(...)` gives the view of ONE account
// (`AccountSession`) that the tool handlers work with, so a handler never has to know that there are several.
import { DaClient, verifyPanelHost } from './da.js';
import { Store } from './store.js';
import { NotConnectedError, UserError, redactor, secretName } from './util.js';

const union = (a, b) => [...new Set([...(a || []), ...(b || [])])];

export class Session {
  /**
   * @param {Store} store
   * @param {{verifyOpts?: object}} [o] verifyOpts: passed to verifyPanelHost (tests only: fetchFn/lookupFn, so a test that
   *   needs a non-loopback, non-kapaweb host to be checked does not have to reach the real network or real DNS for it).
   */
  constructor(store, o = {}) {
    this.store = store;
    this.verifyOpts = o.verifyOpts;
    this.conns = []; // non-secret connection info of every connected account (each with an `id`: "username@panel")
    this.loaded = false;
    this._das = new Map(); // account id -> DaClient (one client per account keeps its own "key was rejected" latch)
    this.memoryOnly = new Set(); // ids whose key could not be stored on this computer: they live only in this process
  }

  static async create() {
    return new Session(await Store.open());
  }

  /** Reads the saved accounts again (another process may have added one) and registers stored secrets for redaction. */
  async load() {
    const saved = await this.store.loadConnections();
    const inFile = new Set(saved.map((c) => c.id));
    const next = [...saved, ...this.conns.filter((c) => this.memoryOnly.has(c.id) && !inFile.has(c.id))]; // nothing was saved for those
    for (const id of [...this._das.keys()]) {
      const before = this.conns.find((c) => c.id === id);
      const now = next.find((c) => c.id === id);
      // an unchanged connection keeps its client, and with it the "key was rejected" latch
      if (!before || !now || before.keyId !== now.keyId || before.panelHost !== now.panelHost || before.username !== now.username) this._das.delete(id);
    }
    this.conns = next;
    this.loaded = true;
    // Stored database passwords and generic secrets are registered for redaction from the first call on, so they are
    // scrubbed from tool output even after the AI app was restarted (they are otherwise only known after a write or a read).
    for (const conn of next) {
      for (const db of conn.databases || []) await this.store.getSecret(secretName(conn, 'db', db)).catch(() => null);
      for (const name of conn.secrets || []) await this.store.getSecret(secretName(conn, 'secret', name)).catch(() => null);
    }
    return this.conns;
  }

  /** The connected accounts (no secrets). */
  list() {
    return this.conns;
  }

  isExpired(conn) {
    return Boolean(conn?.expiresAt && Date.parse(conn.expiresAt) <= Date.now());
  }

  /**
   * The account a call is for. `selector` is its username or "username@panel". Without one, the only connected account is
   * used; with several, the AI must say which: a deploy that lands on the wrong hosting is not something to guess about.
   * Returns null when nothing is connected.
   */
  resolve(selector) {
    const all = this.conns;
    if (all.length === 0) return null;
    const sel = typeof selector === 'string' ? selector.trim().toLowerCase() : '';
    if (sel) {
      const byId = all.filter((c) => c.id === sel);
      if (byId.length === 1) return byId[0];
      const byUser = all.filter((c) => String(c.username).toLowerCase() === sel);
      if (byUser.length === 1) return byUser[0];
      if (byUser.length > 1) throw new UserError(`More than one connected account has the username "${selector}" (${byUser.map((c) => c.id).join(', ')}). Use the full form username@panel.`, 'ACCOUNT_AMBIGUOUS');
      throw new UserError(`No connected account matches "${selector}". Connected accounts: ${all.map((c) => c.id).join(', ')}.`, 'ACCOUNT_UNKNOWN');
    }
    if (all.length === 1) return all[0];
    throw new UserError(
      `More than one hosting account is connected (${all.map((c) => c.id).join(', ')}). Say which one this call is for: pass account=<username> (or username@panel). account_info lists the domains of each account. If it is not clear which one the user means, ask them (one short question).`,
      'ACCOUNT_REQUIRED',
    );
  }

  /** The view of one account for a tool call (call `load()` first). With nothing connected it is a view that is "not connected". */
  forAccount(selector) {
    return new AccountSession(this, this.resolve(selector)?.id || null);
  }

  /** What the sign-in page is prefilled with: the account that is being renewed, else the panel that all accounts share. */
  prefill(conn = null) {
    if (conn) return { panel: conn.panelHost, username: conn.username };
    if (this.conns.length === 1 && this.isExpired(this.conns[0])) return this.prefill(this.conns[0]); // one expired key: sign in again
    const hosts = new Set(this.conns.map((c) => c.panelHost));
    return hosts.size === 1 ? { panel: [...hosts][0] } : {};
  }

  /** Called after a successful setup: remember the account (a new one is added, the same one gets its new key) and use the new key. */
  async adopt(conn, key) {
    await this.load(); // another process may have added an account since this one started
    const id = `${String(conn.username).toLowerCase()}@${String(conn.panelHost).toLowerCase()}`;
    conn = { ...conn, id };
    // a reconnect to the same account keeps what this connector created there, and where its secrets are kept
    const prev = this.conns.find((c) => c.id === id);
    if (prev) {
      conn = {
        ...conn,
        databases: union(prev.databases, conn.databases),
        subdomains: union(prev.subdomains, conn.subdomains),
        secrets: union(prev.secrets, conn.secrets),
        ...(prev.legacy ? { legacy: true } : {}),
      };
    }
    let warning = null;
    try {
      await this.store.setSecret(secretName(conn, 'key'), key);
      await this.#writeFile((list) => upsert(list, conn)); // only remembered when the key could be stored safely
    } catch (err) {
      if (err instanceof UserError && err.code === 'NO_SECRET_STORE') warning = err.message;
      else throw err;
    }
    // the session state changes only after storing worked (or was knowingly skipped)
    this.conns = upsert(this.conns, conn);
    this.loaded = true;
    if (warning) this.memoryOnly.add(id);
    else this.memoryOnly.delete(id);
    const pinnedIp = await verifyPanelHost(conn.panelHost, this.verifyOpts); // re-checked here too: the file is only trusted after this, not before
    this._das.set(id, new DaClient({ host: conn.panelHost, port: conn.port, username: conn.username, key, fileApi: conn.fileApi, pinnedIp }));
    return { warning };
  }

  /** Changes one account's saved details (the databases it created, its secret names ...). */
  async update(id, change) {
    const cur = this.conns.find((c) => c.id === id);
    if (!cur) return;
    const next = change(cur);
    this.conns = upsert(this.conns, next);
    if (!this.memoryOnly.has(id)) await this.#writeFile((list) => upsert(list, next));
  }

  /** Removes one account from this computer (its secrets are removed by the caller). */
  async remove(id) {
    this.conns = this.conns.filter((c) => c.id !== id);
    this._das.delete(id);
    const wasMemory = this.memoryOnly.delete(id);
    if (!wasMemory) await this.#writeFile((list) => list.filter((c) => c.id !== id));
  }

  /** Read-modify-write of the saved file, so an account that another process added in the meantime is not lost. */
  async #writeFile(change) {
    await this.store.saveConnections(change(await this.store.loadConnections()));
  }
}

function upsert(list, conn) {
  return list.some((c) => c.id === conn.id) ? list.map((c) => (c.id === conn.id ? conn : c)) : [...list, conn];
}

/** One connected account (or none): what the tool handlers use. Always looks at the current state of the account. */
export class AccountSession {
  constructor(manager, id) {
    this.m = manager;
    this.id = id;
  }

  get store() {
    return this.m.store;
  }

  get conn() {
    return this.id ? this.m.conns.find((c) => c.id === this.id) || null : null;
  }

  async load() {
    await this.m.load();
    return this.conn;
  }

  isExpired() {
    return this.m.isExpired(this.conn);
  }

  async da() {
    if (!this.m.loaded) await this.m.load();
    const conn = this.conn;
    if (!conn) throw new NotConnectedError();
    if (this.m.isExpired(conn)) {
      throw new UserError(
        `The login key of ${conn.id} expired on ${conn.expiresAt}. Call \`connect\` so the user can sign in again (it takes a minute and the password never enters the chat).`,
        'KEY_EXPIRED',
      );
    }
    let da = this.m._das.get(conn.id);
    if (!da) {
      const key = await this.store.getSecret(secretName(conn, 'key'));
      if (!key) {
        throw new NotConnectedError(
          `The connection details of ${conn.id} are saved but its login key is missing from this computer's secure storage. Call \`connect\` again.`,
        );
      }
      // The saved connection file is plain JSON on disk: whatever it says, credentials only ever go to a kapaweb panel.
      // (verifyPanelHost's own message already distinguishes "not a kapaweb server" from "could not resolve it right now".)
      const pinnedIp = await verifyPanelHost(conn.panelHost, this.m.verifyOpts);
      da = new DaClient({ host: conn.panelHost, port: conn.port, username: conn.username, key, fileApi: conn.fileApi, pinnedIp });
      this.m._das.set(conn.id, da);
    }
    return da;
  }

  async username() {
    if (!this.m.loaded) await this.m.load();
    return this.conn?.username || null;
  }

  /** Forget this account on this computer (its login key, database passwords and stored secrets). */
  async forget() {
    const conn = this.conn;
    if (!conn) return;
    for (const db of conn.databases || []) await this.store.deleteSecret(secretName(conn, 'db', db)).catch(() => {});
    for (const name of conn.secrets || []) await this.store.deleteSecret(secretName(conn, 'secret', name)).catch(() => {});
    await this.store.deleteSecret(secretName(conn, 'key'));
    await this.m.remove(conn.id);
  }

  // ---- databases created through the connector (only these may be dropped) ----
  async recordDatabase(name) {
    await this.m.update(this.id, (c) => ({ ...c, databases: union(c.databases, [name]) }));
  }

  async forgetDatabase(name) {
    const conn = this.conn;
    await this.m.update(this.id, (c) => ({ ...c, databases: (c.databases || []).filter((d) => d !== name) }));
    if (conn) await this.store.deleteSecret(secretName(conn, 'db', name));
  }

  createdDatabases() {
    return this.conn?.databases || [];
  }

  // ---- subdomains created through the connector (only these may be deleted) ----
  async recordSubdomain(fullName) {
    await this.m.update(this.id, (c) => ({ ...c, subdomains: union(c.subdomains, [fullName]) }));
  }

  async forgetSubdomain(fullName) {
    await this.m.update(this.id, (c) => ({ ...c, subdomains: (c.subdomains || []).filter((s) => s !== fullName) }));
  }

  createdSubdomains() {
    return this.conn?.subdomains || [];
  }

  async saveDbPassword(name, password) {
    const conn = this.#need();
    redactor.add(password);
    try {
      await this.store.setSecret(secretName(conn, 'db', name), password);
    } catch (err) {
      if (err instanceof UserError && err.code === 'NO_SECRET_STORE') {
        throw new UserError(
          'This computer has no protected storage (macOS Keychain, Windows DPAPI or Linux secret-tool) for the database password, and it must not be kept anywhere else, so no database was created. To allow a 0600 file instead, set KAPAWEB_CONNECTOR_ALLOW_FILE_SECRETS=1 in the connector environment.',
          'NO_SECRET_STORE',
        );
      }
      throw err;
    }
  }

  async dbPassword(name) {
    const conn = this.conn;
    return conn ? this.store.getSecret(secretName(conn, 'db', name)) : null;
  }

  /** Removes a database password that was stored but whose database could not be created. */
  async discardDbPassword(name) {
    const conn = this.conn;
    if (conn) await this.store.deleteSecret(secretName(conn, 'db', name)).catch(() => {});
  }

  // ---- generic secrets the AI already has (e.g. a WordPress Application Password) ----
  async saveSecret(name, value) {
    const conn = this.#need();
    redactor.add(value);
    try {
      await this.store.setSecret(secretName(conn, 'secret', name), value);
    } catch (err) {
      if (err instanceof UserError && err.code === 'NO_SECRET_STORE') {
        throw new UserError(
          'This computer has no protected storage (macOS Keychain, Windows DPAPI or Linux secret-tool) for this secret, and it must not be kept anywhere else, so it was not stored. To allow a 0600 file instead, set KAPAWEB_CONNECTOR_ALLOW_FILE_SECRETS=1 in the connector environment.',
          'NO_SECRET_STORE',
        );
      }
      throw err;
    }
    await this.m.update(this.id, (c) => ({ ...c, secrets: union(c.secrets, [name]) }));
  }

  async secret(name) {
    const conn = this.conn;
    return conn ? this.store.getSecret(secretName(conn, 'secret', name)) : null;
  }

  async forgetSecret(name) {
    const conn = this.conn;
    await this.m.update(this.id, (c) => ({ ...c, secrets: (c.secrets || []).filter((n) => n !== name) }));
    if (conn) await this.store.deleteSecret(secretName(conn, 'secret', name));
  }

  storedSecretNames() {
    return this.conn?.secrets || [];
  }

  #need() {
    const conn = this.conn;
    if (!conn) throw new NotConnectedError();
    return conn;
  }
}

