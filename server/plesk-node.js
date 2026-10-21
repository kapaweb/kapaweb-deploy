// The Node.js extension of a Plesk panel, as the panel's own pages use it: JSON endpoints under /modules/nodejs/index.php/api
// (names read from the extension's JavaScript: domain-list, versions-list, application/domainId/<id>, enable-domain,
// restart-domain, install-dependencies, run-command, change-version, change-package-manager, change-document-root,
// change-application-mode, change-application-path, change-application-startup-file ...). Needs a PleskWeb session.
//
// STATUS: endpoint names and request bodies are from the extension's JavaScript; the ANSWER shapes are guessed defensively and
// get fixed by the first real run (see PLESK_SUPPORT.md). Covered by tests against a fake panel only.
import { PleskTasks } from './plesk-tasks.js';
import { UserError } from './util.js';

const BASE = '/modules/nodejs/index.php/api';
const NAME_KEYS = ['name', 'domain', 'domainName', 'displayName', 'asciiName', 'ascii-name'];
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

/** A list in whatever envelope Plesk used: the array itself, or { data | domains | items | versions: [...] }. */
export function asList(body) {
  if (Array.isArray(body)) return body;
  for (const k of ['data', 'domains', 'items', 'versions', 'commands', 'result']) if (Array.isArray(body?.[k])) return body[k];
  return [];
}

/** The names a domain entry goes by (lower case). */
export function namesOf(entry) {
  return NAME_KEYS.map((k) => entry?.[k]).filter((v) => typeof v === 'string' && v).map((v) => v.toLowerCase());
}

export class PleskNode {
  /** @param {import('./plesk-web.js').PleskWeb} web */
  constructor(web, xml = null) {
    this.web = web;
    this.tasks = new PleskTasks(web);
    this.xml = xml; // optional PleskClient: it knows the subscriptions' names and ids even where the extension's own list is empty
  }

  async #get(path) {
    return (await this.web.request('GET', BASE + path)).body;
  }

  async #post(path, json, opts = {}) {
    return (await this.web.request('POST', BASE + path, { json, ...opts })).body;
  }

  /** The domains the extension manages: [{ id, name, version, mode, package_manager }] (the panel calls the id "key"). */
  async domains() {
    return asList(await this.#get('/domain-list')).map((d) => ({
      id: Number(d.id ?? d.domainId ?? d.key),
      name: d.name,
      version: d.handlerName,
      mode: d.mode,
      package_manager: d.pkgManager,
    }));
  }

  /** The versions the administrator offers (a customer login is refused: use handlers() of an application instead). */
  versions() {
    return this.#get('/versions-list').then(asList);
  }

  /** The Node.js versions this domain may use: [{ id, version, package_managers }]. */
  async handlers(domainId) {
    const app = await this.app(domainId);
    return (app?.handlers || []).map((h) => ({ id: h.id, version: h.version, package_managers: h.packageManagers || [] }));
  }

  /** "21", "21.7" or "21.7.3" (or the full handler id) -> the handler id Plesk wants; says which versions exist when none fits. */
  async resolveHandler(domainId, wanted) {
    const list = await this.handlers(domainId);
    const w = String(wanted).trim().replace(/^v/i, '');
    const hit = list.find((h) => h.id === w) || list.find((h) => h.version === w) || list.find((h) => h.version.startsWith(w + '.')) || list.find((h) => h.id.includes(`/node/${w}/`));
    if (!hit) throw new UserError(`Node.js version "${wanted}" is not available for this domain. Available: ${list.map((h) => h.version).join(', ') || 'none'}.`, 'NODE_VERSION_UNKNOWN');
    return hit.id;
  }

  /** The custom environment variables of an application: { NAME: value }. */
  async env(domainId) {
    const e = (await this.app(domainId))?.application?.environment;
    return e && typeof e === 'object' && !Array.isArray(e) ? { ...e } : {};
  }

  /**
   * Sets the custom environment variables to exactly this list (Plesk's own form replaces the whole list), then reads them back.
   * @param {Record<string,string>} vars
   */
  async setEnv(domainId, vars) {
    const entries = Object.entries(vars);
    if (entries.length > 100) throw new UserError('At most 100 environment variables.');
    const form = { hidden: '', send: '', forgery_protection_token: this.web.token };
    entries.forEach(([name, value], i) => {
      if (!ENV_NAME.test(name)) throw new UserError(`"${name}" is not a valid environment variable name (letters, digits and underscore, not starting with a digit).`);
      if (/[\r\n\0]/.test(String(value)) || String(value).length > 4000) throw new UserError(`The value of ${name} may not contain line breaks and is at most 4000 characters.`);
      form[`environmentForm[${i}][variableName]`] = name;
      form[`environmentForm[${i}][variableValue]`] = String(value);
    });
    const { body } = await this.web.request('POST', `/modules/nodejs/index.php/domain/environment/site_id/${Number(domainId)}`, { form });
    if (!body || typeof body !== 'object' || String(body.status).toLowerCase() !== 'success') throw new UserError('Plesk did not accept the environment variables.');
    const now = await this.env(domainId);
    const wrong = entries.filter(([k, v]) => now[k] !== String(v)).map(([k]) => k);
    if (wrong.length || Object.keys(now).length !== entries.length) throw new UserError(`Plesk said it saved the environment variables, but reading them back differs (${wrong.join(', ') || 'a different number of variables'}).`);
    return now;
  }

  app(domainId) {
    return this.#get(`/application/domainId/${Number(domainId)}`);
  }

  availableCommands(domainId, packageManager) {
    const pm = packageManager ? `/packageManager/${encodeURIComponent(packageManager)}` : '';
    return this.#get(`/available-commands/domainId/${Number(domainId)}${pm}`).then(asList);
  }

  /** The panel's numeric id of a domain, by its name; says which names exist when it is not there. */
  async domainId(name) {
    const want = String(name).toLowerCase();
    const list = await this.domains();
    let hit = list.find((d) => namesOf(d).includes(want));
    if (!hit && this.xml) {
      // The extension lists the domains it already manages; a subscription's main domain can be switched on before that
      const site = (await this.xml.webspaces()).find((w) => String(w.name || '').toLowerCase() === want);
      if (site) hit = { id: site.id, name: site.name };
    }
    if (!hit) {
      const known = [...new Set(list.flatMap((d) => namesOf(d)[0] || []))];
      throw new UserError(`"${name}" is not a domain that this Plesk login can use Node.js on.${known.length ? ` Known: ${known.join(', ')}.` : ' The login has no domain with the Node.js extension available (an administrator has to allow it for the subscription).'}`, 'NODE_DOMAIN_UNKNOWN');
    }
    const id = hit.id ?? hit.domainId ?? hit.key;
    if (!Number.isInteger(Number(id))) throw new UserError('Plesk did not give an id for that domain.');
    return Number(id);
  }

  enable(domainId, enabled) {
    return this.#post('/enable-domain', { domainId: Number(domainId), enabled: Boolean(enabled) });
  }

  restart(domainId) {
    return this.#post('/restart-domain', { domainId: Number(domainId) });
  }

  /** Starts the package install (npm install / yarn install) and waits for its task; returns { status, errors, output }. */
  async installDependencies(domainId, { progress, timeoutMs } = {}) {
    const started = await this.#post('/install-dependencies', { domainId: Number(domainId) });
    const id = started?.id;
    if (!id) return { status: 'started', errors: [], output: [] };
    const task = await this.tasks.wait({ id, progress, timeoutMs, label: 'Installing the packages' });
    await this.tasks.forget([task.id]);
    return task;
  }

  /** Runs `<package manager> <command>` in the application root and returns { code, stdout, stderr } (a build can take minutes). */
  runCommand(domainId, command, handlerVersion, packageManager) {
    return this.#post('/run-command', { domainId: Number(domainId), command, handlerVersion, packageManager }, { timeoutMs: 900000 });
  }

  changeVersion(domainId, handlerId) {
    return this.#post('/change-version', { domainId: Number(domainId), handlerId });
  }

  changePackageManager(domainId, pkgManager) {
    return this.#post('/change-package-manager', { domainId: Number(domainId), pkgManager });
  }

  changeDocumentRoot(domainId, path) {
    return this.#post('/change-document-root', { domainId: Number(domainId), path });
  }

  changeApplicationMode(domainId, mode) {
    return this.#post('/change-application-mode', { domainId: Number(domainId), mode });
  }

  changeApplicationPath(domainId, path) {
    return this.#post('/change-application-path', { domainId: Number(domainId), path });
  }

  changeStartupFile(domainId, startupFile) {
    return this.#post('/change-application-startup-file', { domainId: Number(domainId), startupFile });
  }
}
