// Local state: a small JSON file with non-secret connection details, and secrets
// (the DirectAdmin login key, generated database passwords) in the operating
// system's protected storage:
//   Windows : DPAPI (current user) via PowerShell, one encrypted file per secret
//   macOS   : Keychain via the `security` tool
//   Linux   : Secret Service via `secret-tool`
// If none of these is available the secret is NOT stored (the connection then only
// lasts for this session) unless the user explicitly opts in to a 0600 file with
// KAPAWEB_CONNECTOR_ALLOW_FILE_SECRETS=1.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile, rm, chmod } from 'node:fs/promises';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';
import { UserError, accountId, isPlainObject, redactor } from './util.js';

const SERVICE = 'kapaweb-connector';
const ENTROPY = 'kapaweb-connector-v1';

export function configDir() {
  if (process.env.KAPAWEB_CONNECTOR_HOME) return process.env.KAPAWEB_CONNECTOR_HOME;
  const p = platform();
  if (p === 'win32') return join(process.env.APPDATA || join(homedir(), 'AppData', 'Roaming'), 'kapaweb-connector');
  if (p === 'darwin') return join(homedir(), 'Library', 'Application Support', 'kapaweb-connector');
  return join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'kapaweb-connector');
}

function run(cmd, args, stdin, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    let out = '';
    let err = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`${cmd} timed out`));
    }, timeoutMs);
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, out, err });
    });
    if (stdin !== undefined) child.stdin.write(stdin);
    child.stdin.end();
  });
}

// --- Windows DPAPI ---------------------------------------------------------

function psExe() {
  return join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
}

function psEncoded(script) {
  return Buffer.from(script, 'utf16le').toString('base64');
}

const PS_PROTECT = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$b64 = [Console]::In.ReadToEnd().Trim()
$bytes = [Convert]::FromBase64String($b64)
$ent = [Text.Encoding]::UTF8.GetBytes('${ENTROPY}')
$enc = [Security.Cryptography.ProtectedData]::Protect($bytes, $ent, [Security.Cryptography.DataProtectionScope]::CurrentUser)
[Console]::Out.Write([Convert]::ToBase64String($enc))
`;

const PS_UNPROTECT = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$b64 = [Console]::In.ReadToEnd().Trim()
$bytes = [Convert]::FromBase64String($b64)
$ent = [Text.Encoding]::UTF8.GetBytes('${ENTROPY}')
$dec = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $ent, [Security.Cryptography.DataProtectionScope]::CurrentUser)
[Console]::Out.Write([Convert]::ToBase64String($dec))
`;

async function dpapi(script, inputB64) {
  const r = await run(psExe(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', psEncoded(script)], inputB64);
  if (r.code !== 0 || !r.out) throw new Error('DPAPI call failed');
  return r.out.trim();
}

// --- Backends --------------------------------------------------------------

function fileNameFor(name) {
  return createHash('sha256').update(name).digest('hex').slice(0, 32) + '.bin';
}

class WindowsStore {
  name = 'Windows DPAPI';
  async set(name, value) {
    const dir = join(configDir(), 'secrets');
    await mkdir(dir, { recursive: true });
    const enc = await dpapi(PS_PROTECT, Buffer.from(value, 'utf8').toString('base64'));
    await writeFile(join(dir, fileNameFor(name)), enc, 'utf8');
  }
  async get(name) {
    let enc;
    try {
      enc = await readFile(join(configDir(), 'secrets', fileNameFor(name)), 'utf8');
    } catch {
      return null;
    }
    const b64 = await dpapi(PS_UNPROTECT, enc);
    return Buffer.from(b64, 'base64').toString('utf8');
  }
  async delete(name) {
    await rm(join(configDir(), 'secrets', fileNameFor(name)), { force: true });
  }
}

class MacStore {
  name = 'macOS Keychain';
  async set(name, value) {
    // NOTE: `security` only accepts the password as an argument, so it is briefly
    // visible to other processes of the same user. Documented limitation.
    const r = await run('security', ['add-generic-password', '-U', '-a', name, '-s', SERVICE, '-w', value]);
    if (r.code !== 0) throw new Error('keychain write failed');
  }
  async get(name) {
    const r = await run('security', ['find-generic-password', '-a', name, '-s', SERVICE, '-w']);
    return r.code === 0 ? r.out.replace(/\n$/, '') : null;
  }
  async delete(name) {
    await run('security', ['delete-generic-password', '-a', name, '-s', SERVICE]);
  }
}

class LinuxStore {
  name = 'Secret Service (secret-tool)';
  async set(name, value) {
    const r = await run('secret-tool', ['store', '--label=kapaweb connector', 'service', SERVICE, 'account', name], value);
    if (r.code !== 0) throw new Error('secret-tool store failed');
  }
  async get(name) {
    const r = await run('secret-tool', ['lookup', 'service', SERVICE, 'account', name]);
    return r.code === 0 && r.out ? r.out.replace(/\n$/, '') : null;
  }
  async delete(name) {
    await run('secret-tool', ['clear', 'service', SERVICE, 'account', name]);
  }
}

class FileStore {
  name = 'plain file (0600) - explicitly enabled';
  async #path() {
    const dir = join(configDir(), 'secrets');
    await mkdir(dir, { recursive: true });
    return join(dir, 'secrets.json');
  }
  async #read() {
    try {
      return JSON.parse(await readFile(await this.#path(), 'utf8'));
    } catch {
      return {};
    }
  }
  async set(name, value) {
    const all = await this.#read();
    all[name] = value;
    const p = await this.#path();
    await writeFile(p, JSON.stringify(all), { encoding: 'utf8', mode: 0o600 });
    await chmod(p, 0o600).catch(() => {});
  }
  async get(name) {
    return (await this.#read())[name] ?? null;
  }
  async delete(name) {
    const all = await this.#read();
    delete all[name];
    await writeFile(await this.#path(), JSON.stringify(all), { encoding: 'utf8', mode: 0o600 });
  }
}

/** Test store: nothing touches the disk or the OS. */
export class MemoryStore {
  name = 'memory';
  #m = new Map();
  async set(name, value) {
    this.#m.set(name, value);
  }
  async get(name) {
    return this.#m.get(name) ?? null;
  }
  async delete(name) {
    this.#m.delete(name);
  }
}

async function commandExists(cmd) {
  try {
    const r = await run(platform() === 'win32' ? 'where' : 'which', [cmd], undefined, 5000);
    return r.code === 0;
  } catch {
    return false;
  }
}

async function pickBackend() {
  if (process.env.KAPAWEB_CONNECTOR_STORE === 'memory') return new MemoryStore();
  // tests only: a plain file, so that separate processes (the `--connect` worker, then a later `--call`) share the secrets
  if (process.env.KAPAWEB_CONNECTOR_STORE === 'file' && process.env.KAPAWEB_CONNECTOR_TEST === '1') return new FileStore();
  const p = platform();
  if (p === 'win32') return new WindowsStore();
  if (p === 'darwin') return new MacStore();
  if (await commandExists('secret-tool')) return new LinuxStore();
  if (process.env.KAPAWEB_CONNECTOR_ALLOW_FILE_SECRETS === '1') return new FileStore();
  return null;
}

export class Store {
  #backend;
  #cache = new Map();

  constructor(backend) {
    this.#backend = backend;
  }

  static async open() {
    return new Store(await pickBackend());
  }

  get backendName() {
    return this.#backend ? this.#backend.name : 'none';
  }

  // ---- non-secret connection state: every connected hosting account ----
  /** The saved accounts (no secrets). The file used to hold the one account directly; that account is marked `legacy`. */
  async loadConnections() {
    let raw;
    try {
      raw = JSON.parse(await readFile(join(configDir(), 'connection.json'), 'utf8'));
    } catch {
      return [];
    }
    if (Array.isArray(raw?.accounts)) {
      return raw.accounts.filter((c) => isPlainObject(c) && c.username && c.panelHost).map((c) => ({ ...c, id: c.id || accountId(c) }));
    }
    if (isPlainObject(raw) && raw.username && raw.panelHost) return [{ ...raw, id: accountId(raw), legacy: true }];
    return [];
  }

  async saveConnections(accounts) {
    if (accounts.length === 0) {
      await rm(join(configDir(), 'connection.json'), { force: true });
      return;
    }
    await mkdir(configDir(), { recursive: true });
    await writeFile(join(configDir(), 'connection.json'), JSON.stringify({ version: 2, accounts }, null, 2), { encoding: 'utf8', mode: 0o600 });
  }

  // ---- secrets ----
  async setSecret(name, value) {
    redactor.add(value);
    if (!this.#backend) {
      this.#cache.set(name, value); // session only
      throw new UserError(
        'This computer has no protected secret storage available (macOS Keychain, Windows DPAPI or Linux secret-tool), so the key was NOT saved and only works until this AI app is closed. To allow a 0600 file instead, set KAPAWEB_CONNECTOR_ALLOW_FILE_SECRETS=1 in the connector environment.',
        'NO_SECRET_STORE',
      );
    }
    await this.#backend.set(name, value);
    this.#cache.set(name, value);
  }

  async getSecret(name) {
    if (this.#cache.has(name)) return this.#cache.get(name);
    if (!this.#backend) return null;
    const v = await this.#backend.get(name);
    if (v) {
      redactor.add(v);
      this.#cache.set(name, v);
    }
    return v;
  }

  async deleteSecret(name) {
    this.#cache.delete(name);
    if (this.#backend) await this.#backend.delete(name);
  }
}
