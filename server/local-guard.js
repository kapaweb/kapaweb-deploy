// Checks for the files of THIS computer that the file tools upload or write, shared by the Plesk and DirectAdmin versions.
import { dirname, resolve } from 'node:path';
import { homedir } from 'node:os';
import { octalToDecimal } from './fm.js';
import { UserError } from './util.js';
import { configDir } from './store.js';

/**
 * A local file that may be uploaded or written. Refused: hidden folders of the home folder (.ssh, .config, .aws ...), the operating
 * system's own folders and other people's home folders, the program-data folders of the home folder (macOS ~/Library except CloudStorage,
 * Windows AppData: keychains, browser profiles, autostart folders such as LaunchAgents and Startup), and the connector's own folder (it holds
 * the database exports it made). A file name such as "photo.jpg" must not let a credential store through, and a download must not be able to
 * land where the system starts programs from.
 */
export function assertLocalFileAllowed(file) {
  const home = resolve(homedir());
  const norm = (p) => p.replace(/\\/g, '/');
  const f = norm(file);
  const h = norm(home).replace(/\/$/, '');
  const lower = f.toLowerCase();
  const insideHome = lower.startsWith(h.toLowerCase() + '/');
  const all = insideHome ? f.slice(h.length + 1).split('/') : [];
  const rel = all.slice(0, -1);
  if (rel.some((seg) => seg.startsWith('.'))) throw new UserError('That file is inside a hidden folder of the home folder (settings or credentials of this computer), which the connector does not touch.');
  if (norm(dirname(file)) === h) throw new UserError('Files directly in the home folder are not handled by the connector: use the project\'s folder.');
  const top = (all[0] || '').toLowerCase();
  const second = (all[1] || '').toLowerCase();
  if ((top === 'library' && second !== 'cloudstorage') || top === 'appdata' || top === 'application data' || top === 'local settings') {
    throw new UserError('That file is in the program-data folder of this computer (keychains, browser profiles, autostart folders): the connector does not read or write there. Use the project\'s own folder.');
  }
  const own = norm(configDir()).replace(/\/$/, '').toLowerCase();
  if (lower === own || lower.startsWith(own + '/')) throw new UserError('That file is in the connector\'s own folder (its settings and the database exports it made), which it does not upload or overwrite.');
  if (/^(\/(etc|private\/etc|system|library|usr|bin|sbin|root|proc|sys|dev)(\/|$)|[a-z]:\/(windows|programdata|program files( \(x86\))?)(\/|$))/.test(lower)) {
    throw new UserError('That file is in a system folder of this computer, which the connector does not read or write.');
  }
  if (!insideHome && /^(\/users|\/home)\/[^/]+(\/|$)/.test(lower)) throw new UserError('That file is in another user\'s home folder, which the connector does not touch.');
}

/** Permissions the way the DirectAdmin tools take them: plain rwx bits, never world-writable. */
export function checkedMode(mode) {
  const decimal = octalToDecimal(mode);
  if (decimal > 0o777) throw new UserError('Set-uid, set-gid and sticky bits are not allowed: use plain permissions such as "0644" or "0755".');
  if ((decimal & 0o002) !== 0) throw new UserError('World-writable permissions are refused: 0644/0755 is enough.');
  return decimal;
}
