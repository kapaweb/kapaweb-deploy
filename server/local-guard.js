// Checks for the files of THIS computer that the file tools upload or write, shared by the Plesk and DirectAdmin versions.
import { dirname, resolve } from 'node:path';
import { homedir } from 'node:os';
import { octalToDecimal } from './fm.js';
import { UserError } from './util.js';

/** A local file that may be uploaded or written: not inside a hidden folder of the home folder (.ssh, .config, .aws ...). */
export function assertLocalFileAllowed(file) {
  const home = resolve(homedir());
  const norm = (p) => p.replace(/\\/g, '/');
  const f = norm(file);
  const h = norm(home).replace(/\/$/, '');
  const rel = f.toLowerCase().startsWith(h.toLowerCase() + '/') ? f.slice(h.length + 1).split('/').slice(0, -1) : [];
  if (rel.some((seg) => seg.startsWith('.'))) throw new UserError('That file is inside a hidden folder of the home folder (settings or credentials of this computer), which the connector does not touch.');
  if (norm(dirname(file)) === h) throw new UserError('Files directly in the home folder are not handled by the connector: use the project\'s folder.');
}

/** Permissions the way the DirectAdmin tools take them: plain rwx bits, never world-writable. */
export function checkedMode(mode) {
  const decimal = octalToDecimal(mode);
  if (decimal > 0o777) throw new UserError('Set-uid, set-gid and sticky bits are not allowed: use plain permissions such as "0644" or "0755".');
  if ((decimal & 0o002) !== 0) throw new UserError('World-writable permissions are refused: 0644/0755 is enough.');
  return decimal;
}
