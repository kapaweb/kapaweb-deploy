// Path rules for the account's home directory (File Manager paths are chrooted there).
// The connector only ever touches /domains, /tmp and /public_html; everything else
// (dotfiles, mail, ssh keys...) is off limits.
import { UserError } from './util.js';

const ALLOWED_ROOTS = ['domains', 'tmp', 'public_html'];
const DOMAIN_FOLDERS_KEPT = new Set(['public_html', 'private_html', 'logs', 'stats', 'public_ftp']);

export function normPath(input) {
  if (typeof input !== 'string' || input.trim() === '') throw new UserError('A path is required.');
  if (/[\u0000-\u001f\u007f]/.test(input)) throw new UserError('Path contains control characters.');
  if (input.includes('\\')) throw new UserError('Paths use forward slashes (/domains/example.gr/public_html), not backslashes.');
  const parts = [];
  for (const seg of input.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') throw new UserError('Paths may not contain "..".');
    // look-alikes of "..": segments made only of dots/spaces/unicode dot characters, or percent-encoded dots and slashes
    if (DOTS_ONLY.test(seg) || /%2e|%2f|%5c/i.test(seg)) throw new UserError(`"${seg}" is not an allowed path segment.`);
    parts.push(seg);
  }
  return '/' + parts.join('/');
}

const DOTS_ONLY = /^[.\s․‥﹒．。｡]+$/;

export function segments(p) {
  return p.split('/').filter(Boolean);
}

export function join(...parts) {
  return normPath('/' + parts.join('/'));
}

function root(p) {
  return segments(p)[0];
}

/** Listing may include the home root itself ("/") but never dotfile folders. */
export function assertListable(p) {
  const s = segments(p);
  if (s.length === 0) return;
  if (!ALLOWED_ROOTS.includes(s[0])) throw new UserError(`The connector only works inside /domains, /tmp and /public_html (got ${p}).`);
}

export function assertReadable(p) {
  const s = segments(p);
  if (s.length === 0 || !ALLOWED_ROOTS.includes(s[0])) {
    throw new UserError(`The connector only works inside /domains, /tmp and /public_html (got ${p}).`);
  }
}

export function assertWritable(p) {
  const s = segments(p);
  if (s.length < 2 || !ALLOWED_ROOTS.includes(s[0])) {
    throw new UserError(`The connector only writes inside /domains/<domain>/..., /tmp/... and /public_html/... (got ${p}).`);
  }
}

/** True when p is (or is inside) a domain's web root; returns the path relative to it. */
export function docrootInfo(p) {
  const s = segments(p);
  if (s[0] === 'domains' && s.length >= 3 && s[2] === 'public_html') return { domain: s[1], rel: s.slice(3).join('/') };
  if (s[0] === 'public_html') return { domain: null, rel: s.slice(1).join('/') };
  return null;
}

export function assertDeletable(p) {
  assertWritable(p);
  const s = segments(p);
  if (s[0] === 'tmp') {
    if (s.length < 2) throw new UserError('Refusing to delete /tmp itself.');
    return;
  }
  if (s[0] === 'domains') {
    const rest = s.slice(2);
    if (rest.length === 0) throw new UserError('Refusing to delete a whole domain folder. Domains are removed by kapaweb support or in DirectAdmin.');
    if (rest.length === 1 && DOMAIN_FOLDERS_KEPT.has(rest[0])) throw new UserError(`Refusing to delete ${p} itself; delete its contents instead.`);
    if (rest.length === 2 && rest[0] === 'public_html' && rest[1] === '.htaccess') {
      throw new UserError('Refusing to delete the web root .htaccess (it carries the kapaweb firewall block). Use write_file or deploy, which keep that block.');
    }
    return;
  }
  if (s[0] === 'public_html') {
    if (s.length < 2) throw new UserError('Refusing to delete the web root itself; delete its contents instead.');
    if (s.length === 2 && s[1] === '.htaccess') {
      throw new UserError('Refusing to delete the web root .htaccess (it carries the kapaweb firewall block). Use write_file or deploy, which keep that block.');
    }
  }
}

/**
 * The connector's own safety net: /tmp/kw-deploy (backups, safety copies, exports) and the deploy manifests
 * (/domains/<domain>/.kw-deploy-manifest*.json, which decide which files a later deploy removes as stale).
 * Tools may read and list them, but never write, move, chmod or replace them - a forged backup or manifest could
 * make rollback or a deploy delete the wrong things. Single backup FILES may be deleted to free space.
 */
export function isConnectorInternal(p) {
  const s = segments(p);
  if (s[0] === 'tmp' && s[1] === 'kw-deploy') return true;
  return s[0] === 'domains' && s.length === 3 && /^\.kw-deploy-manifest(-[A-Za-z0-9_]+)?\.json$/.test(s[2]);
}

export function assertNotInternal(p, { allowDeleteOfBackupFile = false } = {}) {
  if (!isConnectorInternal(p)) return;
  const s = segments(p);
  if (allowDeleteOfBackupFile && s[0] === 'tmp' && s.length >= 3) return;
  throw new UserError(`${p} belongs to the connector's own safety net (backups and deploy manifests): it can be read and listed, but not written, moved or replaced through this tool.`);
}

/**
 * Places that must never be replaced wholesale: a web root itself and its .htaccess, which carries the
 * kapaweb firewall block (write_file and deploy merge into it and keep the block; a move would drop it).
 */
export function assertNotWebRootTarget(p, { allowHtaccess = false } = {}) {
  const info = docrootInfo(p);
  if (!info) return;
  if (info.rel === '') throw new UserError(`${p} is a web root and cannot be replaced as a whole; work on its contents.`);
  if (info.rel === '.htaccess' && !allowHtaccess) {
    throw new UserError('The web root .htaccess carries the kapaweb firewall block and cannot be replaced by a move. Use write_file or deploy, which keep that block.');
  }
}

// ---------------------------------------------------------------------------
// Secret-looking file names: never read back to the AI, never uploaded by deploy.
// ---------------------------------------------------------------------------

const HARD_SECRET_NAMES = [
  /^\.env(\..*)?$/i,
  /^wp-config\.php$/i,
  /^configuration\.php$/i,
  /^config\.inc\.php$/i,
  /\.pem$/i,
  /\.key$/i,
  /\.p12$/i,
  /\.pfx$/i,
  /\.kdbx$/i,
  /^id_(rsa|dsa|ecdsa|ed25519)/i,
  /\.(ppk|p8|jks|keystore|tfstate|tfvars)(\.backup)?$/i,
  /^terraform\.tfstate/i,
  /^\.htpasswd$/i,
  /^\.npmrc$/i,
  /^\.netrc$/i,
  /^\.pypirc$/i,
  /^\.pgpass$/i,
  /^\.my\.cnf$/i,
  /^\.git-credentials$/i,
  /^\.(dockercfg|s3cfg|boto)$/i,
  /^\.envrc$/i,
  /^auth\.json$/i,
  /^credentials(\..*)?$/i,
  /^secrets?(\..*)?$/i,
  /^service-account.*\.json$/i,
  /^firebase.*adminsdk.*\.json$/i,
];

export function isSecretFileName(name) {
  return HARD_SECRET_NAMES.some((re) => re.test(name));
}

/** Data files that read_file will not return (dumps are big and full of user data). */
export function isUnreadableName(name) {
  return isSecretFileName(name) || /\.(sql|sqlite|sqlite3|db)(\.gz)?$/i.test(name);
}
