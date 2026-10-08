// .htaccess handling. Every web root .htaccess on kapaweb hosting carries an
// auto-managed "kapaweb-firewall" block that returns 403 for secret/config paths.
// Whatever we write must keep that block (every such block, byte for byte) at the top.
import { UserError } from './util.js';

const BLOCK = '^# BEGIN kapaweb-firewall[^\\n]*\\r?\\n[\\s\\S]*?^# END kapaweb-firewall[^\\n]*(?:\\r?\\n|$)';
const BLOCK_RE = new RegExp(BLOCK, 'm');
const BLOCKS_RE = new RegExp(BLOCK, 'gm');

/** Split a .htaccess into its firewall block(s) (or null) and everything else. */
export function splitFirewallBlock(text) {
  const blocks = [];
  const rest = text.replace(BLOCKS_RE, (m) => {
    blocks.push(m.endsWith('\n') ? m : m + '\n');
    return '';
  });
  if (blocks.length === 0) return { block: null, rest: text };
  return { block: blocks.join(''), rest: rest.replace(/^\s*\n/, '') };
}

/**
 * existing: current server file (string|null); incoming: new app rules (string).
 * Returns { content, action } where action is 'merged' | 'written'.
 */
export function mergeHtaccess(existing, incoming) {
  const inc = splitFirewallBlock(incoming);
  const cur = existing ? splitFirewallBlock(existing) : { block: null, rest: '' };
  if (cur.block) {
    const rest = inc.rest.replace(/^\s+/, '');
    // the directive is per file: a later "RewriteEngine Off" would silently switch the firewall block off again
    if (/^[ \t]*RewriteEngine[ \t]+Off\b/im.test(rest)) {
      throw new UserError('This .htaccess contains "RewriteEngine Off", which would switch off the kapaweb firewall block that is kept at its top (it protects .env and config files). Remove that line and try again.');
    }
    return { content: cur.block + (rest ? '\n' + rest : ''), action: 'merged' };
  }
  return { content: incoming, action: 'written' };
}

export function hasFirewallBlock(text) {
  return BLOCK_RE.test(text);
}
