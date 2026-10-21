// The logs of a Plesk subscription, through the panel's own log browser (/smb/log-file/browser-data/id/<subscription>), which reads
// the root-owned log files for the customer. Rows come oldest first; "load more" asks for the lines before the first one.
//   sources: error_log (Apache error), proxy_error_log (nginx error), passenger (Node.js app + Passenger), access_ssl_log, access_log,
//            proxy_access_ssl_log, proxy_access_log
import { UserError } from './util.js';

export const LOG_SOURCES = {
  error: ['error_log', 'proxy_error_log'],
  log: ['access_ssl_log', 'access_log'],
  node: ['passenger'],
};

const line = (r) => {
  const bits = r.type === 'access' ? [r.date, r.ip, r.code, r.message, r.size] : [r.date, `[${r.source || ''}${r.type ? ' ' + r.type : ''}]`, r.message];
  return bits.filter((x) => x !== undefined && x !== null && String(x) !== '').join(' ');
};

/** @returns {Promise<string[]>} the last `tail` lines (after the `contains` filter), oldest first */
export async function readPleskLogs(web, siteId, { sources, tail = 150, contains, maxPages = 6 }) {
  if (!Number.isInteger(Number(siteId))) throw new UserError('Internal error: bad subscription id.');
  const base = `/smb/log-file/browser-data/id/${Number(siteId)}`;
  const src = encodeURIComponent(JSON.stringify(sources));
  let rows = [];
  let more = null;
  for (let page = 0; page < maxPages; page++) {
    const url = page === 0 ? `${base}?sources=${src}` : `${base}?sources=${src}&showBefore=${encodeURIComponent(JSON.stringify(more))}&short=true`;
    const { body } = await web.request('GET', url);
    const got = Array.isArray(body?.data) ? body.data : Array.isArray(body?.data?.data) ? body.data.data : [];
    rows = page === 0 ? got : [...got, ...rows];
    more = body?.additional?.showMoreBefore || body?.data?.additional?.showMoreBefore || null;
    const filtered = contains ? rows.filter((r) => line(r).toLowerCase().includes(String(contains).toLowerCase())) : rows;
    if (filtered.length >= tail || !more) break;
  }
  const lines = rows.map(line);
  return (contains ? lines.filter((l) => l.toLowerCase().includes(String(contains).toLowerCase())) : lines).slice(-tail);
}
