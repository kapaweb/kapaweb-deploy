// {{KW_DB_PASSWORD:<database>}}, {{KW_SECRET:<name>}} and {{KW_RANDOM:<8-64>}}: the connector fills these in so that secrets never pass
// through the chat. The first two are refused where the text would become public (`refuseSecrets(label)` throws).
import { UserError, randomAlnum } from './util.js';

/**
 * @param {string} text
 * @param {{dbPassword:(name:string)=>Promise<string|null>, secret:(name:string)=>Promise<string|null>}} session
 * @param {{refuseSecrets?:(label:string)=>void}} [o]
 * @returns {Promise<{text:string, substituted:number}>}
 */
export async function fillPlaceholders(text, session, { refuseSecrets = () => {} } = {}) {
  let substituted = 0;
  for (const m of [...text.matchAll(/\{\{KW_DB_PASSWORD:([A-Za-z0-9_]{1,64})\}\}/g)]) {
    refuseSecrets('A database password');
    const secret = await session.dbPassword(m[1]);
    if (!secret) throw new UserError(`No stored password for database "${m[1]}". Placeholders only work for databases created with db_create on this computer.`);
    text = text.split(m[0]).join(secret);
    substituted += 1;
  }
  for (const m of [...text.matchAll(/\{\{KW_SECRET:([a-z0-9_.-]{1,64})\}\}/g)]) {
    refuseSecrets('A stored secret');
    const secret = await session.secret(m[1]);
    if (!secret) throw new UserError(`No stored secret named "${m[1]}". Placeholders only work for secrets stored with secret_set on this computer.`);
    text = text.split(m[0]).join(secret);
    substituted += 1;
  }
  const randoms = [...text.matchAll(/\{\{KW_RANDOM:(\d{1,3})\}\}/g)];
  if (randoms.length > 100) throw new UserError('At most 100 {{KW_RANDOM:n}} placeholders per file.');
  text = text.replace(/\{\{KW_RANDOM:(\d{1,3})\}\}/g, (_m, n) => {
    const len = Number(n);
    if (len < 8 || len > 64) throw new UserError('{{KW_RANDOM:n}} needs a length between 8 and 64.');
    substituted += 1;
    return randomAlnum(len);
  });
  if (/\{\{KW_[A-Z_]+:/.test(text)) throw new UserError('The content still has a {{KW_...}} placeholder that could not be filled in. Check its spelling: {{KW_DB_PASSWORD:<database>}}, {{KW_SECRET:<name>}} or {{KW_RANDOM:<8-64>}}.');
  return { text, substituted };
}
