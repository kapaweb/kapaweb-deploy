// `node server/index.js --doctor`: a local self-check for support. Prints no secrets and makes no network calls.
import { Store, configDir } from './store.js';
import { describeWait, pausedHosts } from './lockout.js';
import { randomAlnum, secretName, VERSION } from './util.js';

export async function doctor() {
  const out = [];
  const ok = (m) => out.push(`  OK    ${m}`);
  const bad = (m) => out.push(`  FAIL  ${m}`);
  out.push(`kapaweb connector ${VERSION}`);
  out.push(`Node.js ${process.version} on ${process.platform}/${process.arch}`);
  Number(process.versions.node.split('.')[0]) >= 18 ? ok('Node.js version is new enough (18 or newer)') : bad('Node.js 18 or newer is required');
  out.push(`Settings folder: ${configDir()}`);

  const writer = await Store.open();
  out.push(`Secret storage: ${writer.backendName}`);
  if (writer.backendName === 'none') {
    bad('no protected secret storage on this computer (Linux needs secret-tool / libsecret)');
  } else {
    try {
      const probe = randomAlnum(24);
      await writer.setSecret('doctor-test', probe);
      const reader = await Store.open(); // fresh instance: reads from the real storage, not from memory
      const back = await reader.getSecret('doctor-test');
      await reader.deleteSecret('doctor-test');
      back === probe ? ok('a test secret was stored, read back and removed') : bad('the test secret could not be read back');
    } catch (err) {
      bad(`secret storage failed: ${String(err?.message || err).slice(0, 200)}`);
    }
  }

  const conns = await new Store(null).loadConnections();
  if (conns.length === 0) out.push('Connection: none yet (the AI app will call `connect`)');
  else {
    const store = await Store.open();
    for (const conn of conns) {
      out.push(`Connection: ${conn.username} on ${conn.panelHost}, key ${conn.keyId}`);
      out.push(`  key expires: ${conn.expiresAt || 'never'}${conn.expiresAt && Date.parse(conn.expiresAt) < Date.now() ? '  (EXPIRED)' : ''}`);
      out.push(`  locked to IP: ${conn.ipLock || 'no'}`);
      const stored = await store.getSecret(secretName(conn, 'key')).catch(() => null);
      stored ? ok('the login key is present in protected storage') : bad('the login key is missing from protected storage: run connect again');
    }
  }
  const paused = pausedHosts();
  if (paused.length === 0) ok('sign-in is not paused (no run of wrong passwords is being held back)');
  else for (const p of paused) out.push(`  PAUSED sign-in to ${p.host} for ${describeWait(p.retryAfterMs)} after several wrong passwords in a row (state: lockout.json, history: signin.log in the settings folder)`);
  return out.join('\n');
}
