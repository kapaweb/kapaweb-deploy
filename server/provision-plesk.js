// The one-time exchange for a PLESK customer: panel password -> Plesk secret key.
// The password signs in once, asks Plesk for a secret key and is then dropped; only the key is kept (OS keychain).
//
// Unlike the DirectAdmin flow (provision.js) the key CANNOT be restricted: Plesk gives a customer's secret key the rights
// of the customer's whole login. The sign-in page and the result say so. The IP lock and the "key lasts" choice are
// handled as follows: an IP lock is refused (Plesk would need our public address, which it does not tell us), and the
// duration is only a local rule (the connector stops using the key after that time; the key itself stays in Plesk until it
// is deleted there, which `disconnect` does when it can).
//
// Real finding (ns67, 2026-10-15): a Plesk CUSTOMER may not create a secret key for itself ("Permission denied"; only an
// administrator creates a customer's key). So when the key cannot be made, the Plesk PASSWORD is kept in this computer's
// protected storage instead (`keepPassword`, on by default so that the customer has nothing to choose; the owner decided
// this explicitly on 2026-10-15). The sign-in page says so in plain words right above the Connect button, and so does the
// result. `keepPassword: false` refuses instead.
//
// STATUS: the Plesk packets are written from the documentation and covered by tests against a fake Plesk; they have not
// been run against a real server yet.
import { PleskClient, PleskError } from './plesk.js';
import { LockedError, checkPaused, describeWait, journal, recordRefused, recordSignedIn } from './lockout.js';
import { UserError, randomLower } from './util.js';

function isoNoMillis(date) {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * @param {{host:string, port:number, pinnedIp:string, username:string, password:string, days:number|null, ipLock?:boolean,
 *          keepPassword?:boolean, adopt?:(conn:object, key:string)=>Promise<any>}} input  `days` null = no local expiry;
 *   `keepPassword` (default true): when Plesk will not create a key, store the password instead of refusing
 * @returns {Promise<{conn:object, key:string, notes:string[], adopted:any, keepsPassword?:boolean}>} `key` is the stored secret:
 *   the Plesk secret key, or (keepPassword) the password itself, in which case `conn.credential` is 'password'
 */
export async function provisionPlesk({ host, port, pinnedIp, username, password, days, ipLock = false, keepPassword = true, adopt }) {
  if (!username || !/^[a-z0-9_.@-]{1,60}$/i.test(username)) throw new UserError('Enter the Plesk username (the login name of your Plesk panel).');
  if (!password) throw new UserError('Enter the password.');
  if (ipLock) {
    throw new UserError('The IP lock is available for DirectAdmin accounts only. Untick it to connect a Plesk account (Plesk cannot restrict what the key may do, so it is stored only in this computer\'s protected storage).');
  }
  const paused = checkPaused(host);
  if (paused.paused) {
    journal(host, 'paused');
    throw new LockedError(
      `Sign-in to ${host} is paused for ${describeWait(paused.retryAfterMs)} after several wrong passwords in a row. This protects you from being blocked by the server's firewall. Check the password in your welcome e-mail or ask kapaweb support, then try again after the pause.`,
      paused.retryAfterMs,
    );
  }

  // 1. sign in with the password (this is also the check that the password is right)
  const sess = new PleskClient({ host, port, username, password, pinnedIp });
  try {
    await sess.webspaces();
  } catch (err) {
    if (err instanceof PleskError && err.code === 'FORBIDDEN') {
      // not counted as a wrong password: the sign-in is not what was refused
      journal(host, 'forbidden', { http_status: err.status });
      throw new UserError(`${err.message} Ask kapaweb support to check the XML API access of this Plesk login. Nothing was created.`);
    }
    if (err instanceof PleskError && err.code === 'AUTH') {
      const wrong = recordRefused(host);
      journal(host, 'refused', { ...(err.status ? { http_status: err.status } : {}), ...(err.errcode ? { errcode: err.errcode } : {}), ...(wrong.pauseMs ? { pause_s: Math.round(wrong.pauseMs / 1000) } : {}) });
      const refused = 'Plesk did not accept that username and password.';
      if (wrong.pauseMs) {
        throw new LockedError(`${refused} To protect you from being blocked by the server's firewall, sign-in to ${host} is now paused for ${describeWait(wrong.pauseMs)}.`, wrong.pauseMs);
      }
      throw new UserError(`${refused} Check them and try again. Repeated wrong attempts can get your internet address blocked by the server for a while.`);
    }
    journal(host, 'error');
    if (err instanceof PleskError) throw new UserError(`Plesk answered with an error while signing in: ${err.message}`);
    throw err;
  }
  recordSignedIn(host); // the password was right: the brake starts over
  journal(host, 'accepted');

  // 2. a customer login only: an administrator's key would carry the rights of the whole server
  if (await sess.isAdministrator()) {
    throw new UserError('This is a Plesk administrator login. The connector works with hosting (customer) logins only, never with an administrator login. Nothing was created.');
  }

  // 3. mint the key (a customer is normally refused: then the opt-in password route, or a clear explanation)
  const label = 'kw-' + randomLower(6);
  let key = null;
  try {
    key = await sess.createSecretKey(`kapaweb connector ${label}`);
  } catch (err) {
    if (!(err instanceof PleskError)) throw err;
    if (!keepPassword) {
      throw new UserError(
        `Plesk did not create a key for this login (${String(err.message).replace(/\.+$/, '')}). Nothing was saved. Plesk does not let a customer create a key for themselves; ask kapaweb support to create a key for you.`,
        'PLESK_NO_KEY',
      );
    }
  }
  if (key === null) return keepPasswordConnection({ host, port, username, password, days, adopt });
  let keyKnownToPlesk = true;
  const revoke = async () => {
    if (!keyKnownToPlesk) return true;
    try {
      await sess.revokeSecretKey(key);
      keyKnownToPlesk = false;
      return true;
    } catch {
      return false;
    }
  };
  const leftover = async () => ((await revoke()) ? '' : ` The temporary key "kapaweb connector ${label}" could not be removed automatically: delete it in Plesk under your profile's API keys.`);

  try {
    // 4. prove the key works on its own
    const probe = new PleskClient({ host, port, key, pinnedIp });
    try {
      await probe.webspaces();
    } catch {
      throw new UserError('The new key did not work right after it was created. It was removed; nothing was saved.');
    }

    const now = new Date();
    const conn = {
      version: 1,
      panel: 'plesk',
      panelHost: host,
      port,
      username,
      keyId: label,
      createdAt: isoNoMillis(now),
      expiresAt: days ? isoNoMillis(new Date(now.getTime() + days * 86400000)) : null,
      ipLock: null,
      databases: [],
      subdomains: [],
    };
    let adopted = null;
    if (adopt) {
      try {
        adopted = await adopt(conn, key);
      } catch (err) {
        if (err instanceof UserError) throw err;
        throw new UserError('Could not save the key in this computer\'s protected storage, so it was removed again and nothing was saved.');
      }
    }
    keyKnownToPlesk = true; // success: keep it
    const notes = [
      'Plesk cannot limit what a key may do: it has the same rights as your Plesk login (without the password). It is kept only in this computer\'s protected storage.',
      days
        ? `The connector stops using the key after ${days} days, but the key stays valid in Plesk until it is deleted: use the disconnect tool, or delete "kapaweb connector ${label}" in Plesk.`
        : `The key does not expire. Remove it with the disconnect tool, or delete "kapaweb connector ${label}" in Plesk.`,
    ];
    return { conn, key, notes, adopted };
  } catch (err) {
    const extra = await leftover();
    if (err instanceof UserError && extra) throw new UserError(err.message + extra, err.code);
    throw err;
  }
}

/** The opt-in route: the sign-in already proved the password; it is the credential that is stored (OS keychain only). */
async function keepPasswordConnection({ host, port, username, password, days, adopt }) {
  const now = new Date();
  const conn = {
    version: 1,
    panel: 'plesk',
    credential: 'password',
    panelHost: host,
    port,
    username,
    keyId: null,
    createdAt: isoNoMillis(now),
    expiresAt: days ? isoNoMillis(new Date(now.getTime() + days * 86400000)) : null,
    ipLock: null,
    databases: [],
    subdomains: [],
  };
  let adopted = null;
  if (adopt) {
    try {
      adopted = await adopt(conn, password);
    } catch (err) {
      if (err instanceof UserError) throw err;
      throw new UserError('Could not save the password in this computer\'s protected storage, so nothing was saved.');
    }
  }
  const notes = [
    'The connector keeps your Plesk password in this computer\'s protected storage and uses it for every request: it has the same access as you have in Plesk, including changing your password. Plesk gave no way to limit it.',
    days
      ? `The connector stops using it after ${days} days. Use the disconnect tool to forget it now (if this computer is shared or lost, also change your Plesk password).`
      : 'Use the disconnect tool to forget it (if this computer is shared or lost, also change your Plesk password).',
  ];
  return { conn, key: password, notes, adopted, keepsPassword: true };
}
