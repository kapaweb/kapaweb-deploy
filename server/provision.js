// The one-time exchange: account password -> restricted DirectAdmin login key.
// The password is used for a session login and to authorise the key creation,
// then dropped. Only the key is kept, and it can only run the commands below.
import { DaClient, DaError, parsePanelAddress, verifyPanelHost } from './da.js';
import { LockedError, checkPaused, describeWait, journal, recordRefused, recordSignedIn } from './lockout.js';
import { UserError, randomAlnum, randomLower, redactor } from './util.js';

/**
 * Command names the connector's key may use (verified end to end on kapaweb servers).
 * DirectAdmin refuses everything else with 403: login keys, sessions, SSH keys,
 * account details and password changes are NOT in this list.
 */
export const ALLOW_COMMANDS = [
  // files
  'filemanager',
  'filemanager-actions',
  'CMD_API_FILE_MANAGER',
  'CMD_FILE_MANAGER',
  // databases
  'db-manage',
  'db-show',
  'CMD_API_DATABASES',
  'CMD_API_DB_USER',
  'CMD_API_DB_USER_PRIVS',
  // SSL
  'domain-tls',
  'CMD_API_SSL',
  // PHP version, PHP settings, logs
  'CMD_ADDITIONAL_DOMAINS',
  'CMD_API_ADDITIONAL_DOMAINS',
  'CMD_DOMAIN',
  'CMD_API_DOMAIN',
  'CMD_PHP_SETTINGS',
  'CMD_SHOW_LOG',
  // subdomains, cron
  'CMD_API_SUBDOMAIN',
  'CMD_SUBDOMAIN',
  'CMD_API_CRON_JOBS',
  'CMD_CRON_JOBS',
];

/** The connector's core tools cannot work without these, on any panel. */
export const BASE_COMMANDS = ['db-manage', 'db-show', 'CMD_ADDITIONAL_DOMAINS', 'CMD_DOMAIN', 'CMD_PHP_SETTINGS', 'CMD_SHOW_LOG'];
/** A panel with the new File Manager API (and the SSL API). */
export const MODERN_FILE_COMMANDS = ['filemanager', 'filemanager-actions', 'domain-tls'];
/**
 * An older panel (DirectAdmin 1.668 on CentOS 7, for example): the read side of the new File Manager API, and the classic
 * command for every change (fm-legacy.js). It has no SSL API, so the ssl_* tools are not available there.
 */
export const LEGACY_FILE_COMMANDS = ['filemanager', 'CMD_API_FILE_MANAGER'];

export const EXPIRY_CHOICES = { 30: 30, 90: 90, 365: 365, never: null };

/** Panel answers that mean "no": a wrong username or password, a blocked address, too many requests. Anything else (5xx, network) is not the person's fault. */
const REFUSAL_STATUSES = new Set([400, 401, 403, 429]);

function cookieFromResponse(res, body) {
  const list = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [res.headers.get('set-cookie') || ''];
  for (const line of list) {
    const m = /(?:^|[,;\s])session=([^;,\s]+)/.exec(line || '');
    if (m) return `session=${m[1]}`;
  }
  if (body && typeof body === 'object' && body.sessionID) return `session=${body.sessionID}`;
  return null;
}

function isoNoMillis(date) {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * @param {{address:string, username:string, password:string, otp?:string, expiry?:string|number, ipLock?:boolean,
 *          adopt?:(conn:object, key:string)=>Promise<any>, verifyOpts?:object}} input
 *   `adopt` stores the key locally; it runs while the session is still open, so if storing fails the new key is removed again.
 *   `verifyOpts` is passed to verifyPanelHost (tests only: fetchFn/lookupFn, so a non-kapaweb address can be rejected
 *   without reaching the real network or real DNS for it).
 * @returns {Promise<{conn:object, key:string, notes:string[], adopted:any}>}
 */
export async function provision(input) {
  try {
    return await exchange(input);
  } finally {
    // The typed password is registered with the redactor only while it is in use; kept longer it would work as a
    // guessing oracle (write a guess to a file, read the file back, look for "[redacted]").
    if (input?.password) redactor.remove(input.password);
  }
}

async function exchange({ address, username, password, otp, expiry = 30, ipLock = false, adopt, verifyOpts }) {
  if (!username || !/^[a-z0-9_.-]{1,32}$/i.test(username)) throw new UserError('Enter the DirectAdmin username from your welcome e-mail.');
  if (!password) throw new UserError('Enter the password.');
  redactor.add(password); // if a panel message ever echoes it, it is scrubbed before it reaches the AI or a log
  if (!Object.hasOwn(EXPIRY_CHOICES, String(expiry))) throw new UserError('Choose how long the key should last.');
  const days = EXPIRY_CHOICES[String(expiry)];
  let parsed;
  try {
    parsed = parsePanelAddress(address);
  } catch (err) {
    journal(null, 'bad_address'); // nothing was sent anywhere: the address is checked before any network activity
    throw err;
  }
  const { host, port } = parsed;
  const paused = checkPaused(host);
  if (paused.paused) {
    journal(host, 'paused');
    throw new LockedError(
      `Sign-in to ${host} is paused for ${describeWait(paused.retryAfterMs)} after several wrong passwords in a row. This protects you from being blocked by the server's firewall. Check the username and password in your welcome e-mail and try again after the pause.`,
      paused.retryAfterMs,
    );
  }
  // Verified once, then PINNED for every request of this exchange (including the one that carries the password): DNS
  // must not be allowed to answer differently between this check and the connection that follows it.
  let pinnedIp;
  try {
    pinnedIp = await verifyPanelHost(host, verifyOpts);
  } catch (err) {
    journal(host, 'bad_address');
    throw err;
  }
  const notes = [];

  const sess = new DaClient({ host, port, username, pinnedIp });

  // 1. session login
  let loginRes;
  try {
    loginRes = await sess.request('POST', '/api/login', {
      json: { username, password, ...(otp ? { otp: { code: String(otp), remember: false } } : {}) },
    });
  } catch (err) {
    if (err instanceof DaError) {
      if (/otp|2fa|two/i.test(`${err.type} ${err.message}`)) {
        journal(host, 'two_step');
        throw new UserError('This account uses two-step login. Enter the current code from your authenticator app and try again.');
      }
      if (REFUSAL_STATUSES.has(err.status)) {
        const wrong = recordRefused(host);
        journal(host, 'refused', wrong.pauseMs ? { pause_s: Math.round(wrong.pauseMs / 1000) } : {});
        const refused = `The panel did not accept that username and password (status ${err.status}). Check them and try again.`;
        if (wrong.pauseMs) {
          throw new LockedError(`${refused} To protect you from being blocked by the server's firewall, sign-in to ${host} is now paused for ${describeWait(wrong.pauseMs)}.`, wrong.pauseMs);
        }
        throw new UserError(`${refused} Repeated wrong attempts can get your internet address blocked by the server for a while.`);
      }
      journal(host, 'error');
      throw new UserError(`The panel answered with an error (status ${err.status}) while signing in. Try again in a minute; if it keeps happening, contact kapaweb support.`);
    }
    throw err;
  }
  const cookie = cookieFromResponse(loginRes, loginRes.body);
  if (!cookie) throw new UserError('The panel accepted the login but did not start a session. Please try again or contact kapaweb support.');
  sess.setCookie(cookie);
  recordSignedIn(host); // a session exists, so the password was right: the brake starts over
  journal(host, 'accepted');

  let keyId = null;
  let keyLeft = null; // id of a key that could not be removed again (told to the user, never claimed as gone)
  const cleanup = async () => {
    if (keyId) {
      try {
        await sess.request('DELETE', `/api/login-keys/keys/${encodeURIComponent(keyId)}`);
      } catch (err) {
        if (!(err instanceof DaError && err.status === 404)) keyLeft = keyId; // 404: it was never created
      }
    }
    await sess.request('POST', '/api/logout').catch(() => {});
  };
  const leftover = () => (keyLeft ? ` The temporary key "${keyLeft}" could not be removed automatically: delete it in DirectAdmin under Login Keys.` : '');

  try {
    // 2. who is this?
    const { body: cfg } = await sess.get('/api/session/user-config');
    if (!cfg || String(cfg.username || '').toLowerCase() !== username.toLowerCase()) throw new UserError('The panel session did not match the username. Please try again.');
    if (String(cfg.userType || '').toLowerCase() !== 'user') {
      throw new UserError(`This connector works with hosting accounts only, not reseller or admin logins (the panel reported "${String(cfg.userType || 'nothing').slice(0, 20)}" as the login type). Use the account's own DirectAdmin username.`);
    }
    if (cfg.suspended) throw new UserError('This hosting account is suspended. Contact kapaweb support.');
    if (cfg.loginKeys === false) throw new UserError('Login keys are switched off for this hosting plan, so the connector cannot be set up. Contact kapaweb support.');

    // 3. optional IP lock: the panel tells us which address this session comes from
    let networks = [];
    if (ipLock) {
      const { body: sessions } = await sess.get('/api/sessions');
      const me = Array.isArray(sessions) ? sessions.find((s) => s.current) : null;
      const ip = me?.ip;
      if (!ip || !/^[0-9a-f:.]+$/i.test(ip)) throw new UserError('Could not detect this computer\'s internet address, so the IP lock was not applied. Try again without it.');
      networks = [ip.includes(':') ? `${ip}/128` : `${ip}/32`];
    }

    // 4. which command names does this panel offer?
    const { body: cmds } = await sess.get('/api/login-keys/commands');
    const available = new Set(
      Array.isArray(cmds?.extended) ? cmds.extended.filter((c) => c.available).map((c) => c.command) : Array.isArray(cmds?.commands) ? cmds.commands : [],
    );
    const allow = ALLOW_COMMANDS.filter((c) => available.has(c));
    const baseMissing = BASE_COMMANDS.filter((c) => !available.has(c));
    const fileApi = MODERN_FILE_COMMANDS.every((c) => available.has(c)) ? 'modern' : LEGACY_FILE_COMMANDS.every((c) => available.has(c)) ? 'legacy' : null;
    if (baseMissing.length || !fileApi) {
      const missing = [...(fileApi ? [] : MODERN_FILE_COMMANDS.filter((c) => !available.has(c))), ...baseMissing];
      throw new UserError(`This panel does not offer the commands the connector needs (${missing.join(', ')}). Contact kapaweb support; nothing was created.`);
    }
    if (fileApi === 'legacy') notes.push('This panel runs an older DirectAdmin: files are handled through its classic File Manager command, backups are folders (a copy of the files), and the SSL tools are not available.');
    const skipped = ALLOW_COMMANDS.filter((c) => !available.has(c));
    if (skipped.length) notes.push(`Optional commands not offered by this panel: ${skipped.join(', ')}.`);

    // 5. mint the key
    const id = 'kwconn' + randomLower(8);
    const key = randomAlnum(40);
    const now = new Date();
    const expiresAt = days ? isoNoMillis(new Date(now.getTime() + days * 86400000)) : null;
    const body = {
      id,
      password: key,
      currentPassword: password,
      allowLogin: false,
      allowNetworks: networks,
      allowCommands: allow,
      denyCommands: [],
      hasExpiry: Boolean(days),
      autoRemove: Boolean(days),
    };
    if (days) body.expires = expiresAt;
    keyId = id; // set first: if the answer is lost after the panel created the key, cleanup still removes it
    await sess.postJson('/api/login-keys/keys', body);

    // 6. prove it works, and prove it is restricted (fail closed)
    const probe = new DaClient({ host, port, username, key, pinnedIp });
    const ok = await probe.get('/api/session/user-config').catch(() => null);
    if (!ok || String(ok.body?.username || '').toLowerCase() !== username.toLowerCase()) {
      throw new UserError('The new key did not work right after it was created' + (networks.length ? ' (check the IP lock)' : '') + '. It was removed; nothing was saved.');
    }
    const probe2 = new DaClient({ host, port, username, key, pinnedIp });
    let restricted = false;
    try {
      await probe2.get('/api/login-keys/keys');
    } catch (err) {
      restricted = err instanceof DaError && err.status === 403;
    }
    if (!restricted) {
      throw new UserError('The panel did not restrict the new key as requested, so it was removed and nothing was saved. Contact kapaweb support.');
    }
    // Second check: read the key back through the still-open session. Only positive evidence counts: a key shown with
    // panel login allowed, or with commands we did not ask for. An empty list or an unknown shape proves nothing (a
    // list may leave the details out), the refusal above is the main guard.
    const listed = await sess.get('/api/login-keys/keys').then((r) => r.body).catch(() => null);
    const entry = Array.isArray(listed) ? listed.find((k) => k && k.id === id) : null;
    if (entry) {
      const shown = Array.isArray(entry.allowCommands) ? entry.allowCommands : [];
      if (entry.allowLogin === true || shown.some((c) => !allow.includes(c))) {
        throw new UserError('The panel did not store the restrictions of the new key as requested, so it was removed and nothing was saved. Contact kapaweb support.');
      }
    }

    const conn = {
      version: 1,
      panelHost: host,
      port,
      username,
      keyId: id,
      createdAt: isoNoMillis(now),
      expiresAt,
      ipLock: networks[0] || null,
      allowedCommands: allow.length,
      fileApi,
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
    keyId = null; // success: keep the key
    await cleanup();
    return { conn, key, notes, adopted };
  } catch (err) {
    await cleanup();
    if (err instanceof DaError) {
      throw new UserError(`The panel refused a step of the setup: ${err.message}.${leftover() || ' Nothing was left behind.'}`);
    }
    if (err instanceof UserError && keyLeft) throw new UserError(err.message + leftover(), err.code);
    throw err;
  }
}
