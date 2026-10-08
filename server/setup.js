// The local sign-in page. It runs on the user's own computer (127.0.0.1, random port,
// random path), so the password is typed into a page that never touches the chat.
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { timingSafeEqual } from 'node:crypto';
import { platform } from 'node:os';
import { randomToken, UserError } from './util.js';
import { LockedError } from './lockout.js';
import { provision } from './provision.js';

const MAX_ATTEMPTS = 3;
export const LIFETIME_MS = 15 * 60 * 1000; // how long the page waits for the user

const STRINGS = {
  en: {
    title: 'Connect kapaweb hosting',
    lead: 'Type your hosting details once. The password is used only to create a restricted key and is then forgotten; your AI app never sees it.',
    address: 'DirectAdmin address',
    addressHelp: 'From your welcome e-mail, for example server1.kdns.gr',
    username: 'Username',
    password: 'Password',
    otp: 'Two-step code (only if you use one)',
    expiry: 'The key lasts',
    e30: '30 days (recommended)',
    e90: '90 days',
    e365: '1 year',
    enever: 'Until I remove it (not recommended)',
    iplock: 'Lock the key to this computer\'s internet address (safer, but you must reconnect if your address changes)',
    submit: 'Connect',
    working: 'Connecting… this takes a few seconds.',
    doneTitle: 'Connected',
    doneText: 'You can close this tab and go back to your AI app. It can now work on your hosting account.',
    what: 'The key can manage files, databases, PHP settings, logs, SSL, subdomains and cron jobs of this account. It cannot open the control panel, change your password or create other keys. You can remove it any time in DirectAdmin under Login Keys.',
    failTitle: 'Could not connect',
    again: 'Try again',
    tooMany: 'Too many attempts. Go back to your AI app and ask it to start the connection again.',
    paused: 'Sign-in is paused for now. Wait for the time above, then go back to your AI app and ask it to start the connection again.',
    expired: 'This page has expired. Go back to your AI app and ask it to start the connection again.',
    busy: 'A sign-in is already being processed. Wait a few seconds.',
    account: 'Connected account',
  },
  el: {
    title: 'Σύνδεση με το hosting της kapaweb',
    lead: 'Γράψε τα στοιχεία του hosting σου μία φορά. Ο κωδικός χρησιμοποιείται μόνο για να δημιουργηθεί ένα περιορισμένο κλειδί και μετά ξεχνιέται· το AI app δεν τον βλέπει ποτέ.',
    address: 'Διεύθυνση DirectAdmin',
    addressHelp: 'Από το email καλωσορίσματος, π.χ. server1.kdns.gr',
    username: 'Όνομα χρήστη',
    password: 'Κωδικός',
    otp: 'Κωδικός δύο βημάτων (μόνο αν τον χρησιμοποιείς)',
    expiry: 'Το κλειδί διαρκεί',
    e30: '30 ημέρες (προτείνεται)',
    e90: '90 ημέρες',
    e365: '1 χρόνο',
    enever: 'Μέχρι να το αφαιρέσω (δεν προτείνεται)',
    iplock: 'Δέσε το κλειδί στη διεύθυνση internet αυτού του υπολογιστή (πιο ασφαλές, αλλά θα ξανασυνδεθείς αν αλλάξει η διεύθυνση)',
    submit: 'Σύνδεση',
    working: 'Γίνεται σύνδεση… θα πάρει λίγα δευτερόλεπτα.',
    doneTitle: 'Συνδέθηκε',
    doneText: 'Μπορείς να κλείσεις αυτή την καρτέλα και να γυρίσεις στο AI app σου. Πλέον μπορεί να δουλέψει στον λογαριασμό hosting σου.',
    what: 'Το κλειδί διαχειρίζεται αρχεία, βάσεις, ρυθμίσεις PHP, logs, SSL, subdomains και cron jobs αυτού του λογαριασμού. Δεν ανοίγει το panel, δεν αλλάζει τον κωδικό σου και δεν δημιουργεί άλλα κλειδιά. Μπορείς να το αφαιρέσεις όποτε θες από το DirectAdmin, στα Login Keys.',
    failTitle: 'Η σύνδεση δεν έγινε',
    again: 'Δοκίμασε ξανά',
    tooMany: 'Πάρα πολλές προσπάθειες. Γύρνα στο AI app σου και ζήτησέ του να ξεκινήσει ξανά τη σύνδεση.',
    paused: 'Η σύνδεση σταμάτησε προσωρινά. Περίμενε όσο γράφει παραπάνω και μετά ζήτησε από το AI app σου να ξεκινήσει ξανά τη σύνδεση.',
    expired: 'Η σελίδα έληξε. Γύρνα στο AI app σου και ζήτησέ του να ξεκινήσει ξανά τη σύνδεση.',
    busy: 'Μια σύνδεση επεξεργάζεται ήδη. Περίμενε λίγα δευτερόλεπτα.',
    account: 'Συνδεδεμένος λογαριασμός',
  },
};

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

/** Constant-time string comparison for the path token and the CSRF token. */
function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
}

function pickLang(req) {
  return /(^|,)\s*el\b/i.test(req.headers['accept-language'] || '') ? 'el' : 'en';
}

const CSS = `
:root{color-scheme:light dark}
body{font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:32px 16px;background:#f6f7f9;color:#14171c}
main{max-width:520px;margin:0 auto;background:#fff;border:1px solid #e3e6ea;border-radius:14px;padding:28px}
h1{font-size:22px;margin:0 0 8px}p{margin:8px 0}.muted{color:#586573;font-size:14px}
label{display:block;font-weight:600;margin:16px 0 4px}input[type=text],input[type=password],select{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #c5ccd4;border-radius:8px;font:inherit;background:#fff;color:inherit}
.check{display:flex;gap:10px;align-items:flex-start;margin-top:16px;font-weight:400}.check input{margin-top:4px}
button{margin-top:22px;width:100%;padding:12px;border:0;border-radius:10px;background:#f7931e;color:#1a1a1a;font:inherit;font-weight:700;cursor:pointer}
button[disabled]{opacity:.6;cursor:wait}
.err{background:#fdecea;border:1px solid #f5c2c0;border-radius:8px;padding:10px 12px;margin-top:14px}.ok{background:#e8f6ec;border:1px solid #b7e1c1;border-radius:8px;padding:10px 12px}
@media (prefers-color-scheme:dark){body{background:#12151a;color:#e8eaed}main{background:#1a1e25;border-color:#2b313a}input,select{background:#12151a!important;border-color:#3a424d!important}.muted{color:#9aa4b1}.err{background:#3a1f1f;border-color:#6b2f2f}.ok{background:#1b3324;border-color:#2f6b45}}
`;

// The kapaweb "K" (32x32 PNG made from the site's favicon_raster.png), inline so the page still loads nothing from anywhere.
const FAVICON =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAANtSURBVFhH7ZRPiBtVHMdHtLptk5k3782/pPTmxWKVqtT2IKUsXgQpCuJJ8OCKIIUWbdPsJpnsZGfyP7ultdjiYSl4Ugoeih6KIngTdKGrhbbrZmeTTDaZTJL9k93sdvuTOWR5m9us9VDI5zTz+3znx8x77zcMM2DAgKededXHNQx0oqpyZyoqP1JWuQtWnL20GOaO9mf3hKke5NcnpVPNlPBeOyOdryXIW7SvafjaSlrYqiUItAwCLR1DN4OhFOX+mhvxs3TWMysF6cj6pHJ3Na9sdwoywLUANHTySc/fPss8X9PIzHJagFIcgxnDsBDlYTmJwYywtftnXzi0u6NHWlkpCteD0MoqsJxVoG6Ia1WNe7nn3euKhjvVBAFTxVCJY2gbGBZj6LdSFJ3Y3W0PrGblj7uXA9BIK9ApKGAnhZnyiLK/5ysa91E75X49AccgUNUwlFWUn/mCObC70x5ZL4jD7Vxg28kosHVZgbpOpmlfHsdXNnIirKYFqE/guwsR7l3a/2eaaeWYk1E23OXvTilgG8LntLd18sfjSQlqCX569sshmXYPQ/tPm2H/h3TNM5Yqi82sXOxOBcFOypu2IR/vOUcTXrF18qCeIJ/Sz/ysMs9aMf6ik0Dd4qjvJ9p5xm22nJN/h6+C4KTke7bK+nvOUdHhoopfovNW1H98aRzdaek8tHQExTH2V6ADe6GdlX+E64egkZS+73f9VOPo6uM8gfkIAktFYI6xs7Mx5mB/zhONlPQN3HC3QAr3u6+PMc/R9wuj/tfLMdQpqcgdRfgn7LcfXtj3Ip3xTCOpGNtXAlBNisN0vTJO3ujmhF/sBP82XS+p6Ft3C4oR9wW4R/Mh9hTtPbOWC3y2mlea5igf7NWaE8KrzZTQgKsyVDXyA51fHPW9WYmjDXcFyjEExRD7Pu090ykEP+hMKXfow1TXcejRpARLujv/ZKukopOUZopj3C1ngodaHMHcJd952nmmnZXfaaYlna41DOG7Tk6CiibAWkaEchzfpP3cGDtsawg20zzMhX0h2nnGSSmHbV3eGbeFpA/VDXFxsyDDSlqEbl6EdpKAFeV3/hERhnmmHOWmK1H/rb/PDSk7zZ4EdY28ZhvCfNMQ/lxK4NtmDN+04jhnaehIf/Z/wcrKB9wDaZ4LDvW7AQMGPJX8C3NDniFmxkXlAAAAAElFTkSuQmCC';

function page(lang, body, { csrf } = {}) {
  return `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>kapaweb</title><link rel="icon" type="image/png" sizes="32x32" href="${FAVICON}"><meta name="robots" content="noindex"><style>${CSS}</style></head><body><main>${body}</main></body></html>`;
}

function formHtml(lang, { csrf, error, values = {}, needOtp = false }) {
  const t = STRINGS[lang];
  const v = (k) => esc(values[k] || '');
  const sel = (val) => (String(values.expiry || '30') === val ? ' selected' : '');
  return page(
    lang,
    `<h1>${esc(t.title)}</h1><p>${esc(t.lead)}</p>
    ${error ? `<div class="err" role="alert">${esc(error)}</div>` : ''}
    <form method="post" autocomplete="off">
      <input type="hidden" name="csrf" value="${esc(csrf)}">
      <label for="panel">${esc(t.address)}</label>
      <input id="panel" name="panel" type="text" required value="${v('panel')}" placeholder="server1.kdns.gr" autocapitalize="none" spellcheck="false">
      <div class="muted">${esc(t.addressHelp)}</div>
      <label for="username">${esc(t.username)}</label>
      <input id="username" name="username" type="text" required value="${v('username')}" autocapitalize="none" spellcheck="false">
      <label for="password">${esc(t.password)}</label>
      <input id="password" name="password" type="password" required autocomplete="current-password">
      ${needOtp || values.otp ? `<label for="otp">${esc(t.otp)}</label><input id="otp" name="otp" type="text" inputmode="numeric" autocomplete="one-time-code">` : ''}
      <label for="expiry">${esc(t.expiry)}</label>
      <select id="expiry" name="expiry"><option value="30"${sel('30')}>${esc(t.e30)}</option><option value="90"${sel('90')}>${esc(t.e90)}</option><option value="365"${sel('365')}>${esc(t.e365)}</option><option value="never"${sel('never')}>${esc(t.enever)}</option></select>
      <label class="check"><input type="checkbox" name="iplock" value="1"${values.iplock ? ' checked' : ''}><span>${esc(t.iplock)}</span></label>
      <button type="submit">${esc(t.submit)}</button>
    </form>
    <p class="muted" style="margin-top:18px">${esc(t.what)}</p>`,
  );
}

const SECURITY_HEADERS = {
  'Content-Type': 'text/html; charset=utf-8',
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'same-origin', // "no-referrer" makes browsers send "Origin: null" on the form post
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
};

function readBody(req, limit = 8192) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error('too large'));
        req.destroy();
      } else chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

export function openInBrowser(url) {
  if (process.env.KAPAWEB_CONNECTOR_NO_BROWSER === '1') return false;
  try {
    const p = platform();
    const child =
      p === 'win32'
        ? spawn('cmd.exe', ['/c', 'start', '', url], { stdio: 'ignore', detached: true, windowsHide: true }) // '' = the window title `start` expects first
        : spawn(p === 'darwin' ? 'open' : 'xdg-open', [url], { stdio: 'ignore', detached: true });
    child.on('error', () => {});
    child.unref();
    return true;
  } catch {
    return false;
  }
}

/**
 * Starts the sign-in page. `onConnected(conn, key)` is awaited when the exchange succeeded.
 * Returns { url, close, done } where `done` resolves with a summary when the user finished or the page expired.
 * `verifyOpts` is passed to provision (tests only: see its own doc).
 */
export async function startSetup({ onConnected, prefill = {}, open = true, verifyOpts }) {
  const token = randomToken(24);
  const csrf = randomToken(16);
  const pagePath = `/setup/${token}`;
  let attempts = 0;
  let finished = false;
  let busy = false; // a sign-in is being processed: it decides the outcome, and a second post is refused
  let resolveDone;
  const done = new Promise((r) => (resolveDone = r));
  let server;

  const finish = (result) => {
    if (finished) return;
    if (busy && !result.ok) return; // expiry or cancel while the exchange runs: the exchange itself finishes it
    finished = true;
    resolveDone(result);
    // The port stays bound and answers 410 instead of being closed: an old browser tab may still hold the form, and a
    // port that is free again could be taken by another program on this computer, which would then get the password.
    server.unref();
    setTimeout(() => server.closeIdleConnections?.(), 500).unref();
  };

  server = createServer(async (req, res) => {
    const port = server.address().port;
    const okHosts = [`127.0.0.1:${port}`, `localhost:${port}`];
    const send = (code, html, extra = {}) => {
      res.writeHead(code, { ...SECURITY_HEADERS, ...extra });
      res.end(html);
    };
    try {
      if (!okHosts.includes(String(req.headers.host || '').toLowerCase())) return send(403, 'Forbidden');
      const url = new URL(req.url, `http://127.0.0.1:${port}`);
      if (!safeEqual(url.pathname, pagePath)) return send(404, 'Not found');
      const lang = pickLang(req);
      const t = STRINGS[lang];
      if (finished) return send(410, page(lang, `<p>${esc(t.expired)}</p>`));

      if (req.method === 'GET') return send(200, formHtml(lang, { csrf, values: prefill }));

      if (req.method === 'POST') {
        // Some browsers send "Origin: null" for a same-origin form post; that is accepted only together with
        // Sec-Fetch-Site: same-origin. The CSRF token below is the real guard, these checks are extra.
        const origin = req.headers.origin;
        const fetchSite = req.headers['sec-fetch-site'];
        const originOk = !origin || okHosts.some((h) => origin === `http://${h}`) || (origin === 'null' && fetchSite === 'same-origin');
        if (!originOk) return send(403, 'Forbidden');
        if (fetchSite && !['same-origin', 'none'].includes(fetchSite)) return send(403, 'Forbidden');
        const form = new URLSearchParams(await readBody(req));
        if (!safeEqual(form.get('csrf') || '', csrf)) return send(403, 'Forbidden');
        if (busy) return send(409, page(lang, `<p>${esc(t.busy)}</p>`));
        if (attempts >= MAX_ATTEMPTS) {
          finish({ ok: false, reason: 'too many attempts' });
          return send(429, page(lang, `<p>${esc(t.tooMany)}</p>`));
        }
        attempts += 1;
        const values = { panel: form.get('panel') || '', username: form.get('username') || '', expiry: form.get('expiry') || '30', iplock: form.get('iplock') === '1', otp: form.get('otp') || '' };
        let result = null;
        let failure = null;
        busy = true;
        try {
          result = await provision({
            address: values.panel,
            username: values.username.trim(),
            password: form.get('password') || '',
            otp: values.otp.trim() || undefined,
            expiry: values.expiry,
            ipLock: values.iplock,
            adopt: onConnected,
            verifyOpts,
          });
        } catch (err) {
          failure = err;
        } finally {
          busy = false;
        }
        if (result) {
          const adopted = result.adopted;
          finish({ ok: true, conn: result.conn, warning: adopted?.warning || null });
          const extra = adopted?.warning ? `<div class="err">${esc(adopted.warning)}</div>` : '';
          const who = `<p class="muted">${esc(t.account)}: ${esc(result.conn.username)} @ ${esc(result.conn.panelHost)}</p>`;
          return send(200, page(lang, `<h1>${esc(t.doneTitle)}</h1><div class="ok">${esc(t.doneText)}</div>${who}${extra}<p class="muted">${esc(t.what)}</p>`));
        }
        const message = failure instanceof UserError ? failure.message : 'Something went wrong while connecting. Please try again.';
        if (failure instanceof LockedError) {
          // Sign-in to this panel is paused: another try would only be refused, so the page ends here.
          finish({ ok: false, reason: 'paused' });
          return send(429, page(lang, `<h1>${esc(t.failTitle)}</h1><div class="err">${esc(message)}</div><p>${esc(t.paused)}</p>`));
        }
        const needOtp = /two-step/i.test(message);
        if (attempts >= MAX_ATTEMPTS) {
          finish({ ok: false, reason: 'too many attempts' });
          return send(429, page(lang, `<h1>${esc(t.failTitle)}</h1><div class="err">${esc(message)}</div><p>${esc(t.tooMany)}</p>`));
        }
        return send(200, formHtml(lang, { csrf, error: message, values, needOtp }));
      }
      return send(405, 'Method not allowed', { Allow: 'GET, POST' });
    } catch {
      return send(500, 'Error');
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  const url = `http://127.0.0.1:${port}${pagePath}`;
  const timer = setTimeout(() => finish({ ok: false, reason: 'expired' }), LIFETIME_MS);
  timer.unref();
  done.then(() => clearTimeout(timer));
  const opened = open ? openInBrowser(url) : false;
  return { url, opened, done, close: () => finish({ ok: false, reason: 'cancelled' }) };
}
