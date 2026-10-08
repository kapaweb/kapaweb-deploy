// `node server/index.js --connect`: lets the user sign in DURING the installation, before the AI app is restarted.
// It opens the same local sign-in page as the `connect` tool. The AI runs the command but never sees the page's
// address (it is printed only when no browser could be started) and never a password: those are typed on the page.
//
// The command returns at once. A detached worker (`--connect-worker`) keeps the page alive (15 minutes) and saves the
// connection when the user has signed in, so the timeout of an AI app's shell cannot kill the page under the user's hands.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describeWait, pausedHosts } from './lockout.js';
import { clearSignInOpen, describeAgo, markSignInOpen, signInOpen } from './pending.js';
import { Session } from './session.js';
import { startSetup } from './setup.js';

const SELF = fileURLToPath(new URL('./index.js', import.meta.url));
const WORKER_START_MS = 20_000;
// After the sign-in the worker stays a moment (the success page is still being shown); after a failure or an expiry the
// port keeps answering 410 to a stale browser tab for a while instead of freeing the port at once.
const lingerMs = (ok) => {
  const forced = Number(process.env.KAPAWEB_CONNECTOR_LINGER_MS);
  if (Number.isFinite(forced) && forced >= 0 && process.env.KAPAWEB_CONNECTOR_LINGER_MS !== undefined) return forced;
  return ok ? 30_000 : 5 * 60_000;
};

/**
 * The command an AI app runs. Returns the exit code. `session` is only passed by tests.
 * @param {{force?: boolean, showUrl?: boolean, account?: string}} [o] showUrl: the user says that no page appeared, so the address is handed over too;
 * account: sign in again to that one connected account (its key expired)
 */
export async function connectCli({ force = false, showUrl = false, account = '' } = {}, out = (line) => process.stdout.write(line + '\n'), session = null) {
  session ||= await Session.create();
  await session.load();
  const target = account ? session.resolve(account) : null; // throws when no connected account has that name
  const accounts = session.list();
  if ((target ? [target] : accounts).some((c) => !session.isExpired(c)) && !force) {
    out(`Already connected: ${accounts.map((c) => `${c.username} on ${c.panelHost}`).join(', ')}. The sign-in page is not needed; carry on with the next step. To add another hosting account, run this again with force (--force).`);
    return 0;
  }
  if (session.store.backendName === 'none') {
    out('This computer has no protected storage for the login key, so a sign-in made now could not be kept. Do not open the sign-in page yet: after the restart, call the `connect` tool.');
    return 0;
  }
  const paused = pausedHosts();
  if (paused.length > 0) {
    const p = paused.reduce((a, b) => (b.retryAfterMs > a.retryAfterMs ? b : a));
    out(`Sign-in to ${p.host} is paused for ${describeWait(p.retryAfterMs)} because of several wrong passwords in a row (this keeps the user from being blocked by the server's firewall). Tell the user to check the details in their welcome e-mail and to try later. Never try passwords yourself.`);
    return 1;
  }
  const open = signInOpen();
  if (open && !force) {
    out(alreadyOpenMessage(open));
    return 0;
  }
  const first = await startWorker(showUrl);
  if (!first) {
    out('The sign-in page could not be started. After the restart, call the `connect` tool instead.');
    return 1;
  }
  out(startMessage(first));
  return 0;
}

const WAIT_HINT = " When you need the connection, call account_info with wait_seconds=45 (from a shell: --call account_info wait_seconds=45; repeat while sign_in.status is still_waiting, up to 15 minutes in all): it returns the moment they have signed in, so they never have to tell you that they are done.";

/** A page that an earlier `--connect` opened is still waiting: a second one would only confuse the user. */
export function alreadyOpenMessage(open) {
  return `A sign-in page was already opened in the user's browser ${describeAgo(open.seconds)} and is still waiting for them. Do not open another and do not wait for it: carry on. Only if the user says the page is gone or does not work, call connect again with force set to true.${WAIT_HINT}`;
}

/** What the AI is told once the page is up. The address is only handed over when no browser could be started, or when it was asked for. */
export function startMessage(first) {
  if (first.opened && !first.url) {
    return "A sign-in page opened in the user's browser. The user types their DirectAdmin address, username and password THERE (they go only to their hosting panel, never to you or the chat). The page stays open for 15 minutes. Do not open it yourself and do not wait for it: carry on with the next step." +
      " When you need the connection, call account_info with wait_seconds=45 (from a shell: --call account_info wait_seconds=45; repeat while sign_in.status is still_waiting, up to 15 minutes in all): it returns the moment they have signed in, so they never have to tell you that they are done.";
  }
  if (first.opened) {
    return `A sign-in page opened in the user's browser, and the user could not find it, so here is its address. Tell them to open it in their browser on this computer and to sign in there (the password goes only to their hosting panel). Do not open it yourself: ${first.url}`;
  }
  return `No browser could be started here. Tell the user to open this address in their browser on this computer and to sign in there (the password goes only to their hosting panel). Do not open it yourself: ${first.url}`;
}

function startWorker(showUrl = false) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(process.execPath, [SELF, '--connect-worker', ...(showUrl ? ['--show-url'] : [])], { detached: true, stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true, env: process.env });
    } catch {
      resolve(null);
      return;
    }
    let buffer = '';
    const finish = (value) => {
      clearTimeout(timer);
      child.stdout?.destroy();
      child.unref();
      resolve(value);
    };
    const timer = setTimeout(() => {
      try {
        child.kill();
      } catch {
        // already gone
      }
      finish(null);
    }, WORKER_START_MS);
    child.on('error', () => finish(null));
    child.on('exit', () => finish(null));
    child.stdout.on('data', (chunk) => {
      buffer += chunk;
      const end = buffer.indexOf('\n');
      if (end < 0) return;
      try {
        finish(JSON.parse(buffer.slice(0, end)));
      } catch {
        finish(null);
      }
    });
  });
}

/** The detached process: owns the sign-in page until the user is done. Returns the exit code. */
export async function connectWorker() {
  process.stdout.on('error', () => {}); // the parent closes the pipe once it has read the first line
  const maxMs = Number(process.env.KAPAWEB_CONNECTOR_WORKER_MAX_MS); // tests only: a worker must not outlive a failed test
  if (maxMs > 0) setTimeout(() => process.exit(1), maxMs).unref();
  const session = await Session.create();
  await session.load();
  const setup = await startSetup({
    onConnected: (conn, key) => session.adopt(conn, key),
    prefill: session.prefill(),
  });
  markSignInOpen(); // other connector processes see that the user is signing in right now
  process.once('exit', clearSignInOpen);
  process.stdout.write(JSON.stringify({ opened: setup.opened, ...(setup.opened && !process.argv.includes('--show-url') ? {} : { url: setup.url }) }) + '\n');
  const result = await setup.done;
  clearSignInOpen();
  await new Promise((resolve) => setTimeout(resolve, lingerMs(result.ok)));
  return result.ok ? 0 : 1;
}
