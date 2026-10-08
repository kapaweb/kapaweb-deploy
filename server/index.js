#!/usr/bin/env node
// kapaweb connector: MCP server over stdio. Started by the AI app.
import { McpServer, SERVER_INSTRUCTIONS } from './mcp.js';
import { Session } from './session.js';
import { buildTools } from './tools.js';
import { VERSION, redactor } from './util.js';

const major = Number(process.versions.node.split('.')[0]);
if (major < 18) {
  process.stderr.write(`kapaweb connector needs Node.js 18 or newer (this is ${process.versions.node}).\n`);
  process.exit(1);
}

// `--tools [tool]` and `--call <tool> [arguments]`: the tools from a shell, for an AI app that has just installed the connector and
// has not been restarted yet (its tool list does not show them before that). Always the first argument.
if (process.argv[2] === '--tools' || process.argv[2] === '--call') {
  const { callCli, toolsCli } = await import('./call-cli.js');
  const calling = process.argv[2] === '--call';
  process.stdout.on('error', () => {}); // a reader that stops early (`| head`) is not an error of ours
  process.on('SIGINT', () => process.exit(130)); // the exit handlers still let go of the deploy lock
  process.on('SIGTERM', () => process.exit(143));
  let code = 1;
  try {
    code = calling ? await callCli(process.argv.slice(3)) : toolsCli(process.argv.slice(3));
  } catch (err) {
    process.stdout.write(`Unexpected error: ${redactor.text(err?.message || String(err))}\n`);
  }
  await new Promise((resolve) => process.stdout.write('', resolve)); // everything written has left before the process ends
  process.exit(code);
}

if (process.argv.includes('--doctor')) {
  const { doctor } = await import('./doctor.js');
  process.stdout.write((await doctor()) + '\n');
  process.exit(0);
}

// `--print-config [app]`: how to add this connector to an AI app, with this computer's real paths. Prints only; touches nothing.
if (process.argv.includes('--print-config')) {
  const { CLIENT_IDS, printConfig } = await import('./clients.js');
  const at = process.argv.indexOf('--print-config');
  const only = process.argv[at + 1] && !process.argv[at + 1].startsWith('--') ? process.argv[at + 1] : undefined;
  process.stdout.write(printConfig(only) + '\n');
  process.exit(only && !CLIENT_IDS.includes(only.toLowerCase()) ? 2 : 0);
}

// `--connect`: opens the sign-in page for the user during the installation (an AI app runs this before the restart).
// `--connect-worker` is the detached process it starts; nobody runs that one by hand.
if (process.argv.includes('--connect') || process.argv.includes('--connect-worker')) {
  const { connectCli, connectWorker } = await import('./connect-cli.js');
  const code = process.argv.includes('--connect-worker') ? await connectWorker() : await connectCli({ force: process.argv.includes('--force'), showUrl: process.argv.includes('--show-url') });
  process.exit(code);
}

const debug = process.env.KAPAWEB_CONNECTOR_DEBUG === '1';
const log = (m) => process.stderr.write(`[kapaweb-connector] ${redactor.text(m)}\n`);

process.on('uncaughtException', (err) => {
  log(`uncaught: ${err?.message}`);
});
process.on('unhandledRejection', (err) => {
  log(`unhandled rejection: ${err?.message || err}`);
});

const session = await Session.create();
if (debug) log(`secret storage: ${session.store.backendName}`);

const server = new McpServer({
  name: 'kapaweb-connector',
  version: VERSION,
  tools: buildTools(),
  session,
  instructions: SERVER_INSTRUCTIONS,
  log: debug ? log : () => {},
});
server.start();
