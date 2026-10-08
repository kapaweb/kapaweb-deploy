// How to register the connector as a local (stdio) MCP server in the AI apps people use.
// `node server/index.js --print-config [app]` prints this for the computer it runs on, with the REAL absolute paths, so an AI
// (or a person) can copy it without guessing paths, quoting or backslash escaping. It reads nothing, sends nothing, prints no secret.
//
// The formats come from each app's own documentation, read on 2026-09-21. Apps change these now and then: if an app's own current
// documentation says something else, that wins. Only the apps we have actually run the connector in are called "tested" on the web page.
import { homedir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const SERVER_NAME = 'kapaweb';

/** Ids the set-up prompt on kapaweb.gr refers to: keep this list and the prompt in step. */
export const CLIENT_IDS = ['claude-desktop', 'claude-code', 'codex', 'cursor', 'windsurf', 'vscode', 'gemini-cli', 'cline', 'zed', 'jetbrains', 'other'];

/** A path for a TOML file: a literal string needs no escaping, unless the path contains a single quote. */
export function tomlString(s) {
  if (!/['\u0000-\u001f\u007f]/.test(s)) return `'${s}'`;
  return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/[\u0000-\u001f\u007f]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)}"`;
}

/** Quote one word for the shell the person most likely uses on that system (PowerShell/cmd on Windows, sh elsewhere). */
export function shellWord(s, win) {
  return win ? `"${s}"` : `'${s.replace(/'/g, `'\\''`)}'`;
}

function fence(lang, text) {
  return '```' + lang + '\n' + text + '\n```';
}

/**
 * @param {{node?:string, server?:string, platform?:string, home?:string, appdata?:string}} [o] defaults: this computer
 * @returns {{id:string, name:string, text:string}[]}
 */
export function clientSections(o = {}) {
  const platform = o.platform || process.platform;
  const win = platform === 'win32';
  const P = win ? path.win32 : path.posix;
  const node = o.node || process.execPath;
  const server = o.server || fileURLToPath(new URL('./index.js', import.meta.url));
  const home = o.home || homedir();
  const appdata = o.appdata || (win ? P.join(home, 'AppData', 'Roaming') : '');
  const json = (obj) => fence('json', JSON.stringify(obj, null, 2));
  const stdio = { command: node, args: [server] };
  const word = (s) => shellWord(s, win);
  const merge = (what = 'object') => `Add the \`kapaweb\` entry to the existing ${what} and keep every other entry; do not overwrite the file; make a copy of the file first.`;

  const sections = [
    {
      id: 'claude-desktop',
      name: 'Claude Desktop',
      lines: [
        'Easiest: install the `.mcpb` extension file (double-click it, then choose Install). Claude Desktop brings its own Node.js, so nothing below is needed.',
        `By hand instead: edit \`${win ? P.join(appdata, 'Claude', 'claude_desktop_config.json') : P.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')}\` (Settings, Developer, Edit Config). ${merge()} Then quit Claude Desktop completely and start it again.`,
      ],
      blocks: [json({ mcpServers: { [SERVER_NAME]: stdio } })],
    },
    {
      id: 'claude-code',
      name: 'Claude Code',
      lines: [
        'Run this once. `--scope user` makes it available in every project. Then start a new session.',
        `If the \`claude\` command is not found in your shell (the desktop app brings its own copy and puts nothing on the PATH), add the same entry by hand: open \`${P.join(home, '.claude.json')}\`, find the top-level \`mcpServers\` object (create it when it is missing) and add \`kapaweb\` to it. The file also holds Claude Code's own state, so change nothing else in it. ${merge('object')}`,
      ],
      blocks: [
        fence(win ? 'powershell' : 'bash', `claude mcp add --scope user ${SERVER_NAME} -- ${word(node)} ${word(server)}`),
        json({ mcpServers: { [SERVER_NAME]: { type: 'stdio', ...stdio, env: {} } } }),
      ],
    },
    {
      id: 'codex',
      name: 'Codex (CLI and IDE extension) and the ChatGPT desktop app, which share one configuration',
      lines: [
        `Run the command once, or add the table to \`${P.join(home, '.codex', 'config.toml')}\` yourself. ${merge('file')} Then restart the app.`,
      ],
      blocks: [
        fence(win ? 'powershell' : 'bash', `codex mcp add ${SERVER_NAME} -- ${word(node)} ${word(server)}`),
        fence('toml', `[mcp_servers.${SERVER_NAME}]\ncommand = ${tomlString(node)}\nargs = [${tomlString(server)}]`),
      ],
    },
    {
      id: 'cursor',
      name: 'Cursor',
      lines: [`Edit (create if missing) \`${P.join(home, '.cursor', 'mcp.json')}\` for all projects. ${merge()} Then restart Cursor. The switch for each server is under Customize in the sidebar.`],
      blocks: [json({ mcpServers: { [SERVER_NAME]: { type: 'stdio', ...stdio } } })],
    },
    {
      id: 'windsurf',
      name: 'Windsurf',
      lines: [`Edit (create if missing) \`${P.join(home, '.codeium', 'windsurf', 'mcp_config.json')}\`. ${merge()} The MCP list is under the MCPs icon of the Cascade panel; refresh it there or restart Windsurf.`],
      blocks: [json({ mcpServers: { [SERVER_NAME]: stdio } })],
    },
    {
      id: 'vscode',
      name: 'VS Code with GitHub Copilot (agent mode)',
      lines: [
        `Open the Command Palette and run "MCP: Open User Configuration" (all workspaces), or use \`.vscode/mcp.json\` inside one project. The top-level key here is \`servers\`, not \`mcpServers\`. ${merge()} VS Code asks you to trust the server the first time it starts.`,
      ],
      blocks: [json({ servers: { [SERVER_NAME]: { type: 'stdio', ...stdio } } })],
    },
    {
      id: 'gemini-cli',
      name: 'Gemini CLI',
      lines: [`Run this once (\`-s user\` = every project), or add the entry to \`${P.join(home, '.gemini', 'settings.json')}\`. Check with \`/mcp\` inside Gemini CLI.`],
      blocks: [fence(win ? 'powershell' : 'bash', `gemini mcp add -s user ${SERVER_NAME} ${word(node)} ${word(server)}`), json({ mcpServers: { [SERVER_NAME]: stdio } })],
    },
    {
      id: 'cline',
      name: 'Cline (VS Code extension)',
      lines: [`Open the Cline panel, the MCP Servers icon, the Configure tab, then "Configure MCP Servers" (the file is \`~/.cline/mcp.json\` in the current documentation). ${merge()} If the tools do not show up, switch the server off and on.`],
      blocks: [json({ mcpServers: { [SERVER_NAME]: { ...stdio, disabled: false, autoApprove: [] } } })],
    },
    {
      id: 'zed',
      name: 'Zed',
      lines: [`Run "zed: open settings file" and add the entry under \`context_servers\` (or Agent panel settings, Add Server, Add Local Server). ${merge()}`],
      blocks: [json({ context_servers: { [SERVER_NAME]: { ...stdio, env: {} } } })],
    },
    {
      id: 'jetbrains',
      name: 'JetBrains IDEs (AI Assistant)',
      lines: ['Settings, Tools, AI Assistant, Model Context Protocol (MCP), Add, then paste this as JSON. Choose "Global" so it works in every project, then OK and Apply.'],
      blocks: [json({ mcpServers: { [SERVER_NAME]: stdio } })],
    },
    {
      id: 'other',
      name: 'Any other app that supports local (stdio) MCP servers',
      lines: ['Most apps use this shape (an `mcpServers` object with `command` and `args`). Use your app\'s own documented place for it and prefer a user-level (all projects) setting. If your app documents another format, follow that.'],
      blocks: [json({ mcpServers: { [SERVER_NAME]: stdio } })],
    },
  ];
  return sections.map((s) => ({ id: s.id, name: s.name, text: `### ${s.name}  (id: \`${s.id}\`)\n${s.lines.join('\n')}\n\n${s.blocks.join('\n\n')}` }));
}

/** Text for `--print-config [app]`. An unknown id lists the known ones. */
export function printConfig(only, o = {}) {
  const node = o.node || process.execPath;
  const server = o.server || fileURLToPath(new URL('./index.js', import.meta.url));
  const all = clientSections({ ...o, node, server });
  const head = [
    '# kapaweb connector: add it to your AI app',
    '',
    `This computer: node is \`${node}\`, the connector is \`${server}\`.`,
    'Use these absolute paths exactly as shown: apps started from the desktop often do not see the PATH of a terminal, so a bare `node` can fail.',
    'No environment variables are needed, and no password or key goes into any of this. If Node.js or the connector folder is later updated or moved, run this again and replace the paths.',
    "The formats below come from each app's own documentation (read 2026-09-21). If your app's current documentation says something different, follow your app's documentation and keep the same command and argument.",
    '',
  ];
  const win = (o.platform || process.platform) === 'win32';
  const run = `${shellWord(node, win)} ${shellWord(server, win)}`;
  const tail = ['', `You do not have to wait for the restart: until then your app's tool list does not show the connector's tools, but the same tools run from the command line. \`${run} --tools\` lists them and \`${run} --call <tool> name=value\` runs one.`];
  if (only) {
    const hit = all.find((s) => s.id === only.toLowerCase());
    if (!hit) return [...head, `Unknown app "${only}". Known ids: ${CLIENT_IDS.join(', ')}.`].join('\n');
    return [...head, hit.text, ...tail].join('\n');
  }
  return [...head, all.map((s) => s.text).join('\n\n'), ...tail].join('\n');
}
