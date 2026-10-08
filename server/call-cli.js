// `node server/index.js --tools [tool]` and `node server/index.js --call <tool> [arguments]`: the connector's tools from a shell.
// An AI app that has just installed the connector cannot see its tools before it is restarted; with these two commands it carries
// on at once, in the same session. It is the same code as an MCP `tools/call` (`runTool`): the same argument checks, the same
// output redaction, the same one-deploy-at-a-time lock, the same guards inside every tool. Nothing here can do more than the tools.
import { readFile } from 'node:fs/promises';
import { platform } from 'node:os';
import { fileURLToPath } from 'node:url';
import { shellWord } from './clients.js';
import { connectCli } from './connect-cli.js';
import { withFileLock } from './lock.js';
import { SERVER_INSTRUCTIONS, runTool } from './mcp.js';
import { Session } from './session.js';
import { buildTools } from './tools.js';
import { UserError, VERSION, isPlainObject, optBool, optString } from './util.js';

const SELF = fileURLToPath(new URL('./index.js', import.meta.url));
const MAX_ARGS_FILE_BYTES = 8 * 1024 * 1024;

/** The command as it is typed on this computer, with the real paths. */
export function invocation(win = platform() === 'win32', node = process.execPath, script = SELF) {
  return `${shellWord(node, win)} ${shellWord(script, win)}`;
}

/** The command itself was wrong (exit code 2), as opposed to a tool that reported an error (exit code 1). */
export class UsageError extends Error {}

// ---------------------------------------------------------------------------
// --tools
// ---------------------------------------------------------------------------

const required = (tool) => new Set(tool.inputSchema?.required || []);

function signature(tool) {
  const need = required(tool);
  return `${tool.name}(${Object.keys(tool.inputSchema?.properties || {}).map((p) => p + (need.has(p) ? '*' : '')).join(', ')})`;
}

function typeName(def) {
  switch (def?.type) {
    case 'boolean':
      return 'true or false';
    case 'integer':
      return 'whole number';
    case 'array':
      return 'list: repeat the name for each item';
    case 'object':
      return 'JSON object: give it in an --args-file';
    default:
      return def?.enum ? `one of: ${def.enum.join(', ')}` : 'text';
  }
}

/** Every tool on one line, with the rules of use at the top. */
export function listTools(tools, inv = invocation()) {
  return [
    `kapaweb connector ${VERSION}: ${tools.length} tools. They are the tools an MCP client gets, with the same checks. No restart of your app is needed to use them.`,
    '',
    'Run a tool (a shell command):',
    `  ${inv} --call <tool> name=value name=value`,
    'Write true, false and numbers as they are (dry_run=true). Repeat the name for a list (paths=/a paths=/b). Put a value with spaces in quotes.',
    'For anything else (quotes or several lines in a value, an object) write the arguments as JSON into a UTF-8 file and use --args-file <file>. Inline JSON, --call <tool> \'{"name":"value"}\', works in most shells but Windows PowerShell strips the quotes inside it.',
    'The result is printed as text. The exit code is 0 when it worked, 1 when the tool reported a problem (the text says which) and 2 when the command line itself could not be understood.',
    `Everything about one tool: ${inv} --tools <tool>`,
    '',
    SERVER_INSTRUCTIONS,
    '',
    'Tools (* = required argument):',
    ...tools.map((t) => `${signature(t)} - ${t.title}`),
  ].join('\n');
}

/** The full description and the arguments of one tool. */
export function describeTool(tool, inv = invocation()) {
  const need = required(tool);
  const props = Object.entries(tool.inputSchema?.properties || {});
  const a = tool.annotations || {};
  const lines = [`${tool.name}: ${tool.title}`, '', tool.description, ''];
  lines.push(a.readOnlyHint ? 'This tool only reads.' : a.destructiveHint ? 'This tool changes or deletes data on the hosting account.' : 'This tool changes things on the hosting account.');
  if (props.length === 0) lines.push('It takes no arguments.');
  else {
    lines.push('', 'Arguments (* = required):');
    for (const [name, def] of props) lines.push(`  ${name}${need.has(name) ? '*' : ''} (${typeName(def)}): ${def.description || ''}`);
  }
  lines.push('', `Example: ${inv} --call ${tool.name}${[...need].map((n) => ` ${n}=<${n}>`).join('')}`);
  return lines.join('\n');
}

/** `--tools [tool]`. Returns the exit code. */
export function toolsCli(words, out = (line) => process.stdout.write(line + '\n'), tools = buildTools()) {
  const name = words[0];
  if (!name) {
    out(listTools(tools));
    return 0;
  }
  const tool = tools.find((t) => t.name === name);
  if (!tool) {
    out(unknownTool(name, tools));
    return 2;
  }
  out(describeTool(tool));
  return 0;
}

function unknownTool(name, tools) {
  return `There is no tool called "${name}". The tools are: ${tools.map((t) => t.name).join(', ')}. Details of all of them: --tools`;
}

// ---------------------------------------------------------------------------
// --call
// ---------------------------------------------------------------------------

const JSON_HINT = 'The arguments must be one JSON object, for example {"domain":"example.gr"}. If you typed it in Windows PowerShell, the shell removed the quotes inside it: give the arguments as name=value words instead, or write the JSON into a UTF-8 file and pass --args-file <file>.';

function parseJsonObject(text, what) {
  let value;
  try {
    value = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text); // Windows PowerShell writes a BOM in front of UTF-8 files
  } catch {
    throw new UsageError(`Could not read ${what} as JSON. ${JSON_HINT}`);
  }
  if (!isPlainObject(value)) throw new UsageError(`${what} must be one JSON object, {"name": value}, not a list or a single value. ${JSON_HINT}`);
  return value;
}

/** A word from the command line, as the value the schema asks for. What does not fit is passed on as it is: the argument check then names the problem. */
function coerce(raw, def) {
  switch (def?.type) {
    case 'boolean': {
      const v = raw.trim().toLowerCase();
      return v === 'true' ? true : v === 'false' ? false : raw;
    }
    case 'integer':
      return /^-?\d+$/.test(raw.trim()) ? Number(raw) : raw;
    case 'object':
      try {
        return JSON.parse(raw);
      } catch {
        return raw;
      }
    default:
      return raw;
  }
}

function fromPairs(words, schema) {
  const props = schema?.properties || {};
  const args = {};
  for (const word of words) {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)=([\s\S]*)$/.exec(word);
    if (!m) throw new UsageError(`Cannot read "${word}". Write the arguments as name=value, or give all of them as JSON with --args-file <file>.`);
    const [, name, raw] = m;
    const def = props[name];
    if (def?.type === 'array') {
      let items = [raw];
      if (raw.trimStart().startsWith('[')) {
        try {
          items = JSON.parse(raw);
        } catch {
          // not JSON after all: a file name may start with a bracket
        }
      }
      args[name] = [...(args[name] || []), ...(Array.isArray(items) ? items : [items])];
      continue;
    }
    if (Object.hasOwn(args, name)) throw new UsageError(`"${name}" is given twice. Only a list argument can be repeated.`);
    args[name] = coerce(raw, def);
  }
  return args;
}

/**
 * The words after the tool name, as the tool's arguments: nothing, `name=value` words, one JSON text, or `--args-file <file>`.
 * @param {string[]} words
 * @param {{inputSchema?: object}} tool
 */
export async function parseArguments(words, tool, read = readFile) {
  if (words.length === 0) return {};
  if (words[0] === '--args-file') {
    if (words.length !== 2 || !words[1]) throw new UsageError('--args-file needs one file name, and nothing after it.');
    let text;
    try {
      text = await read(words[1]);
    } catch {
      throw new UsageError(`The file ${words[1]} could not be read.`);
    }
    if (text.length > MAX_ARGS_FILE_BYTES) throw new UsageError(`The file ${words[1]} is larger than ${MAX_ARGS_FILE_BYTES / 1048576} MB.`);
    return parseJsonObject(text.toString('utf8'), `the file ${words[1]}`);
  }
  if (words[0].trimStart().startsWith('{')) return parseJsonObject(words.join(' '), 'the arguments'); // a shell may have cut the text at its spaces
  return fromPairs(words, tool.inputSchema);
}

/**
 * `connect` opens the sign-in page, which must outlive this short command: it goes through the detached worker of `--connect`
 * (which the tool's own in-process page could not do), with the same messages.
 */
function connectHere(tool) {
  return {
    ...tool,
    async handler(args, { session }) {
      const lines = [];
      const code = await connectCli({ force: optBool(args, 'force', false), showUrl: optBool(args, 'show_url', false), account: optString(args, 'account') || '' }, (line) => lines.push(line), session);
      if (code !== 0) throw new UserError(lines.join('\n'));
      return lines.join('\n');
    },
  };
}

/**
 * `--call <tool> [arguments]`. Returns the exit code.
 * @param {string[]} words everything after `--call`
 */
export async function callCli(words, out = (line) => process.stdout.write(line + '\n'), { session = null, tools = buildTools() } = {}) {
  const [name, ...rest] = words;
  if (!name || name.startsWith('--')) {
    out('Say which tool to run: --call <tool> name=value ...   All tools: --tools');
    return 2;
  }
  const found = tools.find((t) => t.name === name);
  if (!found) {
    out(unknownTool(name, tools));
    return 2;
  }
  let args;
  try {
    args = await parseArguments(rest, found);
  } catch (err) {
    if (!(err instanceof UsageError)) throw err;
    out(`${err.message} (tool: ${name})`);
    return 2;
  }
  const say = (m) => out(`[progress] ${m}`);
  const { text, isError } = await runTool(found.name === 'connect' ? connectHere(found) : found, args, {
    session: session || (await Session.create()),
    progress: say,
    exclusive: (fn) => withFileLock(fn, { onWait: say }),
  });
  out(text);
  return isError ? 1 : 0;
}
