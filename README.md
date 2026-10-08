# kapaweb deploy

Deploy websites, PHP apps and WordPress to **kapaweb DirectAdmin hosting** from a conversation with Claude, without your hosting password ever entering the chat. The plugin bundles the kapaweb connector, a local MCP server that runs on your computer, and a skill that tells Claude how to use it safely.

## Requirements

- A hosting account at kapaweb (<https://kapaweb.gr>) on a DirectAdmin server.
- Node.js 18.17 or newer on the computer that runs Claude. The connector has no dependencies and nothing to build.
- A Claude surface that starts local MCP servers: Claude Code, or Cowork sessions that run on your computer. Claude chat on the web does not start local servers, so use the Claude Desktop extension from <https://kapaweb.gr/deploy-with-ai/> there.

## Use it

Ask Claude to deploy a project to kapaweb. The skill makes Claude read the public playbook (<https://kapaweb.gr/deploy-with-ai/playbook.md>), check that the connector is current, and call `connect`. `connect` opens a sign-in page on your own computer (`http://127.0.0.1`, random port and token): you type your DirectAdmin address, username and password there, never in the chat. The connector exchanges the password for a restricted DirectAdmin login key, forgets the password, and keeps only the key in your computer's protected storage (Windows DPAPI, macOS Keychain, Linux `secret-tool`).

Tools: `deploy` (always makes a backup first), `rollback`, `list_files`, `read_file`, `write_file`, `db_create`, `db_import`, `db_export` (streamed, any size, saved on your computer), `php_versions`, `set_php_version`, `php_settings`, `ssl_status`, `cron_*`, `subdomain_*`, `check_url`, `logs`, `usage`, `account_info`, `playbook`, `connect`, `disconnect`. Read-only tools are annotated `readOnlyHint`, destructive ones `destructiveHint`.

## What it runs, stores and sends

- **Runs** `node server/index.js` from this plugin, on your computer, over stdio. On macOS it calls `security` (Keychain), on Linux `secret-tool`, on Windows PowerShell DPAPI, to store and read its own login key; it opens your browser on the local sign-in page.
- **Sends** requests only to: your own kapaweb DirectAdmin panel (the address you typed; it is checked against kapaweb's own server list before every connection); `https://firewall.kapaweb.gr/servers.txt` (that list of kapaweb server addresses); `https://kapaweb.gr/deploy-with-ai/playbook.md` (the playbook); `https://kapaweb.gr/downloads/kapaweb-connector.version.json` (a version check at most once a day, nothing is sent but the User-Agent `kapaweb-connector/<version>`; `KAPAWEB_CONNECTOR_NO_UPDATE_CHECK=1` turns it off); and, only when you ask for it with `check_url`, the domains of your own hosting account (plus a short fixed list of sites that kapaweb itself maintains).
- **Stores** on your computer: the saved connection (panel address, user name, key id; no password), the login key and generated database passwords in the protected storage, and database exports you ask for in the connector's settings folder. Nothing is sent to kapaweb for analytics, and nothing about you is collected by this plugin.
- **Never** shows Claude your password, the login key or generated database passwords.

## Privacy policy

Kapaweb (<https://kapaweb.gr>, <info@kapaweb.gr>) provides this plugin.

- **What we collect:** nothing. The plugin has no accounts, no analytics and no telemetry on our side.
- **What stays on your computer:** the address, user name and key id of your hosting panel; a restricted DirectAdmin login key and generated database passwords (in your operating system's protected storage); and the database exports you ask for. Your hosting password is used once, to create the key, and is then forgotten. All of this stays until you delete it: `disconnect`, or remove the key in DirectAdmin under Login Keys. The key expires (30 days by default; you can choose 90 days, a year, or never) and can be revoked at any time.
- **Where data goes:** to your own hosting panel (the files, databases, settings and logs of your account, as far as you ask Claude to work on them). The requests to kapaweb.gr and firewall.kapaweb.gr listed above carry no personal data except the usual network data (your IP address, the time, the file requested and the User-Agent `kapaweb-connector/<version>`), which kapaweb's web server records in its normal access log. What the tools return (file listings, logs, command results) is given to Claude, the AI app you use, and is covered by that app's own terms and privacy policy.
- **Third parties:** we share nothing with anyone. No advertising, no sale of data.
- **Retention:** local data stays until you remove it (see above); kapaweb's web server logs follow kapaweb's normal log retention.
- **Children:** this is a business tool and is not intended for people under 18.
- **Contact:** <info@kapaweb.gr>.

## Notes for reviewers

The directory scan holds this plugin for review because its heuristics see "a credential" near "a remote host". What each finding points at (all checked in the source):

- `server/da.js`: `ssd5.kdns.gr` appears only in a code comment (the example shape of a panel address). The panel address the user typed is checked against kapaweb's own server list (`verifyPanelHost`) and the connection is pinned to the verified IP address before the login key is ever sent.
- `server/setup.js`: `${h}` is a JavaScript template literal in the Origin check of the local sign-in page (`http://127.0.0.1:<random port>`); it is not a host and no secret is sent to it.
- `server/tools.js`: `kapaweb.gr` is a comment and the public playbook URL. That request carries only the header `User-Agent: kapaweb-connector` (no key, no password).
- `server/clients.js`: this file builds help text for the user and mentions the path `~/.claude.json` inside that text. It reads no file and sends nothing.

The only credential the plugin handles is the restricted DirectAdmin login key of the user's own hosting account. It is created from a password typed once on the local sign-in page, kept in the operating system's protected storage, and sent only to that user's own verified kapaweb panel. The plugin does not read any other credential, environment token or file from the user's computer.

## License

MIT. See the `LICENSE` file.
