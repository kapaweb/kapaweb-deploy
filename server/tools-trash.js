// trash_list / trash_empty: look into, and empty, the trash of a hosting account (added 23/11/2026, owner's request).
//   DirectAdmin  GET /api/filemanager/trash                (list)       DELETE /api/filemanager-actions/trash   (empty; "Permanently delete all trashed files and directories")
//                both from the panel's own swagger.json (docs.directadmin.com/developer/api). Entries: { id, originalDir, trashed, file:{name, sizeBytes, unixMode, ...} }.
//   Plesk        the subscription's trash is the folder /.trash (what files_delete trash:true fills): emptied by deleting what is inside it for good.
//   Older DirectAdmin: no trash at all (a removal there is final), so there is nothing to look at or empty.
// Emptying is final: whatever the trash holds (including a backup that backup_delete or delete trash:true put there) can no longer be brought back.
// So it needs the user's clear yes (confirm:true), and it only ever touches the trash, never anything else.
import { normEntry } from './fm.js';
import { UserError } from './util.js';

const SHOWN = 100;
const mb = (n) => `${(n / 1048576).toFixed(n >= 10485760 ? 0 : 1)} MB`;

export function trashTools(h) {
  const { schema, S, B, READ, DESTRUCTIVE, optString } = h;
  const DOMAIN = S('Plesk accounts only: the subscription (domain name), when the login has more than one.');
  const domainOf = (args) => optString(args, 'domain', { max: 253 });

  // ---- DirectAdmin ----
  async function daItems(da) {
    const { body } = await da.get('/api/filemanager/trash');
    const rows = Array.isArray(body) ? body : [];
    return rows.map((e) => {
      const f = e.file ? normEntry(e.file) : {};
      return { id: String(e.id), name: f.name ?? '', type: f.type ?? 'file', size: Number(f.size) || 0, original_dir: e.originalDir ?? '', trashed: e.trashed ?? '' };
    });
  }

  // ---- Plesk ----
  async function pleskItems(files) {
    try {
      const { entries } = await files.list('/.trash');
      return entries.map((e) => ({ id: e.name, name: e.name, type: e.type, size: e.size || 0, trashed: e.modified ?? '' }));
    } catch (err) {
      if (err?.code === 'NOT_FOUND') return [];
      throw err;
    }
  }

  async function load(session, args) {
    if (session.panel === 'plesk') {
      const { pleskContext } = await import('./tools-plesk-db.js');
      const { files } = await pleskContext(session, domainOf(args));
      return { kind: 'plesk', files, items: await pleskItems(files) };
    }
    const da = await session.da();
    if (da.fileApi === 'legacy') return { kind: 'none', items: [] };
    return { kind: 'da', da, items: await daItems(da) };
  }

  const summary = (items, kind) => {
    const bytes = items.reduce((n, i) => n + i.size, 0);
    return {
      count: items.length,
      ...(kind === 'plesk' ? { note_size: 'Plesk does not show folder sizes, so the size of folders in the trash is not counted.' } : {}),
      size_bytes: bytes,
      size: mb(bytes),
    };
  };

  return [
    {
      name: 'trash_list',
      title: 'Look into the trash of the account',
      description: 'Shows what is in the trash of the hosting account (files and folders removed with trash:true, backups removed with backup_delete): how many items and how much space they take (DirectAdmin: File Manager trash; Plesk: /.trash, which counts against the disk quota). Use it before trash_empty so the user knows what would go. Works on Plesk and DirectAdmin accounts. An older DirectAdmin has no trash.',
      inputSchema: schema({ domain: DOMAIN }),
      annotations: READ,
      async handler(args, { session }) {
        const t = await load(session, args);
        if (t.kind === 'none') return { count: 0, note: 'This hosting panel (an older DirectAdmin) has no trash: a deletion there is final.' };
        const sorted = [...t.items].sort((a, b) => b.size - a.size);
        return { ...summary(t.items, t.kind), showing: Math.min(SHOWN, sorted.length), items: sorted.slice(0, SHOWN) };
      },
    },
    {
      name: 'trash_empty',
      title: 'Empty the trash of the account',
      description: 'Empties the trash of the hosting account FOR GOOD: everything in it (also a backup or a safety copy that went there) can then no longer be brought back. Only the trash is touched, nothing else. First call trash_list, tell the user how many items and how much space, get a clear yes, then call with confirm:true. Without confirm nothing is deleted and the call says what would go. Works on Plesk and DirectAdmin accounts.',
      inputSchema: schema({ confirm: B('Must be true, after the user agreed to delete what is in the trash for good.'), domain: DOMAIN }, ['confirm']),
      annotations: DESTRUCTIVE,
      async handler(args, { session }) {
        const t = await load(session, args);
        if (t.kind === 'none') return { emptied: 0, note: 'This hosting panel (an older DirectAdmin) has no trash: nothing to empty.' };
        if (t.items.length === 0) return { emptied: 0, note: 'The trash is already empty.' };
        const s = summary(t.items, t.kind);
        if (args.confirm !== true) {
          throw new UserError(`The trash holds ${s.count} item(s), ${s.size}. Emptying it deletes them for good, nothing can be brought back afterwards. Nothing was deleted. Tell the user, and only after a clear yes call trash_empty again with confirm:true.`, 'CONFIRM');
        }
        if (t.kind === 'da') {
          await t.da.request('DELETE', '/api/filemanager-actions/trash');
          const left = await daItems(t.da);
          if (left.length) throw new UserError(`DirectAdmin said the trash was emptied, but ${left.length} item(s) are still in it.`, 'TRASH_NOT_EMPTY');
        } else {
          await t.files.remove(t.items.map((i) => `/.trash/${i.name}`), { permanent: true });
          const left = await pleskItems(t.files);
          if (left.length) throw new UserError(`Plesk said the trash was emptied, but ${left.length} item(s) are still in it.`, 'TRASH_NOT_EMPTY');
        }
        return { emptied: s.count, freed: s.size, freed_bytes: s.size_bytes, note: 'The trash is empty. These items cannot be brought back.' };
      },
    },
  ];
}
