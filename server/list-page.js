// Paging, filtering and summarising a folder listing, shared by list_files (DirectAdmin) and files_list (Plesk).
// A folder can hold tens of thousands of files (an image library): the tools must never silently show only the first part of it.
// So a listing says how many entries match, where the next page starts (`next_offset`), and `summary` answers "what is in here?"
// without listing anything.
import { UserError } from './util.js';

export const LIST_MAX = 5000;
export const LIST_TYPES = ['any', 'file', 'dir', 'link'];
export const LIST_SORTS = ['name', 'size_desc', 'modified_desc', 'modified_asc'];

const extOf = (name) => {
  const i = name.lastIndexOf('.');
  return i > 0 && i < name.length - 1 ? name.slice(i + 1).toLowerCase() : '(none)';
};
const stamp = (e) => {
  const t = typeof e.modified === 'number' ? e.modified * (e.modified < 1e12 ? 1000 : 1) : Date.parse(e.modified);
  return Number.isFinite(t) ? t : 0;
};

/**
 * @param {Array<{name:string,type:string,size?:number,modified?:any}>} entries every entry of the folder
 * @param {{offset?:number, limit?:number, nameContains?:string, type?:string, sort?:string, summary?:boolean}} o
 */
export function pageList(entries, { offset = 0, limit = 300, nameContains, type = 'any', sort = 'name', summary = false } = {}) {
  if (!LIST_TYPES.includes(type)) throw new UserError(`"type" is one of: ${LIST_TYPES.join(', ')}.`);
  if (!LIST_SORTS.includes(sort)) throw new UserError(`"sort" is one of: ${LIST_SORTS.join(', ')}.`);
  let rows = entries;
  if (type !== 'any') rows = rows.filter((e) => e.type === type);
  if (nameContains) {
    const q = nameContains.toLowerCase();
    rows = rows.filter((e) => e.name.toLowerCase().includes(q));
  }
  const matched = rows.length;

  if (summary) {
    const files = rows.filter((e) => e.type === 'file');
    const byExt = new Map();
    for (const f of files) {
      const k = extOf(f.name);
      const cur = byExt.get(k) || { ext: k, files: 0, bytes: 0 };
      cur.files += 1;
      cur.bytes += Number(f.size) || 0;
      byExt.set(k, cur);
    }
    const bySize = [...files].sort((a, b) => (Number(b.size) || 0) - (Number(a.size) || 0));
    const byTime = [...rows].filter((e) => stamp(e) > 0).sort((a, b) => stamp(b) - stamp(a));
    return {
      matched,
      files: files.length,
      folders: rows.filter((e) => e.type === 'dir').length,
      links: rows.filter((e) => e.type === 'link').length,
      total_bytes: files.reduce((n, f) => n + (Number(f.size) || 0), 0),
      by_extension: [...byExt.values()].sort((a, b) => b.bytes - a.bytes || b.files - a.files).slice(0, 15),
      largest: bySize.slice(0, 10).map((f) => ({ name: f.name, size: f.size })),
      newest: byTime.slice(0, 5).map((e) => ({ name: e.name, modified: e.modified })),
      oldest: byTime.slice(-5).reverse().map((e) => ({ name: e.name, modified: e.modified })),
    };
  }

  const cmp = {
    name: (a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0),
    size_desc: (a, b) => (Number(b.size) || 0) - (Number(a.size) || 0) || (a.name < b.name ? -1 : 1),
    modified_desc: (a, b) => stamp(b) - stamp(a) || (a.name < b.name ? -1 : 1),
    modified_asc: (a, b) => stamp(a) - stamp(b) || (a.name < b.name ? -1 : 1),
  }[sort];
  const sorted = [...rows].sort(cmp);
  const page = sorted.slice(offset, offset + limit);
  const next = offset + limit < matched ? offset + limit : null;
  return {
    matched,
    offset,
    shown: page.length,
    next_offset: next,
    ...(next !== null ? { more: `${matched - next} more entries: call again with offset=${next} (same filters and sort), or narrow with name_contains / type, or use summary=true.` } : {}),
    entries: page,
  };
}
