// Minimal ZIP writer and reader (no dependencies).
//
// Why our own writer: Windows PowerShell 5's Compress-Archive writes backslashes,
// which the DirectAdmin extractor turns into files literally named "dir\file.js".
// This writer only ever emits forward slashes, sets the UTF-8 flag, and can add
// explicit directory entries (empty folders such as Laravel's storage/ dirs).
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { open } from 'node:fs/promises';
import { UserError } from './util.js';

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function dosDateTime(d) {
  const year = Math.max(1980, d.getFullYear());
  const time = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
  const date = ((year - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  return { time: time & 0xffff, date: date & 0xffff };
}

export function assertZipName(name) {
  if (typeof name !== 'string' || name === '') throw new UserError('Empty file name in archive.');
  if (name.includes('\\')) throw new UserError(`Refusing to archive "${name}": file names may not contain backslashes.`);
  if (name.startsWith('/') || /(^|\/)\.\.(\/|$)/.test(name)) throw new UserError(`Refusing to archive unsafe path "${name}".`);
  if (/[\u0000-\u001f]/.test(name)) throw new UserError('Archive entry names may not contain control characters.');
}

const MAX_ENTRIES = 65000; // no zip64: split into several archives instead
const MAX_PART_BYTES = 0xf0000000;

export class ZipWriter {
  #fh = null;
  #offset = 0;
  #entries = [];
  #closed = false;

  constructor(path) {
    this.path = path;
  }

  async #ensureOpen() {
    if (!this.#fh) this.#fh = await open(this.path, 'w');
  }

  get entryCount() {
    return this.#entries.length;
  }

  get bytes() {
    return this.#offset;
  }

  async #write(buf) {
    await this.#fh.write(buf, 0, buf.length);
    this.#offset += buf.length;
  }

  /**
   * data: Buffer. options: { mtime: Date, mode: number, store: boolean }
   */
  async addFile(name, data, { mtime = new Date(), mode = 0o644, store = false } = {}) {
    assertZipName(name);
    if (this.#closed) throw new Error('zip already closed');
    if (this.#entries.length >= MAX_ENTRIES) throw new UserError('Too many files for one archive part.');
    await this.#ensureOpen();
    const nameBuf = Buffer.from(name, 'utf8');
    const crc = crc32(data);
    let method = 0;
    let body = data;
    if (!store && data.length > 64) {
      const deflated = deflateRawSync(data, { level: 6 });
      if (deflated.length < data.length) {
        method = 8;
        body = deflated;
      }
    }
    const { time, date } = dosDateTime(mtime);
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(0x0800, 6);
    header.writeUInt16LE(method, 8);
    header.writeUInt16LE(time, 10);
    header.writeUInt16LE(date, 12);
    header.writeUInt32LE(crc, 14);
    header.writeUInt32LE(body.length, 18);
    header.writeUInt32LE(data.length, 22);
    header.writeUInt16LE(nameBuf.length, 26);
    header.writeUInt16LE(0, 28);
    const offset = this.#offset;
    await this.#write(header);
    await this.#write(nameBuf);
    await this.#write(body);
    this.#entries.push({ nameBuf, crc, csize: body.length, usize: data.length, method, offset, time, date, ext: ((0o100000 | (mode & 0o7777)) << 16) >>> 0 });
  }

  async addDir(name, { mtime = new Date(), mode = 0o755 } = {}) {
    assertZipName(name);
    await this.#ensureOpen();
    const dirName = name.endsWith('/') ? name : name + '/';
    const nameBuf = Buffer.from(dirName, 'utf8');
    const { time, date } = dosDateTime(mtime);
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(0x0800, 6);
    header.writeUInt16LE(0, 8);
    header.writeUInt16LE(time, 10);
    header.writeUInt16LE(date, 12);
    header.writeUInt16LE(nameBuf.length, 26);
    const offset = this.#offset;
    await this.#write(header);
    await this.#write(nameBuf);
    this.#entries.push({ nameBuf, crc: 0, csize: 0, usize: 0, method: 0, offset, time, date, ext: (((0o040000 | (mode & 0o7777)) << 16) | 0x10) >>> 0 });
  }

  async close() {
    if (this.#closed) return { entries: this.#entries.length, bytes: this.#offset };
    await this.#ensureOpen();
    const cdStart = this.#offset;
    for (const e of this.#entries) {
      const h = Buffer.alloc(46);
      h.writeUInt32LE(0x02014b50, 0);
      h.writeUInt16LE((3 << 8) | 20, 4);
      h.writeUInt16LE(20, 6);
      h.writeUInt16LE(0x0800, 8);
      h.writeUInt16LE(e.method, 10);
      h.writeUInt16LE(e.time, 12);
      h.writeUInt16LE(e.date, 14);
      h.writeUInt32LE(e.crc, 16);
      h.writeUInt32LE(e.csize, 20);
      h.writeUInt32LE(e.usize, 24);
      h.writeUInt16LE(e.nameBuf.length, 28);
      h.writeUInt32LE(e.ext, 38);
      h.writeUInt32LE(e.offset, 42);
      await this.#write(h);
      await this.#write(e.nameBuf);
    }
    const cdSize = this.#offset - cdStart;
    if (this.#offset > MAX_PART_BYTES) throw new UserError('Archive part is too large.');
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(this.#entries.length, 8);
    eocd.writeUInt16LE(this.#entries.length, 10);
    eocd.writeUInt32LE(cdSize, 12);
    eocd.writeUInt32LE(cdStart, 16);
    await this.#write(eocd);
    await this.#fh.close();
    this.#closed = true;
    return { entries: this.#entries.length, bytes: this.#offset };
  }
}

/** Read the central directory of a zip held in a Buffer. */
export function readZip(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 65535); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('not a zip file (no end-of-central-directory record)');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  const entries = [];
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('corrupt central directory');
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const csize = buf.readUInt32LE(p + 20);
    const usize = buf.readUInt32LE(p + 24);
    const nlen = buf.readUInt16LE(p + 28);
    const xlen = buf.readUInt16LE(p + 30);
    const clen = buf.readUInt16LE(p + 32);
    const ext = buf.readUInt32LE(p + 38);
    const offset = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nlen);
    entries.push({ name, method, crc, csize, usize, ext, offset, isDir: name.endsWith('/') });
    p += 46 + nlen + xlen + clen;
  }
  return entries;
}

export function extractEntry(buf, entry) {
  const p = entry.offset;
  if (buf.readUInt32LE(p) !== 0x04034b50) throw new Error('corrupt local header');
  const nlen = buf.readUInt16LE(p + 26);
  const xlen = buf.readUInt16LE(p + 28);
  const start = p + 30 + nlen + xlen;
  const raw = buf.subarray(start, start + entry.csize);
  const data = entry.method === 8 ? inflateRawSync(raw) : Buffer.from(raw);
  if (crc32(data) !== entry.crc) throw new Error(`CRC mismatch for ${entry.name}`);
  return data;
}
