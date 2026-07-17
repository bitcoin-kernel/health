// Persistent, engine-validated header chain — the immortal half of the
// pruned-node model (80 bytes/block ≈ 4 MB/year; blocks roll, headers don't).
//
// HeaderChain holds ONE contiguous run of validated headers [start..tip],
// anchored wherever the first window landed (a later genesis backfill can
// extend downward by rebuilding the file — `base` in the meta reserves that).
// Every extension runs the full HeaderEngine ruleset (PoW, linkage, difficulty
// retarget, MTP, future-time, version), so headers taken from a peer, a nostr
// event, or an explorer all clear the same bar — the source is irrelevant,
// which is what makes headers the perfect thing for browsers to share.
//
// Reorgs: a batch that diverges from the stored chain replaces the stored tail
// only if its cumulative work exceeds the tail it displaces.
//
// Concurrency: only the Blocks page writes; Settings reads meta. Two Blocks
// tabs race last-write-wins on meta.json — worst case the loser's next extend
// re-syncs or re-anchors, both safe (everything is re-validated on read paths).

import { bytesToHex, hexToBytes } from './engine/codec/hash.js';

const H = 80; // header size in bytes

export class OpfsHeaderBackend {
  constructor(dir = 'headers') { this.dir = dir; }
  async #dirHandle(create = false) {
    const root = await navigator.storage.getDirectory();
    return root.getDirectoryHandle(this.dir, { create });
  }
  async readMeta() {
    try {
      const d = await this.#dirHandle();
      const fh = await d.getFileHandle('meta.json');
      return JSON.parse(await (await fh.getFile()).text());
    } catch { return null; }
  }
  async writeMeta(meta) {
    const d = await this.#dirHandle(true);
    const fh = await d.getFileHandle('meta.json', { create: true });
    const w = await fh.createWritable();
    await w.write(JSON.stringify(meta));
    await w.close();
  }
  async read(offset, len) {
    try {
      const d = await this.#dirHandle();
      const fh = await d.getFileHandle('chain.bin');
      const file = await fh.getFile();
      if (offset + len > file.size) return null;
      return new Uint8Array(await file.slice(offset, offset + len).arrayBuffer());
    } catch { return null; }
  }
  async write(offset, bytes) {
    const d = await this.#dirHandle(true);
    const fh = await d.getFileHandle('chain.bin', { create: true });
    const w = await fh.createWritable({ keepExistingData: true });
    await w.write({ type: 'write', position: offset, data: bytes });
    await w.close();
  }
  async clear() {
    try {
      const root = await navigator.storage.getDirectory();
      await root.removeEntry(this.dir, { recursive: true });
    } catch { /* nothing to clear */ }
  }
}

// In-memory backend with the same contract — tests, and a graceful fallback
// when OPFS is unavailable (chain works for the session, just doesn't persist).
export class MemoryHeaderBackend {
  constructor() { this.meta = null; this.buf = new Uint8Array(0); }
  async readMeta() { return this.meta; }
  async writeMeta(m) { this.meta = m; }
  async read(offset, len) {
    if (offset + len > this.buf.length) return null;
    return this.buf.slice(offset, offset + len);
  }
  async write(offset, bytes) {
    if (offset + bytes.length > this.buf.length) {
      const next = new Uint8Array(offset + bytes.length);
      next.set(this.buf);
      this.buf = next;
    }
    this.buf.set(bytes, offset);
  }
  async clear() { this.meta = null; this.buf = new Uint8Array(0); }
}

export class HeaderChain {
  constructor({ codec, engine, backend }) {
    this.codec = codec;
    this.engine = engine;
    this.backend = backend;
    this.meta = null; // { base, start, count, tipHash }
  }

  async init() { this.meta = await this.backend.readMeta(); return this; }

  get startHeight() { return this.meta ? this.meta.start : null; }
  get tipHeight() { return this.meta ? this.meta.start + this.meta.count - 1 : null; }
  get tipHash() { return this.meta ? this.meta.tipHash : null; }

  stats() {
    return this.meta
      ? { start: this.meta.start, tip: this.tipHeight, tipHash: this.meta.tipHash, count: this.meta.count, bytes: this.meta.count * H }
      : null;
  }

  async reset() { await this.backend.clear(); this.meta = null; }

  #offset(height) { return (height - this.meta.base) * H; }

  // Raw 80-byte records for heights [from, from+count-1], clamped to the chain.
  async getRangeHex(from, count) {
    if (!this.meta || count < 1) return null;
    const start = Math.max(from, this.meta.start);
    const end = Math.min(start + count - 1, this.tipHeight);
    if (start > end) return null;
    const raw = await this.backend.read(this.#offset(start), (end - start + 1) * H);
    if (!raw) return null;
    return { start, count: end - start + 1, hex: bytesToHex(raw) };
  }

  async #decodedRange(from, count) {
    const r = await this.getRangeHex(from, count);
    if (!r) return [];
    const out = [];
    for (let i = 0; i < r.count; i++) out.push(this.codec.decode('BlockHeader', r.hex.slice(i * H * 2, (i + 1) * H * 2)));
    return out;
  }

  async header(height) { return (await this.#decodedRange(height, 1))[0] ?? null; }

  // Try to connect consecutive headers (as 160-char hex strings) starting at
  // startHeight. Returns one of:
  //   { ok:true, appended, reorged, tipHeight, tipHash }  chain advanced (or no-op)
  //   { ok:false, gap:{from,to} }                          batch starts past our tip
  //   { ok:false, reason, failures? }                      invalid / unlinkable batch
  async extend(hexHeaders, startHeight, { now = null } = {}) {
    if (!Array.isArray(hexHeaders) || !hexHeaders.length) return { ok: true, appended: 0, reorged: 0, tipHeight: this.tipHeight, tipHash: this.tipHash };
    if (!Number.isInteger(startHeight) || startHeight < 0) return { ok: false, reason: 'bad start height' };
    let headers;
    try {
      headers = hexHeaders.map((hx) => {
        if (typeof hx !== 'string' || hx.length !== H * 2 || !/^[0-9a-f]+$/.test(hx)) throw new Error('malformed header hex');
        return this.codec.decode('BlockHeader', hx);
      });
    } catch (e) { return { ok: false, reason: String(e.message || e) }; }

    // clamp anything below our anchor — we can't verify a competing anchor
    if (this.meta && startHeight < this.meta.start) {
      const cut = this.meta.start - startHeight;
      headers = headers.slice(cut); hexHeaders = hexHeaders.slice(cut); startHeight = this.meta.start;
      if (!headers.length) return { ok: true, appended: 0, reorged: 0, tipHeight: this.tipHeight, tipHash: this.tipHash };
    }
    const end = startHeight + headers.length - 1;

    if (!this.meta) return this.#commit(headers, hexHeaders, startHeight, [], now, 0);

    const tip = this.tipHeight;
    if (startHeight > tip + 1) return { ok: false, gap: { from: tip + 1, to: startHeight - 1 } };

    // find where (if anywhere) the batch diverges from what we hold
    const overlapEnd = Math.min(end, tip);
    let divergeAt = null;
    if (startHeight <= overlapEnd) {
      const ours = await this.#decodedRange(startHeight, overlapEnd - startHeight + 1);
      if (ours.length !== overlapEnd - startHeight + 1) return { ok: false, reason: 'store read failed' };
      for (let i = 0; i < ours.length; i++) {
        if (this.codec.blockHash(ours[i]) !== this.codec.blockHash(headers[i])) { divergeAt = startHeight + i; break; }
      }
    }
    if (divergeAt === null && end <= tip) return { ok: true, appended: 0, reorged: 0, tipHeight: tip, tipHash: this.meta.tipHash };
    if (divergeAt === this.meta.start) return { ok: true, appended: 0, reorged: 0, tipHeight: tip, tipHash: this.meta.tipHash }; // competing anchor — unverifiable

    const effStart = divergeAt ?? (tip + 1);
    const k = effStart - startHeight;
    const newPart = headers.slice(k), newHex = hexHeaders.slice(k);

    // a diverging tail must out-work the tail it displaces
    let reorged = 0;
    if (divergeAt !== null) {
      const oldTail = await this.#decodedRange(divergeAt, tip - divergeAt + 1);
      const oldWork = oldTail.reduce((s, h) => s + this.engine.work(h), 0n);
      const newWork = newPart.reduce((s, h) => s + this.engine.work(h), 0n);
      if (newWork <= oldWork) return { ok: true, appended: 0, reorged: 0, tipHeight: tip, tipHash: this.meta.tipHash };
      reorged = tip - divergeAt + 1;
    }
    return this.#commit(newPart, newHex, effStart, await this.#context(effStart, end), now, reorged);
  }

  // prevContext (≤11 headers before effStart) + epoch-first headers for any
  // retarget boundary in [effStart, end] — what validateChain needs from us.
  async #context(effStart, end) {
    const interval = this.engine.interval;
    const prevFrom = Math.max(this.meta.start, effStart - 11);
    const prevContext = effStart > this.meta.start ? await this.#decodedRange(prevFrom, effStart - prevFrom) : [];
    const epochFirsts = {};
    for (let b = Math.ceil(effStart / interval) * interval; b <= end; b += interval) {
      const eh = b - interval;
      if (eh >= this.meta.start && eh < effStart) { const h = await this.header(eh); if (h) epochFirsts[eh] = h; }
    }
    return [prevContext, epochFirsts];
  }

  async #commit(headers, hexHeaders, startHeight, context, now, reorged) {
    const [prevContext, epochFirsts] = context.length ? context : [[], {}];
    const verdicts = this.engine.validateChain(headers, { startHeight, prevContext, epochFirsts, now });
    const bad = verdicts.filter((v) => !v.ok);
    if (bad.length) {
      return { ok: false, reason: 'invalid header chain', failures: bad.map((v) => ({ height: v.height, rules: v.results.filter((r) => r.ok === false).map((r) => r.rule) })) };
    }
    const bytes = new Uint8Array(headers.length * H);
    hexHeaders.forEach((hx, i) => bytes.set(hexToBytes(hx), i * H));
    const base = this.meta ? this.meta.base : startHeight;
    const start = this.meta ? this.meta.start : startHeight;
    await this.backend.write((startHeight - base) * H, bytes);
    this.meta = { base, start, count: startHeight + headers.length - start, tipHash: verdicts[verdicts.length - 1].hash };
    await this.backend.writeMeta(this.meta);
    return { ok: true, appended: headers.length, reorged, tipHeight: this.tipHeight, tipHash: this.meta.tipHash };
  }
}
