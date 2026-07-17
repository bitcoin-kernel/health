// Local block cache backed by the Origin Private File System (OPFS).
//
// SCHEMA
// ------
//   <dir>/<height>_<hash>.blk   — the raw block bytes, exactly as fetched/validated.
//
// Design choices, and why:
//   • Content-addressed. The file name embeds the block hash, which is
//     dsha256 of the 80 header bytes — so a cached block is self-verifying and
//     a wrong/corrupt file is detectable, not trusted. The height prefix is a
//     convenience so the directory listing yields {height, hash, size} with no
//     decode, enabling instant cache stats and range queries.
//   • Contention-safe with the worker pool. Each block is its own file, keyed by
//     content, so N workers writing different blocks never collide, and writing
//     the same block twice is idempotent. There is NO shared manifest to race on.
//   • Cross-context authoritative. has()/get()/put() resolve a file name directly
//     (the caller always knows the height), so a block cached by one worker is
//     immediately visible to another and to the main thread — no in-memory index
//     to keep in sync. list()/stats() re-read the directory, so they never go stale.
//   • Stateless & dependency-free. This module only moves bytes; it never decodes
//     a block. The worker owns read-through/write-through; the main thread reads
//     stats for the Settings page. Both just instantiate a BlockStore.
//
// Deliberately NOT stored yet: per-block tx count / datacarrier classification
// (would need a sidecar or re-decode) and undo/UTXO data. Those belong to later
// steps (persistent stats, full validation); the schema leaves room by keeping
// each block a self-contained content-addressed file.

export const opfsAvailable = () =>
  typeof navigator !== 'undefined' && navigator.storage
  && typeof navigator.storage.getDirectory === 'function'
  && typeof FileSystemFileHandle !== 'undefined'
  && 'createWritable' in FileSystemFileHandle.prototype;

const padHeight = (h) => String(h).padStart(9, '0'); // tidy, lexicographically ordered

export class BlockStore {
  constructor(dir = 'blocks') { this.dir = dir; }

  async #dirHandle(create = false) {
    const root = await navigator.storage.getDirectory();
    return root.getDirectoryHandle(this.dir, { create });
  }

  #name(height, hash) { return `${padHeight(height)}_${hash}.blk`; }

  // ---- hot path (worker): resolve by (height, hash), no listing ----
  async has(height, hash) {
    try { const d = await this.#dirHandle(); await d.getFileHandle(this.#name(height, hash)); return true; }
    catch { return false; }
  }

  async get(height, hash) {
    try {
      const d = await this.#dirHandle();
      const fh = await d.getFileHandle(this.#name(height, hash));
      return new Uint8Array(await (await fh.getFile()).arrayBuffer());
    } catch { return null; }
  }

  async put(height, hash, bytes) {
    const d = await this.#dirHandle(true);
    const fh = await d.getFileHandle(this.#name(height, hash), { create: true });
    const w = await fh.createWritable();
    await w.write(bytes);
    await w.close();
  }

  async delete(height, hash) {
    try { const d = await this.#dirHandle(); await d.removeEntry(this.#name(height, hash)); } catch { /* absent */ }
  }

  // ---- listing based (main thread: stats, and by-hash lookup for peering) ----
  async list() {
    const out = [];
    let d; try { d = await this.#dirHandle(); } catch { return out; }
    for await (const [name, handle] of d.entries()) {
      if (handle.kind !== 'file' || !name.endsWith('.blk')) continue;
      const us = name.indexOf('_');
      if (us < 0) continue;
      const height = parseInt(name.slice(0, us), 10);
      const hash = name.slice(us + 1, -4);
      let size = 0; try { size = (await handle.getFile()).size; } catch { /* mid-write */ }
      out.push({ height, hash, size });
    }
    out.sort((a, b) => a.height - b.height);
    return out;
  }

  async stats() {
    const l = await this.list();
    return {
      count: l.length,
      bytes: l.reduce((s, b) => s + b.size, 0),
      minHeight: l.length ? l[0].height : null,
      maxHeight: l.length ? l[l.length - 1].height : null,
    };
  }

  async findByHash(hash) { return (await this.list()).find((b) => b.hash === hash) || null; }

  // Rolling-window eviction (the pruned-node model): delete oldest-height
  // blocks until the store fits maxBytes. Safe under concurrency — deleting a
  // file another context is mid-reading just yields that reader a cache miss,
  // which every caller already handles by refetching.
  async prune(maxBytes) {
    const l = await this.list(); // ascending by height
    const total = l.reduce((s, b) => s + b.size, 0);
    let deleted = 0, freed = 0;
    for (const b of l) {
      if (total - freed <= maxBytes) break;
      await this.delete(b.height, b.hash);
      deleted++; freed += b.size;
    }
    return { deleted, freed };
  }

  async clear() {
    try { const root = await navigator.storage.getDirectory(); await root.removeEntry(this.dir, { recursive: true }); }
    catch { /* nothing to clear */ }
  }
}
