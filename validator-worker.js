// Off-main-thread block validator. Fetches a raw block by hash, decodes it
// with the bitcoin-kernel engine, runs the structure + block-context rules
// (no prevouts — a pruned window with an empty coin view), and measures
// OP_RETURN datacarrier health. Posts back a compact summary; the raw block
// (up to ~2 MB, ~5000 txs) never crosses back to the UI thread.
import { Codec } from './engine/codec/codec.js';
import { BlockEngine } from './engine/codec/blocks.js';

let codec = null, be = null;

const jl = async (n) => (await fetch(`./engine/schema/${n}.jsonld`)).json();

async function init(network) {
  codec = new Codec(await jl('core'), await jl('proof'), await jl('p2p'));
  be = BlockEngine.fromSchemas(codec, await jl('chain'), await jl('validate'), await jl('script'), network);
}

// Sum the payload bytes pushed after an OP_RETURN, so we can compare against
// the historical 80-byte datacarrier *data* limit (distinct from the 83-byte
// scriptPubKey limit). Returns null if the script isn't a clean OP_RETURN.
function opReturnDataBytes(spkHex) {
  const b = [];
  for (let i = 0; i < spkHex.length; i += 2) b.push(parseInt(spkHex.slice(i, i + 2), 16));
  if (b[0] !== 0x6a) return null;
  let i = 1, data = 0;
  while (i < b.length) {
    const op = b[i++];
    let len;
    if (op >= 0x01 && op <= 0x4b) len = op;
    else if (op === 0x4c) { len = b[i]; i += 1; }
    else if (op === 0x4d) { len = b[i] | (b[i + 1] << 8); i += 2; }
    else if (op === 0x4e) { len = b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24); i += 4; }
    else continue; // OP_N / other opcodes carry no push payload
    data += len; i += len;
  }
  return data;
}

const isWitnessCommitment = (spk) => spk.startsWith('6a24aa21a9ed');

// ---- metaprotocol detection, straight from the scriptPubKey bytes ----
// Runes:   OP_RETURN OP_13 (6a 5d) is the runestone magic.
// Alkanes: a runestone carrying a "protostone" — the protorunes standard packs
//          a metaprotocol message into repeated Protocol-tag (16383) fields,
//          each a u128 holding 15 payload bytes. Concatenating those 15-byte
//          little-endian chunks and LEB128-decoding the first integer yields the
//          protocol id; id 1 is Alkanes. All invisible to Runes indexers (odd tag).
function hexBytes(h) { const a = []; for (let i = 0; i < h.length; i += 2) a.push(parseInt(h.slice(i, i + 2), 16)); return a; }

function collectPushData(bytes, start) {
  let i = start; const out = [];
  while (i < bytes.length) {
    const op = bytes[i++]; let len;
    if (op >= 0x01 && op <= 0x4b) len = op;
    else if (op === 0x4c) { len = bytes[i++]; }
    else if (op === 0x4d) { len = bytes[i] | (bytes[i + 1] << 8); i += 2; }
    else if (op === 0x4e) { len = bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24); i += 4; }
    else continue; // OP_N / other: carries no push payload
    for (let k = 0; k < len && i < bytes.length; k++) out.push(bytes[i++]);
  }
  return out;
}

function leb128List(bytes) {
  const ints = []; let i = 0;
  while (i < bytes.length) { let v = 0n, s = 0n; while (i < bytes.length) { const x = bytes[i++]; v |= BigInt(x & 0x7f) << s; if ((x & 0x80) === 0) break; s += 7n; } ints.push(v); }
  return ints;
}

function firstLeb(bytes) { let v = 0n, s = 0n, i = 0; while (i < bytes.length) { const x = bytes[i++]; v |= BigInt(x & 0x7f) << s; if ((x & 0x80) === 0) break; s += 7n; } return v; }

// Best-effort: a plain-text OP_RETURN that routes a custodial/bridge deposit —
// an EVM-style 0x address and/or a depositor/recipient/refund field, e.g.
//   0x<hex>|depositor=bc1q…|
// This is a HEURISTIC, not a protocol magic byte, so it is kept conservative:
// the payload must be almost entirely printable ASCII and carry a strong signal.
function looksLikeBridge(spk) {
  const data = collectPushData(hexBytes(spk), 1); // pushes after OP_RETURN
  if (data.length < 20) return false;
  const printable = data.filter((x) => x >= 0x20 && x <= 0x7e).length / data.length;
  if (printable < 0.9) return false;
  let s = ''; for (let i = 0; i < data.length && i < 1024; i++) s += String.fromCharCode(data[i]);
  const evm = /0x[0-9a-fA-F]{40}/.test(s); // 20-byte (or longer) EVM-style destination
  const kw = /(depositor|recipient|refund|destination|bridge|deposit|dest)\s*[=:]/i.test(s);
  return evm || kw;
}

// -> 'opnet' | 'alkanes' | 'protostone' | 'runes' | 'bridge' | 'data'  (mutually exclusive)
function classifyOpReturn(spk) {
  if (spk.startsWith('6a58')) return 'opnet';       // OP_RETURN OP_8: OP_NET epoch challenge submission
  if (spk.startsWith('6a5d')) {                     // runestone: Runes / Alkanes / other protostone
    const ints = leb128List(collectPushData(hexBytes(spk), 2)); // payload after 6a 5d
    const chunks = [];
    for (let k = 0; k + 1 < ints.length; k += 2) {
      const tag = ints[k];
      if (tag === 0n) break;                 // Body tag: edicts follow, stop scanning fields
      if (tag === 16383n) chunks.push(ints[k + 1]); // protorunes Protocol field
    }
    if (!chunks.length) return 'runes';      // plain rune op (etch / mint / transfer)
    const pb = [];
    for (const v of chunks) { let x = v; for (let j = 0; j < 15; j++) { pb.push(Number(x & 0xffn)); x >>= 8n; } }
    return firstLeb(pb) === 1n ? 'alkanes' : 'protostone';
  }
  const data = collectPushData(hexBytes(spk), 1);
  // ProofOfWork.Me: OP_RETURN payload begins with one of its ASCII protocol ids
  // (pwt1: credits, pwm1: mail/bonds, pwid1: identities, pwr1: registry).
  let head = ''; for (let i = 0; i < data.length && i < 6; i++) head += String.fromCharCode(data[i]);
  if (/^(pwt1:|pwm1:|pwid1:|pwr1:)/.test(head)) return 'powme';
  if (looksLikeBridge(spk)) return 'bridge';        // ASCII deposit memo
  if (data.length >= 8 && data.every((x) => x === 0)) return 'padding'; // all-zero reservation output
  return 'data';
}

// Datacarrier health across every OP_RETURN output in the block.
// The coinbase witness-commitment OP_RETURN is protocol overhead, not
// user data, so it's counted separately and never flagged oversize.
function measureHealth(block, codec) {
  let outputs = 0, over80 = 0, over83 = 0, maxData = 0, maxSpk = 0, witnessCommitments = 0;
  let alkanes = 0, runes = 0, protostone = 0, opnet = 0, bridge = 0, padding = 0, paddingBytes = 0, powme = 0; // disjoint metaprotocol tallies
  const examples = [];
  block.transactions.forEach((tx, ti) => {
    tx.outputs.forEach((o, vout) => {
      const spk = o.scriptPubKey;
      if (!spk.startsWith('6a')) return;
      if (isWitnessCommitment(spk)) { witnessCommitments++; return; }
      outputs++;
      const proto = classifyOpReturn(spk);
      if (proto === 'opnet') opnet++;
      else if (proto === 'alkanes') alkanes++;
      else if (proto === 'runes') runes++;
      else if (proto === 'protostone') protostone++;
      else if (proto === 'powme') powme++;
      else if (proto === 'bridge') bridge++;
      else if (proto === 'padding') padding++;
      const spkBytes = spk.length / 2;
      if (proto === 'padding') paddingBytes += spkBytes;
      const dataBytes = opReturnDataBytes(spk);
      maxSpk = Math.max(maxSpk, spkBytes);
      if (dataBytes != null) maxData = Math.max(maxData, dataBytes);
      const o80 = dataBytes != null && dataBytes > 80;
      const o83 = spkBytes > 83;
      if (o80) over80++;
      if (o83) over83++;
      if ((o80 || o83) && examples.length < 12) {
        examples.push({ txid: codec.txid(tx), vout, dataBytes, spkBytes, coinbase: ti === 0, proto });
      }
    });
  });
  examples.sort((a, b) => (b.dataBytes ?? b.spkBytes) - (a.dataBytes ?? a.spkBytes));
  return { outputs, over80, over83, maxData, maxSpk, witnessCommitments, alkanes, runes, protostone, opnet, bridge, padding, paddingBytes, powme, examples };
}

const failures = (verdict) =>
  verdict.results.filter((r) => r.ok === false).map((r) => r.label || r.rule);

// Printable-ASCII of the coinbase scriptSig — where pools stamp their mark.
// Non-printable bytes (the BIP34 height push, extranonce, merged-mining tags)
// become spaces so the human-readable marker stands out.
function coinbaseTag(scriptSigHex) {
  let s = '';
  for (let i = 0; i < scriptSigHex.length; i += 2) {
    const b = parseInt(scriptSigHex.slice(i, i + 2), 16);
    s += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : ' ';
  }
  return s.replace(/\s+/g, ' ').trim();
}

// Same signal mempool uses: match the coinbase tag against known pool markers.
// Ordered — first substring hit wins. This is derived from the block itself,
// so no external attribution service is trusted.
const POOLS = [
  ['Foundry USA', 'Foundry USA'], ['AntPool', 'AntPool'], ['SpiderPool', 'SpiderPool'],
  ['ViaBTC', 'ViaBTC'], ['F2Pool', 'F2Pool'], ['f2pool', 'F2Pool'],
  ['Binance', 'Binance Pool'], ['SlushPool', 'Braiins Pool'], ['Braiins', 'Braiins Pool'],
  ['slush', 'Braiins Pool'], ['MARA', 'MARA Pool'], ['Luxor', 'Luxor'],
  ['SBICrypto', 'SBI Crypto'], ['SBI Crypto', 'SBI Crypto'], ['SecPool', 'SECPOOL'],
  ['SECPOOL', 'SECPOOL'], ['Poolin', 'Poolin'], ['poolin', 'Poolin'],
  ['OCEAN', 'OCEAN'], ['Ultimus', 'ULTIMUSPOOL'], ['ULTIMUS', 'ULTIMUSPOOL'],
  ['WhitePool', 'WhitePool'], ['Carbon', 'Carbon Negative'], ['BTC.com', 'BTC.com'],
  ['btccom', 'BTC.com'], ['EMCD', 'EMCD'], ['emcd', 'EMCD'], ['Rawpool', 'Rawpool'],
  ['NovaBlock', 'NovaBlock'], ['bitFuFu', 'Mining Squared'], ['Mining Squared', 'Mining Squared'],
  ['/solo', 'Solo CKPool'], ['ckpool', 'CKPool'], ['PEGA', 'Pega Pool'],
  ['public-pool', 'Public Pool'], ['1THash', '1THash'], ['Bitdeer', 'Bitdeer'],
  ['SigmaPool', 'SigmaPool'], ['Terra Pool', 'Terra Pool'],
];
function identifyPool(tag) {
  for (const [needle, name] of POOLS) if (tag.includes(needle)) return name;
  return null;
}

// Fetch with a hard timeout so a throttled/hung source aborts and fails over
// to the next one — a stuck fetch must never wedge a pool worker forever.
async function fetchWithTimeout(url, ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try { return await fetch(url, { signal: ctrl.signal }); }
  finally { clearTimeout(t); }
}

async function fetchRawHex(hash) {
  const sources = [
    `https://mempool.space/api/block/${hash}/raw`,
    `https://blockstream.info/api/block/${hash}/raw`,
  ];
  let lastErr;
  // two passes: give each source a turn, then retry the list once
  for (let attempt = 0; attempt < 2; attempt++) {
    for (const url of sources) {
      try {
        const r = await fetchWithTimeout(url, 15000);
        if (!r.ok) { lastErr = new Error(`${url} -> ${r.status}`); continue; }
        const buf = new Uint8Array(await r.arrayBuffer());
        let hex = '';
        for (let i = 0; i < buf.length; i++) hex += buf[i].toString(16).padStart(2, '0');
        return hex;
      } catch (e) { lastErr = e; }
    }
  }
  throw lastErr || new Error('no block source');
}

self.onmessage = async (ev) => {
  const msg = ev.data;
  try {
    if (msg.type === 'init') {
      await init(msg.network || 'btc:mainnet');
      self.postMessage({ type: 'ready' });
      return;
    }
    if (msg.type === 'validate') {
      const { hash, height } = msg;
      const hex = await fetchRawHex(hash);
      const block = codec.decode('Block', hex);
      const struct = be.validateBlockStructure(block);
      const ctx = be.validateBlockContext(block, { height });
      const powOk = codec.checkProofOfWork(block.header);
      const health = measureHealth(block, codec);
      const cb = block.transactions[0];
      const tag = coinbaseTag(cb.inputs[0].scriptSig);
      self.postMessage({
        type: 'result', hash, height,
        result: {
          txCount: block.transactions.length,
          sizeBytes: hex.length / 2,
          weight: be.blockWeight(block),
          powOk,
          structOk: struct.ok, structFailures: failures(struct),
          ctxOk: ctx.ok, ctxFailures: failures(ctx),
          coinbaseOutValue: cb.outputs.reduce((s, o) => s + o.value, 0),
          miner: { pool: identifyPool(tag), tag },
          health,
        },
      });
    }
  } catch (e) {
    self.postMessage({ type: 'error', hash: msg.hash, height: msg.height, error: String(e && e.message || e) });
  }
};
