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

// Datacarrier health across every OP_RETURN output in the block.
// The coinbase witness-commitment OP_RETURN is protocol overhead, not
// user data, so it's counted separately and never flagged oversize.
function measureHealth(block, codec) {
  let outputs = 0, over80 = 0, over83 = 0, maxData = 0, maxSpk = 0, witnessCommitments = 0;
  const examples = [];
  block.transactions.forEach((tx, ti) => {
    tx.outputs.forEach((o, vout) => {
      const spk = o.scriptPubKey;
      if (!spk.startsWith('6a')) return;
      if (isWitnessCommitment(spk)) { witnessCommitments++; return; }
      outputs++;
      const spkBytes = spk.length / 2;
      const dataBytes = opReturnDataBytes(spk);
      maxSpk = Math.max(maxSpk, spkBytes);
      if (dataBytes != null) maxData = Math.max(maxData, dataBytes);
      const o80 = dataBytes != null && dataBytes > 80;
      const o83 = spkBytes > 83;
      if (o80) over80++;
      if (o83) over83++;
      if ((o80 || o83) && examples.length < 12) {
        examples.push({ txid: codec.txid(tx), vout, dataBytes, spkBytes, coinbase: ti === 0 });
      }
    });
  });
  examples.sort((a, b) => (b.dataBytes ?? b.spkBytes) - (a.dataBytes ?? a.spkBytes));
  return { outputs, over80, over83, maxData, maxSpk, witnessCommitments, examples };
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
