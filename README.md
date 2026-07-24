# block·health

A single-page, no-build site — a mempool.space-style block row that shows the newest
Bitcoin blocks as they arrive over **[NIP-333](https://nip-333.github.io/)** (Nostr kind
`33333`), validates them in the browser, and scores each block for **OP_RETURN datacarrier
health**.

Everything is static: open `index.html` from any host (GitHub Pages, a pod, `file://` via a
local server). No backend, no build step, no framework.

## What it does

1. **Fetches the live header stream** — pulls the newest kind-`33333` event (mainnet `d=btc`)
   from several Nostr relays, verifies the event's NIP-01 id hash and BIP-340 signature, and
   takes the newest valid one. The publisher key is a *filter, not an authority*.
2. **Verifies the 12 headers** — checks each header's proof-of-work and its linkage to the
   previous header. A lying relay or publisher is detected here, not trusted.
3. **Validates each full block (no prevouts)** — fetches the raw block from esplora
   (mempool.space, falling back to blockstream.info), decodes it with the
   [bitcoin-kernel](https://github.com/bitcoin-kernel) engine in a Web Worker, and runs the
   structure and block-context rulesets. Prevout resolution is deliberately skipped — this is
   a pruned window with an empty coin view — so value/fee rules honestly report "unresolved"
   while merkle root, sizes, weight, sigops and the witness commitment are fully checked.
4. **Scores datacarrier health** — for every `OP_RETURN` output it measures the pushed data
   size and flags outputs over the historical **80-byte data** / **83-byte scriptPubKey**
   standard. The coinbase witness-commitment `OP_RETURN` is counted separately as protocol
   overhead, never as user data. Click any block for the full breakdown.

## Layout

```
index.html            the whole app (styles + logic inline, ES module)
validator-worker.js   off-main-thread: fetch raw block, decode, validate, measure health
engine/               vendored bitcoin-kernel engine (codec + JSON-LD schemas)
```

The `engine/` directory is copied verbatim from
[bitcoin-kernel/browser-node](https://github.com/bitcoin-kernel) so the site is fully
self-contained on a static host.

## Trust model

Bitcoin headers are self-certifying (proof-of-work + linkage), so no relay, publisher, or
esplora host is trusted. Consumers re-check everything on receipt; redundancy is additive.
See the [NIP-333 spec](https://nip-333.github.io/) for the header-distribution details.

## Run locally

```
python3 -m http.server 8899   # then open http://localhost:8899/
```

A server (not `file://`) is needed because the page loads ES modules and a module worker.

## License

AGPL-3.0-or-later. Copyright © 2026 Melvin Carvalho. See [LICENSE](LICENSE).

Includes vendored code from [bitcoin-kernel](https://github.com/bitcoin-kernel/kernel), also AGPL-3.0.
