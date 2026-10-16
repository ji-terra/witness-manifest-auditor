import { MMR } from './mmr.mjs';
import { generateKeys, signObject } from './keys.mjs';
import { leafHash, hashObject } from './hash.mjs';

// Builds a witness manifest in the format the auditor consumes.
//
// recordSpecs: [{ client, payload, receipt = true, seal = true, delay = 0,
//                 source = 'holder' }]
//   receipt:false  — the keeper never issued an ingress receipt (door loss)
//   seal:false     — receipted at ingress but never sealed (seal loss)
//   delay:n        — attempted in its natural epoch, sealed n windows later
//   source         — custody label of the receipt copy in the evidence bundle
//
// Windows group sealed records by seal epoch; a record's position is its leaf
// index in seal order (position is structural, never keeper-assigned).
export function buildManifest({ recordSpecs, windowSize = 4, maxLatencyWindows = 2 }) {
  const keeper = generateKeys();
  const clientKeys = {};
  const clientPubs = {};
  for (const spec of recordSpecs) {
    if (!clientKeys[spec.client]) {
      clientKeys[spec.client] = generateKeys();
      clientPubs[spec.client] = clientKeys[spec.client].publicHex;
    }
  }

  // --- attempt log (client-signed, hash-chained) ---
  const counters = {};
  const attempts = [];
  let prev = 'GENESIS';
  recordSpecs.forEach((spec, i) => {
    const counter = (counters[spec.client] = (counters[spec.client] || 0) + 1);
    const epoch = Math.floor(i / windowSize) + 0; // natural epoch at attempt time
    const body = { client: spec.client, counter, payloadHash: leafHash(spec.payload), epoch, prev };
    const sig = signObject(clientKeys[spec.client].privateKey, body);
    const entry = { ...body, sig };
    attempts.push(entry);
    prev = hashObject(entry);
    spec._attemptIndex = i;
    spec._epoch = epoch;
  });

  // --- sealing order: by (natural epoch + delay, submission order) ---
  const sealed = recordSpecs
    .map((spec, i) => ({ spec, i }))
    .filter(({ spec }) => spec.seal !== false)
    .sort((a, b) => (a.spec._epoch + (a.spec.delay || 0)) - (b.spec._epoch + (b.spec.delay || 0)) || a.i - b.i);

  const mmr = new MMR();
  const records = [];
  const positionOf = new Map(); // spec index -> leaf position
  for (const { spec, i } of sealed) {
    const pos = mmr.append(leafHash(spec.payload));
    positionOf.set(i, pos);
    records.push({ payload: spec.payload, payloadHash: leafHash(spec.payload), client: spec.client });
  }

  // --- windows and signed heads ---
  const windows = [];
  let prevHeadHash = 'GENESIS';
  const byEpoch = new Map();
  sealed.forEach(({ spec, i }) => {
    const epoch = spec._epoch + (spec.delay || 0);
    if (!byEpoch.has(epoch)) byEpoch.set(epoch, []);
    byEpoch.get(epoch).push(i);
  });
  const epochs = [...byEpoch.keys()].sort((a, b) => a - b);
  const windowOfSpec = new Map();
  epochs.forEach((epoch, wIdx) => {
    const members = byEpoch.get(epoch).sort((a, b) => positionOf.get(a) - positionOf.get(b));
    const positions = members.map((i) => positionOf.get(i));
    const start = Math.min(...positions);
    const end = Math.max(...positions) + 1;
    // delta digest: an MMR over exactly this window's leaves, in position order
    const delta = new MMR();
    for (const i of members) delta.append(leafHash(recordSpecs[i].payload));
    const size = end;
    // head commits the MMR state at this window's end: rebuild peaks at `size`
    const atSize = new MMR();
    for (let k = 0; k < size; k++) atSize.append(records[k].payloadHash);
    const head = {
      windowIndex: wIdx,
      epoch,
      size,
      count: size,
      root: atSize.root(),
      peaks: atSize.peakSet(),
      deltaDigest: delta.root(),
      positionRange: [start, end],
      prevHeadHash,
    };
    const headSig = signObject(keeper.privateKey, head);
    windows.push({ index: wIdx, start, end, head, headSig });
    members.forEach((i) => windowOfSpec.set(i, wIdx));
    prevHeadHash = hashObject({ head, headSig });
  });

  // --- receipts (keeper-signed at ingress) ---
  const receipts = [];
  recordSpecs.forEach((spec, i) => {
    if (spec.receipt === false) return;
    const position = positionOf.has(i) ? positionOf.get(i) : i; // unsealed: ingress position
    const body = { payloadHash: leafHash(spec.payload), position };
    receipts.push({ ...body, sig: signObject(keeper.privateKey, body), source: spec.source || 'holder' });
  });

  const manifest = {
    format: 'witness-manifest/0.1',
    keeperPublicKey: keeper.publicHex,
    clients: clientPubs,
    maxLatencyWindows,
    attempts,
    records,
    receipts,
    windows,
  };
  // Non-serialized test handles: latency expectations per payload.
  const latency = {};
  recordSpecs.forEach((spec, i) => {
    if (spec.seal !== false && windowOfSpec.has(i)) {
      latency[leafHash(spec.payload)] = { attemptEpoch: spec._epoch, sealWindow: windowOfSpec.get(i) };
    }
  });
  return { manifest, keeper, clientKeys, latency };
}
