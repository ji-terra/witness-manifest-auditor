import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildManifest } from '../src/manifest.mjs';
import { audit } from '../src/audit.mjs';
import { MMR, verifyInclusion, verifyConsistency, bagPeaks } from '../src/mmr.mjs';
import { leafHash, hashObject } from '../src/hash.mjs';
import { signObject } from '../src/keys.mjs';

const specs = (n, opts = {}) =>
  Array.from({ length: n }, (_, i) => ({ client: i % 2 ? 'beta' : 'alpha', payload: `record-${i}`, ...opts }));

const check = (report, id) => report.checks.find((c) => c.id === id);

// Rebuild a manifest's attempt log from bare bodies, re-chaining and
// re-signing every entry with the clients' real keys.
function rebuildAttempts(manifest, clientKeys, bodies) {
  let prev = 'GENESIS';
  manifest.attempts = bodies.map((b) => {
    const body = { ...b, prev };
    const entry = { ...body, sig: signObject(clientKeys[b.client].privateKey, body) };
    prev = hashObject(entry);
    return entry;
  });
  return manifest;
}

test('honest manifest passes every check (doc_page26 acceptance: enumeration matches count and root)', () => {
  const { manifest } = buildManifest({ recordSpecs: specs(10), windowSize: 4 });
  const report = audit(manifest);
  assert.equal(report.verdict, 'PASS', JSON.stringify(report.checks.filter((c) => c.status === 'FAIL')));
  assert.equal(check(report, 'enumeration-count-root').status, 'PASS');
  assert.equal(report.metrics.committedCount, 10);
});

test('omission: a record dropped from the enumeration breaks count and root, shortfall named', () => {
  const { manifest } = buildManifest({ recordSpecs: specs(10), windowSize: 4 });
  manifest.records.splice(3, 1); // keeper serves an enumeration with one record gone
  const report = audit(manifest);
  assert.equal(check(report, 'enumeration-count-root').status, 'FAIL');
  assert.match(check(report, 'enumeration-count-root').detail, /shortfall 1/);
});

test('falsified count: even a validly keeper-signed inflated count fails recomputation', () => {
  const { manifest, keeper } = buildManifest({ recordSpecs: specs(6), windowSize: 3 });
  const last = manifest.windows[manifest.windows.length - 1];
  last.head = { ...last.head, count: 99 };
  last.headSig = signObject(keeper.privateKey, last.head); // signature is genuine
  const report = audit(manifest);
  assert.equal(check(report, 'head-signatures').status, 'PASS', 'the forgery is signed — that is the point');
  assert.equal(check(report, 'enumeration-count-root').status, 'FAIL');
});

test('withhold-one-leaf: receipted but never sealed — seal loss names the record from the ingress side', () => {
  const s = specs(8);
  s[5] = { ...s[5], seal: false };
  const { manifest } = buildManifest({ recordSpecs: s, windowSize: 4 });
  const report = audit(manifest);
  assert.equal(check(report, 'seal-loss').status, 'FAIL');
  assert.equal(report.findings.sealLoss.length, 1);
  assert.equal(report.findings.sealLoss[0].payloadHash, leafHash('record-5'));
  assert.equal(check(report, 'door-loss').status, 'PASS');
});

test('door loss: an attempt the keeper never receipted is named', () => {
  const s = specs(6);
  s[2] = { ...s[2], receipt: false, seal: false };
  const { manifest } = buildManifest({ recordSpecs: s, windowSize: 3 });
  const report = audit(manifest);
  assert.equal(check(report, 'door-loss').status, 'FAIL');
  assert.deepEqual(report.findings.doorLoss.map((d) => d.payloadHash), [leafHash('record-2')]);
});

test('phantom door loss: a client double-signing one payload counts once (attempt identity = payload hash)', () => {
  const { manifest, clientKeys } = buildManifest({ recordSpecs: specs(4), windowSize: 2 });
  const prev = hashObject(manifest.attempts[manifest.attempts.length - 1]);
  const body = { client: 'alpha', counter: 3, payloadHash: leafHash('record-0'), epoch: 1, prev };
  manifest.attempts.push({ ...body, sig: signObject(clientKeys.alpha.privateKey, body) });
  const report = audit(manifest);
  assert.equal(report.metrics.distinctAttemptedPayloads, 4);
  assert.equal(check(report, 'door-loss').status, 'PASS', 'the duplicate attempt must not manufacture door loss');
});

test('client reordering: counters signed out of order are CLIENT-ANOMALY, blamed on the client', () => {
  const built = buildManifest({ recordSpecs: specs(4), windowSize: 2 });
  const bodies = [
    { client: 'alpha', counter: 2, payloadHash: leafHash('record-0'), epoch: 0 },
    { client: 'beta', counter: 1, payloadHash: leafHash('record-1'), epoch: 0 },
    { client: 'alpha', counter: 1, payloadHash: leafHash('record-2'), epoch: 0 },
    { client: 'beta', counter: 2, payloadHash: leafHash('record-3'), epoch: 0 },
  ];
  rebuildAttempts(built.manifest, built.clientKeys, bodies);
  const report = audit(built.manifest);
  assert.equal(check(report, 'attempt-chain').status, 'PASS', 'every signature is genuine — the client signed in this order');
  assert.equal(check(report, 'attempt-counters').status, 'FAIL');
  assert.match(check(report, 'attempt-counters').detail, /CLIENT-ANOMALY/);
  assert.equal(report.findings.clientAnomalies[0].client, 'alpha');
});

test('position rewrite: a holder-retained receipt catches a rewrite that keeper-served evidence cannot', () => {
  const honest = buildManifest({ recordSpecs: specs(8), windowSize: 4 });
  const holderReceipt = honest.manifest.receipts.find((r) => r.payloadHash === leafHash('record-3'));
  assert.equal(holderReceipt.position, 3);

  // attacker: records 3 and 7 swap positions; keeper reissues every receipt
  // and re-signs every head, so the rewritten history is internally consistent
  const swapped = specs(8);
  [swapped[3], swapped[7]] = [swapped[7], swapped[3]];
  const rewritten = buildManifest({ recordSpecs: swapped, windowSize: 4 });
  // the one artifact the keeper cannot reissue retroactively: the holder's copy
  rewritten.manifest.receipts.push({ ...holderReceipt, source: 'holder' });
  const report = audit(rewritten.manifest);
  assert.equal(check(report, 'enumeration-count-root').status, 'PASS', 'rewritten history still recomputes');
  assert.equal(check(report, 'position-binding').status, 'FAIL');
  assert.ok(report.findings.rangeViolations.some((v) => v.payloadHash === leafHash('record-3') && v.source === 'holder'));

  // control: the honest manifest labels its windows by evidence source
  const honestReport = audit(honest.manifest);
  assert.equal(check(honestReport, 'position-binding').status, 'PASS');
  assert.match(check(honestReport, 'position-binding').detail, /HOLDER-VERIFIED/);
});

test('peak partition: a proof padded with peaks from a larger tree is rejected before counting', () => {
  const small = new MMR(); const leaves = [];
  for (let i = 0; i < 8; i++) { const h = leafHash(`x-${i}`); leaves.push(h); small.append(h); }
  const big = new MMR();
  for (let i = 0; i < 16; i++) big.append(leafHash(`x-${i}`));
  const proof = small.proveInclusion(3);
  proof.peaks = [...proof.peaks, { height: 3, start: 8, hash: big.peakSet()[0].hash }]; // smuggled peak
  const res = verifyInclusion({ leaf: leaves[3], proof, root: small.root() });
  assert.equal(res.ok, false);
  assert.match(res.reason, /partition/);
});

test('consistency: consecutive heads verify; a wrong new root fails', () => {
  const mmr = new MMR();
  for (let i = 0; i < 5; i++) mmr.append(leafHash(`c-${i}`));
  const oldPeaks = mmr.peakSet(); const oldRoot = mmr.root();
  for (let i = 5; i < 12; i++) mmr.append(leafHash(`c-${i}`));
  const proof = mmr.proveConsistency(oldPeaks);
  const ok = verifyConsistency({ oldSize: 5, oldRoot, oldPeaks, newSize: 12, newRoot: mmr.root(), newPeaks: mmr.peakSet(), proof });
  assert.equal(ok.ok, true, ok.reason);
  const bad = verifyConsistency({ oldSize: 5, oldRoot, oldPeaks, newSize: 12, newRoot: bagPeaks(['ab'.repeat(32)]), newPeaks: mmr.peakSet(), proof });
  assert.equal(bad.ok, false);
});

test('latency: a record sealed past the declared maximum window latency is named', () => {
  const s = specs(9);
  s[0] = { ...s[0], delay: 2 };
  const { manifest } = buildManifest({ recordSpecs: s, windowSize: 3, maxLatencyWindows: 1 });
  const report = audit(manifest);
  assert.equal(check(report, 'latency').status, 'FAIL');
  assert.ok(report.findings.latencyBreaches.some((b) => b.payloadHash === leafHash('record-0')));
});
