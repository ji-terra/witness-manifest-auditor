import { MMR, verifyInclusion, verifyConsistency } from './mmr.mjs';
import { verifyObject } from './keys.mjs';
import { leafHash, hashObject } from './hash.mjs';

// The auditor. Consumes a manifest (see manifest.mjs for the format) and
// produces a structured report. Design: witness-manifest-auditor-design
// (paper v0.10). Every check names what it proves and what it does not.

export function audit(manifest) {
  const checks = [];
  const findings = { doorLoss: [], sealLoss: [], clientAnomalies: [], rangeViolations: [], latencyBreaches: [] };
  const add = (id, status, detail) => checks.push({ id, status, detail });

  const keeperPub = manifest.keeperPublicKey;
  const windows = manifest.windows || [];
  const records = manifest.records || [];
  const finalHead = windows.length ? windows[windows.length - 1].head : null;

  // ---- head signatures and chain linkage ----
  let sigOk = true, chainOk = true, prevHeadHash = 'GENESIS';
  for (const w of windows) {
    if (!verifyObject(keeperPub, w.head, w.headSig)) { sigOk = false; add('head-signatures', 'FAIL', `window ${w.index}: signature invalid`); }
    if (w.head.prevHeadHash !== prevHeadHash) { chainOk = false; add('head-chain', 'FAIL', `window ${w.index}: prevHeadHash does not link`); }
    prevHeadHash = hashObject({ head: w.head, headSig: w.headSig });
  }
  if (sigOk) add('head-signatures', 'PASS', `${windows.length} heads verified`);
  if (chainOk) add('head-chain', 'PASS', 'heads link genesis → final');

  // ---- enumeration vs committed count and root (the acceptance test) ----
  const mmr = new MMR();
  const leafIndex = new Map();
  records.forEach((r, i) => { mmr.append(r.payloadHash); leafIndex.set(r.payloadHash, i); });
  const computedRoot = mmr.root();
  if (!finalHead) {
    add('enumeration-count-root', 'FAIL', 'manifest has no heads');
  } else if (finalHead.count !== records.length || finalHead.root !== computedRoot) {
    add('enumeration-count-root', 'FAIL',
      `enumeration has ${records.length} records and root ${computedRoot.slice(0, 12)}…, head commits count ${finalHead.count} and root ${String(finalHead.root).slice(0, 12)}… — shortfall ${finalHead.count - records.length}`);
  } else {
    add('enumeration-count-root', 'PASS', `enumeration matches committed count ${finalHead.count} and root`);
  }

  // ---- per-head recomputation (full tier) + window delta digests ----
  let headsOk = true, deltaOk = true;
  for (const w of windows) {
    if (w.head.size > records.length) {
      headsOk = false; add('head-recomputation', 'FAIL', `window ${w.index}: head commits size ${w.head.size} beyond the ${records.length} enumerated records`);
      continue;
    }
    const prefix = new MMR();
    for (let k = 0; k < w.head.size; k++) prefix.append(records[k].payloadHash);
    if (prefix.root() !== w.head.root || JSON.stringify(prefix.peakSet()) !== JSON.stringify(w.head.peaks)) {
      headsOk = false; add('head-recomputation', 'FAIL', `window ${w.index}: head root/peaks do not recompute from enumeration`);
    }
    const delta = new MMR();
    for (let k = w.head.positionRange[0]; k < w.head.positionRange[1]; k++) delta.append(records[k].payloadHash);
    if (delta.root() !== w.head.deltaDigest) {
      deltaOk = false; add('window-delta-digests', 'FAIL', `window ${w.index}: delta digest mismatch`);
    }
  }
  if (headsOk && windows.length) add('head-recomputation', 'PASS', 'every head recomputes from the enumeration');
  if (deltaOk && windows.length) add('window-delta-digests', 'PASS', 'window delta digests compose from their leaves');

  // ---- consistency between consecutive heads (head-only verifiable) ----
  let consOk = true;
  for (let k = 1; k < windows.length; k++) {
    const prev = windows[k - 1].head, next = windows[k].head;
    if (next.size > records.length) { consOk = false; add('head-consistency', 'FAIL', `heads ${k - 1}→${k}: head size beyond enumeration`); continue; }
    const atNext = new MMR();
    for (let i = 0; i < next.size; i++) atNext.append(records[i].payloadHash);
    const proof = atNext.proveConsistency(prev.peaks);
    const res = verifyConsistency({
      oldSize: prev.size, oldRoot: prev.root, oldPeaks: prev.peaks,
      newSize: next.size, newRoot: next.root, newPeaks: next.peaks, proof,
    });
    if (!res.ok) { consOk = false; add('head-consistency', 'FAIL', `heads ${k - 1}→${k}: ${res.reason}`); }
  }
  if (consOk && windows.length > 1) add('head-consistency', 'PASS', `${windows.length - 1} consecutive head pairs consistent`);

  // ---- inclusion proofs for every leaf (exercises the partition check) ----
  let inclOk = true, inclCount = 0;
  if (finalHead) {
    for (let i = 0; i < records.length; i++) {
      const proof = mmr.proveInclusion(i);
      const res = verifyInclusion({ leaf: records[i].payloadHash, proof, root: finalHead.root });
      if (!res.ok) { inclOk = false; add('inclusion-proofs', 'FAIL', `leaf ${i}: ${res.reason}`); break; }
      inclCount++;
    }
    if (inclOk) add('inclusion-proofs', 'PASS', `${inclCount} inclusion proofs verified against the final head`);
  }

  // ---- attempt log: chain, signatures, counters ----
  const attempts = manifest.attempts || [];
  let chainAttemptsOk = true, prev = 'GENESIS';
  const validAttempts = [];
  attempts.forEach((a, idx) => {
    const pub = manifest.clients[a.client];
    const { sig, ...body } = a;
    if (a.prev !== prev || !pub || !verifyObject(pub, body, sig)) {
      chainAttemptsOk = false;
      add('attempt-chain', 'FAIL', `attempt ${idx} (client ${a.client}): chain link or signature invalid`);
      return;
    }
    validAttempts.push({ ...a, index: idx });
    prev = hashObject(a);
  });
  if (chainAttemptsOk) add('attempt-chain', 'PASS', `${validAttempts.length} attempts chain-linked and signature-valid`);

  const lastCounter = {};
  for (const a of validAttempts) {
    if (lastCounter[a.client] !== undefined && a.counter <= lastCounter[a.client]) {
      findings.clientAnomalies.push({ client: a.client, counter: a.counter, previousCounter: lastCounter[a.client], attemptIndex: a.index });
    }
    lastCounter[a.client] = a.counter;
  }
  if (findings.clientAnomalies.length) {
    add('attempt-counters', 'FAIL', `CLIENT-ANOMALY: ${findings.clientAnomalies.length} counter regression(s); the client signed out of order — classified client-side, not keeper door loss`);
  } else {
    add('attempt-counters', 'PASS', 'per-client counters strictly increase in log order');
  }

  // ---- three-leg reconciliation over DISTINCT PAYLOAD HASHES ----
  const attempted = new Map(); // payloadHash -> first attempt
  for (const a of validAttempts) if (!attempted.has(a.payloadHash)) attempted.set(a.payloadHash, a);
  const receipted = new Map();
  for (const r of manifest.receipts || []) if (!receipted.has(r.payloadHash)) receipted.set(r.payloadHash, r);
  const sealed = new Set(records.map((r) => r.payloadHash));

  for (const [hash, a] of attempted) {
    if (!receipted.has(hash)) findings.doorLoss.push({ payloadHash: hash, client: a.client, counter: a.counter });
  }
  for (const [hash, r] of receipted) {
    if (!sealed.has(hash)) findings.sealLoss.push({ payloadHash: hash, position: r.position });
  }
  add('door-loss', findings.doorLoss.length ? 'FAIL' : 'PASS',
    findings.doorLoss.length
      ? `${findings.doorLoss.length} attempted payload(s) never receipted — named from the ingress side`
      : 'every attempted payload was receipted (lower bound: attempts that never entered the log leave no trace)');
  add('seal-loss', findings.sealLoss.length ? 'FAIL' : 'PASS',
    findings.sealLoss.length
      ? `${findings.sealLoss.length} receipted payload(s) never sealed — named from the ingress side`
      : 'every receipted payload is sealed');

  // ---- receipt floor: a presented receipt beyond the committed count falsifies it ----
  const beyond = (manifest.receipts || []).filter((r) => finalHead && r.position >= finalHead.count);
  add('receipt-floor', beyond.length ? 'FAIL' : 'PASS',
    beyond.length
      ? `${beyond.length} presented receipt(s) carry positions at or beyond the committed count ${finalHead.count} — the count is falsified by its own receipts`
      : `${receipted.size} distinct receipted payloads presented; floor rises as holders come forward`);

  // ---- position binding + evidence-source labels ----
  const holderCheckedWindows = new Set();
  for (const r of manifest.receipts || []) {
    if (!leafIndex.has(r.payloadHash)) continue;
    const actual = leafIndex.get(r.payloadHash);
    const w = windows.find((win) => actual >= win.head.positionRange[0] && actual < win.head.positionRange[1]);
    if (r.source === 'holder' && w) holderCheckedWindows.add(w.index);
    if (r.position !== actual) {
      findings.rangeViolations.push({ payloadHash: r.payloadHash, receiptPosition: r.position, actualPosition: actual, source: r.source });
    }
  }
  if (findings.rangeViolations.length) {
    add('position-binding', 'FAIL',
      `RANGE-VIOLATION: ${findings.rangeViolations.length} receipt(s) name a position the record does not occupy — a holder-retained copy is a keeper-signed falsifier the keeper cannot reissue retroactively`);
  } else {
    const labels = windows.map((w) => `window ${w.index}: ${holderCheckedWindows.has(w.index) ? 'HOLDER-VERIFIED' : 'KEEPER-REPORTED'}`);
    add('position-binding', 'PASS', `receipt positions match leaf positions (${labels.join('; ')})`);
  }

  // ---- latency: ingress epoch → seal window epoch, in windows ----
  const latencies = [];
  for (const [hash, a] of attempted) {
    if (!leafIndex.has(hash)) continue;
    const pos = leafIndex.get(hash);
    const w = windows.find((win) => pos >= win.head.positionRange[0] && pos < win.head.positionRange[1]);
    if (!w) continue;
    const latency = w.head.epoch - a.epoch;
    latencies.push(latency);
    if (latency > manifest.maxLatencyWindows) {
      findings.latencyBreaches.push({ payloadHash: hash, latency, maxLatencyWindows: manifest.maxLatencyWindows });
    }
  }
  add('latency', findings.latencyBreaches.length ? 'FAIL' : 'PASS',
    findings.latencyBreaches.length
      ? `${findings.latencyBreaches.length} record(s) sealed beyond the declared maximum ${manifest.maxLatencyWindows} windows — named in findings`
      : `latency distribution (windows): ${latencies.length ? `min ${Math.min(...latencies)}, max ${Math.max(...latencies)}` : 'none'}, declared max ${manifest.maxLatencyWindows}`);

  const verdict = checks.some((c) => c.status === 'FAIL') ? 'FAIL' : 'PASS';
  return {
    format: 'wma-report/0.1',
    verdict,
    checks,
    findings,
    metrics: {
      records: records.length,
      attempts: validAttempts.length,
      distinctAttemptedPayloads: attempted.size,
      distinctReceiptedPayloads: receipted.size,
      windows: windows.length,
      committedCount: finalHead ? finalHead.count : null,
    },
  };
}
