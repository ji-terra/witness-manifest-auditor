import { hashPair, sha256hex } from './hash.mjs';

// Merkle Mountain Range over leaf hashes.
//
// Peaks are perfect subtrees, kept as node objects {height, start, hash, left,
// right}; merging retains the children, so any historical node stays reachable
// from the current peaks — that is what makes consistency proofs between an
// old head and a new head generatable by anyone holding the leaf set.
//
// Root = "bagging" the peak hashes right-to-left:
//   root = H(peak[0] || H(peak[1] || ... H(peak[k-1] || peak[k])))
// A peak of height h at start s covers the leaf range [s, s + 2^h).

export const EMPTY_ROOT = sha256hex('wma/empty');

export function bagPeaks(peakHashes) {
  if (peakHashes.length === 0) return EMPTY_ROOT;
  let acc = peakHashes[peakHashes.length - 1];
  for (let i = peakHashes.length - 2; i >= 0; i--) acc = hashPair(peakHashes[i], acc);
  return acc;
}

// The partition check (make889tek, 2026-10-16): peak ranges must be disjoint,
// contiguous, and jointly cover [0, n). A proof whose peaks fail partition is
// rejected before any counting — otherwise peaks padded from a larger tree
// pass a node budget while the underlying tree outgrows it.
export function checkPartition(peaks, n) {
  let cursor = 0;
  const sorted = [...peaks].sort((a, b) => a.start - b.start);
  for (const p of sorted) {
    if (p.start !== cursor) return { ok: false, reason: `gap or overlap at ${cursor}, peak starts at ${p.start}` };
    if (!Number.isInteger(p.height) || p.height < 0 || p.height > 60) return { ok: false, reason: 'bad height' };
    cursor += 2 ** p.height;
  }
  if (cursor !== n) return { ok: false, reason: `peaks cover [0, ${cursor}), declared size is ${n}` };
  return { ok: true };
}

export class MMR {
  constructor() {
    this.peaks = []; // node objects, ascending start
    this.size = 0;
  }

  append(leaf) {
    let node = { height: 0, start: this.size, hash: leaf, left: null, right: null };
    this.size += 1;
    while (this.peaks.length > 0 && this.peaks[this.peaks.length - 1].height === node.height) {
      const left = this.peaks.pop();
      node = { height: node.height + 1, start: left.start, hash: hashPair(left.hash, node.hash), left, right: node };
    }
    this.peaks.push(node);
    return this.size - 1;
  }

  peakSet() {
    return this.peaks.map((p) => ({ height: p.height, start: p.start, hash: p.hash }));
  }

  root() {
    return bagPeaks(this.peaks.map((p) => p.hash));
  }

  // Path of siblings from a node inside `peak` up to the peak root.
  // Each step: {hash, side} — side is where the SIBLING sits.
  #pathWithin(peak, height, start) {
    if (peak.height === height && peak.start === start) return [];
    const mid = peak.start + 2 ** (peak.height - 1);
    if (start < mid) {
      return [...this.#pathWithin(peak.left, height, start), { hash: peak.right.hash, side: 'right' }];
    }
    return [...this.#pathWithin(peak.right, height, start), { hash: peak.left.hash, side: 'left' }];
  }

  #containingPeak(height, start) {
    const end = start + 2 ** height;
    return this.peaks.find((p) => p.start <= start && end <= p.start + 2 ** p.height) || null;
  }

  proveInclusion(leafIndex) {
    const peak = this.#containingPeak(0, leafIndex);
    if (!peak) return null;
    return {
      leafIndex,
      size: this.size,
      peaks: this.peakSet(),
      path: this.#pathWithin(peak, 0, leafIndex),
    };
  }

  // Inclusion proof for an arbitrary node (height, start, hash) — used to show
  // an old peak survives inside the new tree.
  proveNode(height, start) {
    const peak = this.#containingPeak(height, start);
    if (!peak) return null;
    return {
      height, start,
      size: this.size,
      peaks: this.peakSet(),
      containingPeak: { height: peak.height, start: peak.start, hash: peak.hash },
      path: this.#pathWithin(peak, height, start),
    };
  }

  // Consistency proof between the head at `oldPeaks` (a serialized peak set)
  // and this MMR's current state.
  proveConsistency(oldPeaks) {
    return oldPeaks.map((op) => {
      const surviving = this.peaks.find((p) => p.height === op.height && p.start === op.start && p.hash === op.hash);
      if (surviving) return { mode: 'survives', height: op.height, start: op.start, hash: op.hash };
      const proof = this.proveNode(op.height, op.start);
      if (!proof) return { mode: 'missing', height: op.height, start: op.start, hash: op.hash };
      return { mode: 'inside', height: op.height, start: op.start, hash: op.hash, path: proof.path, containingPeak: proof.containingPeak };
    });
  }
}

function applyPath(hash, path) {
  let acc = hash;
  for (const step of path) {
    acc = step.side === 'left' ? hashPair(step.hash, acc) : hashPair(acc, step.hash);
  }
  return acc;
}

// Pure verifiers — these run on serialized data only, so a head-only verifier
// (no leaf set) can use them exactly as the full auditor does.

export function verifyInclusion({ leaf, proof, root }) {
  const part = checkPartition(proof.peaks, proof.size);
  if (!part.ok) return { ok: false, reason: 'partition: ' + part.reason };
  const peakHash = applyPath(leaf, proof.path);
  const peak = proof.peaks.find((p) => p.start <= proof.leafIndex && proof.leafIndex < p.start + 2 ** p.height);
  if (!peak) return { ok: false, reason: 'no peak covers the leaf index' };
  if (peak.hash !== peakHash) return { ok: false, reason: 'path does not recompute the peak' };
  if (bagPeaks(proof.peaks.map((p) => p.hash)) !== root) return { ok: false, reason: 'peaks do not bag to the root' };
  return { ok: true };
}

export function verifyConsistency({ oldSize, oldRoot, oldPeaks, newSize, newRoot, newPeaks, proof }) {
  const oldPart = checkPartition(oldPeaks, oldSize);
  if (!oldPart.ok) return { ok: false, reason: 'old partition: ' + oldPart.reason };
  if (bagPeaks(oldPeaks.map((p) => p.hash)) !== oldRoot) return { ok: false, reason: 'old peaks do not bag to the old root' };
  const newPart = checkPartition(newPeaks, newSize);
  if (!newPart.ok) return { ok: false, reason: 'new partition: ' + newPart.reason };
  if (bagPeaks(newPeaks.map((p) => p.hash)) !== newRoot) return { ok: false, reason: 'new peaks do not bag to the new root' };
  if (proof.length !== oldPeaks.length) return { ok: false, reason: 'proof does not cover every old peak' };
  for (const step of proof) {
    if (step.mode === 'survives') {
      const found = newPeaks.find((p) => p.height === step.height && p.start === step.start && p.hash === step.hash);
      if (!found) return { ok: false, reason: `peak at ${step.start} claimed surviving but absent` };
    } else if (step.mode === 'inside') {
      const recomputed = applyPath(step.hash, step.path);
      if (recomputed !== step.containingPeak.hash) return { ok: false, reason: `old peak at ${step.start} does not recompute its containing peak` };
      const found = newPeaks.find((p) => p.height === step.containingPeak.height && p.start === step.containingPeak.start && p.hash === step.containingPeak.hash);
      if (!found) return { ok: false, reason: 'containing peak is not in the new peak set' };
    } else {
      return { ok: false, reason: `old peak at ${step.start} is missing from the new tree` };
    }
  }
  return { ok: true };
}
