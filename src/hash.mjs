import { createHash } from 'node:crypto';

export function sha256hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

// Domain-separated hash of two child hashes (MMR internal node).
export function hashPair(leftHex, rightHex) {
  return sha256hex(Buffer.concat([
    Buffer.from('wma/node:', 'utf8'),
    Buffer.from(leftHex, 'hex'),
    Buffer.from(rightHex, 'hex'),
  ]));
}

// Leaf hash of a record payload.
export function leafHash(payload) {
  return sha256hex(Buffer.concat([
    Buffer.from('wma/leaf:', 'utf8'),
    Buffer.from(String(payload), 'utf8'),
  ]));
}

// Canonical JSON: recursively sorted keys, no whitespace. Used for every
// signed or hashed object so independent implementations agree byte-for-byte.
export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
}

export function hashObject(value) {
  return sha256hex(Buffer.from(canonical(value), 'utf8'));
}
