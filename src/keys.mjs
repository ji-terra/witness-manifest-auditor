import { generateKeyPairSync, createPublicKey, sign, verify } from 'node:crypto';
import { canonical } from './hash.mjs';

// Ed25519 keys, exported as SPKI-DER hex (the same representation the UUAID
// substrate uses for agent public keys).
export function generateKeys() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicHex: publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
    privateKey,
  };
}

export function signObject(privateKey, obj) {
  return sign(null, Buffer.from(canonical(obj), 'utf8'), privateKey).toString('hex');
}

export function verifyObject(publicHex, obj, sigHex) {
  try {
    const pub = createPublicKey({ key: Buffer.from(publicHex, 'hex'), format: 'der', type: 'spki' });
    return verify(null, Buffer.from(canonical(obj), 'utf8'), pub, Buffer.from(sigHex, 'hex'));
  } catch {
    return false;
  }
}
