// ChaCha20 + Poly1305 (RFC 8439), implemented from the specification.
// Used for the authenticated container seal: each transport chunk is sealed
// independently with a per-container salt-derived nonce, and Poly1305 tags
// bind chunk index, total chunk count, and chunk length as AAD.
// Nothing here is copied from third-party code; correctness is cross-checked
// against Python's `cryptography` package in the fuzz harness.
import { randomBytes } from 'node:crypto';

const MASK32 = 0xffffffffn;
const u32le = value => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(value >>> 0);
  return b;
};
const u64le = value => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(value));
  return b;
};
const rotl32 = (value, bits) => (((value << BigInt(bits)) | (value >> BigInt(32 - bits))) & MASK32);

function quarterRound(state, a, b, c, d) {
  state[a] = (state[a] + state[b]) & MASK32; state[d] = rotl32(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) & MASK32; state[b] = rotl32(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b]) & MASK32; state[d] = rotl32(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) & MASK32; state[b] = rotl32(state[b] ^ state[c], 7);
}

export function chacha20Block(key, counter, nonce) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new TypeError('ChaCha20 key must be 32 bytes');
  if (!Buffer.isBuffer(nonce) || nonce.length !== 12) throw new TypeError('ChaCha20 nonce must be 12 bytes');
  const constants = [0x61707865n, 0x3320646en, 0x79622d32n, 0x6b206574n];
  const state = [...constants];
  for (let i = 0; i < 8; i++) state.push(BigInt(key.readUInt32LE(i * 4)));
  state.push(BigInt(counter >>> 0));
  for (let i = 0; i < 3; i++) state.push(BigInt(nonce.readUInt32LE(i * 4)));
  const working = [...state];
  for (let round = 0; round < 10; round++) {
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }
  const out = Buffer.alloc(64);
  for (let i = 0; i < 16; i++) out.writeUInt32LE(Number((working[i] + state[i]) & MASK32), i * 4);
  return out;
}

export function chacha20Xor(key, nonce, counter, data) {
  const out = Buffer.alloc(data.length);
  let offset = 0;
  let block = counter >>> 0;
  while (offset < data.length) {
    const keystream = chacha20Block(key, block, nonce);
    const n = Math.min(64, data.length - offset);
    for (let i = 0; i < n; i++) out[offset + i] = data[offset + i] ^ keystream[i];
    offset += n;
    block = (block + 1) >>> 0;
  }
  return out;
}

const POLY_P = (1n << 130n) - 5n;

export function poly1305Mac(key, message) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new TypeError('Poly1305 key must be 32 bytes');
  let r = 0n;
  for (let i = 15; i >= 0; i--) r = (r << 8n) | BigInt(key[i]);
  // Clamp r per RFC 8439: clear bits 4,5,6,7 of bytes 3,7,11,15 and bits 0,1,2 of bytes 4,8,12.
  r &= 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  let s = 0n;
  for (let i = 15; i >= 0; i--) s = (s << 8n) | BigInt(key[16 + i]);
  let h = 0n;
  for (let offset = 0; offset < message.length; offset += 16) {
    const len = Math.min(16, message.length - offset);
    let n = 0n;
    for (let i = len - 1; i >= 0; i--) n = (n << 8n) | BigInt(message[offset + i]);
    n += 1n << BigInt(8 * len); // the appended 0x01 byte (for a full block, the 2^128 bit)
    h = ((h + n) * r) % POLY_P;
  }
  h = (h + s) % (1n << 128n);
  const out = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) { out[i] = Number(h & 0xffn); h >>= 8n; }
  return out;
}

const pad16 = length => Buffer.alloc((16 - (length % 16)) % 16);
const macData = (aad, ciphertext) => Buffer.concat([
  aad, pad16(aad.length),
  ciphertext, pad16(ciphertext.length),
  u64le(aad.length), u64le(ciphertext.length),
]);
const aeadAad = (index, chunkCount, chunkLength) =>
  Buffer.concat([Buffer.from('NILAEAD1', 'latin1'), u32le(index >>> 0), u32le(chunkCount >>> 0), u32le(chunkLength >>> 0)]);

/**
 * Seal one chunk. Nonce = salt(4 bytes) || u64le(index) (12 bytes total).
 * @returns {{ciphertext: Buffer, tag: Buffer}}
 */
export function sealChunk(key, salt, index, chunkCount, plaintext) {
  const nonce = Buffer.concat([salt, u64le(index)]);
  const aad = aeadAad(index, chunkCount, plaintext.length);
  const polyKey = chacha20Block(key, 0, nonce).subarray(0, 32);
  const ciphertext = chacha20Xor(key, nonce, 1, plaintext);
  return { ciphertext, tag: poly1305Mac(polyKey, macData(aad, ciphertext)) };
}

/** Verify and open one chunk. Throws on tag mismatch. */
export function openChunk(key, salt, index, chunkCount, ciphertext, tag) {
  const nonce = Buffer.concat([salt, u64le(index)]);
  const aad = aeadAad(index, chunkCount, ciphertext.length);
  const polyKey = chacha20Block(key, 0, nonce).subarray(0, 32);
  const expected = poly1305Mac(polyKey, macData(aad, ciphertext));
  let diff = expected.length ^ tag.length;
  for (let i = 0; i < 16; i++) diff |= expected[i] ^ (tag[i] ?? 0);
  if (diff !== 0) throw new Error('Poly1305 verification failed');
  return chacha20Xor(key, nonce, 1, ciphertext);
}

/**
 * Seal a whole payload into chunk frames.
 * @returns {{salt: Buffer, chunkSize: number, chunks: Buffer[]}} each chunk is framed as u32le(ctLen) || ct || tag
 */
export function sealPayload(key, raw, chunkSize = 4096) {
  if (!Buffer.isBuffer(raw)) throw new TypeError('Payload must be a buffer');
  if (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > 262144) throw new RangeError('Chunk size out of range');
  const salt = randomBytes(4);
  const count = Math.max(1, Math.ceil(raw.length / chunkSize));
  const chunks = [];
  for (let i = 0; i < count; i++) {
    const piece = raw.subarray(i * chunkSize, Math.min(raw.length, (i + 1) * chunkSize));
    const { ciphertext, tag } = sealChunk(key, salt, i, count, piece);
    const frame = Buffer.alloc(4 + ciphertext.length + 16);
    frame.writeUInt32LE(ciphertext.length, 0);
    ciphertext.copy(frame, 4);
    tag.copy(frame, 4 + ciphertext.length);
    chunks.push(frame);
  }
  return { salt, chunkSize, chunks, count };
}

/** Open a sealed payload. Throws on any verification failure. */
export function openPayload(key, salt, chunkCount, frames) {
  const pieces = [];
  let total = 0;
  for (let i = 0; i < frames.length; i++) {
    const frame = frames[i];
    if (frame.length < 20) throw new Error('AEAD chunk frame too small');
    const ctLen = frame.readUInt32LE(0);
    if (4 + ctLen + 16 !== frame.length) throw new Error('AEAD chunk frame length mismatch');
    const plain = openChunk(key, salt, i, chunkCount, frame.subarray(4, 4 + ctLen), frame.subarray(4 + ctLen));
    total += plain.length;
    if (total > 64 * 1024 * 1024) throw new Error('AEAD payload limit exceeded');
    pieces.push(plain);
  }
  return Buffer.concat(pieces);
}
