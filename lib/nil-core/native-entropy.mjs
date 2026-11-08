import { readFileSync } from 'node:fs';

// Canonical Huffman after LZ4. This is compression, not encryption. Codes are
// LSB-first on the wire so Luau can decode with one unaligned buffer.readu32.
export function encodeNativeEntropy(bytes, { compactLengths = true } = {}) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 16777216) throw new RangeError('Invalid entropy input');
  if (typeof compactLengths !== 'boolean') throw new TypeError('Invalid entropy header mode');
  const frequencies = new Uint32Array(256); for (const value of bytes) frequencies[value]++;
  const queue = [];
  for (let symbol = 0; symbol < 256; symbol++) if (frequencies[symbol]) queue.push({ frequency: frequencies[symbol], symbol, order: symbol });
  if (queue.length < 2) return undefined;
  while (queue.length > 1) {
    queue.sort((a, b) => a.frequency - b.frequency || a.order - b.order);
    const left = queue.shift(), right = queue.shift();
    queue.push({ frequency: left.frequency + right.frequency, order: Math.min(left.order, right.order), left, right });
  }
  const lengths = new Uint8Array(256);
  const visit = (node, depth) => { if (node.symbol !== undefined) lengths[node.symbol] = depth; else { visit(node.left, depth + 1); visit(node.right, depth + 1); } };
  visit(queue[0], 0);
  const maximum = Math.max(...lengths); if (maximum > 15) return undefined;
  const counts = new Uint32Array(maximum + 1), next = new Uint32Array(maximum + 1), codes = new Uint32Array(256);
  let bits = 0;
  for (let i = 0; i < 256; i++) if (lengths[i]) { counts[lengths[i]]++; bits += lengths[i] * frequencies[i]; }
  let code = 0;
  for (let width = 1; width <= maximum; width++) { code = (code + (counts[width - 1] || 0)) * 2; next[width] = code; }
  for (let symbol = 0; symbol < 256; symbol++) if (lengths[symbol]) {
    let value = next[lengths[symbol]]++, reversed = 0;
    for (let i = 0; i < lengths[symbol]; i++) { reversed = reversed * 2 + (value & 1); value >>>= 1; }
    codes[symbol] = reversed;
  }
  const base = compactLengths ? 136 : 264;
  const output = Buffer.alloc(base + Math.ceil(bits / 8) + 4);
  output.writeUInt32LE(bytes.length, 0); output.writeUInt32LE(bits + (compactLengths ? 2147483648 : 0), 4);
  if (compactLengths) for (let i = 0; i < 128; i++) output[8 + i] = lengths[i * 2] + lengths[i * 2 + 1] * 16;
  else Buffer.from(lengths).copy(output, 8);
  let reservoir = 0, width = 0, at = base;
  for (const symbol of bytes) {
    reservoir += codes[symbol] * 2 ** width; width += lengths[symbol];
    while (width >= 8) { output[at++] = reservoir & 255; reservoir = Math.floor(reservoir / 256); width -= 8; }
  }
  if (width) output[at] = reservoir;
  return output;
}
export const nativeEntropyRuntime = readFileSync(new URL('./native-entropy.lua', import.meta.url), 'utf8');
