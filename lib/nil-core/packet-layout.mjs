import { randomInt } from 'node:crypto';
import { LIMITS } from './opcodes.mjs';

const MAX_PACKET_BYTES = 8192;
// One wrapper root and one materializer function also occupy prototype slots.
const MAX_PAGES = LIMITS.prototypes - 2;

export function planPacketLayout(size, policy = {}) {
  if (!Number.isInteger(size) || size < 1 || size > LIMITS.blobBytes) {
    throw new RangeError('Invalid payload size');
  }
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new TypeError('Packet layout must be an object');
  }
  for (const name of Object.keys(policy)) {
    if (!['minimumPages', 'targetBytes'].includes(name)) throw new TypeError('Unknown packet layout option: ' + name);
  }
  const minimumPages = policy.minimumPages ?? 4;
  const targetBytes = policy.targetBytes ?? 6144;
  if (!Number.isInteger(minimumPages) || minimumPages < 1 || minimumPages > 64) {
    throw new RangeError('minimumPages must be between 1 and 64');
  }
  if (!Number.isInteger(targetBytes) || targetBytes < 256 || targetBytes > MAX_PACKET_BYTES) {
    throw new RangeError('targetBytes must be between 256 and 8192');
  }
  const count = Math.max(Math.min(size, minimumPages), Math.ceil(size / targetBytes));
  if (count > MAX_PAGES) throw new RangeError('Packet layout exceeds the prototype budget');
  const ranges = [];
  let offset = 0;
  for (let remainingPages = count; remainingPages > 0; remainingPages--) {
    const remaining = size - offset;
    const average = remaining / remainingPages;
    const low = Math.max(1, remaining - (remainingPages - 1) * MAX_PACKET_BYTES, Math.floor(average * 0.65));
    const high = Math.min(MAX_PACKET_BYTES, remaining - remainingPages + 1, Math.ceil(average * 1.35));
    if (low > high) throw new RangeError('Inconsistent packet layout');
    const length = remainingPages === 1 ? remaining : randomInt(low, high + 1);
    ranges.push(Object.freeze({ offset, length }));
    offset += length;
  }
  return Object.freeze({ size, count, minimumPages, targetBytes, ranges: Object.freeze(ranges) });
}
