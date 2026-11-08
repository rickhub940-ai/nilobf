import { LIMITS } from './opcodes.mjs';

const RESERVED = new Set('and break do else elseif end false for function if in local nil not or repeat return then true until while'.split(' '));
export const DEFAULT_OPAQUE_ENTRY = '__nil_opaque';

export function validateOpaqueEntry(name) {
  if (typeof name !== 'string' || name.length > 128 || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || RESERVED.has(name)) {
    throw new TypeError('Opaque entry must be a Lua identifier');
  }
  return name;
}

export function opaqueSourceBytes(source) {
  if (typeof source !== 'string' && !Buffer.isBuffer(source)) throw new TypeError('Opaque source must be a string or Buffer');
  const length = Buffer.isBuffer(source) ? source.length : Buffer.byteLength(source, 'utf8');
  if (length < 1 || length > LIMITS.blobBytes) throw new RangeError('Opaque source size limit exceeded');
  return Buffer.from(source);
}

export function normalizeOpaqueChunks(chunks) {
  if (chunks === undefined) return [];
  if (chunks === null || typeof chunks !== 'object' || Array.isArray(chunks)) throw new TypeError('opaqueChunks must be a Map or object');
  const entries = chunks instanceof Map ? [...chunks] : Object.entries(chunks);
  if (entries.length > 64) throw new RangeError('Opaque chunk count limit exceeded');
  let total = 0;
  return entries.map(([name, source]) => {
    validateOpaqueEntry(name);
    const bytes = opaqueSourceBytes(source);
    total += bytes.length;
    if (total > LIMITS.blobBytes) throw new RangeError('Combined opaque source size limit exceeded');
    return { name, bytes };
  });
}

