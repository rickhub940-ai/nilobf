// Cost-aware LZ4 parsing. This changes build-time choices, not the decoder format.
// All match lengths through 1024 and the longest match enter a shortest-path
// search. A bounded hash chain supplies candidates; this is not optimal LZ4 HC.
const MAX_INPUT = 1048576, HORIZON = 1024;

export function parseNativeBlock(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 16777216) throw new RangeError('Invalid native block');
  if (bytes.length < 13 || bytes.length > MAX_INPUT) return undefined;
  const n = bytes.length;
  let capacity = 1; while (capacity < n) capacity *= 2;
  const costs = new Float64Array(n + 1); costs.fill(Infinity); costs[0] = 0;
  const previous = new Int32Array(n + 1), starts = new Int32Array(n + 1), offsets = new Int32Array(n + 1);
  const edgeCost = new Float64Array(capacity * 2); edgeCost.fill(Infinity);
  const edgeAnchor = new Int32Array(capacity * 2), edgeStart = new Int32Array(capacity * 2), edgeOffset = new Int32Array(capacity * 2);
  const relax = (left, right, cost, anchor, start, offset) => {
    for (left += capacity, right += capacity + 1; left < right; left >>= 1, right >>= 1) {
      if (left & 1) { if (cost < edgeCost[left]) { edgeCost[left] = cost; edgeAnchor[left] = anchor; edgeStart[left] = start; edgeOffset[left] = offset; } left++; }
      if (right & 1) { --right; if (cost < edgeCost[right]) { edgeCost[right] = cost; edgeAnchor[right] = anchor; edgeStart[right] = start; edgeOffset[right] = offset; } }
    }
  };
  const visit = at => {
    for (let node = at + capacity; node; node >>= 1) if (edgeCost[node] < costs[at]) {
      costs[at] = edgeCost[node]; previous[at] = edgeAnchor[node]; starts[at] = edgeStart[node]; offsets[at] = edgeOffset[node];
    }
  };
  // For long literal runs, extension cost is a quotient plus one residue test.
  // A 255-residue range-minimum tree makes anchor selection O(log 255), rather
  // than scanning every preceding match endpoint at every input position.
  const residues = new Float64Array(512); residues.fill(Infinity);
  const anchors = new Int32Array(512);
  const insert = at => {
    const value = costs[at] - at - Math.floor(at / 255); let slot = 256 + at % 255;
    if (value >= residues[slot]) return;
    residues[slot] = value; anchors[slot] = at;
    while ((slot >>= 1)) { const a = slot * 2, b = a + 1, pick = residues[a] <= residues[b] ? a : b; residues[slot] = residues[pick]; anchors[slot] = anchors[pick]; }
  };
  const minimum = (left, right) => {
    let value = Infinity, anchor = 0;
    for (left += 256, right += 257; left < right; left >>= 1, right >>= 1) {
      if (left & 1) { if (residues[left] < value) { value = residues[left]; anchor = anchors[left]; } left++; }
      if (right & 1) { --right; if (residues[right] < value) { value = residues[right]; anchor = anchors[right]; } }
    }
    return [value, anchor];
  };
  const literalChoice = at => {
    if (at >= 15 && costs[at - 15] !== Infinity) insert(at - 15);
    let cost = Infinity, anchor = 0;
    for (let a = Math.max(0, at - 14); a <= at; a++) if (costs[a] + at - a < cost) { cost = costs[a] + at - a; anchor = a; }
    if (at >= 15) {
      const q = Math.floor((at - 15) / 255), r = (at - 15) % 255;
      const low = minimum(0, r), high = minimum(r + 1, 254);
      for (const [entry, adjustment] of [[low, 0], [high, -1]]) {
        const value = entry[0] + at + q + 1 + adjustment;
        if (value < cost) { cost = value; anchor = entry[1]; }
      }
    }
    return { cost, anchor };
  };
  const dictionary = new Int32Array(65536); dictionary.fill(-1);
  const chain = new Int32Array(65536); chain.fill(-1);
  let lastPosition = -1, lastLength = 0;
  for (let at = 0; at <= n - 5; at++) {
    visit(at);
    const literals = literalChoice(at);
    if (at > n - 12) continue;
    const first = bytes.readUInt32LE(at), slot = Math.imul(first, 0x9e3779b1) >>> 16;
    let candidate = dictionary[slot], length = lastLength > 4 ? lastLength - 1 : 0, best = length ? lastPosition + 1 : -1;
    chain[at & 65535] = candidate; dictionary[slot] = at;
    for (let depth = 0; depth < 64 && candidate >= 0 && at - candidate <= 65535; depth++) {
      if (bytes.readUInt32LE(candidate) === first && (!length || bytes[candidate + length] === bytes[at + length])) {
        let matched = 4; while (at + matched < n - 5 && bytes[candidate + matched] === bytes[at + matched]) matched++;
        if (matched > length) { length = matched; best = candidate; if (at + length === n - 5) break; }
      }
      candidate = chain[candidate & 65535];
    }
    lastPosition = best; lastLength = length;
    if (length < 4 || literals.cost === Infinity) continue;
    const end = Math.min(length, HORIZON), base = literals.cost + 3, offset = at - best;
    relax(at + 4, at + Math.min(18, end), base, literals.anchor, at, offset);
    for (let low = 19; low <= end; low += 255) relax(at + low, at + Math.min(low + 254, end), base + Math.floor((low - 19) / 255) + 1, literals.anchor, at, offset);
    if (length > end) relax(at + length, at + length, base + Math.floor((length - 19) / 255) + 1, literals.anchor, at, offset);
  }
  // Literal-only tail must be at least five bytes after the final match.
  let tail = 0, total = Infinity;
  for (let a = 0; a <= n - 5; a++) {
    const count = n - a, ext = count < 15 ? 0 : Math.floor((count - 15) / 255) + 1;
    const cost = costs[a] + 1 + count + ext;
    if (cost < total) { total = cost; tail = a; }
  }
  if (tail === 0 || total === Infinity) return undefined;
  const path = [];
  for (let end = tail; end; end = previous[end]) path.push({ anchor: previous[end], start: starts[end], end, offset: offsets[end] });
  path.reverse();
  const output = Buffer.allocUnsafe(total); let cursor = 0;
  const extension = length => { while (length >= 255) { output[cursor++] = 255; length -= 255; } output[cursor++] = length; };
  const emit = (anchor, start, length, offset) => {
    const literal = start - anchor, match = length ? length - 4 : 0;
    output[cursor++] = Math.min(literal, 15) * 16 + Math.min(match, 15);
    if (literal >= 15) extension(literal - 15);
    cursor += bytes.copy(output, cursor, anchor, start);
    if (length) { output.writeUInt16LE(offset, cursor); cursor += 2; if (match >= 15) extension(match - 15); }
  };
  for (const step of path) emit(step.anchor, step.start, step.end - step.start, step.offset);
  emit(tail, n, 0, 0);
  if (cursor !== total) throw new Error('Compression parse cost mismatch');
  return output;
}
