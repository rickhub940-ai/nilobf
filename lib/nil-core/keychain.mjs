import { randomBytes } from 'node:crypto';
import { compileLuaToNil } from './compiler.mjs';
import { lowerNil } from './lowering.mjs';
import { dataProgram, dataSchema, dataRuntime, serializeData } from './data-vm.mjs';
import { OP } from './opcodes.mjs';
import { randomRadix85Alphabet } from './radix85.mjs';
import { packContainer } from './container.mjs';

// Key-chain design: the main container is masked with a random key K whose
// stored header is (K + P) % 256. The pad P is never serialized; it is
// *computed* at boot by a small Nil VM bootstrap program (embedded as a second,
// self-contained packed container). Static analysis therefore has to emulate
// the bootstrap bytecode to recover P — exactly the barrier that matters for
// "read the payload without running it", without any third-party runtime.
//
// The bootstrap also mixes in anti-tamper results: if any environment check
// fails, every pad byte is shifted and the main container's Adler checksum no
// longer verifies (fail-silent via error()/invalid path).

export function lcgPadBytes(seed) {
  let x = seed >>> 0;
  const out = [];
  for (let i = 0; i < 32; i++) {
    x = (x * 1664525 + 1013904223) % 4294967296;
    out.push(x % 256);
  }
  return Buffer.from(out);
}

function buildBootstrapSource(seed) {
  // The seed ships only as an additive split inside the bootstrap bytecode
  // (which itself ships as Nil VM bytecode, never as source).
  const r = () => randomBytes(4).readUInt32LE(0);
  const a = r(), b = r();
  const c = (seed - ((a + b) % 4294967296) + 3 * 4294967296) % 4294967296;
  return `
local seed=(${a}+${b}+${c})%4294967296
local x=seed
local o={}
for i=1,32 do x=(x*1664525+1013904223)%4294967296 o[i]=x%256 end
local m=0
local ok1=pcall(function() local t=setmetatable({},{__add=function() return 7 end}) return (t+0)==7 end)
if not ok1 then m=m+3 end
local ok2,e2=pcall(function() error({tag="nilkey"}) end)
if ok2 or type(e2)~="table" or e2.tag~="nilkey" then m=m+5 end
local t3={1,2,3,4}
if #t3~=4 or t3[4]~=4 then m=m+7 end
if math.floor(9.7)~=9 then m=m+9 end
for i=1,32 do o[i]=(o[i]+m*(i*149+37))%256 end
local u=table.unpack or unpack
return string.char(u(o))
`;
}

/**
 * Build the key-chain bootstrap for one wrapper.
 * @returns {{pad: Buffer, bootPacked: Buffer, bootAlphabet: string, bootDispatcher: string}}
 */
export function buildKeyChain() {
  const seed = randomBytes(4).readUInt32LE(0);
  const pad = lcgPadBytes(seed);
  const source = buildBootstrapSource(seed);
  const bootOptions = { vmVersion: 5, maxSteps: 1_000_000 };
  const lowered = lowerNil(compileLuaToNil(source, bootOptions), { dependentFusion: true });
  const bootBlob = serializeData(dataProgram(lowered), { contextCount: 2 });
  const opcodeMap = [0, ...Array.from({ length: Object.keys(OP).length }, (_, i) => i + 1)];
  const bootPacked = packContainer(bootBlob, [], opcodeMap, {});
  const bootAlphabet = randomRadix85Alphabet();
  // The delivery schema randomizes contexts/profile per serialization, so the
  // bootstrap bytecode can only run on a dispatcher generated for *this* blob.
  const bootDispatcher = dataRuntime(dataSchema(bootBlob));
  return { pad, bootPacked, bootAlphabet, bootDispatcher };
}
