import { randomBytes, randomInt } from 'node:crypto';

// Pad seal — a native (non-VM) anti-tamper layer that runs INSIDE the
// key-chain boot section, after the bootstrap VM derived the 32-byte pad and
// before the container decoder consumes it.
//
// Model: environment probes (pcall lanes, error-box integrity, metatable
// hooks, raw-table behavior, math core, 2^64 float range, optional buffer or
// bit32 known-answers). Each probe yields 0 in a clean environment and a
// non-zero build-specific residue otherwise. Residues fold into a 32-bit
// accumulator through odd multipliers, interleaved with salted re-verification
// lanes that re-check error-box delivery k times independently.
//
//   * clean:    h stays exactly 0 -> pad untouched -> payload boots normally;
//   * tampered: any single flipped probe makes h non-zero, which shifts every
//               pad byte through a feedback generator, so the boot-derived
//               key unmasks to garbage and AEAD/Adler verification fails
//               inside the decoder. The wrapper fails closed at boot, before
//               a single payload byte is interpreted. No diagnostics are
//               emitted on any path.
//
// This layer only *shifts bytes*; it carries no payload by itself. It is
// deliberately inseparable from the key chain: the pad never leaves the boot
// scope, so the seal can only ever act through key derivation.
//
// The emitted source carries no comments; its only string literals are type
// names ('table', 'function'), which the runner concealment passes rewrite
// together with the rest of the wrapper.
//
// operatorSeal: emit the fold arithmetic through an overloaded table type
// (metatable __add/__sub/__mul/__mod) instead of raw numbers, in the style of
// the reference VM's operator-overloaded cipher. Wrapping is semantics-preserving
// for the exact integer range used here (products stay below 2^53), and the
// only place a raw value is read back is the final zero test.

const oddPrime = () => 2 * randomInt(40, 127) + 1;
const r32 = () => randomBytes(4).readUInt32LE(0);
const num = n => (n >>> 0).toString(10);

export function buildPadSeal({ operator = false } = {}) {
  if (typeof operator !== 'boolean') throw new TypeError('Invalid operator seal mode');
  const FP1 = oddPrime(), FP2 = oddPrime(), FP3 = oddPrime(), FP4 = oddPrime();
  const FP5 = oddPrime(), FP6 = oddPrime(), FP7 = oddPrime(), FP8 = oddPrime();
  const VFP = oddPrime(), VSTEP = 2 * randomInt(3, 41);
  const KP1 = 1664525 + randomInt(0, 3) * 2 | 1; // odd LCG-ish multiplier, per build
  const KP2 = randomInt(1, 65535) | 1;
  const KP3 = randomInt(3, 251) | 1;
  const TAG = r32() & 0xffff | 1;
  const LEN = (r32() % 32768) + 17;
  const TAG2 = r32() & 0xffff | 1;
  const LEN2 = (r32() % 32768) + 17;
  const ADD = randomBytes(2).readUInt16LE(0) + 100;
  const HOP = randomBytes(2).readUInt16LE(0) + 100;
  const FV = r32();
  const FV_B0 = FV % 256;
  const FV_B3 = Math.floor(FV / 16777216) % 256;
  const BAND_A = r32() & 0xffff, BAND_B = r32() & 0xffff;
  const BAND_R = BAND_A & BAND_B;
  const BXOR_A = r32() & 0xffff, BXOR_B = r32() & 0xffff;
  const BXOR_R = BXOR_A ^ BXOR_B;
  const V1 = r32() | 1;
  const LANE = 2 * randomInt(40, 120) + 1;

  // Only string literals are type names; all constants are per-build random.
  const probes = [
    // Nested pcall: inner failure must be catchable by the outer lane.
    `local p1=${13 + (randomInt(0, 3) * 2)}
local ok1,r1=pcall(function()
 local a,b=pcall(function() error({tag=${num(TAG2)},n=${num(LEN2)}}) end)
 return a==false and type(b)=='table' and rawget(b,'tag')==${num(TAG2)} and rawget(b,'n')==${num(LEN2)}
end)
p1=(ok1==true and r1==true) and 0 or p1`,
    // Error-box lane: error() must deliver a table object intact.
    `local p2=${5 + (randomInt(0, 3) * 2)}
local ok2,box=pcall(function() error({tag=${num(TAG)},n=${num(LEN)}}) end)
p2=(ok2==false and type(box)=='table' and rawget(box,'tag')==${num(TAG)} and rawget(box,'n')==${num(LEN)}) and 0 or p2`,
    // Metatable hook: __add must fire for a table-left operand.
    `local p3=${7 + (randomInt(0, 3) * 2)}
local ok3,r3=pcall(function()
 local t=setmetatable({},{__add=function() return ${ADD} end})
 return t+0==${ADD}
end)
p3=(ok3==true and r3==true) and 0 or p3`,
    // Metatable hook: __eq must fire only for shared-metatable tables.
    `local p4=${11 + (randomInt(0, 3) * 2)}
local ok4,r4=pcall(function()
 local m={__eq=function(a,b) return a.v==b.v end}
 local a=setmetatable({v=1},m)
 local b=setmetatable({v=1},m)
 local c=setmetatable({v=2},m)
 return (a==b)==true and (a==c)==false
end)
p4=(ok4==true and r4==true) and 0 or p4`,
    // Environment hop: getfenv/setfenv must round-trip a function's env.
    `local p5=${17 + (randomInt(0, 3) * 2)}
local ok5,r5=pcall(function()
 local e1=getfenv(1)
 if type(e1)~='table' then return false end
 local f=function() return ${HOP} end
 local before=getfenv(f)
 setfenv(f,e1)
 local same=rawequal(getfenv(f),e1)
 setfenv(f,before)
 local back=rawequal(getfenv(f),before)
 return same and back and f()==${HOP}
end)
p5=(ok5==true and r5==true) and 0 or p5`,
    // Raw table behavior: length, indexing, rawget.
    `local p6=${19 + (randomInt(0, 3) * 2)}
local ok6,r6=pcall(function() local t={1,2,3,4} return #t==4 and t[4]==4 and rawget(t,1)==1 end)
p6=(ok6==true and r6==true) and 0 or p6`,
    // Math core: floor/abs/sin/sqrt/max must behave per IEEE doubles.
    `local p7=${23 + (randomInt(0, 3) * 2)}
local ok7,r7=pcall(function()
 return math.floor(9.7)==9 and math.floor(-9.7)==-10 and math.abs(math.sin(0))==0 and math.sqrt(81)==9 and math.max(3,4)==4
end)
p7=(ok7==true and r7==true) and 0 or p7`,
    // 2^64 float range: doubles must span [2^32, 2^64) exactly.
    `local p8=${29 + (randomInt(0, 3) * 2)}
local ok8,r8=pcall(function()
 return math.floor(2^64)/4294967296==4294967296 and math.floor(2^32)==4294967296
end)
p8=(ok8==true and r8==true) and 0 or p8`,
    // Optional capability: absence is clean, wrong behavior is not.
    `local p9=0
if type(buffer)=='table' and type(buffer.create)=='function' then
 local ok9,r9=pcall(function()
  local b=buffer.create(4)
  buffer.writeu32(b,0,${num(FV)})
  return buffer.readu8(b,0)==${num(FV_B0)} and buffer.readu8(b,3)==${num(FV_B3)} and buffer.len(b)==4
 end)
 if not (ok9==true and r9==true) then p9=${oddPrime()} end
end`,
    // Optional capability: absence is clean, wrong behavior is not.
    `local p10=0
if type(bit32)=='table' and type(bit32.band)=='function' and type(bit32.bxor)=='function' and type(bit32.bor)=='function' then
 if not (bit32.band(${num(BAND_A)},${num(BAND_B)})==${num(BAND_R)} and bit32.bxor(${num(BXOR_A)},${num(BXOR_B)})==${num(BXOR_R)} and bit32.bor(0,0)==0) then p10=${oddPrime()} end
end`,
  ];

  // Operator-overloaded fold lane: constants live inside an overloaded table
  // type (metatable __add/__sub/__mul/__mod); raw values are only read back at
  // the final zero test and inside the pad feedback loop.
  const head = operator ? [
    'local NT={}',
    'local function U(v) if getmetatable(v)==NT then return v.v end return v end',
    'local function N(v) return setmetatable({v=v},NT) end',
    'NT.__add=function(a,b) return N(U(a)+U(b)) end',
    'NT.__sub=function(a,b) return N(U(a)-U(b)) end',
    'NT.__mul=function(a,b) return N((U(a)*U(b))%4294967296) end',
    'NT.__mod=function(a,b) return N(U(a)%U(b)) end',
    'local MOD=N(4294967296)',
    `local FP1=N(${num(FP1)})`,`local FP2=N(${num(FP2)})`,`local FP3=N(${num(FP3)})`,`local FP4=N(${num(FP4)})`,
    `local FP5=N(${num(FP5)})`,`local FP6=N(${num(FP6)})`,`local FP7=N(${num(FP7)})`,`local FP8=N(${num(FP8)})`,
    `local VFP=N(${num(VFP)})`,`local KP1=N(${num(KP1)})`,`local KP2=N(${num(KP2)})`,`local KP3=N(${num(KP3)})`,
    'local h=N(0)',
  ] : ['local h=0'];
  const fold = (name, p) => operator ? `h=(h*${name}+${p})%MOD` : `h=(h*${num({ FP1, FP2, FP3, FP4, FP5, FP6, FP7, FP8, VFP }[name])}+${p})%4294967296`;
  const kp = (name) => operator ? name : num({ KP1, KP2, KP3 }[name]);
  const readAcc = operator ? 'hh.v' : 'hh';

  const script = [
    'do',
    ...head,
    probes.join('\n'),
    fold('FP1', 'p1'),
    fold('FP2', 'p2'),
    fold('FP3', 'p3'),
    fold('FP4', 'p4'),
    fold('FP5', 'p5'),
    fold('FP6', 'p6'),
    fold('FP7', 'p7'),
    fold('FP8', 'p8'),
    fold('FP1', 'p9'),
    fold('FP2', 'p10'),
    // Salted re-verification lanes: three independent error-box round trips.
    'for k=1,3 do',
    ` local tag=${num(V1)}+k*${num(VSTEP)}`,
    ' local okv,boxv=pcall(function() error({tag=tag,n=k}) end)',
    ` local v=(okv==false and type(boxv)=='table' and rawget(boxv,'tag')==tag and rawget(boxv,'n')==k) and 0 or (${num(LANE)}+k)`,
    fold('VFP', 'v'),
    'end',
    // Only this final guard is conditional; all probes above are data.
    operator ? 'if h.v~=0 then' : 'if h~=0 then',
    ' local hh=h',
    ' for i=1,32 do',
    `  hh=(hh*${kp('KP1')}+${kp('KP2')}+i*${kp('KP3')})%${operator ? 'MOD' : '4294967296'}`,
    `  pad[i]=(pad[i]+math.floor(${readAcc}/65536)%256+1)%256`,
    ' end',
    'end',
    'end',
  ].join('\n');

  return { source: script, probeCount: probes.length, foldCount: 13, operator };
}
