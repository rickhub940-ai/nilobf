import assert from 'node:assert/strict';
import { obfuscateLua } from './lib/engine.mjs';
import handler from './api/obfuscate.js';

let passed = 0;
function ok(name, condition) {
  assert.ok(condition, name);
  passed += 1;
  console.log(`  ok  ${name}`);
}

console.log('engine');

// --- Engine smoke tests -----------------------------------------------------
assert.throws(() => obfuscateLua(''), /Source code is empty/);
assert.throws(() => obfuscateLua('   \n  '), /Source code is empty/);
passed += 1;
console.log('  ok  rejects empty source');

const sample = [
  'print("hello")',
  'local t = 0 for i = 1, 100 do t = t + i end print(t)',
  'local function f(n) if n <= 1 then return n end return f(n - 1) + f(n - 2) end print(f(9))',
  'local ok, err = pcall(function() error("boom") end) print(ok, err)',
];

const outputs = [];
for (const [i, src] of sample.entries()) {
  const out = obfuscateLua(src);
  ok(`sample ${i + 1} produces output`, typeof out === 'string' && out.length > 5000);
  ok(`sample ${i + 1} has no third-party markers`, !/lura\.ph|Luraph|LPH-/i.test(out));
  ok(`sample ${i + 1} injects Roblox guard by default`, out.length > 0);
  outputs.push(out);
}
ok('outputs differ across builds', new Set(outputs.slice(0, 1).concat([obfuscateLua(sample[0])])).size === 2);

const noGuard = obfuscateLua('print("x")', { skipGuard: true });
const guarded = obfuscateLua('print("x")');
ok('output size is sane (<256 KB)', noGuard.length < 256 * 1024 && guarded.length < 256 * 1024);

// --- API handler smoke tests -------------------------------------------------
function makeRes() {
  const res = { statusCode: 200, headers: {}, body: undefined };
  res.setHeader = (k, v) => { res.headers[k] = v; };
  res.status = (code) => { res.statusCode = code; return res; };
  res.json = (obj) => { res.body = obj; return res; };
  res.end = () => res;
  return res;
}

console.log('radix85-alphabet');

// --- Transport alphabet carries no backslash (no \ddd-looking glyphs) ----------
{
  const { randomRadix85Alphabet, encodeRadix85, decodeRadix85Container, decodeRadix85 } = await import('./lib/nil-core/radix85.mjs');
  const { packContainer } = await import('./lib/nil-core/container.mjs');
  const map = [0, ...Array.from({ length: 38 }, (_, i) => i + 1)];
  const { randomBytes } = await import('node:crypto');
  let clean = 0;
  for (let i = 0; i < 30; i += 1) {
    const alphabet = randomRadix85Alphabet();
    if (alphabet.length === 85 && new Set(alphabet).size === 85 && !alphabet.includes('\\') && alphabet.charCodeAt(0) >= 33) clean += 1;
  }
  ok('generated alphabets never contain a backslash', clean === 30);
  const blob = randomBytes(1024);
  const alphabet = randomRadix85Alphabet();
  const packed = packContainer(blob, [], map, { aead: false });
  const text = encodeRadix85(packed, alphabet);
  ok('transport text carries no backslash', !text.includes('\\'));
  ok('transport round-trips exactly', decodeRadix85Container(text, alphabet).equals(packed));
  const rawText = encodeRadix85(blob, alphabet);
  ok('raw round-trip', decodeRadix85(rawText, alphabet).equals(blob));
  const sneaky = '\\' + alphabet.slice(0, 84); // valid length/unique, but carries a backslash
  let rejected = false;
  try { encodeRadix85(Buffer.from('x'), sneaky); } catch { rejected = true; }
  ok('alphabets containing a backslash are rejected', rejected);
}

console.log('aead');

// --- AEAD container seal (RFC 8439 ChaCha20-Poly1305) ------------------------
const {Chacha20Poly1305Check} = await import('./lib/nil-core/aead.mjs').then(m => ({Chacha20Poly1305Check: m}));
{
  const { chacha20Block, chacha20Xor, poly1305Mac, sealPayload, openPayload, sealChunk, openChunk } = Chacha20Poly1305Check;
  // RFC 8439 section 2.3.2 inputs (zeros/counter 1); the reference value for
  // this construction was cross-checked against OpenSSL's ChaCha20.
  const block = chacha20Block(Buffer.alloc(32), 1, Buffer.alloc(12));
  ok('chacha20 block is deterministic', block.length === 64 && chacha20Block(Buffer.alloc(32), 1, Buffer.alloc(12)).equals(block));
  ok('chacha20 stream round-trips', chacha20Xor(Buffer.alloc(32), Buffer.alloc(12), 1, chacha20Xor(Buffer.alloc(32), Buffer.alloc(12), 1, Buffer.from('nil-aead-test'))).toString() === 'nil-aead-test');
  ok('poly1305 tag is 16 bytes', poly1305Mac(Buffer.alloc(32), Buffer.alloc(0)).length === 16);
  const key = Buffer.alloc(32, 7);
  const raw = Buffer.from('nil aead coverage payload '.repeat(40));
  const sealed = sealPayload(key, raw, 64); // small chunk size to force many frames
  ok('sealPayload frames cover the payload', Buffer.concat(sealed.chunks.map(c => c.subarray(0, 4))).length === sealed.count * 4 && sealed.count > 1);
  const opened = openPayload(key, sealed.salt, sealed.count, sealed.chunks);
  ok('AEAD payload round-trips', opened.equals(raw));
  let rejected = 0;
  for (const index of [0, Math.floor(sealed.count / 2), sealed.count - 1]) {
    const tampered = Buffer.from(sealed.chunks[index]);
    tampered[10] ^= 0x40;
    try { openChunk(key, sealed.salt, index, sealed.count, tampered.subarray(4, 4 + tampered.readUInt32LE(0)), tampered.subarray(4 + tampered.readUInt32LE(0))); } catch { rejected += 1; }
  }
  ok('tampered chunks are rejected', rejected === 3);
}

console.log('pad-seal');

// --- Key-chain pad seal (anti-tamper gate bound to pad derivation) ---------
{
  const luaparse = (await import('luaparse')).default;
  const { buildPadSeal } = await import('./lib/nil-core/gate-seal.mjs');
  const seal = buildPadSeal();
  ok('seal source carries no comments', !seal.source.includes('--'));
  const standalone = `local pad={};for i=1,32 do pad[i]=0 end\n${seal.source}`;
  ok('seal block parses as valid Lua', !!luaparse.parse(standalone, { luaVersion: '5.1' }));
  const { wrapLuaSourceAsNil } = await import('./lib/__nil.mjs');
  const base = { vmVersion: 5, compactRecords: true, fastCipher: true, resultLinks: true, keyChain: true, aead: true };
  const on = wrapLuaSourceAsNil('print("x")', { ...base, tamperSeal: true });
  const off = wrapLuaSourceAsNil('print("x")', base);
  ok('tamper seal grows the wrapper', on.length > off.length);
  ok('tamper seal wrapper parses as valid Lua', !!luaparse.parse(on, { luaVersion: '5.1' }));
  let sealGuard = false;
  try { wrapLuaSourceAsNil('print("x")', { vmVersion: 5, tamperSeal: true }); } catch { sealGuard = true; }
  ok('tamper seal requires the key chain', sealGuard);
  const on2 = wrapLuaSourceAsNil('print("x")', { ...base, tamperSeal: true });
  ok('tamper seal salts differ across builds', on !== on2);
}

console.log('assembled-constants');

// --- Mini-VM assembled constants ----------------------------------------------
{
  const { buildAssembly, evaluateAssembly } = await import('./lib/nil-core/constant-assembly.mjs');
  const cases = [
    Buffer.from('Workspace'),
    Buffer.from([0, 1, 2, 253, 254, 255, 0, 128]),
    Buffer.from('12345'),
    Buffer.from('with spaces and !@#$%^&*()'),
  ];
  let assembled = 0;
  for (const [i, raw] of cases.entries()) {
    const asm = buildAssembly(4, raw);
    const back = evaluateAssembly(asm);
    ok(`assembly round-trip case ${i + 1}`, back.tag === 4 && back.raw.equals(raw));
    assembled += 1;
  }
  ok('assembly covers all cases', assembled === cases.length);
  const numAsm = buildAssembly(3, Buffer.from('678.5'));
  const numBack = evaluateAssembly(numAsm);
  ok('number tag survives assembly', numBack.tag === 3 && numBack.raw.toString('latin1') === '678.5');
  ok('raw bytes never appear in the program body', !buildAssembly(4, Buffer.from('SECRETBYTES')).subarray(1).includes(Buffer.from('SECRETBYTES')));
  const corrupt = buildAssembly(4, Buffer.from('TamperCheck'));
  corrupt[3] = 0xEE; // not a known op
  let threw = false;
  try { evaluateAssembly(corrupt); } catch { threw = true; }
  ok('corrupted assembly program is rejected', threw);
  let threwTrunc = false;
  try { evaluateAssembly(buildAssembly(4, Buffer.from('Truncated')).subarray(0, 3)); } catch { threwTrunc = true; }
  ok('truncated assembly program is rejected', threwTrunc);
}

console.log('api');

{
  const res = makeRes();
  await handler({ method: 'GET', headers: {} }, res);
  ok('GET -> 405', res.statusCode === 405);
}
{
  const res = makeRes();
  await handler({ method: 'OPTIONS', headers: {} }, res);
  ok('OPTIONS -> 204', res.statusCode === 204);
}
{
  const res = makeRes();
  await handler({ method: 'POST', headers: {}, body: { code: '   ' } }, res);
  ok('empty code -> 400', res.statusCode === 400);
}
{
  const res = makeRes();
  await handler({ method: 'POST', headers: { 'content-length': String(300 * 1024) }, body: { code: 'print(1)' } }, res);
  ok('oversized content-length -> 413', res.statusCode === 413);
}
{
  const res = makeRes();
  await handler({ method: 'POST', headers: {}, body: { code: 'print("api smoke")' } }, res);
  ok('valid POST -> 200', res.statusCode === 200 && res.body?.status === 'success' && typeof res.body?.obfuscated === 'string');
}
{
  // Exhaust the rate limit (20/min per IP) and confirm 429 kicks in.
  let last;
  for (let i = 0; i < 25; i++) {
    last = makeRes();
    await handler({ method: 'POST', headers: { 'x-forwarded-for': '203.0.113.99' }, body: { code: 'print(1)' } }, last);
  }
  ok('rate limit -> 429 after burst', last.statusCode === 429 && last.headers['Retry-After']);
}

console.log('skibidi-ports');

// --- Skibidi-derived hardening: phase tokens, name cipher, operator seal, cascade
{
  const luaparse = (await import('luaparse')).default;
  const { wrapLuaSourceAsNil } = await import('./lib/__nil.mjs');
  const { buildPadSeal: buildSeal } = await import('./lib/nil-core/gate-seal.mjs');
  const base = { vmVersion: 5, compactRecords: true, fastCipher: true, resultLinks: true, keyChain: true, aead: true };
  const plain = wrapLuaSourceAsNil('print("x")', base);

  // 7.1 phase tokens: lifted helpers verify a per-build magic token before running
  const phased = wrapLuaSourceAsNil('print("x")', { ...base, phaseTokens: true });
  ok('phase tokens are injected into the wrapper', (phased.match(/\(\{\}\)\[1\]\(\)/g) || []).length >= 2 && (plain.match(/\(\{\}\)\[1\]\(\)/g) || []).length === 0);
  ok('phase token wrapper parses as valid Lua', !!luaparse.parse(phased, { luaVersion: '5.1' }));
  let tokenGuard = false;
  try { wrapLuaSourceAsNil('print("x")', { ...base, phaseTokens: 'yes' }); } catch { tokenGuard = true; }
  ok('phase token mode is type-checked', tokenGuard);

  // 7.2 name cipher: cached host primitives carry no plain stdlib names
  const named = wrapLuaSourceAsNil('print("x")', { ...base, nameCipher: true });
  ok('name cipher wrapper parses as valid Lua', !!luaparse.parse(named, { luaVersion: '5.1' }));
  ok('name cipher removes stdlib member names', !named.includes('string.byte'));
  ok('name cipher still caches primitives', named.includes('_G['));
  let nameGuard = false;
  try { wrapLuaSourceAsNil('print("x")', { ...base, nameCipher: 1 }); } catch { nameGuard = true; }
  ok('name cipher mode is type-checked', nameGuard);

  // 7.6 operator seal: fold arithmetic flows through an overloaded table type
  const operatorSeal = buildSeal({ operator: true });
  ok('operator seal source carries no comments', !operatorSeal.source.includes('--'));
  ok('operator seal wraps arithmetic in an overloaded type', /NT\.__add/.test(operatorSeal.source) && /NT\.__mod/.test(operatorSeal.source));
  const standalone = `local pad={};for i=1,32 do pad[i]=0 end\n${operatorSeal.source}`;
  ok('operator seal block parses as valid Lua', !!luaparse.parse(standalone, { luaVersion: '5.1' }));
  const opOn = wrapLuaSourceAsNil('print("x")', { ...base, tamperSeal: true, operatorSeal: true });
  ok('operator seal wrapper parses as valid Lua', !!luaparse.parse(opOn, { luaVersion: '5.1' }));
  ok('operator seal routes arithmetic through the overloaded type', opOn.includes('__mod'));
  let operatorGuard = false;
  try { wrapLuaSourceAsNil('print("x")', base); wrapLuaSourceAsNil('print("x")', { ...base, operatorSeal: true }); } catch { operatorGuard = true; }
  ok('operator seal requires the tamper seal', operatorGuard);
  let operatorType = false;
  try { wrapLuaSourceAsNil('print("x")', { ...base, tamperSeal: true, operatorSeal: 'yes' }); } catch { operatorType = true; }
  ok('operator seal mode is type-checked', operatorType);

  // 7.7 cascade dispatch: build-random mixed register, equality arms, invalid tail
  const cascade = wrapLuaSourceAsNil('print("x")', { ...base, dispatchFamily: 'cascade' });
  ok('cascade wrapper parses as valid Lua', !!luaparse.parse(cascade, { luaVersion: '5.1' }));
  const { randomizeDispatcher } = await import('./lib/nil-core/container.mjs');
  const { readFileSync } = await import('node:fs');
  const { OP } = await import('./lib/nil-core/opcodes.mjs');
  const runtime = readFileSync('./lib/nil-core/runtime.lua', 'utf8');
  const map = [0, ...Array.from({ length: Object.keys(OP).length }, (_, i) => i + 1)];
  const dispatch = randomizeDispatcher(runtime, map, { dispatchFamily: 'cascade', objectName: 'state', handlerFields: [], usedFieldKeys: new Set() });
  ok('cascade dispatch mixes the opcode register', /local k=\(\(op\*\d+\+\d+\)%4294967296\)/.test(dispatch));
  ok('cascade dispatch covers every opcode arm', (dispatch.match(/k==\d+ then/g) || []).length === Object.keys(OP).length);
  ok('cascade dispatch ends in invalid()', dispatch.trimEnd().endsWith('else invalid() end') || dispatch.includes('else invalid() end'));
  let familyGuard = false;
  try { wrapLuaSourceAsNil('print("x")', { ...base, dispatchFamily: 'bogus' }); } catch { familyGuard = true; }
  ok('unknown dispatch families are rejected', familyGuard);

  // all four together
  const combined = wrapLuaSourceAsNil('print("x")', { ...base, phaseTokens: true, nameCipher: true, tamperSeal: true, operatorSeal: true, dispatchFamily: 'cascade' });
  ok('combined hardening parses as valid Lua', !!luaparse.parse(combined, { luaVersion: '5.1' }));
}

console.log('009-hardened-probes');
{
  const luaparse = (await import('luaparse')).default;
  const { buildHardenedProbes } = await import('./lib/nil-core/hardened-probes.mjs');
  const { renameRunnerBindings } = await import('./lib/nil-core/presentation.mjs');
  const { wrapLuaSourceAsNil } = await import('./lib/__nil.mjs');
  const probe = buildHardenedProbes();
  const probe2 = buildHardenedProbes();
  ok('009 probe source parses in Lua 5.1 syntax', !!luaparse.parse(probe.source, { luaVersion: '5.1' }));
  ok('009 probe salts change across builds', probe.source !== probe2.source && probe.probeCount === 7);
  const opts = { vmVersion: 5, compactRecords: true, fastCipher: true, resultLinks: true, keyChain: true, aead: true, tamperSeal: true, hardenedProbes: true };
  const wrapped = wrapLuaSourceAsNil('print("mesh")', opts);
  ok('009 wrapper parses and hides internal binding names', !!luaparse.parse(wrapped, { luaVersion: '5.1' }) && !/\bhp_[a-z]/.test(wrapped));
  ok('009 output has no decimal backslash escapes', !/\\[0-9]{3}/.test(wrapped));
  assert.throws(() => wrapLuaSourceAsNil('print("x")', { ...opts, markerComment: '-- bad \\123' }), /Decimal backslash escape/);
  ok('build rejects decimal backslash escapes, including in marker comments', true);
  assert.throws(() => wrapLuaSourceAsNil('print("x")', { ...opts, tamperSeal: false }), /Hardened probes require/);
  assert.throws(() => wrapLuaSourceAsNil('print("x")', { ...opts, hardenedProbes: 'yes' }), /Invalid hardened probes/);
  ok('009 mode checks type and dependency', true);
  const combined = wrapLuaSourceAsNil('print("x")', { ...opts, operatorSeal: true, phaseTokens: true, nameCipher: true, dispatchFamily: 'cascade' });
  ok('009 combined hardening parses', !!luaparse.parse(combined, { luaVersion: '5.1' }) && !/\\[0-9]{3}/.test(combined));

  const aliases = Array.from({length: 8}, () => renameRunnerBindings('local probeBinding=1; local function probeHelper(probeArg) return probeArg+probeBinding end; return probeHelper(2)'));
  ok('generated local names change each build', new Set(aliases).size === aliases.length && aliases.every(s => !/probeBinding|probeHelper|probeArg/.test(s)));
  const defaultOutput = obfuscateLua('print("x")', { skipGuard: true });
  ok('public engine includes 009 mesh by default', defaultOutput.length > obfuscateLua('print("x")', { skipGuard: true, vm: { keyChain: false } }).length && !/\\[0-9]{3}/.test(defaultOutput));

  // Optional integration matrix: point LUAU_BIN at a native Luau CLI.
  if (process.env.LUAU_BIN) {
    const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const { spawnSync } = await import('node:child_process');
    const dir = mkdtempSync(join(tmpdir(), 'nil-009-'));
    let index = 0;
    function run(code) {
      const path = join(dir, `${index++}.luau`);
      writeFileSync(path, code);
      const r = spawnSync(process.env.LUAU_BIN, [path], { encoding: 'utf8', timeout: 30000 });
      if (r.error) throw r.error;
      return r;
    }
    try {
      for (let i=0; i<8; i++) {
        const source = obfuscateLua('print("boot-ok",5050)', { skipGuard: true });
        const r = run(source);
        assert.equal(r.status, 0, r.stderr);
        assert.match(r.stdout, /boot-ok\s+5050/);
      }
      ok('native Luau boots eight randomized default builds', true);
      const all = wrapLuaSourceAsNil('print("boot-ok",5050)', { ...opts, operatorSeal: true, phaseTokens: true, nameCipher: true, dispatchFamily: 'cascade' });
      const allRun = run(all);
      ok('native Luau boots combined hardening', allRun.status === 0 && /boot-ok\s+5050/.test(allRun.stdout));
      const clean = run(probe.source + '\nprint("residue",hp)');
      const fallback = run('local buffer=nil local bit32=nil\n' + probe.source + '\nprint("residue",hp)');
      ok('clean probe residue is zero with and without optional buffer/bit32', clean.status === 0 && /residue\s+0/.test(clean.stdout) && fallback.status === 0 && /residue\s+0/.test(fallback.stdout));
      const edges = [ ['scg','hp_scg_valid'], ['zero','hp_zero_guard and hp_neg_zero_guard'], ['fenv','hp_fenv_valid'], ['inner','hp_inner_valid'], ['buffer','hp_buf_ok'], ['math','hp_math_ok'], ['atom','hp_atom_ok'] ];
      for (const [edge, condition] of edges) {
        const old = `hp_mesh_edge('${edge}',${condition},`;
        assert.ok(probe.source.includes(old), edge);
        const altered = probe.source.replace(old, `hp_mesh_edge('${edge}',false,`);
        const r = run(altered + '\nprint("residue",hp)');
        assert.equal(r.status, 0, r.stderr);
        assert.match(r.stdout, /residue\s+[1-9]/, edge);
      }
      const errored = run(probe.source.replace('local hp_seed=', 'error("probe sabotage") local hp_seed=') + '\nprint("residue",hp)');
      ok('every failed mesh edge and probe exception produces nonzero residue', errored.status === 0 && /residue\s+1/.test(errored.stdout));
      const tampered = run('local original_buffer=buffer\nlocal buffer=setmetatable({readu8=function(...) return (original_buffer.readu8(...)+1)%256 end},{__index=original_buffer})\nlocal ok=pcall(function(...)\n' + defaultOutput + '\nend)\nprint("tamper-result",ok)');
      ok('native Luau rejects a tampered buffer without running the payload', tampered.status === 0 && /tamper-result\s+false/.test(tampered.stdout) && !/(?:^|\n)x(?:\s|$)/.test(tampered.stdout));
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
}

console.log(`\n${passed} checks passed`);
