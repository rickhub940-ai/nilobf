# Nil Obfuscator

เว็บแอป + REST API สำหรับ obfuscate โค้ด **Lua/Luau (เป้าหมายหลัก: Roblox)** โดยแปลงโค้ดให้เป็นโปรแกรมของ **Nil VM (Data V5)** — obfuscator เดิมของโปรเจกต์นี้ฝัง runtime ของ Luraph ไว้ แต่ตั้งแต่เวอร์ชันนี้เป็น **Nil VM ล้วนๆ ที่พัฒนาขึ้นเองทั้งหมด** ไม่มีโค้ดบุคคลที่สามฝังอยู่

## สถาปัตยกรรม

```
Lua source ──► compiler (luaparse) ──► Nil VM bytecode ──► lowering / fusion
     ──► data V5 serialization (compact records, result links, sealed records)
     ──► packed container (radix85 + mask + Adler checksum)
     ──► self-contained wrapper รันได้ทันที ไม่พึ่ง loadstring / runtime ภายนอก
```

- `lib/nil-core/` — Nil VM ทั้งหมด: compiler (`compiler.mjs`), lowering, data-V5 program (`data-vm.mjs`), dispatcher/runtime (`runtime-v5.lua`, `dataRuntime`), container format (`container.mjs`), การนำเสนอชื่อตัวแปร (`presentation.mjs`, `runner-*.mjs`)
- `lib/__nil.mjs` — `wrapLuaSourceAsNil()` public API
- `lib/engine.mjs` — ชั้น obfuscation ระดับเว็บ (guard + header + ตัวเลือก VM)
- `api/obfuscate.js` — REST endpoint (rate limit 20 req/min/IP, body ≤ 256 KB)
- `index.html` — Web UI

## ฟีเจอร์

- **Nil VM Data V5**: compile Lua เป็น bytecode โดยตรง ไม่ใช้ `loadstring` ของ payload หลัก
- **Compact records + Result links (CFG)**: ลดขนาด instruction และทำให้ dataflow ไม่ติด trace ตรงๆ
- **Sealed records**: เข้ารหัส constant/record ใน instruction stream
- **Activated constants + Consumer handlers**: opcode พิเศษที่อ่าน operand เป็นข้อมูล ไม่ใช่คำสั่ง
- **Radicx85 transport + additive mask + Adler checksum**: ตรวจความเสียหายของ payload ตอนโหลด — alphabet ไม่มีอักขระ `\` และ `\ddd` escape runs ไม่มีใน output เลย (มี unit test คุมไว้)
- **Anti-tamper แบบ silent-fail**: เช็กสภาพแวดล้อมตอน boot ถ้าผิดปกติ VM จะไม่ทำงานอย่างเงียบๆ
- **Key chain** (`keyChain: true`): container key จริงไม่เคยถูกเก็บไว้ในไฟล์ — เก็บเป็น `(key + pad) % 256` โดย pad ถูกคำนวณตอน boot โดยโปรแกรม Nil VM ขนาดเล็ก (boot program) ที่ฝังมาแยกต่างหาก พร้อม anti-tamper ในตัว (ถ้าสภาพแวดล้อมถูก hook pad จะเพี้ยนทุกไบต์ checksum หลักจะไม่ผ่าน) — การถอด payload แบบ static ต้อง emulate boot VM ก่อน จึงเพิ่มงานให้ static analysis จริงๆ แต่ก็ทำให้ output ใหญ่ขึ้น ~66 KB (boot VM ต้องพก dispatcher ของตัวเอง)
- **Assembled constants** (`assembledConstants: true`): constant ทุกตัวไม่ถูกเก็บเป็น bytes ดิบใน payload — แต่เก็บเป็น *โปรแกรมขนาดเล็กของ VM ประกอบ constant* (tag 6) ที่ runtime ถอด/ตรวจ/ประกอบตอนใช้งานจริง: แต่ละ byte ของ constant ถูกส่งผ่าน chain ของ `PUSH`/`ADD`/`SUB`/`MUL`/`NOT` แบบสุ่ม (รวมตัวประกอบที่เป็นเลขคี่เพื่อบังคับ inverse mod 256) ทำให้แม้แต่ bytes ที่ผ่าน mask แล้วก็ไม่ปรากฏตรงๆ — โปรแกรมถูก seal ด้วย key/seal เดิมของ sealed record จึงถูกแก้ไขไม่ได้ ถ้า tag/seal ไม่ผ่าน VM จะ fail-closed ทันที — รองรับ constant ชนิด string/number เท่านั้น ใช้คู่กับ `sealedRecords` ได้ (ตัวอย่าง output +9 B เมื่อปิด sealed, +~1.3 KB เมื่อเปิด)
- **AEAD seal** (`aead: true`): แทน additive mask + Adler checksum ด้วย **ChaCha20-Poly1305 (RFC 8439)** แยกทีละ chunk 4096 ไบต์ — payload ถูก authenticate ก่อนใช้งานเสมอ แก้ไข/ตัดทอนไบต์ใดๆ ใน payload ทำให้ boot ล้มเหลวทันที (fail-closed) เอนจินเข้ารหัสเขียนใหม่จาก spec (ไม่ใช่โค้ดบุคคลที่สาม) และตรวจสอบตรงกับ OpenSSL/`cryptography` แล้ว — output ใหญ่ขึ้น ~4 KB
- **Tamper seal** (`tamperSeal: true`): anti-tamper layer รอบใหม่ที่ฝัง __ใน boot scope ของ key chain__ (ต้องเปิด `keyChain` ด้วย) — probes สภาพแวดล้อม 10 ตัว (pcall lane, error-box integrity, metatable `__add`/`__eq`, `getfenv`/`setfenv` round-trip, raw table, math core, `2^64` float, และ known-answer ของ `buffer`/`bit32` แบบ optional) พับผลผ่าน odd-multiplier 32-bit folds พร้อม re-verification lanes 3 ชั้น — ถ้าสภาพแวดล้อมไม่สะอาดแม้แต่ probe เดียว pad จะถูกเลื่อนทุกไบต์ด้วย feedback generator → key เพี้ยน → AEAD/Adler ไม่ผ่าน → boot ล้มเหลวทันที — พัฒนาจากการวิเคราะห์ obfuscator จริง (ดู `docs/skibidi-analysis.md`) — ไม่มี diagnostics ใดๆ บนทุก path — output ใหญ่ขึ้น ~4 KB
- **Phase tokens** (`phaseTokens: true`): helper ที่ lift ออกจาก object ทุกตัวต้องรับ build-time magic token เป็น argument แรก — token ถูกตรวจในตัว method ก่อนแตะสถานะ VM มิฉะนั้น crash แบบ nil-call เงียบๆ (รูปแบบเดียวกับ call-contract ของ obfuscator จริงที่วิเคราะห์ไว้ใน `docs/skibidi-analysis.md`) — caller ที่ถอด/เรียกใช้ method ตรงๆ โดยไม่มี token จะตายเงียบ — output ใหญ่ขึ้น ~1 KB
- **Name cipher** (`nameCipher: true`): primitives ของ host ที่ถูก cache ลง numeric slots (`string.byte`, `table.insert`, `error`, …) ไม่ถูกเขียนเป็นชื่อเต็มใน output — แต่ถูกประกอบจาก byte-subtract table ต่อ slot ตอนสร้าง object (`_G[string.char(...)][string.char(...)]`) ด้วย key สุ่มต่อ build — output ไม่มีชื่อ stdlib ให้ regex ได้ (ยกเว้น `string.char` ที่ตัว decoder ใช้เอง) — output ใหญ่ขึ้น ~2 KB
- **Operator seal** (`operatorSeal: true`, ต้องเปิด `tamperSeal` ด้วย): fold arithmetic ใน tamper seal ถูกส่งผ่าน overloaded table type (metatable `__add`/`__sub`/`__mul`/`__mod`) แทน raw numbers — semantics เหมือนเดิม 100% แต่การอ่านออกลักษณะ cipher จาก branch/arithmetic แบบ static ทำได้ยากขึ้นมาก — output ใหญ่ขึ้น ~1 KB
- **Cascade dispatch** (`dispatchFamily: 'cascade'`): dispatch family ที่สาม (นอกจาก `tree`/`bucket`) — ผสม opcode register ด้วยค่า build-random (`k = (op*MUL + ADD) % 2^32`) แล้ว if/elseif chain ตามค่า probe ที่ไม่ซ้ำกัน + `invalid()` tail เดียว — branch structure ไม่เปิดเผย opcode→handler mapping — ช้ากว่า tree dispatch (linear scan) แลกกับ obfuscation — output ใหญ่ขึ้นเล็กน้อย
- **009 coupled probe mesh** (`hardenedProbes: true`, ต้องเปิด `tamperSeal` และ `keyChain`): ผูก env proxy หลายชั้น, wire/trace, operator chains, fenv, buffer round-trip (เมื่อมี buffer), math graph และ atom proxy เข้าด้วยกัน 7 edges พร้อม final gate; ถ้า probe ล้มเหลว ผล mesh จะทำให้ pad ของ boot VM เปลี่ยนและ container ไม่ผ่านการตรวจสอบ โดยไม่เปิดเผยรายละเอียด probe — ต้องมี `getfenv`/`setfenv` ที่ทำงานได้ตามปกติ
- **Token/field/slot และชื่อตัวแปรที่ wrapper สร้างสุ่มทุกครั้ง**: รวมตัวแปรของชั้น 009 ด้วย โดยสุ่มแบบรักษา scope; ชื่อ global และ API ภายนอกที่โปรแกรมต้องใช้ไม่ถูกสุ่มเปลี่ยน

## ใช้เป็นไลบรารี

```js
import { obfuscateLua } from './lib/engine.mjs';

const out = obfuscateLua('print("hello")');
```

หรือระดับ VM:

```js
import { wrapLuaSourceAsNil } from './lib/__nil.mjs';

const out = wrapLuaSourceAsNil('print("hello")', {
  vmVersion: 5,
  compactRecords: true,
  fastCipher: true,
  resultLinks: true,
  keyChain: true,   // optional: boot-derived container key (~+66 KB)
  aead: true,       // optional: ChaCha20-Poly1305 chunk seal (~+4 KB)
  assembledConstants: true, // optional: constants as sealed mini-VM programs (~+10 B)
  tamperSeal: true, // optional: pad-poisoning environment probes (requires keyChain, ~+4 KB)
  hardenedProbes: true, // optional: 009-style coupled mesh (requires tamperSeal)
  operatorSeal: true, // optional: tamper seal arithmetic via overloaded table type (requires tamperSeal, ~+1 KB)
  phaseTokens: true,  // optional: per-helper magic-token call contracts (~+1 KB)
  nameCipher: true,   // optional: byte-subtract names for cached host primitives (~+2 KB)
  // dispatchFamily: 'cascade', // optional: mixed-register equality cascade dispatch
});
```

ค่า default ของ `obfuscateLua` (รวมเว็บ/API): `compactRecords`, `fastCipher`, `resultLinks`, `cfgResultLinks`, `sealedRecords`, `activatedConstants`, `consumerHandlers`, `keyChain`, `tamperSeal`, `hardenedProbes` + guard `if not game or not Instance then return end` (ปิด guard ได้ด้วย `{ skipGuard: true }`) สามารถปิด key chain และชั้นที่พึ่งพากันได้ด้วย `{ vm: { keyChain: false } }`; ตัวเลือก `wrapLuaSourceAsNil` ระดับต่ำยังต้องเปิดชั้นเหล่านี้เอง โค้ดป้องกันที่เพิ่มทำให้ output ใหญ่ขึ้นและมีค่าใช้จ่ายตอน boot

หมายเหตุ: guard ทำให้ script ไม่ทำงานนอกสภาพแวดล้อมที่มี `game` และ `Instance` (เช่น Roblox) เหมาะสำหรับ Roblox scripts ไม่เหมาะกับ server/plain Lua

## REST API

```
POST /api/obfuscate
Content-Type: application/json

{ "code": "print('hello world')" }
```

Response 200:

```json
{
  "status": "success",
  "original_size": 20,
  "obfuscated_size": 51234,
  "duration_ms": 320,
  "obfuscated": "-- Protected with Nil Obfuscator ..."
}
```

Error codes: `400` code ว่าง · `405` method ผิด · `413` body > 256 KB · `429` rate limit (20/min/IP, `Retry-After` header) · `500` compile error

## พัฒนาในเครื่อง

```sh
npm install
npm test        # smoke tests (node-only, ไม่ต้องต่อเน็ต)
```

ทดสอบว่า output รันได้จริงบน Luau: ติดตั้ง Luau CLI (เช่น build จาก https://github.com/luau-lang/luau) แล้ว:

```sh
printf 'game = {}\nInstance = {}\n' > mock.lua
cat mock.lua your-output.lua > run.lua
luau run.lua   # หรือ ./build/luau run.lua
```

## Deploy (Vercel)

โปรเจกต์พร้อม deploy: `vercel.json` rewrite ทุก path ยกเว้น `/api/*` ไปที่ `index.html`, และ `api/obfuscate.js` เป็น serverless function (`maxDuration: 60`)

## ข้อจำกัดที่รู้ตัว (อ่านก่อนใช้)

- Output ต้องการ `buffer` + `bit32` (มีใน Roblox/Luau อยู่แล้ว) — `aead: true` ต้องการ `bit32` เสมอ (มีใน Roblox)
- `keyChain`/`aead` ไม่ใช่การเข้ารหัสลับแบบผู้เห็นข้อมูลไม่ได้ ถ้า executor dump หน่วยความจำหลัง boot สำเร็จ ย่อมได้ plaintext เสมอ — เป้าหมายคือยกระดับต้นทุนของการถอดแบบ static/offline ให้สูงขึ้น ไม่ใช่หวังผลเป็นความลับเด็ดขาด
- `aead` ให้ integrity + authenticity ของ payload แต่ไม่เพิ่ม confidentiality เมื่อใช้เดี่ยวๆ (ใครอ่าน key จากไฟล์ได้ก็ถอดได้) — ต้องใช้คู่กับ `keyChain` เพื่อให้อ่าน key จากไฟล์ไม่ได้
- `assembledConstants` ไม่รองรับการใช้คู่กับ `activatedConstants` หรือ `leanRuntime` (build จะ error ทันที) — เป็นสแตกเก่าที่แทนด้วย assembly ที่แข็งกว่า; รองรับ string/number constant เท่านั้น
- Anti-tamper ของ Nil ทำให้การแกะต้องใช้การ emulate ไม่ใช่ pattern matching — **ไม่ใช่การเข้ารหัสลับ** ข้อมูลที่รันบนเครื่องผู้ใช้ย่อมดึงออกได้เสมอด้วย executor
- Rate limit เป็นแบบ in-memory ต่อ instance; ถ้าต้องการ quota ระดับ edge ให้ใช้ Vercel Firewall/WAF เพิ่ม
- ไฟล์ output ~50 KB ขึ้นไปเสมอ (Nil VM runtime เดินไปกับโปรแกรม)
