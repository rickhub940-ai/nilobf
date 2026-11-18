# วิเคราะห์ `skibidi_obfuscator` เชิงลึก + สิ่งที่ยกมาใช้ใน Nil

> วิเคราะห์จากไฟล์ตัวอย่าง `skibidi_obfuscator.lua.txt` (156,607 bytes, บรรทัดเดียว)
> **วิเคราะห์แบบ static เท่านั้น — ไม่ได้รันตัวอย่าง** (ไม่ไว้ใจโค้ด obfuscated โดยตรง)
> เอกสารนี้สรุปโครงสร้างที่ทำให้ถอดยาก และบอกว่าแต่ละอย่างถูกยกมาใช้ใน Nil obfuscator ตรงไหน

## 1. ภาพรวมของตัวอย่าง

ลายเซ็นแรกของไฟล์คือ

```
return setmetatable({[63]=string.sub,[23]=table.unpack,[79]=function(u,g,d) ... ,
```

และตอนท้ายสุด:

```
},{}):q()(...);
```

คือ `setmetatable(<dispatch table>, {})` แล้วเรียกเมทอด `q` ของตารางนั้นด้วย `...` —
`q` คือ **factory** ที่อ่าน payload blob, ถอด layer ต่างๆ แล้วคืนค่าเป็น
"ฟังก์ชันรันงานจริง" ที่ถูกเรียกทันที ผลลัพธ์ทั้งหมดคือ closure เดียวที่ทำงานแทน main ตัวจริง

### ตัวเลขที่วัดได้

| สิ่งที่วัด | ค่า |
|---|---|
| ขนาดไฟล์ | 156,607 bytes (บรรทัดเดียว ไม่มี `\n`) |
| คีย์ตัวเลขที่นิยามในตาราง dispatch (top-level) | 90 คีย์ (วัดจาก `[N]=`) |
| คีย์ที่ถูกอ้างอิงผ่าน `u[N]` | 76 คีย์ รวม 194 จุดอ้างอิง |
| payload blob `[190]` | 149,817 ตัวอักษร (base-91) — คิดเป็น ~96% ของไฟล์ |
| alphabet `[248]` | พิมพ์ได้ 91 ตัว (base-91, ไม่มี whitespace ไม่มี `\`) |

## 2. โครงสร้างที่ทำให้ถอดยาก (ชั้นต่อชั้น)

### 2.1 Numeric dispatch table แทนชื่อฟังก์ชัน — ทุกอย่างเรียกผ่าน `u[N]`

ฟังก์ชัน runtime ทุกตัว (`string.byte`, `buffer.fromstring`, …) ถูกจับเป็นค่าในตาราง
ที่คีย์ด้วยเลข ไม่ใช่ชื่อ ผู้อ่านไม่เห็น `string.byte` ตรงๆ — เห็นแค่ `u[149]`
ซึ่ง conceal ได้ดีกว่าชื่อตัวแปรธรรมดา: ต้อง build map `N -> ความหมาย` ทั้งไฟล์ก่อน
ถึงจะเดาได้ว่าเรียกอะไร

### 2.2 Alias chain หลายชั้น — เรียกผ่านฟังก์ชันที่คืนฟังก์ชัน

จุดที่น่าสนใจคือ pattern แบบนี้ (ย่อ):

```lua
u[2e2]=function(g,d) return u[254](g,d) end
u[208]=function(g,d,X) return u[86](g,d,X) end
```

คือ alias ที่ห่อฟังก์ชันอีกที — ตัวเรียกจริง `u[2e2]` ไม่ได้ทำอะไรนอกจาก
"ส่งต่อให้ `u[254]`" ซึ่งในที่สุดวิ่งลงไปถึง `buffer.fromstring` หรือตัวถอด alphabet
การไล่ chain แบบนี้ที่มีเกือบ 200 จุด ทำให้ CFG-based decompiler สร้าง graph
ที่ไร้ประโยชน์ออกมาทั้งก้อน — ต้อง resolve alias 100% ก่อนถึงจะสรุปเรียกอะไร

### 2.3 Custom alphabet (base-91) + ตัวถอดเอง 5→4 byte

```lua
[248]=[[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"]]
```

91 ตัว และ decoder หลัก (เจอใน `[118]` และบริเวณใกล้กัน) ทำงานแบบ
"อ่าน 5 ตัวอักษร ถอดเป็น 4 ไบต์" ด้วย weights ที่คูณด้วย 91 (base-91 packing)
พร้อม special-case remainder (`{[0]=0,[1]=3,[2]=1,[4]=2}[(X%5)]`)
ไม่ใช่ base64/base85 มาตรฐาน — ต้องเขียน decoder เองจาก spec ที่ฝังในโค้ด

### 2.4 Blob ถูก XOR บางส่วน + ผ่าน bit reader

หลังจากได้ bytes จาก base-91 แล้ว ยังมี layer XOR บนขอบเขตที่ header ของ blob ระบุ
(`d[5..4+X]`) ก่อนจะถูกป้อนเข้า VM ของตัวเอง การแกะจึงต้องทำสองขั้น:
แยกส่วนที่ถูก XOR ออกจากส่วนที่ไม่ถูกก่อน

### 2.5 Bit-buffer reader pipeline + varint

หัวใจของการถอดคือชุดฟังก์ชันอ่านบิต:

- `[40]` — bit reader: เลื่อนบิตทีละบิต เทียบ threshold 2048/32
- `[4]`/`[144]` — อ่าน u32 LE จาก offset แล้วแยก bit field
- `[86]` — reader หลักของ instruction stream
- `[59]` — varint decoder: อ่าน 3-bit tag แล้วตามด้วย payload ความยาวตาม tag

ทั้งหมดนี้ออกแบบมาให้ linear scan ทำไม่ได้ — ต้อง emulate ตัวอ่านเอง

### 2.6 Custom bytecode VM + `eI` interpreter method

หลังถอด base-91 + XOR แล้วได้ **bytecode ของ VM ส่วนตัว** ซึ่งถูกส่งเข้า
`E:eI(...)` — `eI` คือเมทอดหลักของ interpreter object (ปรากฏ 19 จุด)
bytecode ไม่ใช่ Lua bytecode มาตรฐาน ไม่มี tool สาธารณะรองรับ
ต้อง reverse VM semantics ทีละ instruction เองทั้งหมด — นี่คือชั้นที่แพงที่สุด

### 2.7 Metatable plumbing + closure ปิดปาก

`setmetatable(<table>, {})` ครอบทั้งไฟล์ แล้ว `:q()(...)` สร้าง closure งานจริง
__ไม่มี__ string literal สำหรับ error path, ทุกอย่าง fail ด้วยการคืนค่าผิด
ทำให้การ trace ด้วย print ธรรมดาไม่เห็นอะไรเลย

### สรุป

ตัวอย่างนี้ "ยากต่อ decompiler" ไม่ใช่เพราะเทคนิคใดเทคนิคหนึ่ง แต่เพราะ
**เชนการแปลง 4 ชั้น** (base-91 → XOR → bytecode VM → `eI`) ที่ทุกชั้น
ไม่มีสเปคสาธารณะ + numeric dispatch + alias chains 200 จุด
ถ้าไม่ emulate boot ทั้งหมด จะไม่มีทางเห็นแม้แต่ค่าคงที่ 1 ตัว

## 3. สิ่งที่ยกมาใช้ใน Nil obfuscator (และที่ไม่ใช้ เพราะอะไร)

### 3.1 ยกมาใช้แล้ว

| โครงสร้างจากตัวอย่าง | ของ Nil | สถานะ |
|---|---|---|
| Boot-derived key: pad คำนวณตอน boot ไม่เคยอยู่ในไฟล์ | Key chain (`buildKeyChain`): boot VM สร้าง pad 32 ไบต์, container header เก็บ `(key+pad)%256` | มีอยู่แล้ว |
| Anti-tamper penalty ฝังใน pad derivation | boot pad ผสม `m*(i*149+37)` ก่อนคืน | มีอยู่แล้ว |
| Probes สภาพแวดล้อม + บิด pad เมื่อพบสิ่งผิดปกติ | **`tamperSeal: true`** (ใหม่): probes 10 ตัว (pcall lane, error-box, metatable `__add`/`__eq`, `getfenv`/`setfenv` round-trip, raw table, math core, `2^64` float, optional `buffer`/`bit32` known-answer) พับผลด้วย odd-multiplier folds 32-bit + 3 salted re-verification lanes — ถ้าผิดแม้แต่ตัวเดียว pad จะถูกเลื่อนทุกไบต์ด้วย feedback generator → key ปลอดเป็นขยะ → AEAD/Adler ไม่ผ่าน → boot ล้มเหลวแบบ fail-closed โดยไม่มี output ใดๆ | **ใหม่** |
| Alias chain indirection | runner passes: `liftRunnerHelpers`/`poolRunnerPrimitives`/`concealRunnerStrings`/`renameRunnerBindings` | มีอยู่แล้ว |
| Randomized printable alphabet (base-91 ในตัวอย่าง) | `randomRadix85Alphabet()` — radix-85 alphabet สุ่มต่อ build | มีอยู่แล้ว |
| Numeric dispatch / ไม่มีชื่อฟังก์ชัน | V5 dispatcher + `randomNumericKey` handler fields | มีอยู่แล้ว |
| Callable entry ผ่าน metatable | `callableEntry: true` (`__call`) | มีอยู่แล้ว |
| Blob เข้ารหัสที่ต้อง emulate ก่อนอ่านอะไรได้ | AEAD seal + key chain + VM blob | มีอยู่แล้ว |

### 3.2 ที่ไม่ยกมา (และเหตุผล)

- **Custom bytecode VM ใหม่ทั้งหมด** — Nil VM V5 มีอยู่แล้ว (compact records,
  result links, sealed records, activated constants) ไม่จำเป็นต้องมี VM ที่สอง
  ทับซ้อนกัน
- **base-91 transport แทน radix-85** — หลักการเดียวกัน เปลี่ยนแค่ alphabet
  ซึ่ง Nil สุ่มอยู่แล้ว; การเพิ่มอีก codec ไม่เพิ่มความยากจริง
- **LZ/Huffman บีบ blob ก่อนเข้ารหัส** — ทดลองบน blob จริงแล้ว **บีบไม่ได้**
  (opcode stream ใกล้จะ random: Huffman ratio ไม่ผ่านเกณฑ์, LZSS greedy
  ได้ ratio > 1) การเพิ่ม decode stage ที่ไม่เคยทำงาน = ค่าใช้จ่ายล้วนๆ จึงไม่เอา
- **XOR layer เดี่ยว** — เรามี ChaCha20-Poly1305 ที่แข็งกว่า ไม่ต้องถอยหลัง

### 3.3 ข้อจำกัดที่ยอมรับได้ (เหมือนเดิม)

Anti-tamper ฝั่ง client ทุกตัวถูก NOP ได้เสมอถ้าจับคู่กับเครื่อง executor ที่ดัก
memory — จุดประสงค์คือทำให้การถอดแบบ static/offline แพงขึ้นมาก ไม่ใช่หวังผล
เป็นความลับระดับการ์ดเครดิต

## 4. การตรวจสอบ

รอบทดสอบ `tamperSeal` (ดู `test.mjs` + การรันจริงใต้ Luau 0.747):

- wrapper ที่เปิด `tamperSeal` boot สำเร็จเหมือนปกติ (hello/42, sum 338350, …)
- sabotage สภาพแวดล้อม 5 แบบ (broken `getfenv`, `math.sin` โกหก,
  `error()` แปลงทุกอย่างเป็น string, `buffer` ที่ไม่ทำงาน, ตาราง `setmetatable`
  ที่ตัด `__eq`/`__add`) → **boot ล้มเหลวทั้งหมด**
- สภาพแวดล้อม custom ที่ __ไม่ได้__ sabotage (ตารางใหม่ + `__index = global`) → boot ปกติ
- saboteur แบบเดียวกันแต่ wrapper ที่ __ไม่มี__ `tamperSeal` → boot ปกติ
  (พิสูจน์ว่า gate คือสิ่งที่ทำให้ล้ม ไม่ใช่ payload)

ไม่ commit จนกว่าจะได้รับอนุญาตจากผู้ใช้

## 5. ถอด Layer 2 จริง (emulation ชั้น decompress) — สำเร็จ

การทำงานของชั้นที่ 2 (หลัง base-91 transport) ทำสำเร็จตั้งแต่รอบที่ผ่านมาโดย
**สร้าง decoder ใหม่ใน Python จาก source ต้นฉบับ** (`.scratch/decomp.py`)
โดยไม่ execute อะไรที่ดาวน์โหลดมา ผลคือ:

- input: `.scratch/skibidi_decoded.bin` (119,853 ไบต์, entropy ≈ 7.999)
- reservoir `r = 0xFFFFFFFF`, seed 4 ไบต์แรก (ข้าม magic 0x00) เป็น big-endian
- bit decoder แบบ adaptive (u32 reservoir + `E=(r//2048)*X` split + update
  `X += (2048-X)//32` ทุกศูนย์) + canonical Huffman หลายชุด (สไตล์ u[86]/u[59])
- output: **351,759 ไบต์** ตรงเป๊ะ 100% printable Lua

Head ของ output: `<u32le 317,593>` + `return({ie=function(W,...`

```
X = u32le(d[:4]) = 317,593  →  .scratch/skibidi_bootstrap.lua  (source ของ Lua จริง)
d[4+X:] (segB)              →  34,162 ไบต์ ไบนารี (entropy ≈ 7.993 → ข้อมูลถูกเข้ารหัส/บีบอัดอยู่)
```

segB ถูกส่งให้ VM พร้อม `u[52]` ตอน `loadstring` bootstrap แล้วเรียก
`(bridge)(buffer.fromstring(segB), u[52])` — ตัว bootstrap เอง **ไม่ถูก execute**
ในการวิเคราะห์นี้ (static analysis เท่านั้น)

## 6. สถาปัตยกรรมของ bootstrap ที่กู้คืนมาได้

bootstrap (317,593 ไบต์) เป็น **source Lua ชิ้นเดียว**:
`return({...methods...}):ek(...)` — ตาราง methods (key 1–2 ตัวอักษร,
259 ฟังก์ชัน, 235 ชื่อไม่ซ้ำ) + ตัว dispatch `ek` ที่รับ `W` (runtime object)
กับ varargs (`segB`, `u[52]`)

### 6.1 ชั้น runtime ของ VM (reconstructed statically)

| โครงสร้าง | หน้าที่ |
|---|---|
| `ek=function(W,...)W.Xs,W.Ig=...;if not bit32 then({})[1]();end` | ทางเข้าหลักของ VM; ตรวจ `bit32` (Roblox/Luau) — ถ้าไม่ใช่ให้ตายเงียบๆ |
| `W[238..18],W.D = buffer.create, buffer.readu32/16/8, bit32.*, table.*, ...` | mapping ตัวเลข → global primitives ใน VM namespace; **ไม่มีชื่อตัวแปรของ runtime เหลือเลย** |
| `W[231] = function(h,y,f,z)...` | เทมเพลต executor: ถ้า `y` เป็น function คืนตรงๆ ไม่งั้นห่อด้วย `Rf` + ก๊อป 117 register ผ่าน `wz` |
| `W.rI = function(h,y)W[h]=y` | ตัว set แบบ dynamic: `W[number] = value` — ผูก function เข้ากับช่องตัวเลข (VM ต่อไปเรียกด้วย `W[idx]`) |
| `W.eK` | round-function Feistel ที่ key schedule มาจาก `W.ft` (ตาราง constant ถูก derive จาก `(k*P*2654435769)%2^32` rotations) |
| `W.Re` (ตาราง constant หลายสิบช่อง `{seed, ka, kb, len, data}`) | resources ที่เข้ารหัส — แต่ละช่องคือ Lua chunk ที่ถูกเข้ารหัส |
| `W.Uu` / `W.Tv` (metatable `__sub`) / `W.L6` | ตัวถอด block cipher: derive round keys, allocate buffer, เขียนผลทีละบล็อก |
| `setmetatable(W.zx, {[W.P("…__index…")]=function(c,V)…W.eK…W.uK…})` | **lazy decryption**: แตะ `W.zx[i]` ครั้งแรก → ถอด chunk i; แคชใน `W.uK` |
| `W.P(n)`/`W.P` | helper ประกอบ byte → string |
| `fz` และอีกหลายตัว | **interpreter ภายใน VM**: dispatch ด้วย cascade `if(F<const)` บนค่าตัวเลข — magic thresholds สุ่ม (เป็น interpreter ของ bytecode อีกชั้น) |
| `C0=getfenv` | เก็บตัวอ้างอิง global env ก่อน sandbox |
| `W.wu=9; W.L=W.m; W.N=W.J` | env descriptor — ตาราง `W.D` (ว่างตอนแรก) คือ sandbox environment ที่ VM สร้างแล้ว inject เข้า chunk |

### 6.2 Phase-handshake (สิ่งที่น่าสนใจที่สุดสำหรับการทำ anti-reverse)

VM เดินเป็น **เฟส**: แต่ละ method มี signature `function(W,Q,...)if(Q~=N)then local J;J();end`
— ถ้า caller ส่ง token เฟสผิด (ไม่ใช่ N) จะ crash แบบ nil-call ทันที
token ทุกตัวถูก derive จาก bootstrap เองไม่มีเบาะแสอื่น

chain ที่กู้คืนจาก static analysis:

```
ek(...)  →  vh(W,229)  →  f8(W,122)  →  AX(W,160)  →  ha(W,49)  →  jx(W,172)
              (ปล่อย W.m,W.J เป็น nil)
```

และทุกเฟส resolve ตัวข้างหน้าโดย **ถอดชื่อฟังก์ชันจาก `W.x4` ด้วย byte-subtract cipher**:

- `HS` → `W.x4["coroutine"(213,225,228,... − 114)]["yield"(246,230,... − 125)]` → `coroutine.yield`
- `BA` → `"coroutine" + "wrap"(139,134,117,132 − 20)` → `coroutine.wrap`

ดังนั้น: ไม่มี symbol ชื่อจริงเหลือในไฟล์เลย — แม้แต่ชื่อ `coroutine.yield`
ก็ถูกเข้ารหัส + ถูก bind หลังผ่าน checkpoint เท่านั้น และทุกเฟสตรวจ token
ก่อนทำงาน (mismatch = crash ทันที โดยไม่มี error message)

### 6.3 Resource pipeline (ฝั่ง payload จริง)

```
W.Re[i] = {seed, ka, kb, len, data(encrypted)}
  → W.eK(key schedule) + W.Uu/W.Tv (rounds: xor/rotate/sub แบบ variable rotations)
  → plaintext bytes → W[166] (buffer.fromstring) → W.qy (source Lua)
  → W.W8(W, W.qy, abs(H), H<0) (execute ใน sandbox W.D) → cache ใน W.uK
```

นั่นคือ "bytecode" ของ skibidi = **Lua source ที่เข้ารหัสไว้เป็น resources**

นั่นคือ "bytecode" ของ skibidi = **Lua source ที่เข้ารหัสไว้เป็น resources**
ไม่ใช่ bytecode ของ VM อีกชุด — VM เป็นแค่ตัวถอด + ตัว trampoline

### 6.4 ข้อสังเกตสำคัญ

- ไม่มี string ที่อ่านรู้เรื่องเลยนอกจาก key constant + ข้อความ encrypted
- ไม่มีชื่อ global ของ Roblox โผล่ตรงๆ (ไม่มี `game`, `script`, `require` เลย)
- ตัวเลข magic ทุกตัว (`2654435769`, `0x9E3779B1`, rotations) เป็นค่า multiplier ของ
  hash/mixing — สื่อถึงตระกูล Murmur-style mixing
- `({})[1]()` = nil-call 64 ครั้ง = crash แบบไม่มี error message
- ทั้งระบบถูกออกแบบเป็นสาย **sequential** — ถ้าแตะลำดับเฟสเดียว ทั้ง VM ตายเงียบ

### 6.5 สิ่งที่ตั้งใจไม่ทำ

- **ไม่ execute bootstrap** และไม่พยายามถอด resource chunks ออกมา — นั่นคือ
  payload จริงของคนอื่น; เป้าหมายของงานนี้คือสถาปัตยกรรม anti-reverse ไม่ใช่
  การเรียกใช้โค้ดของผู้อื่น

### 7. สิ่งที่เอามาใช้กับ Nilobf ได้ (ข้อเสนอ)

| # | เทคนิคจาก skibidi | สถานะ | รายละเอียด |
|---|---|---|---|
| 7.1 | Phase-handshake token guard | **เสร็จ (`phaseTokens: true`)** | helper ที่ `liftRunnerHelpers` ยกออกจาก object ทุกตัวต้องรับ magic token ต่อ build เป็น argument แรก — method ตรวจ token ก่อนแตะสถานะ VM มิฉะนั้น `({})[1]()` (nil-call) ทันที — call site ที่ wrapper สร้างให้ถูกแก้ให้ส่ง token อัตโนมัติ ผู้เรียกภายนอกไม่ได้รับผลกระทบ — เทสต์: wrapper boot ใต้ Luau 0.747 ถูกต้อง (print 5050) + parse check + type guard |
| 7.2 | Byte-subtract name cipher | **เสร็จ (`nameCipher: true`)** | primitives ที่ `poolRunnerPrimitives` cache ลง numeric slots ถูกประกอบจาก byte-subtract table ต่อ slot ตอน object ถูกสร้าง (`_G[string.char((b+K)%256,…)]…`) key สุ่ม 32–200 ต่อ slot — output ไม่มีชื่อ `string.byte` ฯลฯ ให้ regex ได้เลย |
| 7.3 | Lazy resource decryption ผ่าน `setmetatable(env, __index)` + cache | ยังไม่ทำ | ต้องมีแนวคิด resource/loader — รออนุมัติ scope |
| 7.4 | Feistel/rotate-XOR rounds แบบ variable rotations | ยังไม่ทำ | มี ChaCha20-Poly1305 อยู่แล้ว — ถ้าจะทำควรเป็นชั้นเสริมไม่ใช่แทน AEAD |
| 7.5 | Sandbox environment `W.D` (env แยก + เก็บ/คืน global) | ยังไม่ทำ | setfenv/_G proxy — รออนุมัติ scope |
| 7.6 | Operator-overloaded int ops บนตาราง | **เสร็จ (`operatorSeal: true`, ต้องเปิด `tamperSeal`)** | fold arithmetic ใน tamper seal (gate-seal) ส่งผ่าน overloaded table type (`NT` metatable `__add`/`__sub`/`__mul`/`__mod`) semantics เหมือนเดิมทุกไบต์ (ตรวจ boot ใต้ Luau 0.747: clean ผ่าน + sabotaged 6 แบบ (math.sin โกหก, error() ป่วย, setmetatable ถูกตัด hook, getfenv nil, pcall ถูก gut) ล้มทั้งหมด) |
| 7.7 | Numeric-threshold dispatch cascade | **เสร็จ (`dispatchFamily: 'cascade'`)** | dispatch family ที่สาม: `k = (op*MUL + ADD) % 2^32` (MUL/ADD สุ่มต่อ build) แล้ว if/elseif chain ด้วย probe `k==…` + `invalid()` tail เดียว — branch structure ไม่เผย mapping opcode→handler — 38 arms — ยืนยันใต้ Luau 0.747 |

หมายเหตุการตรวจสอบ:

- ทั้ง 4 ตัว boot จริงใต้ **Luau 0.747** (build จาก source ติดตั้งใหม่ที่ /tmp/luau-build/luau)
  — payload ตัวอย่าง (`print` + loop 100 รอบ → 5050) ทำงานถูกต้องทุก variant
  รวมถึง `all` (ครบ 4 ตัวพร้อมกัน)
- Node test suite: 47 → 67 checks ผ่านทั้งหมด (เพิ่ม 20: parse/type-guard/content/guard tests)
- Name cipher ยังเหลือ `string.char` เป็นชื่อตรงในตัว decoder ของมันเอง (หลีกเลี่ยงได้
  แต่ไม่จำเป็น — ไม่เผย stdlib อื่น)
- cascade ช้ากว่า tree (linear scan) — เป็นตัวเลือก ไม่ใช่ default
