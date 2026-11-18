-- ChaCha20 + Poly1305 (RFC 8439) for the Nil container AEAD seal.
-- Implemented from the specification; no third-party code.
-- Embedded by containerDecoder when the wrapper is built with aead=true.
-- All values are local; nothing is exported or written to globals.
-- Requires: string.byte/char/sub, table.concat, math.floor, bit32.bxor/band.
local byte, char, concat = string.byte, string.char, table.concat
local floor = math.floor
local bxor, band = bit32.bxor, bit32.band
local MOD32 = 4294967296

local function aeadRotl(x, n)
  x = x % MOD32
  return (x * 2^n + floor(x / 2^(32 - n))) % MOD32
end

local function aeadQr(st, a, b, c, d)
  st[a] = (st[a] + st[b]) % MOD32; st[d] = aeadRotl(bxor(st[d], st[a]), 16)
  st[c] = (st[c] + st[d]) % MOD32; st[b] = aeadRotl(bxor(st[b], st[c]), 12)
  st[a] = (st[a] + st[b]) % MOD32; st[d] = aeadRotl(bxor(st[d], st[a]), 8)
  st[c] = (st[c] + st[d]) % MOD32; st[b] = aeadRotl(bxor(st[b], st[c]), 7)
end

local function aeadBlock(key, counter, nonce)
  local st = { 1634760805, 857760878, 2036477234, 1797285236 }
  for i = 1, 8 do
    local o = (i - 1) * 4
    st[4 + i] = byte(key, o + 1) + byte(key, o + 2) * 256 + byte(key, o + 3) * 65536 + byte(key, o + 4) * 16777216
  end
  st[13] = counter % MOD32
  for i = 1, 3 do
    local o = (i - 1) * 4
    st[13 + i] = byte(nonce, o + 1) + byte(nonce, o + 2) * 256 + byte(nonce, o + 3) * 65536 + byte(nonce, o + 4) * 16777216
  end
  local wk = {}
  for i = 1, 16 do wk[i] = st[i] end
  for _ = 1, 10 do
    aeadQr(wk, 1, 5, 9, 13); aeadQr(wk, 2, 6, 10, 14); aeadQr(wk, 3, 7, 11, 15); aeadQr(wk, 4, 8, 12, 16)
    aeadQr(wk, 1, 6, 11, 16); aeadQr(wk, 2, 7, 12, 13); aeadQr(wk, 3, 8, 9, 14); aeadQr(wk, 4, 5, 10, 15)
  end
  local out = {}
  for i = 1, 16 do
    local w = (wk[i] + st[i]) % MOD32
    out[#out + 1] = char(w % 256, floor(w / 256) % 256, floor(w / 65536) % 256, floor(w / 16777216) % 256)
  end
  return concat(out)
end

local function aeadXor(key, nonce, counter, data)
  local pieces, block = {}, {}
  local offset = 1
  local current = counter % MOD32
  local length = #data
  while offset <= length do
    local keystream = aeadBlock(key, current, nonce)
    local n = math.min(64, length - offset + 1)
    for j = 1, n do
      block[#block + 1] = char(bxor(byte(data, offset + j - 1), byte(keystream, j)))
      if #block == 4096 then pieces[#pieces + 1] = concat(block); block = {} end
    end
    offset = offset + n
    current = (current + 1) % MOD32
  end
  pieces[#pieces + 1] = concat(block)
  return concat(pieces)
end

-- Poly1305 over 16-bit limbs; every column sum fits doubles exactly.
-- p = 2^130 - 5. h stays < p after every block (canonicalized).
local POLY_P = { 65531, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 3 }
local function aeadPoly(key, message)
  local clamped = { byte(key, 1, 16) }
  clamped[4] = band(clamped[4], 15)
  clamped[8] = band(clamped[8], 15)
  clamped[12] = band(clamped[12], 15)
  clamped[16] = band(clamped[16], 15)
  clamped[5] = band(clamped[5], 252)
  clamped[9] = band(clamped[9], 252)
  clamped[13] = band(clamped[13], 252)
  local r = {}
  for i = 1, 8 do r[i] = clamped[2 * i - 1] + clamped[2 * i] * 256 end
  local s = {}
  for i = 1, 8 do s[i] = byte(key, 16 + 2 * i - 1) + byte(key, 16 + 2 * i) * 256 end
  local h = {}
  for i = 1, 10 do h[i] = 0 end
  local length = #message
  local offset = 1
  while offset <= length do
    local blockLen = math.min(16, length - offset + 1)
    -- n = h + (block || 0x01); marker bit lands at absolute bit 8*blockLen
    local n = {}
    for i = 1, 8 do
      local b1 = byte(message, offset + 2 * i - 2)
      local b2 = byte(message, offset + 2 * i - 1)
      if b1 then n[i] = b1 + (b2 or 0) * 256 else n[i] = 0 end
    end
    n[9] = 0
    n[floor(blockLen / 2) + 1] = n[floor(blockLen / 2) + 1] + 2^((blockLen % 2) * 8)
    local carry = 0
    for i = 1, 10 do
      local v = h[i] + (n[i] or 0) + carry
      h[i] = v % 65536
      carry = floor(v / 65536)
    end
    -- t = h * r (limbs 1..18)
    local t = {}
    for i = 1, 18 do t[i] = 0 end
    for i = 1, 10 do
      local hi = h[i]
      if hi ~= 0 then
        for j = 1, 8 do
          t[i + j - 1] = t[i + j - 1] + hi * r[j]
        end
      end
    end
    carry = 0
    for i = 1, 18 do
      local v = t[i] + carry
      t[i] = v % 65536
      carry = floor(v / 65536)
    end
    -- h = (t mod 2^130) + 5*(t div 2^130)
    local lo = {}
    for i = 1, 8 do lo[i] = t[i] end
    lo[9] = band(t[9], 3)
    -- u = t >> 128 (drop 8 limbs), then u >>= 2 (shift across limbs)
    local u = {}
    for i = 1, 10 do u[i] = t[8 + i] end
    local prev = 0
    for i = 10, 1, -1 do
      local cur = u[i]
      u[i] = floor(cur / 4) + prev * 16384
      prev = cur % 4
    end
    carry = 0
    for i = 1, 11 do
      local v = (lo[i] or 0) + (u[i] or 0) * 5 + carry
      lo[i] = v % 65536
      carry = floor(v / 65536)
    end
    -- fold bits >= 130 (w = floor(h / 2^130), small); h = (h mod 2^130) + 5w
    local w = floor((lo[9] or 0) / 4) + (lo[10] or 0) * 16384 + (lo[11] or 0) * 1073741824
    lo[9] = band(lo[9], 3)
    lo[10] = 0
    lo[11] = 0
    carry = w * 5
    local i = 1
    while carry > 0 do
      local v = (lo[i] or 0) + carry
      lo[i] = v % 65536
      carry = floor(v / 65536)
      i = i + 1
    end
    -- one more 2^130 fold if limbs 10/11 are still set (paranoia bound of 3 folds)
    for _ = 1, 3 do
      local over = floor((lo[9] or 0) / 4) + (lo[10] or 0) * 16384 + (lo[11] or 0) * 1073741824
      if over == 0 then break end
      local b = over * 5
      for j = 1, 9 do
        local v = lo[j] + b
        lo[j] = v % 65536
        b = floor(v / 65536)
      end
      lo[9] = band(lo[9], 3)
      lo[10] = 0
      lo[11] = 0
      carry = b
      local j = 1
      while carry > 0 and j <= 11 do
        local v = (lo[j] or 0) + carry
        lo[j] = v % 65536
        carry = floor(v / 65536)
        j = j + 1
      end
    end
    -- canonicalize: if h >= p subtract p once (h < 2^130 after folding above)
    local i = 9
    while i > 0 and lo[i] == POLY_P[i] do i = i - 1 end
    local ge = (i == 0) or (lo[i] > POLY_P[i])
    if ge then
      carry = 5
      for j = 1, 9 do
        local v = lo[j] + carry
        lo[j] = v % 65536
        carry = floor(v / 65536)
      end
      lo[9] = band(lo[9], 3)
    end
    for j = 1, 10 do h[j] = lo[j] or 0 end
    offset = offset + blockLen
  end
  -- tag = (h + s) mod 2^128: carry beyond limb 8 is discarded
  carry = 0
  for i = 1, 8 do
    local v = h[i] + s[i] + carry
    h[i] = v % 65536
    carry = floor(v / 65536)
  end
  local out = {}
  for i = 1, 8 do
    out[#out + 1] = char(h[i] % 256, floor(h[i] / 256) % 256)
  end
  return concat(out)
end
