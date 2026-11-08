-- Native buffer/bit32 candidate. The block format and 32 XTEA cycles are unchanged.
local bxor,shiftLeft,shiftRight=bit32.bxor,bit32.lshift,bit32.rshift
local pageWrite32,pageFill=buffer.writeu32,buffer.fill
local function clearPageSpan(data,offset,length)pageFill(data,offset,0,length)end
local function pageWord(text,at)local a,b,c,d=byte(text,at,at+3);return a+b*256+c*65536+d*16777216 end
local function pageEntry(key)if type(key)~='string'or #key~=16 then invalid()end;return pageWord(key,1)%4294967295+1 end
if not native then invalid()end
local ok,valid=pcall(function()local n=137438953471;return bxor(n,0)==4294967295 and shiftLeft(n,4)==4294967280 and shiftRight(n,5)==134217727 end)
local nativeWords=ok and valid
local function openSealed(section,key)
 local length=section[3]-8;if length<34 then invalid()end
 local keys={pageWord(key,1),pageWord(key,5),pageWord(key,9),pageWord(key,13)}
 local leftRounds,rightRounds={},{};local sum=0
 for round=1,32 do
  leftRounds[round]=(sum+keys[sum%4+1])%modulus;sum=(sum+2654435769)%modulus
  rightRounds[round]=(sum+keys[floor(sum/2048)%4+1])%modulus
 end
 local low,high=read32(section[2]),read32(section[2]+4)
 local decoded=createBuffer(length)
 for at=0,length-1,8 do
  local a,b=low,high
  if nativeWords then for round=1,32 do
   a=a+bxor(bxor(shiftLeft(b,4),shiftRight(b,5))+b,leftRounds[round])
   b=b+bxor(bxor(shiftLeft(a,4),shiftRight(a,5))+a,rightRounds[round])
  end;a=a%modulus;b=b%modulus
  else for round=1,32 do
   a=(a+bxor((bxor(shiftLeft(b,4),shiftRight(b,5))+b)%modulus,leftRounds[round]))%modulus
   b=(b+bxor((bxor(shiftLeft(a,4),shiftRight(a,5))+a)%modulus,rightRounds[round]))%modulus
  end end
  if at+8<=length then
   pageWrite32(decoded,at,bxor(read32(section[2]+8+at),a));pageWrite32(decoded,at+4,bxor(read32(section[2]+12+at),b))
  else for j=0,7 do if at+j<length then
   local word=j<4 and a or b;local mask=floor(word/256^(j%4))%256
   writeBuffer8(decoded,at+j,bxor(read8(section[2]+8+at+j),mask))
  end end end
  low=(low+1)%modulus;if low==0 then high=(high+1)%modulus end
 end
 return decoded,length
end
