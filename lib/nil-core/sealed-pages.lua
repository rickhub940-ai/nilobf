-- Bounded cipher over owned VM pages, including opaque packet bytes when inline.
local nibble={}
local bxor=type(bit32)=='table'and type(bit32.bxor)=='function'and bit32.bxor or nil
local shiftLeft=type(bit32)=='table'and type(bit32.lshift)=='function'and bit32.lshift or nil
local shiftRight=type(bit32)=='table'and type(bit32.rshift)=='function'and bit32.rshift or nil
local pageWrite32=native and type(buffer.writeu32)=='function'and buffer.writeu32 or nil
local pageFill=native and type(buffer.fill)=='function'and buffer.fill or nil
local function clearPageSpan(data,offset,length)
 if pageFill then pageFill(data,offset,0,length)
 else for i=offset,offset+length-1 do writeBuffer8(data,i,0)end end
end
if not bxor then
 for a=0,15 do local row={};nibble[a]=row
  for b=0,15 do local x,y,value,factor=a,b,0,1;for i=1,4 do if x%2~=y%2 then value=value+factor end;x=floor(x/2);y=floor(y/2);factor=factor*2 end;row[b]=value end
 end
 bxor=function(a,b)local value,factor=0,1;for i=1,8 do value=value+nibble[a%16][b%16]*factor;a=floor(a/16);b=floor(b/16);factor=factor*16 end;return value end
end
local function pageWord(text,at)local a,b,c,d=byte(text,at,at+3);return a+b*256+c*65536+d*16777216 end
local function pageEntry(key)if type(key)~='string'or #key~=16 then invalid()end;return pageWord(key,1)%4294967295+1 end
local function openSealed(section,key)
 local length=section[3]-8;if length<34 then invalid()end
 local keys={pageWord(key,1),pageWord(key,5),pageWord(key,9),pageWord(key,13)}
 local leftRounds,rightRounds={},{};local sum=0
 for round=1,32 do
  leftRounds[round]=(sum+keys[sum%4+1])%modulus;sum=(sum+2654435769)%modulus
  rightRounds[round]=(sum+keys[floor(sum/2048)%4+1])%modulus
 end
 local low,high=read32(section[2]),read32(section[2]+4)
 local decoded=native and createBuffer(length)or nil;local pieces,block={},{}
 for at=0,length-1,8 do
  local a,b=low,high
  if shiftLeft and shiftRight then for round=1,32 do
   a=(a+bxor((bxor(shiftLeft(b,4),shiftRight(b,5))+b)%modulus,leftRounds[round]))%modulus
   b=(b+bxor((bxor(shiftLeft(a,4),shiftRight(a,5))+a)%modulus,rightRounds[round]))%modulus
  end else for round=1,32 do
   a=(a+bxor((bxor(b*16%modulus,floor(b/32))+b)%modulus,leftRounds[round]))%modulus
   b=(b+bxor((bxor(a*16%modulus,floor(a/32))+a)%modulus,rightRounds[round]))%modulus
  end end
  if pageWrite32 and at+8<=length then
   pageWrite32(decoded,at,bxor(read32(section[2]+8+at),a));pageWrite32(decoded,at+4,bxor(read32(section[2]+12+at),b))
  else for j=0,7 do if at+j<length then
   local word=j<4 and a or b;local mask=floor(word/256^(j%4))%256
   local value=bxor(read8(section[2]+8+at+j),mask)
   if native then writeBuffer8(decoded,at+j,value)else block[#block+1]=string.char(value)end
  end end end
  if not native and #block>=4096 then pieces[#pieces+1]=table.concat(block);block={}end
  low=(low+1)%modulus;if low==0 then high=(high+1)%modulus end
 end
 if not native then pieces[#pieces+1]=table.concat(block);decoded=table.concat(pieces)end
 return decoded,length
end
