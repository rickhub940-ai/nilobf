-- Streaming HMAC-SHA-256, truncated to 128 bits. Candidate; runtime vectors
-- have not been executed. Keys are gate bytes in the executing host's scope.
local function createBoundPageMac()
 local band,xor,rotate,shift,notBits=bit32.band,bit32.bxor,bit32.rrotate,bit32.rshift,bit32.bnot
 local create,read8,write8,read32,write32,fill=buffer.create,buffer.readu8,buffer.writeu8,buffer.readu32,buffer.writeu32,buffer.fill
 local K={1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298}
 local function start()
  return {h={1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225},block=create(64),words=create(256),used=0,size=0}
 end
 local function clear(s)
  if not s then return end;fill(s.block,0,0,64);fill(s.words,0,0,256)
  for i=1,8 do s.h[i]=0 end;s.used,s.size=0,0
 end
 local function compress(s)
  local w=s.words
  for i=0,15 do write32(w,i*4,bit32.byteswap(read32(s.block,i*4)))end
  for i=16,63 do
   local a,b=read32(w,(i-15)*4),read32(w,(i-2)*4)
   local x=xor(rotate(a,7),rotate(a,18),shift(a,3));local y=xor(rotate(b,17),rotate(b,19),shift(b,10))
   write32(w,i*4,(read32(w,(i-16)*4)+x+read32(w,(i-7)*4)+y)%4294967296)
  end
  local a,b,c,d,e,f,g,h=s.h[1],s.h[2],s.h[3],s.h[4],s.h[5],s.h[6],s.h[7],s.h[8]
  for i=1,64 do
   local x=xor(rotate(e,6),rotate(e,11),rotate(e,25));local choose=xor(band(e,f),band(notBits(e),g))
   local first=(h+x+choose+K[i]+read32(w,(i-1)*4))%4294967296
   local y=xor(rotate(a,2),rotate(a,13),rotate(a,22));local majority=xor(band(a,b),band(a,c),band(b,c))
   local second=(y+majority)%4294967296
   h,g,f,e,d,c,b,a=g,f,e,(d+first)%4294967296,c,b,a,(first+second)%4294967296
  end
  local v=s.h
  v[1],v[2],v[3],v[4]=(v[1]+a)%4294967296,(v[2]+b)%4294967296,(v[3]+c)%4294967296,(v[4]+d)%4294967296
  v[5],v[6],v[7],v[8]=(v[5]+e)%4294967296,(v[6]+f)%4294967296,(v[7]+g)%4294967296,(v[8]+h)%4294967296
 end
 local function put(s,value)
  write8(s.block,s.used,value);s.used=s.used+1;s.size=s.size+1
  if s.used==64 then compress(s);s.used=0 end
 end
 local function finish(s)
  local bits=s.size*8;put(s,128);while s.used~=56 do put(s,0)end
  for i=1,4 do put(s,0)end
  for i=3,0,-1 do put(s,math.floor(bits/256^i)%256)end
  local out=create(32);for i=1,8 do write32(out,(i-1)*4,bit32.byteswap(s.h[i]))end
  clear(s);return out
 end
 return function(key,domain,fields,reader,length)
  if type(key)~='string'or #key~=16 or type(domain)~='number'or domain%1~=0 or domain<0 or domain>3 or type(fields)~='table'or #fields>8 or type(length)~='number'or length%1~=0 or length<0 or length>16777216 or length>0 and type(reader)~='function'then invalid()end
  local inner,outer,digest,output=nil,nil,nil,nil
  local ok,result=pcall(function()
   inner=start();for i=1,64 do put(inner,xor(i<=16 and string.byte(key,i)or 0,54))end
   put(inner,domain);put(inner,#fields)
   for i=1,#fields do
    local n=fields[i];if type(n)~='number'or n%1~=0 or n<0 or n>=4294967296 then invalid()end
    for j=0,3 do put(inner,math.floor(n/256^j)%256)end
   end
   for i=0,length-1 do local value=reader(i);if type(value)~='number'or value%1~=0 or value<0 or value>255 then invalid()end;put(inner,value)end
   digest=finish(inner)
   outer=start();for i=1,64 do put(outer,xor(i<=16 and string.byte(key,i)or 0,92))end
   for i=0,31 do put(outer,read8(digest,i))end
   output=finish(outer)
   return buffer.readstring(output,0,16)
  end)
  clear(inner);clear(outer);if digest then fill(digest,0,0,32)end;if output then fill(output,0,0,32)end
  if not ok then error(result,0)end;return result
 end
end
local boundPageMac=createBoundPageMac()
