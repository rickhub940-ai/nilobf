local function expandNativeEntropy(source,inputSize)
 local target,lookup
 local function expand()
  if type(inputSize)~='number'or inputSize%1~=0 or inputSize<141 or inputSize>16777216 or buffer.len(source)~=inputSize then invalid()end
  local size,bits=buffer.readu32(source,0),buffer.readu32(source,4)
  local packed=bits>=2147483648;if packed then bits=bits-2147483648 end
  local base=packed and 136 or 264
  if size<1 or size>16777216 or bits<size or bits>size*15 or inputSize~=base+4+math.floor((bits+7)/8)then invalid()end
  local function codeWidth(symbol)
   local value=buffer.readu8(source,8+(packed and math.floor(symbol/2)or symbol))
   if packed then if symbol%2==0 then return value%16 end;return math.floor(value/16)end
   return value
  end
  local counts,starts,maximum,used={},{},0,0
  for i=1,15 do counts[i]=0 end
  for symbol=0,255 do
   local width=codeWidth(symbol)
   if width>15 then invalid()end
   if width>0 then counts[width]=counts[width]+1;used=used+1;if width>maximum then maximum=width end end
  end
  if used<2 then invalid()end
  local code=0
  for width=1,maximum do
   code=(code+(counts[width-1]or 0))*2;starts[width]=code
   if code+counts[width]>2^width then invalid()end
  end
  if code+counts[maximum]~=2^maximum then invalid()end
  local limit=2^maximum;lookup=buffer.create(limit*2)
  local read8,read32,read16,write8,write16=buffer.readu8,buffer.readu32,buffer.readu16,buffer.writeu8,buffer.writeu16
  local band,shift=bit32.band,bit32.rshift
  for symbol=0,255 do
   local width=codeWidth(symbol)
   if width>0 then
    local value=starts[width];starts[width]=value+1;local reversed=0
    for i=1,width do reversed=reversed*2+value%2;value=math.floor(value/2)end
    for index=reversed,limit-1,2^width do write16(lookup,index*2,width*256+symbol)end
   end
  end
  target=buffer.create(size);local position,available,reservoir=0,0,0
  for at=0,size-1 do
   if available<maximum then local offset=position%8;reservoir=shift(read32(source,base+math.floor(position/8)),offset);available=32-offset end
   local value=read16(lookup,band(reservoir,limit-1)*2);local width=shift(value,8)
   if width<1 or position+width>bits then invalid()end
   write8(target,at,value%256);reservoir=shift(reservoir,width);available=available-width;position=position+width
  end
  if position~=bits then invalid()end
  local finish=base+math.floor((bits+7)/8)
  for at=finish,inputSize-1 do if read8(source,at)~=0 then invalid()end end
  if bits%8~=0 and shift(read8(source,finish-1),bits%8)~=0 then invalid()end
  return target
 end
 local ok,result=pcall(expand)
 if lookup then buffer.fill(lookup,0,0,buffer.len(lookup))end
 if not ok then if target then buffer.fill(target,0,0,buffer.len(target))end;error(result,0)end
 return result
end
