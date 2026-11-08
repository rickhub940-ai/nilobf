local function executeWindow(state,input,operation)
 local at,width,stride,destination=operation.at,operation.width,operation.stride,operation.destination
 if type(input.batch)~='function'then invalid()end
 local window=input.batch(at,width,stride)
 if type(window)~='string'or #window~=width then invalid()end
 if state.phase~=2 or state.version~=operation.version or input.version~=operation.inputVersion or input.pending~=operation.token then invalid()end
 local source=buffer.fromstring(window)
 local read32,write32=buffer.readu32,buffer.writeu32
 local xor,extract,swap=bit32.bxor,bit32.extract,bit32.byteswap
 local seed,multiplier,increment=operation.seed,operation.multiplier,operation.increment
 local sum,weighted,cursor=0,0,0
 while cursor+4<=width do
  local encoded=read32(source,stride==1 and cursor or width-cursor-4)
  if stride==-1 then encoded=swap(encoded)end
  local key=(seed*multiplier+increment+destination+cursor)%4294967296
  local value=xor(encoded,key)
  write32(state.data,destination+cursor,value)
  local a,b,c,d=extract(value,0,8),extract(value,8,8),extract(value,16,8),extract(value,24,8)
  weighted=weighted+4*sum+4*a+3*b+2*c+d;sum=sum+a+b+c+d
  seed=(key+value*257)%4294967296;cursor=cursor+4
 end
 if cursor<width then
  local count=width-cursor;local encoded=0
  for j=0,count-1 do encoded=encoded+read(source,stride==1 and cursor+j or width-cursor-j-1)*256^j end
  local key=(seed*multiplier+increment+destination+cursor)%4294967296
  local value=bit32.band(xor(encoded,key),256^count-1)
  for j=0,count-1 do local octet=extract(value,j*8,8);write(state.data,destination+cursor+j,octet);sum=sum+octet;weighted=weighted+sum end
  seed=(key+value*257)%4294967296
 end
 buffer.fill(source,0,0,width)
 operation.nextSeed=seed
 return sum,weighted
end
