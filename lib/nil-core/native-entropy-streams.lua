local function expandNativeStreams(source,inputSize,outputSize)
 local streams,positions,sizes={},{},{},{}
 local target,compressed
 local function expand()
  integer(inputSize,40,16777216);integer(outputSize,1,16777216)
  if buffer.len(source)~=inputSize then invalid()end
  local size=buffer.readu32(source,0);if size<1 or size>16777216 then invalid()end
  local at,total=40,0
  for i=1,4 do
   local header=4+(i-1)*9
   local codec=buffer.readu8(source,header);local length,stored=buffer.readu32(source,header+1),buffer.readu32(source,header+5)
   if codec>1 or length>size or at+stored>inputSize or codec==0 and length~=stored or codec==1 and(length==0 or stored<141)then invalid()end
   compressed=buffer.create(stored);buffer.copy(compressed,0,source,at,stored);at=at+stored
   if codec==1 then streams[i]=expandNativeEntropy(compressed,stored);buffer.fill(compressed,0,0,stored);compressed=nil
   else streams[i]=compressed;compressed=nil end
   if buffer.len(streams[i])~=length then invalid()end
   positions[i]=0;sizes[i]=length;total=total+length
  end
  if at~=inputSize or total~=size or sizes[3]~=sizes[4]then invalid()end
  target=buffer.create(outputSize);local out=0
  local function take(i)
   local at=positions[i];if at>=sizes[i]then invalid()end
   local value=buffer.readu8(streams[i],at);positions[i]=at+1;return value
  end
  local function length(value)
   if value==15 then local extra;repeat extra=take(1);value=value+extra;if value>outputSize then invalid()end until extra~=255 end
   return value
  end
  while positions[1]<sizes[1]do
   local token=take(1);local literals=length(math.floor(token/16))
   if positions[2]+literals>sizes[2]or out+literals>outputSize then invalid()end
   buffer.copy(target,out,streams[2],positions[2],literals);positions[2]=positions[2]+literals;out=out+literals
   if positions[1]==sizes[1]and positions[3]==sizes[3]and positions[4]==sizes[4]then break end
   local offset=take(3)+take(4)*256;local count=length(token%16)+4
   if offset<1 or offset>out or out+count>outputSize then invalid()end
   local start,available=out-offset,offset
   while count>0 do
    local width=math.min(count,available);buffer.copy(target,out,target,start,width)
    out=out+width;count=count-width;available=available+width
   end
  end
  if out~=outputSize then invalid()end
  for i=1,4 do if positions[i]~=sizes[i]then invalid()end end
  return buffer.tostring(target)
 end
 local ok,result=pcall(expand)
 for i=1,4 do if streams[i]then buffer.fill(streams[i],0,0,buffer.len(streams[i]))end end
 if compressed then buffer.fill(compressed,0,0,buffer.len(compressed))end
 if target then buffer.fill(target,0,0,buffer.len(target))end
 if not ok then error(result,0)end
 return result
end
