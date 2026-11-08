-- Buffer-only LZ4 reader; caller supplies the compressed allocation.
local function expandNativeBlock(source,inputSize,outputSize)
 integer(inputSize,1,16777216);integer(outputSize,1,16777216)
 if buffer.len(source)~=inputSize then invalid()end
 local target=create(outputSize)
 local copy,read16=buffer.copy,buffer.readu16
 local function expand()
  local at,out=0,0
  local function octet()
   if at>=inputSize then invalid()end
   local value=read(source,at);at=at+1;return value
  end
  local function length(value)
   if value==15 then
    local extra
    repeat extra=octet();value=value+extra;if value>outputSize then invalid()end until extra~=255
   end
   return value
  end
  while at<inputSize do
   local token=octet();local literals=length(floor(token/16))
   if at+literals>inputSize or out+literals>outputSize then invalid()end
   copy(target,out,source,at,literals);at=at+literals;out=out+literals
   if at==inputSize then if out~=outputSize then invalid()end;return to(target)end
   if at+2>inputSize then invalid()end
   local offset=read16(source,at);at=at+2
   if offset<1 or offset>out then invalid()end
   local count=length(token%16)+4
   if out+count>outputSize then invalid()end
   local start,available=out-offset,offset
   -- copy snapshots its input. Grow the written prefix before copying again.
   while count>0 do
    local width=math.min(count,available);copy(target,out,target,start,width)
    out=out+width;count=count-width;available=available+width
   end
  end
  invalid()
 end
 local ok,result=pcall(expand)
 clearNativeBuffer(target,0,outputSize)
 if not ok then error(result,0)end
 return result
end
