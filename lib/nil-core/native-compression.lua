-- Bounded LZ4 block reader. Metadata is supplied by the private VM allocation.
local function expandNativeBlock(source,inputSize,outputSize)
 integer(inputSize,1,16777216);integer(outputSize,1,16777216)
 local isString=type(source)=='string'
 if isString and #source~=inputSize then invalid()end
 local target=binary and create(outputSize)or {}
 local copy= binary and type(buffer.copy)=='function'and buffer.copy or nil
 local writes= binary and type(buffer.writestring)=='function'and buffer.writestring or nil
 local function octet(position)
  if position<0 or position>=inputSize then invalid()end
  return isString and byte(source,position+1)or read(source,position)
 end
 local function expand()
  local at,out=0,0
  local function length(value)
   if value==15 then
    local extra
    repeat extra=octet(at);at=at+1;value=value+extra;if value>outputSize then invalid()end until extra~=255
   end
   return value
  end
  while at<inputSize do
   local token=octet(at);at=at+1
   local literals=length(floor(token/16))
   if at+literals>inputSize or out+literals>outputSize then invalid()end
   if binary and not isString and copy then copy(target,out,source,at,literals)
   elseif binary and isString and writes then writes(target,out,string.sub(source,at+1,at+literals))
   else for i=0,literals-1 do local value=octet(at+i);if binary then write(target,out+i,value)else target[out+i+1]=char(value)end end end
   at=at+literals;out=out+literals
   if at==inputSize then if out~=outputSize then invalid()end;return binary and to(target)or concat(target)end
   local offset=octet(at)+octet(at+1)*256;at=at+2
   if offset<1 or offset>out then invalid()end
   local count=length(token%16)+4
   if out+count>outputSize then invalid()end
   local start=out-offset
   if binary and copy then
    -- Never read unwritten bytes: copy available prefix, then double it.
    local available=offset
    while count>0 do
     local width=math.min(count,available);copy(target,out,target,start,width)
     out=out+width;count=count-width;available=available+width
    end
   else
    for i=1,count do
     if binary then write(target,out,read(target,out-offset))else target[out+1]=target[out-offset+1]end
     out=out+1
    end
   end
  end
  invalid()
 end
 local ok,result=pcall(expand)
 if binary then clearNativeBuffer(target,0,outputSize)else clearNativePieces(target)end
 if not ok then error(result,0)end
 return result
end
