-- Private session state. Only compiler-owned materializer code uses the methods.
local host=(getfenv and getfenv(1))or _ENV or _G
local loader,assign=host.loadstring or host.load,host.setfenv
local floor=math.floor
__LIFETIME__
local owners=setmetatable({},{__mode='k'})
local inputs=setmetatable({},{__mode='k'})
local binary=type(buffer)=='table'and type(buffer.create)=='function'and type(buffer.fromstring)=='function'and type(buffer.readu8)=='function'and type(buffer.writeu8)=='function'and type(buffer.tostring)=='function'
local create,read,write,to
if binary then create,read,write,to=buffer.create,buffer.readu8,buffer.writeu8,buffer.tostring end
local function integer(n,low,high)if type(n)~='number'or n%1~=0 or n<low or n>high then invalid()end end
__COMPRESSION_RUNTIME__
__MASK_RUNTIME__
local function owned(output,phase)
 local state=owners[output]
 if not state or state.phase~=phase then invalid()end
 return state
end
local function retireInput(handle,input)
 inputs[handle]=nil
 local release=input.release
 input.reader,input.release,input.batch,input.owner,input.pending=nil,nil,nil,nil,nil
 input.remaining=0;input.version=input.version+1
 return pcall(release)
end
local function retireOutput(output,state)
 owners[output]=nil;state.phase=5
 for handle in pairs(state.leases)do
  local input=inputs[handle]
  if input and input.owner==output then retireInput(handle,input)end
  state.leases[handle]=nil
 end
 local ok,reason=true,nil
 if binary and state.data then ok,reason=pcall(clearNativeBuffer,state.data,0,state.size)end
 clearNativePieces(state.pieces);clearNativePieces(state.starts);__CLEAR_MASK__clearNativePieces(state.operation)
 state.data=nil;state.size,state.cursor=0,0
 return ok,reason
end
local methods={}
local objectMeta={__index=methods,__metatable=false}
methods[__PREPARE__]=function(output,region,at,stride,width,destination,seed,multiplier,increment)
 local state=owned(output,0);local input=inputs[region]
 if not input or input.pending or input.owner and input.owner~=output then invalid()end
 integer(width,1,4096);integer(destination,0,state.size-width);integer(at,1,input.size)
 integer(seed,0,__SEED_LIMIT__);integer(multiplier,1,65535);integer(increment,1,65535)
 if stride~=1 and stride~=-1 or multiplier%2~=1 or increment%2~=1 then invalid()end
 integer(at+(width-1)*stride,1,input.size)
 if destination~=state.cursor or input.remaining<width then invalid()end
 if input.nextAt then if at~=input.nextAt or stride~=input.stride then invalid()end
 elseif at~=(stride==1 and 1 or input.size)then invalid()end
 local token={};local operation=state.operation
 operation.token,operation.receipt=token,nil
 operation.version,operation.inputVersion=state.version,input.version
 operation.region,operation.at,operation.stride,operation.width,operation.destination=region,at,stride,width,destination
 input.owner,input.pending=output,token;state.leases[region]=true;state.phase=1
 __PREPARE_MASK__
end
local function executeWindow(state,input,operation)
 local at,width,stride,destination=operation.at,operation.width,operation.stride,operation.destination
 local window=input.batch and input.batch(at,width,stride)or nil
 if window~=nil and (type(window)~='string'or #window~=width)then invalid()end
 -- Readers and batch functions are internal span closures. Reject reentry and
 -- recheck ownership after any callback before touching the output buffer.
 if state.phase~=2 or state.version~=operation.version or input.version~=operation.inputVersion or input.pending~=operation.token then invalid()end
 local sum,weighted=0,0;local block={};__WINDOW_SEED__
 for i=1,width do
  local position=at+(i-1)*stride
  local encoded=window and byte(window,stride==1 and i or width-i+1)or input.reader(position)
  if not window and (state.phase~=2 or state.version~=operation.version or input.version~=operation.inputVersion or input.pending~=operation.token)then invalid()end
  __DECODE_MASK__
  sum=sum+value;weighted=weighted+sum
  if binary then write(state.data,destination+i-1,value)else block[i]=char(value)end
 end
 if not binary then state.starts[#state.pieces+1]=destination;state.pieces[#state.pieces+1]=concat(block)end
 return sum,weighted
end
methods[__APPLY__]=function(output,token)
 local state=owned(output,1);local operation=state.operation;local input=inputs[operation.region]
 if token~=operation.token or not input or input.owner~=output or input.pending~=token or input.version~=operation.inputVersion or state.version~=operation.version or state.cursor~=operation.destination then invalid()end
 state.phase=2
 local ok,sum,weighted=pcall(executeWindow,state,input,operation)
 if not ok then retireOutput(output,state);error(sum,0)end
 if state.phase~=2 or owners[output]~=state or input.version~=operation.inputVersion or input.pending~=token then retireOutput(output,state);invalid()end
 local receipt={};operation.receipt=receipt;operation.sum,operation.weighted=sum,weighted
 state.phase=3
 return receipt
end
methods[__COMMIT__]=function(output,receipt)
 local state=owned(output,3);local operation=state.operation;local input=inputs[operation.region]
 if receipt~=operation.receipt or not input or input.owner~=output or input.pending~=operation.token or input.version~=operation.inputVersion or state.version~=operation.version or state.cursor~=operation.destination then invalid()end
 local sum,weighted=operation.sum,operation.weighted
 __COMMIT_SEED__
 state.phase=4;state.cursor=operation.destination+operation.width;state.version=state.version+1
 input.remaining=input.remaining-operation.width;input.nextAt=operation.at+operation.width*operation.stride;input.stride=operation.stride
 input.pending=nil;input.version=input.version+1
 local handle=operation.region
 clearNativePieces(operation)
 if input.remaining==0 then
  state.leases[handle]=nil
  local ok,reason=retireInput(handle,input)
  if not ok then retireOutput(output,state);error(reason,0)end
 end
 if owners[output]~=state or state.phase~=4 then retireOutput(output,state);invalid()end
 state.phase=0
 return sum,weighted__RETURN_SEED__
end
methods[__KEY__]=function(output,offset,length,seed)
 local state=owned(output,0)
 integer(length,1,state.size);integer(offset,0,state.size-length);integer(seed,0,4294967295)
 if offset+length>state.cursor or state.version<=1 then invalid()end
 local cursor=seed;local values={}
 for i=0,15 do
  local at=offset+(cursor+i*997)%length;local value
  if binary then value=read(state.data,at)
  else local low,high=1,#state.starts;while low<high do local middle=floor((low+high+1)/2);if state.starts[middle]<=at then low=middle else high=middle-1 end end;value=byte(state.pieces[low],at-state.starts[low]+1)end
  seed=((seed+value+i*4271)%4294967296*65599+floor(seed/65536)*257)%4294967296;values[i+1]=char((value+floor(seed/256^(i%4)))%256)
 end
 return concat(values)
end
methods[__COMPILE__]=function(output)
 local state=owned(output,0)
 if state.cursor~=state.size or state.version<=1 or next(state.leases)then invalid()end
 if type(loader)~='function'then retireOutput(output,state);error('Nil native loader unavailable',0)end
 state.phase=4
 local ok,source=pcall(function()__DECOMPRESS__return binary and to(state.data)or concat(state.pieces)end)
 if not ok then retireOutput(output,state);error(source,0)end
 local cleared,reason=retireOutput(output,state)
 if not cleared then source=nil;error(reason,0)end
 local fn,e=loader(source);source=nil
 if type(fn)~='function'then error(e or 'Nil opaque compile failed',0)end
 if type(assign)=='function'then assign(fn,host)end
 return fn
end
local capabilities={
 [__FLOOR__]=math.floor,
 [__REJECT__]=invalid,
 [__ALLOCATE__]=function(size,decodedSize)
  integer(size,1,16777216)
  if decodedSize~=nil then integer(decodedSize,size+1,16777216)end
  local output=setmetatable({},objectMeta)
  owners[output]={size=size,decodedSize=decodedSize,cursor=0,version=1,phase=0,pieces={},starts={},__MASK_FIELD__operation={},leases={},data=binary and create(size)or nil}
  return output
 end
}
local function nativeRead(slot,key,release__BATCH_ARGUMENT__)
 if type(slot)=='function'then
  integer(key,1,8192)
  if type(release)~='function'__BATCH_CHECK__ then invalid()end
  local input={};inputs[input]={size=key,reader=slot,release=release,batch=__BATCH__,remaining=key,version=1}
  return input
 end
 if key==0 then return host[slot]end
 local value=capabilities[slot];if not value then invalid()end
 return value
end
local nativeWrite=nil
local environment=host
