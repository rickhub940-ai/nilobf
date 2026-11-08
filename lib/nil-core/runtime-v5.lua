-- Encoded records remain encoded at open; handlers consume their own domains.
return function(blob,environment,maxSteps,nativeRead,nativeWrite,entryOverride)
 local signature=__SIGNATURE__
 local byte,sub,floor=string.byte,string.sub,math.floor
 local unpackValues=table.unpack or unpack
 local function pack(...)return {n=select('#',...),...}end
 local function invalid()error('Nil invalid bytecode',0)end
 if type(blob)~='string'or #blob>16777216 or sub(blob,1,#signature)~=signature or type(environment)~='table'or type(maxSteps)~='number'or maxSteps<1 or maxSteps>1000000000 or maxSteps%1~=0 then invalid()end
 local modulus,contextCount=4294967296,__COUNT__
 local function mix(a,b)__MIX__ end
 local function contextFor(history)return (history+floor(history/256))%contextCount+1 end
 local native=type(buffer)=='table'and type(buffer.fromstring)=='function'and type(buffer.readu8)=='function'and type(buffer.readu32)=='function'and type(buffer.create)=='function'and type(buffer.writeu8)=='function'
 local fromBuffer,createBuffer,readBuffer8,readBuffer32,writeBuffer8
 if native then fromBuffer,createBuffer,readBuffer8,readBuffer32,writeBuffer8=buffer.fromstring,buffer.create,buffer.readu8,buffer.readu32,buffer.writeu8 end
 local storage=native and fromBuffer(blob)or blob
 local function read8(offset)if native then return readBuffer8(storage,offset)end;return byte(storage,offset+1)end
 local function read32(offset)if native then return readBuffer32(storage,offset)end;local a,b,c,d=byte(storage,offset+1,offset+4);return a+b*256+c*65536+d*16777216 end
 local position=#signature
 local function need(n)if n<0 or position+n>#blob then invalid()end end
 local function u8()need(1);local n=read8(position);position=position+1;return n end
 local function u32()need(4);local n=read32(position);position=position+4;return n end
 local function range()local n=u32();need(n);local start=position;position=position+n;return {start,n}end
 __PROTOTYPES__
 local function witness(value)
  local kind=type(value)
  if kind=='nil'then return 0 elseif kind=='boolean'then return value and 1 or 2
  elseif kind=='number'then if value~=value or value==math.huge or value==-math.huge then return 3 end;return mix(floor(math.abs(value))%modulus,value<0 and 4 or 5)
  elseif kind=='string'then local n=#value;return mix(n%modulus,n>0 and byte(value,1)+byte(value,n)*256 or 0)
  elseif kind=='table'then return 7 elseif kind=='function'then return 11 elseif kind=='thread'then return 13 else return 17 end
 end
 local contexts,budget,make=nil,{maxSteps},nil
 local privateValues={}
 local function ready(frame)
  if frame.phase~=1 or frame.history~=frame.openHistory or frame.bank~=frame.openBank then invalid()end
 end
 local function constant(frame,slot,key)
  if frame.phase~=1 or frame.history~=frame.openHistory then invalid()end;local p=frame.prototype
  if slot<1 or slot>p.constantCount or key==0 then invalid()end
  local cached=p.cache[slot];if cached then if cached[1]~=key then invalid()end;return cached[2]end
  local tag,value=p.tags[slot],nil
  if tag==0 then return nil elseif tag==1 then value=false elseif tag==2 then value=true
  else
   local r=p.constantData[slot];local pieces,block={},{};local seal=mix(key,tag)
   for j=1,r[2]do
    local v=(p.reader8(r[1]+j-1)-floor(key/256^((j-1)%4))-(j%251)*17)%256
    seal=mix(seal,v);block[#block+1]=string.char(v)
    if #block==4096 then pieces[#pieces+1]=table.concat(block);block={}end
   end
   if seal~=p.constantSeals[slot]then invalid()end
   pieces[#pieces+1]=table.concat(block);value=table.concat(pieces)
   if tag==3 then value=tonumber(value);if not value or value~=value or value==math.huge or value==-math.huge then invalid()end end
  end
  p.cache[slot]={key,value};return value
 end
 local function inverse(odd)local result=1;for i=1,3 do result=result*(2-odd*result)%256 end;return result end
 local function open(frame)
  if frame.phase~=0 or frame.bank~=contextFor(frame.history)then invalid()end
  local offsets=frame.prototype.offsets[frame.cursor];if not offsets then invalid()end
  local ctx=contexts[frame.bank];local offset=offsets[frame.bank];local p,key=frame.prototype,frame.key
  __RECORD_LOOKUP__
  local record=records[frame.bank]
  if record and record.key~=key then invalid()end
  if not record then
  __RECORD_MASKS__
  local encoded=p.reader8(offset);local raw={}
  local stamp=mix(mix(key,ctx.guard),encoded)
  for i=1,8 do raw[i]=p.reader32(offset+1+(i-1)*4);stamp=mix(stamp,raw[i])end
  if (p.reader32(offset+33)-masks[ctx.domains[9]])%modulus~=stamp then invalid()end
  local slot=(encoded-(floor(key/128)+ctx.salt)%256)*masks.inverse%256
  local handler=ctx.handlers[slot];if not handler then invalid()end
  local semantic=mix(mix(key,ctx.guard),slot);for i=1,6 do semantic=mix(semantic,raw[i])end
  record={key=key,masks=masks,encoded=encoded,slot=slot,handler=handler,raw=raw,semantic=semantic,stamp=stamp};records[frame.bank]=record
  end
  frame.masks,frame.raw,frame.semantic,frame.stamp=record.masks,record.raw,record.semantic,record.stamp
  __PATCH_FETCH__
  frame.phase,frame.openHistory,frame.openBank=1,frame.history,frame.bank
  return record.handler
 end
 __PATCH_HELPER__
 local function transfer(frame,nextPc,first,second,result,gated)
  ready(frame)
  local edge;if nextPc==first then edge=1 elseif nextPc==second and second~=first then edge=2 else invalid()end
  if not frame.prototype.offsets[nextPc]then invalid()end
  local ctx=contexts[frame.bank];local capsule=(frame.raw[6+edge]-frame.masks[ctx.domains[6+edge]])%modulus
  local target=(capsule-mix(frame.semantic,(nextPc+ctx.domains[6+edge])%modulus))%modulus;if gated then target=(target-mix(result,ctx.domains[6+edge]))%modulus end;if target==0 then invalid()end
  frame.history=mix(frame.history,mix(frame.stamp,witness(result)))
  frame.cursor,frame.key,frame.phase=nextPc,target,0
  frame.bank=contextFor(frame.history)
  __RETIRE_VIEW__
 end
 contexts={__BANKS__}
 local invocations=0
 make=function(id,upvalues)
  local prototype=prototypes[id]
  return function(...)
   local args,registers,cells=pack(...),{},{}
   for i=1,prototype.parameters do cells[i]={v=args[i]}end
   local varargs={n=0};if prototype.vararg then for i=prototype.parameters+1,args.n do varargs.n=varargs.n+1;varargs[varargs.n]=args[i]end end
   invocations=(invocations+1)%modulus;local history=mix(prototype.entryKey,invocations)
   for i=1,args.n do history=mix(history,witness(args[i]))end
   local frame={id=id,prototype=prototype,cursor=1,key=prototype.entryKey,history=history,phase=0,bank=contextFor(history),raw={},maskCache={},records={}__FRAME_PATCH__}
   while true do
    budget[1]=budget[1]-1;if budget[1]<0 then error('Nil instruction budget exceeded',0)end
    local handler=open(frame)
    local tail,result,values=handler(frame,registers,cells,upvalues,varargs)
    if tail==false then __RETIRE_FRAME__ return unpackValues(result,1,result.n)
    elseif tail==true then __RETIRE_FRAME__ return result(unpackValues(values,1,values.n))end
   end
  end
 end
 return make(entry,{})
end
