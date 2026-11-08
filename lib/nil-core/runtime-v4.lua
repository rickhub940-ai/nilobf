-- Per-invocation state and transition records; no bulk instruction decoder.
return function(blob, environment, maxSteps)
 local signature=__SIGNATURE__
 local byte,sub,floor=string.byte,string.sub,math.floor
 local unpackValues=table.unpack or unpack
 local function pack(...)return {n=select('#',...),...}end
 local function invalid()error('Nil invalid bytecode',0)end
 if type(blob)~='string' or #blob>16777216 or sub(blob,1,#signature)~=signature or type(environment)~='table' or type(maxSteps)~='number' or maxSteps<1 or maxSteps>1000000000 or maxSteps%1~=0 then invalid()end
 local modulus=4294967296
 local function mix(a,b)__MIX__ end
 local function mask(key,slot)return mix(key,slot*65537)end
 local native=type(buffer)=='table' and type(buffer.fromstring)=='function' and type(buffer.readu8)=='function' and type(buffer.readu32)=='function' and type(buffer.create)=='function' and type(buffer.writeu8)=='function' and type(buffer.writeu32)=='function'
 local fromBuffer,createBuffer,readBuffer8,readBuffer32,writeBuffer8,writeBuffer32
 if native then fromBuffer,createBuffer,readBuffer8,readBuffer32,writeBuffer8,writeBuffer32=buffer.fromstring,buffer.create,buffer.readu8,buffer.readu32,buffer.writeu8,buffer.writeu32 end
 local storage=native and fromBuffer(blob) or blob
 local function read8(offset)if native then return readBuffer8(storage,offset)end;return byte(storage,offset+1)end
 local function read32(offset)if native then return readBuffer32(storage,offset)end;local a,b,c,d=byte(storage,offset+1,offset+4);return a+b*256+c*65536+d*16777216 end
 local position=#signature
 local function need(n)if n<0 or position+n>#blob then invalid()end end
 local function u8()need(1);local n=read8(position);position=position+1;return n end
 local function u32()need(4);local n=read32(position);position=position+4;return n end
 local function range()local n=u32();need(n);local start=position;position=position+n;return {start,n}end
 local nilType,booleanType,numberType,stringType,tableType,functionType,threadType='nil','boolean','number','string','table','function','thread'
 local function witness(value)
  local kind=type(value)
  if kind==nilType then return 0 elseif kind==booleanType then return value and 1 or 2
  elseif kind==numberType then if value~=value or value==math.huge or value==-math.huge then return 3 end;return mix(floor(math.abs(value))%modulus,value<0 and 4 or 5)
  elseif kind==stringType then local n=#value;return mix(n%modulus,n>0 and byte(value,1)+byte(value,n)*256 or 0)
  elseif kind==tableType then return 7 elseif kind==functionType then return 11 elseif kind==threadType then return 13 else return 17 end
 end
 local count,entry=u32(),u32()
 if count<1 or count>4096 or entry<1 or entry>count then invalid()end
 local prototypes,totalConstants,totalInstructions={},0,0
 for id=1,count do
  local p={};p.parent,p.parameters,p.vararg=u32(),u32(),u8();p.registers,p.cells=u32(),u32()
  if p.parent>=id or p.vararg>1 or p.registers>65535 or p.cells>8192 or p.parameters>p.cells then invalid()end
  p.vararg=p.vararg==1;p.upCount=u32();if p.upCount>8192 then invalid()end;p.up={}
  for i=1,p.upCount do local kind,slot=u8(),u32();if kind>1 or slot<1 then invalid()end;p.up[i]={kind,slot}end
  p.entryKey=u32();if p.entryKey==0 then invalid()end
  p.constantCount=u32();totalConstants=totalConstants+p.constantCount;if totalConstants>65536 then invalid()end
  p.tags,p.constantData,p.constantSeals,p.cache={},{},{},{}
  for i=1,p.constantCount do local tag=u8();if tag>4 then invalid()end;p.tags[i]=tag;if tag>=3 then p.constantSeals[i]=u32();p.constantData[i]=range()end end
  p.instructionCount=u32();totalInstructions=totalInstructions+p.instructionCount;if p.instructionCount<1 or totalInstructions>100000 then invalid()end
  p.offsets={}
  for i=1,p.instructionCount do local length=u8();if length<37 or length>44 then invalid()end;need(length);p.offsets[(i-1)*5+1]=position;position=position+length end
  prototypes[id]=p
 end
 if position~=#blob or prototypes[entry].parent~=0 then invalid()end
 for id=1,count do local p=prototypes[id];if id~=entry and p.parent==0 then invalid()end;for i=1,p.upCount do local d=p.up[i];local parent=prototypes[p.parent];if not parent or d[2]>(d[1]==0 and parent.cells or parent.upCount)then invalid()end end end
 local function constant(frame,slot,keyIndex)
  if frame.phase~=1 then invalid()end
  local p,key=frame.prototype,frame.values[4+keyIndex]
  if slot<1 or slot>p.constantCount or not key or key==0 then invalid()end
  local cached=p.cache[slot];if cached and cached[1]==key then return cached[2]end
  local tag=p.tags[slot];local value
  if tag==0 then return nil elseif tag==1 then value=false elseif tag==2 then value=true
  else
   local r=p.constantData[slot];local pieces,block={},{};local seal=mix(key,tag)
   for j=1,r[2] do
    local v=(read8(r[1]+j-1)-floor(key/256^((j-1)%4))-(j%251)*17)%256
    seal=mix(seal,v);block[#block+1]=string.char(v)
    if #block==4096 then pieces[#pieces+1]=table.concat(block);block={}end
   end
   if seal~=p.constantSeals[slot] then invalid()end
   pieces[#pieces+1]=table.concat(block);value=table.concat(pieces)
   if tag==3 then value=tonumber(value);if not value or value~=value or value==math.huge or value==-math.huge then invalid()end end
  end
  p.cache[slot]={key,value};return value
 end
 local function inverse(odd)local result=1;for i=1,3 do result=result*(2-odd*result)%256 end;return result end
 local function open(frame)
  if frame.phase~=0 then invalid()end
  local offset=frame.prototype.offsets[frame.cursor];if not offset then invalid()end
  local key=frame.key;local rotate,reverse=key%4,floor(key/4)%2;local values=frame.scratch
  local codeMasks=frame.maskCache[key]
  if not codeMasks then codeMasks={};__CODE_MASKS__codeMasks[10]=inverse(2*(key%128)+1);frame.maskCache[key]=codeMasks end
  local op=(read8(offset)-floor(key/128)%256)*codeMasks[10]%256
  for j=1,4 do local slot=(rotate+(reverse==1 and 4-j or j-1))%4;values[j]=(read32(offset+1+slot*4)-codeMasks[j])%modulus end
  for j=5,9 do values[j]=(read32(offset+1+(j-1)*4)-codeMasks[j])%modulus end
  -- Working bytes and operand order depend on this invocation's accumulated
  -- result state. Shared encoded records remain immutable across coroutines.
  local active=mix(key,frame.history);local turn,flip=active%4,floor(active/4)%2
  local aodd=2*(active%128)+1;local add=floor(active/128)%256
  local masks=frame.workingMasks;__WORKING_MASKS__
  if native then
   writeBuffer8(frame.window,0,(op*aodd+add)%256)
   for j=1,4 do local slot=(turn+(flip==1 and 4-j or j-1))%4;writeBuffer32(frame.window,1+slot*4,(values[j]+masks[j])%modulus)end
   for j=5,9 do writeBuffer32(frame.window,1+(j-1)*4,(values[j]+masks[j])%modulus)end
   op=(readBuffer8(frame.window,0)-add)*inverse(aodd)%256
   for j=1,4 do local slot=(turn+(flip==1 and 4-j or j-1))%4;values[j]=(readBuffer32(frame.window,1+slot*4)-masks[j])%modulus end
   for j=5,9 do values[j]=(readBuffer32(frame.window,1+(j-1)*4)-masks[j])%modulus end
  else
   -- Portable host compatibility; the byte representation is retained on Luau.
   for j=1,9 do frame.window[j]=(values[j]+masks[j])%modulus end
   for j=1,9 do values[j]=(frame.window[j]-masks[j])%modulus end
  end
  -- The seal fold already computes the transition's semantic digest. Retain
  -- that prefix after validating the consumed working words; commit uses it.
  local semantic=mix(key,op);for i=1,6 do semantic=mix(semantic,values[i])end
  if mix(mix(semantic,values[7]),values[8])~=values[9] then invalid()end
  frame.semantic=semantic
  frame.phase,frame.values,frame.openHistory=1,values,frame.history
  return op,values[1],values[2],values[3],values[4]
 end
 local function commit(frame,op,a,b,c,d,nextPc,registers)
  if frame.phase~=1 or frame.history~=frame.openHistory then invalid()end
  local first,second=frame.cursor+5,nil
  if op == 20 then first=a elseif op == 30 then first=c
  elseif op == 21 or op == 22 or op == 23 then second=b elseif op == 29 then second=d end
  local edge;if nextPc==first then edge=1 elseif nextPc==second and second~=first then edge=2 else invalid()end
  if not frame.prototype.offsets[nextPc] then invalid()end
  local values=frame.values;local semantic=frame.semantic
  local target=(values[6+edge]-mask(semantic,nextPc))%modulus;if target==0 then invalid()end
  frame.history=mix(frame.history,mix(values[9],witness(registers[a])))
  frame.cursor,frame.key,frame.phase=nextPc,target,0;frame.values=nil
 end
 local remaining, make = maxSteps, nil
 local invocations=0
 make=function(id,upvalues)
  local prototype=prototypes[id]
  return function(...)
   local args,registers,cells=pack(...),{},{}
   for i=1,prototype.parameters do cells[i]={v=args[i]}end
   local varargs={n=0};if prototype.vararg then for i=prototype.parameters+1,args.n do varargs.n=varargs.n+1;varargs[varargs.n]=args[i]end end
   invocations=(invocations+1)%modulus;local history=mix(prototype.entryKey,invocations)
   for i=1,args.n do history=mix(history,witness(args[i]))end
   local frame={id=id,prototype=prototype,cursor=1,key=prototype.entryKey,history=history,phase=0,maskCache={},scratch={},workingMasks={},window=native and createBuffer(37) or {}}
   local constants,pc=frame,1
   while true do
    remaining=remaining-1;if remaining<0 then error('Nil instruction budget exceeded',0)end
    local op,a,b,c,d=open(frame);pc=pc+5
    __DISPATCH__
    commit(frame,op,a,b,c,d,pc,registers)
   end
  end
 end
 return make(entry,{})
end
