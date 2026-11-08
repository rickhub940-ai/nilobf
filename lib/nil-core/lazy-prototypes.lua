 -- The startup directory has only parent IDs and encrypted section ranges.
 -- Child metadata/entry keys are opened by the active closure instruction.
 local count,entry=u32(),u32()
 if count<1 or count>4096 or entry<1 or entry>count then invalid()end
 local rootKey=u32();if rootKey==0 then invalid()end
 local sections,prototypes={},{}
 for id=1,count do
  local parent=u32();local r=range()
  if parent>=id or r[2]<34 or (id==entry and parent~=0)or(id~=entry and parent==0)then invalid()end
  sections[id]={parent,r[1],r[2]}
 end
 if position~=#blob then invalid()end
 local totalConstants,totalInstructions=0,0
 local function openPrototype(id,key)
  if id<1 or id>count or key<1 or key>=modulus or key%1~=0 then invalid()end
  local p=prototypes[id];if p then if p.entryKey~=key then invalid()end;return p end
  local section=sections[id];local length=section[3]
  local keyBytes={key%256,floor(key/256)%256,floor(key/65536)%256,floor(key/16777216)%256}
  local decoded=native and createBuffer(length)or {};local parts,block={},{}
  for j=1,length do
   local v=(read8(section[2]+j-1)-keyBytes[(j-1)%4+1]-(j%251)*17)%256
   if native then writeBuffer8(decoded,j-1,v)else
    block[#block+1]=string.char(v)
    if #block==4096 then parts[#parts+1]=table.concat(block);block={}end
   end
  end
  if not native then parts[#parts+1]=table.concat(block);decoded=table.concat(parts)end
  local function read8(offset)if native then return readBuffer8(decoded,offset)end;return byte(decoded,offset+1)end
  local function read32(offset)if native then return readBuffer32(decoded,offset)end;local a,b,c,d=byte(decoded,offset+1,offset+4);return a+b*256+c*65536+d*16777216 end
  local position=0
  local function need(n)if n<0 or position+n>length then invalid()end end
  local function u8()need(1);local value=read8(position);position=position+1;return value end
  local function u32()need(4);local value=read32(position);position=position+4;return value end
  local function range()local n=u32();need(n);local start=position;position=position+n;return {start,n}end
  p={};p.parent,p.parameters,p.vararg=u32(),u32(),u8();p.registers,p.cells=u32(),u32()
  if p.parent~=section[1]or p.vararg>1 or p.registers>65535 or p.cells>8192 or p.parameters>p.cells then invalid()end
  p.vararg=p.vararg==1;p.upCount=u32();if p.upCount>8192 then invalid()end;p.up={}
  local parent=prototypes[p.parent]
  for i=1,p.upCount do local kind,slot=u8(),u32();if kind>1 or slot<1 or not parent or slot>(kind==0 and parent.cells or parent.upCount)then invalid()end;p.up[i]={kind,slot}end
  p.entryKey=u32();if p.entryKey~=key then invalid()end
  p.constantCount=u32();totalConstants=totalConstants+p.constantCount;if totalConstants>65536 then invalid()end
  p.tags,p.constantData,p.constantSeals,p.cache={},{},{},{}
  for i=1,p.constantCount do local tag=u8();if tag>4 then invalid()end;p.tags[i]=tag;if tag>=3 then p.constantSeals[i]=u32();p.constantData[i]=range()end end
  p.instructionCount=u32();totalInstructions=totalInstructions+p.instructionCount;if p.instructionCount<1 or totalInstructions>100000 then invalid()end
  p.offsets={}
  for i=1,p.instructionCount do local n=u8();if n<37 or n>44 then invalid()end;need(n);p.offsets[(i-1)*5+1]=position;position=position+n end
  if position~=length then invalid()end
  p.reader8,p.reader32=read8,read32
  prototypes[id]=p
  return p
 end
 openPrototype(entry,rootKey)
