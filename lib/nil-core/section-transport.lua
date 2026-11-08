local byte,sub,char,concat=string.byte,string.sub,string.char,table.concat
local function invalid()error('Nil invalid transport',0)end
__RADIX__
__INPUT__
local modulus=4294967296
local function transportMix(a,b)__MIX__ end
local function integer(n,low,high)if type(n)~='number'or n%1~=0 or n<low or n>high then invalid()end end
if physicalLength<12 then invalid()end
local logicalLength,prefixLength,count=physical32(0),physical32(4),physical32(8)
integer(logicalLength,34,16777216);integer(prefixLength,28,44);integer(count,1,4096)
local payloadAt=12+prefixLength+count*20
if payloadAt>physicalLength then invalid()end
local transportSections,ranges={},{};local logical=prefixLength
for id=1,count do
 local at=12+prefixLength+(id-1)*20
 local header,parent,length,physical,nonce=physical32(at),physical32(at+4),physical32(at+8),physical32(at+12),physical32(at+16)
 if header~=logical or length<34 or header+8+length>logicalLength or physical<payloadAt or physical+length>physicalLength then invalid()end
 transportSections[id]={header,parent,length,physical,nonce};ranges[id]={physical,physical+length}
 logical=header+8+length
end
if logical~=logicalLength then invalid()end
table.sort(ranges,function(a,b)return a[1]<b[1]end)
local finish=payloadAt
for _,range in ipairs(ranges)do if range[1]~=finish then invalid()end;finish=range[2]end
if physicalLength-finish>3 then invalid()end
for at=finish,physicalLength-1 do if physical8(at)~=0 then invalid()end end
local cachedMetadata
local function metadataSection(at)
 if cachedMetadata and at>=cachedMetadata[1]and at<cachedMetadata[1]+8 then return cachedMetadata end
 local low,high=1,count
 while low<=high do
  local mid=math.floor((low+high)/2);local section=transportSections[mid]
  if at<section[1]then high=mid-1
  elseif at>=section[1]+8 then low=mid+1
  else cachedMetadata=section;return section end
 end
 invalid()
end
local function metadata8(at)
 integer(at,0,logicalLength-1)
 if at<prefixLength then return physical8(12+at)end
 local section=metadataSection(at);local n=at-section[1]
 return math.floor((n<4 and section[2]or section[3])/256^(n%4))%256
end
local function metadata32(at)
 integer(at,0,logicalLength-4)
 if at+4<=prefixLength then return physical32(12+at)end
 if at>=prefixLength then
  local section=metadataSection(at);local relative=at-section[1]
  if relative==0 then return section[2]elseif relative==4 then return section[3]end
 end
 return metadata8(at)+metadata8(at+1)*256+metadata8(at+2)*65536+metadata8(at+3)*16777216
end
local function openSection(id,key,gate)
 integer(id,1,count);integer(key,1,4294967295)
 local section=transportSections[id];local sealed=section[2]>=2147483648
 if sealed then
  if type(gate)~='string'or #gate~=16 then invalid()end
  local a,b,c,d=byte(gate,1,4);if(a+b*256+c*65536+d*16777216)%4294967295+1~=key then invalid()end
 elseif gate~=nil then invalid()end
 local initial=transportMix(transportMix(section[5],id),key)
 if sealed then for i=1,16 do initial=transportMix(initial,byte(gate,i))end end
 local active,state,current,value=true,initial,-1,0
 local length,start,physical=section[3],section[1]+8,section[4]
 local function openWord(target)
  if not active then invalid()end
  if target<current then state,current,value=initial,-1,0 end
  while current<target do
   current=current+1;local at=current*4;local width=math.min(4,length-at)
   local limit=4294967296;local cipher
   if width==4 then cipher=physical32(physical+at)
   else
    limit=256^width;cipher=0
    for j=0,width-1 do cipher=cipher+physical8(physical+at+j)*256^j end
   end
   state=transportMix(state,current+1);value=(cipher-state)%limit
   state=transportMix(state,value)
  end
  return value
 end
 local function section8(at)
  integer(at,start,start+length-1);local relative=at-start
  return math.floor(openWord(math.floor(relative/4))/256^(relative%4))%256
 end
 local function section32(at)
  integer(at,start,start+length-4);local relative=at-start
  local target,shift=math.floor(relative/4),relative%4
  if shift==0 then return openWord(target)end
  local low=openWord(target);local high=openWord(target+1)
  return math.floor(low/256^shift)+(high%256^shift)*256^(4-shift)
 end
 local function closeSection()
  if not active then invalid()end;active=false;initial,state,current,value=0,0,-1,0
 end
 return section8,section32,closeSection
end
local program={length=logicalLength,read8=metadata8,read32=metadata32,openSection=openSection}
