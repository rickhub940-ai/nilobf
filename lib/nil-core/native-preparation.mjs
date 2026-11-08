import {packNativePackets} from './native-packets.mjs';
import {nativeReceiptDecoder} from './bound-native.mjs';
import {dataProgram,serializeData,dataSchema,dataRuntime,NATIVE_STEP,NATIVE_FINISH} from './data-vm.mjs';
import {nativeLifetimeRuntime} from './native-lifetime.mjs';

const M=2**32,mix=(a,b)=>((a+b)%M*65599+Math.floor(a/65536)*257)%M;
const mask=(state,field)=>mix(state,field*4271),word=n=>{const b=Buffer.alloc(4);b.writeUInt32LE(n);return b;};
export function packetDigest(bytes){let a=1,b=0;for(const v of bytes){a=(a+v)%65521;b=(b+a)%65521;}return b*65536+a;}
export const preparationEntryKey=binding=>mix(binding.accessKey,binding.nameKey)%(M-1)+1;

/** Native bytes stay opaque. The VM schedules packets, never parses Luraph. */
export function prepareNative(bytes,binding){
 const legacy=packNativePackets(bytes),size=legacy.readUInt32LE(0),count=legacy.readUInt32LE(4),records=[];
 let at=8;
 for(let i=0;i<count;i++){
  const length=legacy.readUInt32LE(at+4);
  records.push({index:i+1,offset:legacy.readUInt32LE(at),length,fields:[0,8,12,16].map(n=>legacy.readUInt32LE(at+n)),reverse:legacy[at+20],cipher:legacy.subarray(at+21,at+21+length)});
  at+=21+length;
 }
 let state=mix(binding.accessKey,binding.nameKey);
 const seal=mix(mix(state,size),count),code=[],gates={};
 for(const p of [...records].sort((a,b)=>a.offset-b.offset)){
  p.digest=packetDigest(bytes.subarray(p.offset,p.offset+p.length));
  const fields=p.fields.map((n,j)=>(n+mask(state,j+1))%M),direction=(p.reverse+mask(state,5)%256)%256;
  p.encoded=Buffer.concat([word(p.length),...fields.map(word),Buffer.from([direction]),p.cipher]);
  gates[code.length]=p.digest;code.push([NATIVE_STEP,p.index,0,0,0]);
  state=mix(state,p.digest);
 }
 code.push([NATIVE_FINISH,0,0,0,0]);
 const program=dataProgram({version:3,root:1,stats:{instructions:code.length,prototypes:1,fusedInstructions:0},prototypes:[{parent:0,parameters:0,vararg:false,registers:0,cells:0,upvalues:[],constants:[],code,gates}]});
 program.prototypes[0].layout.keys[0]=preparationEntryKey(binding);
 const blob=serializeData(program,{externalEntry:true});
 const frame=Buffer.concat([word(size),word(count),word(seal),word(blob.length),blob,...records.map(p=>p.encoded)]);
 return {frame,schema:dataSchema(blob),blob,steps:count+1};
}

export function preparationBridge(salt,preparations){
 const factories=[...preparations].map(([route,p])=>`[${route}]=(function()${dataRuntime(p.schema)}end)()`).join(',');
 return `${nativeReceiptDecoder}
${nativeLifetimeRuntime}
local host=(getfenv and getfenv(1))or _ENV or _G
local loader,assign=host.loadstring or host.load,host.setfenv
local compiled,bindings={},{}
local preparations={${factories}}
local function route(name)local value=${salt};for i=1,#name do value=nativeMix(value,byte(name,i))end;return value end
local function prepare(body,key,nameKey,factory)
 local state,size,count=nativeReceipt(body,key,nameKey)
 local function word(at)if at<1 or at+3>#body then invalid()end;local a,b,c,d=byte(body,at,at+3);return a+b*256+c*65536+d*16777216 end
 local width=word(13);if width<1 or width>16777216 or width+16>#body then invalid()end
 local program=sub(body,17,16+width)
 local offsets,used={},{};local position=17+width
 for i=1,count do local length=word(position);if length<1 or length>8192 or position+20+length>#body then invalid()end;offsets[i]={position,length};position=position+21+length end
 if position~=#body+1 then invalid()end
 local binary=type(buffer)=='table'and type(buffer.fromstring)=='function'and type(buffer.create)=='function'and type(buffer.readu8)=='function'and type(buffer.writeu8)=='function'and type(buffer.tostring)=='function'
 local from,read,write,to,output
 if binary then from,read,write,to=buffer.fromstring,buffer.readu8,buffer.writeu8,buffer.tostring;output=buffer.create(size)end
 local pieces,nextOffset,completed={},0,0
 local finished=false
 local function step(index)
  if finished then invalid()end
  local item=offsets[index];if not item or used[index]then invalid()end
  local at,length=item[1],item[2]
  local offset=(word(at+4)-nativeMask(state,1))%4294967296
  local seed=(word(at+8)-nativeMask(state,2))%4294967296
  local multiplier=(word(at+12)-nativeMask(state,3))%4294967296
  local increment=(word(at+16)-nativeMask(state,4))%4294967296
  local reverse=(byte(body,at+20)-nativeMask(state,5)%256)%256
  if offset~=nextOffset or offset+length>size or seed>65535 or multiplier<1 or multiplier>65535 or multiplier%2~=1 or increment<1 or increment>65535 or increment%2~=1 or reverse>1 then invalid()end
  local encoded=sub(body,at+21,at+20+length);if binary then encoded=from(encoded)end
  local block,a,b={},1,0
  for j=1,length do
   seed=(seed*multiplier+increment)%65536
   local slot=reverse==1 and length-j+1 or j
   local value=((binary and read(encoded,slot-1)or byte(encoded,slot))-math.floor(seed/256))%256
   a=a+value;b=b+a
   if binary then write(output,nextOffset+j-1,value)else block[j]=char(value)end
  end
  if not binary then pieces[#pieces+1]=concat(block)end
  local digest=(b%65521)*65536+a%65521;state=nativeMix(state,digest)
  nextOffset=nextOffset+length;completed=completed+1;used[index]=true
  return digest
 end
 local function finish()
  if finished or completed~=count or nextOffset~=size then invalid()end
  local source;if type(loader)=='function'then source=binary and to(output)or concat(pieces)end
  finished=true
  if binary then clearNativeBuffer(output,0,size)end
  clearNativePieces(pieces)
  output,pieces=nil,nil
  if type(loader)~='function'then error('Nil native loader unavailable',0)end
  local fn,e=loader(source);source=nil
  if type(fn)~='function'then error(e or 'Nil opaque compile failed',0)end
  if type(assign)=='function'then assign(fn,host)end
  return fn
 end
 return factory(program,host,count+1,step,finish,state%4294967295+1)()
end
local function nativeRead(name,key,nameKey)
 if key==0 then return host[name]end
 local id=route(name);local body=chunks[id];local factory=preparations[id];if not body or not factory then invalid()end
 nativeReceipt(body,key,nameKey)
 local cached=bindings[id];if cached then if cached[1]~=key or cached[2]~=nameKey then invalid()end;return cached[3]end
 local function binding(...)
  local fn=compiled[id];if not fn then fn=prepare(body,key,nameKey,factory);compiled[id]=fn end
  return fn(...)
 end
 bindings[id]={key,nameKey,binding};return binding
end
local function nativeWrite(name,value,key)
 if key~=0 then error('Nil opaque entry is read-only',0)end;host[name]=value
end
local environment=host
`;
}
