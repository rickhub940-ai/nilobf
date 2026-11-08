import { randomBytes, randomInt } from 'node:crypto';
import { OP, LIMITS, OPERAND_ROLES } from './opcodes.mjs';
import { packNativePackets, nativePacketDecoder } from './native-packets.mjs';
import {packBoundNativePackets,boundNativeBridge,validateNativeBindings} from './bound-native.mjs';
import {preparationBridge} from './native-preparation.mjs';
import {jointBridge} from './joint-materializer.mjs';
import { randomMethodKey, randomNumericKey } from './runner-object.mjs';
import { radix85Decoder } from './radix85.mjs';
import luaparse from 'luaparse';

export function randomOpcodeMap() {
  const pool = Array.from({ length: 255 }, (_, i) => i + 1);
  for (let i = pool.length - 1; i > 0; i--) {
    const j = randomInt(i + 1); [pool[i], pool[j]] = [pool[j], pool[i]];
  }
  return [0, ...pool.slice(0, Object.keys(OP).length)];
}
export function validateOpcodeMap(map) {
  if (!Array.isArray(map) || map.length !== Object.keys(OP).length+1 || map[0] !== 0 ||
      map.slice(1).some(n => !Number.isInteger(n) || n < 1 || n > 255) || new Set(map.slice(1)).size !== Object.keys(OP).length) {
    throw new TypeError('Invalid opcode map');
  }
}
export function randomizeDispatcher(runtime, map, { dispatchFamily, objectName, handlerFields, usedFieldKeys, stateful=false,lazyPrototypes=false } = {}) {
  const start = runtime.indexOf('if op == 1 then');
  const end = runtime.indexOf('else invalid() end', start);
  if (start < 0 || end < start) throw new Error('VM dispatcher layout changed');
  const body = runtime.slice(start, end);
  const headers = [...body.matchAll(/\b(?:if|elseif) op == (\d+) then/g)];
  if (headers.length !== Object.keys(OP).length) throw new Error('VM opcode handler count changed');
  const blocks = headers.map((h,i) => ({ op: Number(h[1]), body: body.slice(h.index+h[0].length, headers[i+1]?.index ?? body.length) }));
  if(objectName!==undefined){
    if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(objectName)||!Array.isArray(handlerFields)||!(usedFieldKeys instanceof Set))throw new TypeError('Invalid object dispatcher options');
    const args=['registers','constants','cells','upvalues','environment','prototypes','varargs','pack','unpackValues','make','invalid','budget','pc','a','b','c','d',...(stateful?['frame','constant']:[]),...(lazyPrototypes?['count','sections','openPrototype']:[])];
    for(const block of blocks){
      // Keep native tail returns in the caller to retain Lua tail-call behavior
      // and nil-hole/multiple-return semantics. All other handlers are real
      // object functions; table writes remain shared and pc returns explicitly.
      if(block.op===19||block.op===31)continue;
      if(block.op===25||block.op===26){
        const validation=stateful?block.body.match(/^\s*if[^\n]+ then invalid\(\)end\s*/)?.[0]:'';
        if(stateful&&!validation)throw new Error('Stateful arithmetic validation missing');
        const expressions=block.op===25?['-left','not left','#left']:['left+right','left-right','left*right','left/right','left%right','left^right','left..right','left==right','left~=right','left<right','left<=right','left>right','left>=right'];
        const keys=expressions.map(expression=>{const key=randomMethodKey(usedFieldKeys);handlerFields.push(`${key}=function(object,left,right)return ${expression} end`);return '"'+key+'"';});
        const mapping=randomNumericKey(usedFieldKeys);
        handlerFields.push(`[${mapping}]={${keys.join(',')}}`);
        block.body=validation+(block.op===25?`registers[a]=object[object[${mapping}][c]](object,registers[b])`:`registers[a]=object[object[${mapping}][d]](object,registers[b],registers[c])`);
      }
      const numeric=block.op%6===0;
      const key=numeric?randomNumericKey(usedFieldKeys):randomMethodKey(usedFieldKeys);
      const lifted=block.body.replace(/\bremaining\b/g,'budget[1]');
      // Keep only the bindings actually consumed by this handler. The old
      // uniform signature copied every VM binding into every invocation.
      // Per-handler argument order is shared by definition and call site.
      const refs=new Set(),ast=luaparse.parse(`local function handler(object)${lifted}\nreturn pc end`,{luaVersion:'5.1',scope:true,encodingMode:'pseudo-latin1'});
      function visit(n){if(!n||typeof n!=='object')return;if(n.type==='Identifier'&&n.isLocal===false)refs.add(n.name);for(const v of Object.values(n))if(Array.isArray(v))v.forEach(visit);else if(v&&typeof v==='object')visit(v);}
      visit(ast);const parameters=args.filter(name=>refs.has(name));
      for(let i=parameters.length-1;i>0;i--){const j=randomInt(i+1);[parameters[i],parameters[j]]=[parameters[j],parameters[i]];}
      handlerFields.push(`${numeric?'['+key+']':key}=function(object,${parameters.join(',')})${lifted}\nreturn pc end`);
      block.body=` pc=${objectName}[${numeric?key:'"'+key+'"'}](${objectName},${parameters.join(',')})\n`;
    }
  }
  for (let i = blocks.length - 1; i > 0; i--) {
    const j = randomInt(i+1);[blocks[i],blocks[j]]=[blocks[j],blocks[i]];
  }
  const family = dispatchFamily ?? (randomInt(2) ? 'bucket' : 'tree');
  if (!['tree','bucket'].includes(family)) throw new TypeError('Unknown dispatch family');
  function tree(list) {
    const sorted=[...list].sort((a,b)=>map[a.op]-map[b.op]);
    if (sorted.length===1) { const b=sorted[0];return `if op == ${map[b.op]} then${b.body}else invalid() end\n`; }
    const middle=Math.floor(sorted.length/2);
    return `if op < ${map[sorted[middle].op]} then\n${tree(sorted.slice(0,middle))}else\n${tree(sorted.slice(middle))}end\n`;
  }
  let dispatch;
  if (family==='tree') dispatch=tree(blocks);
  else {
    const modulus=randomInt(5,12), buckets=new Map();
    for (const b of blocks) { const key=map[b.op]%modulus; const list=buckets.get(key)||[];list.push(b);buckets.set(key,list); }
    dispatch=[...buckets].map(([key,list],i)=>`${i?'elseif':'if'} op % ${modulus} == ${key} then\n${tree(list)}`).join('')+'else invalid()end\n';
  }
  const suffix=runtime.slice(end+'else invalid() end'.length).replace(/op == (\d+)/g,(_,n)=>`op == ${map[Number(n)]}`);
  let generated=runtime.slice(0,start).replace(/op == (\d+)/g,(_,n)=>`op == ${map[Number(n)]}`)+dispatch+suffix;
  const roleStart=generated.indexOf('local roles = {');
  const roleEnd=generated.indexOf('for id = 1, count do',roleStart);
  if(!stateful){
   if(roleStart<0||roleEnd<0)throw new Error('VM validation layout changed');
   const roles=blocks.map(b=>`[${map[b.op]}]={${OPERAND_ROLES[b.op-1].map(s=>`'${s}'`).join(',')}}`).join(',');
   generated=generated.slice(0,roleStart)+`local roles={${roles}}\n`+generated.slice(roleEnd);
  }
  if(objectName!==undefined){
    const anchor='local remaining, make = maxSteps, nil';
    if(generated.split(anchor).length!==2)throw new Error('VM shared budget initializer changed');
    generated=generated.replace(anchor,'local budget, make = {maxSteps}, nil').replace(/\bremaining\b/g,'budget[1]');
  }
  return generated;
}
function u32(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; }
function checksum(bytes) {
  let a = 1, b = 0;
  for (const v of bytes) { a = (a + v) % 65521; b = (b + a) % 65521; }
  return b * 65536 + a;
}
// This reversible mask obscures static strings. It is not a secrecy boundary
// against the process that executes the decoder. Transport authentication remains
// the loader protocol's responsibility; the checksum detects encoding damage.
export function packContainer(blob, entries, map, {nativeBindings,preparations,materializer}={}) {
  validateOpcodeMap(map);
  if(nativeBindings)validateNativeBindings(nativeBindings,entries);
  // Do not ship a canonical opcode reverse map. Validation and dispatch are
  // generated together; bytecode alone does not label handler semantics.
  const externalEntries=materializer?.inlinePages?[]:entries;
  const parts = [u32(blob.length), blob, Buffer.from([externalEntries.length])];
  for (const { name, bytes } of externalEntries) {
    if(materializer){const index=materializer.entries.findIndex(e=>e.name===name),region=materializer.regions[index];if(!region)throw new TypeError('Missing materializer region');parts.push(u32(region.id),u32(region.frame.length),region.frame);}
    else if(nativeBindings){const binding=nativeBindings.entries.get(name),packets=preparations?.get(binding.route)?.frame??packBoundNativePackets(bytes,binding);parts.push(u32(binding.route),u32(packets.length),packets);}
    else{const key=Buffer.from(name,'ascii'),packets=packNativePackets(bytes);parts.push(Buffer.from([key.length]),key,u32(packets.length),packets);}
  }
  const padding = randomBytes(randomInt(32, 96));
  parts.push(Buffer.from([padding.length]), padding);
  const raw = Buffer.concat(parts);
  if (raw.length > LIMITS.blobBytes * 2 + 1048576) throw new RangeError('Container size limit exceeded');
  const key = randomBytes(32);
  const masked = Buffer.allocUnsafe(raw.length);
  for (let i = 0; i < raw.length; i++) masked[i] = (raw[i] + key[i % 32] + i % 251) % 256;
  return Buffer.concat([key, u32(raw.length), u32(checksum(raw)), masked]);
}

export function containerDecoder(hasNative,{alphabet85,nativeBindings,preparations,materializer,fastTransport=false}={}) {
  if(typeof fastTransport!=='boolean'||fastTransport&&!alphabet85)throw new TypeError('Fast transport requires radix85');
  return `
local byte,sub,char,concat=string.byte,string.sub,string.char,table.concat
local function invalid()error('Nil invalid container',0)end
${alphabet85?radix85Decoder(alphabet85,{bufferOutput:fastTransport}):`if type(data)~='string'or #data<56 or #data%4~=0 or #data>46137400 then invalid()end
local alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
local lookup={};for i=1,64 do lookup[byte(alphabet,i)]=i-1 end
local output,part={},{}
for i=1,#data,4 do
 local a,b,c,d=byte(data,i,i+3);a,b=lookup[a],lookup[b]
 if not a or not b then invalid()end
 local padC,padD=c==61,d==61;c,d=lookup[c],lookup[d]
 if (padC or padD)and i~=#data-3 then invalid()end
 if padC then if not padD or b%16~=0 then invalid()end
 elseif not c then invalid()end
 if not padD and not d then invalid()end
 if padD and not padC and c%4~=0 then invalid()end
 part[#part+1]=char(a*4+math.floor(b/16))
 if not padC then part[#part+1]=char(b%16*16+math.floor(c/4))end
 if not padD then part[#part+1]=char(c%4*64+d)end
 if #part>=4096 then output[#output+1]=concat(part);part={}end
end
output[#output+1]=concat(part);data=concat(output)`}
local function at(n)${fastTransport?'if packedBuffer then return packedRead32(packedBuffer,n-1)end;':''}local a,b,c,d=byte(data,n,n+3);return a+b*256+c*65536+d*16777216 end
${fastTransport?'local decodedLength=packedBuffer and packedLength or #data':'local decodedLength=#data'}
if type(data)~='string'or decodedLength<40 or decodedLength>34603048 then invalid()end
local size,seal=at(33),at(37)
${alphabet85?`if size+40>decodedLength or decodedLength-size-40>3 then invalid()end
for i=size+41,decodedLength do if ${fastTransport?'(packedBuffer and packedRead8(packedBuffer,i-1)or byte(data,i))':'byte(data,i)'}~=0 then invalid()end end
${fastTransport?'if not packedBuffer then ':''}data=sub(data,1,size+40)${fastTransport?' end':''}`:'if size~=#data-40 then invalid()end'}
local binary=type(buffer)=='table'and type(buffer.fromstring)=='function'and type(buffer.readu8)=='function'and type(buffer.writeu8)=='function'and type(buffer.readstring)=='function'
local binaryRead,binaryWrite,binaryString,decoded
if binary then binaryRead,binaryWrite,binaryString=buffer.readu8,buffer.writeu8,buffer.readstring;decoded=${fastTransport?'packedBuffer or ':''}buffer.fromstring(data)end
local keys={};for i=1,32 do keys[i]=${fastTransport?'packedBuffer and packedRead8(packedBuffer,i-1)or ':''}byte(data,i)end
local pieces,block={},{};local a,b=1,0;local reduction=4095
for i=0,size-1 do
 local v=((binary and binaryRead(decoded,i+40)or byte(data,i+41))-keys[i%32+1]-i%251)%256
 a=a+v;b=b+a
 if i==reduction then a=a%65521;b=b%65521;reduction=reduction+4096 end
 if binary then binaryWrite(decoded,i+40,v)else
  block[#block+1]=char(v)
  if #block==4096 then pieces[#pieces+1]=concat(block);block={}end
 end
end
pieces[#pieces+1]=concat(block);local raw=binary and binaryString(decoded,40,size)or concat(pieces)
a=a%65521;b=b%65521
if b*65536+a~=seal then invalid()end
local pos=1
local function take(n)if n<0 or pos+n-1>#raw then invalid()end;local v=sub(raw,pos,pos+n-1);pos=pos+n;return v end
local function u8()return byte(take(1))end
local function u32()local v=take(4);local a,b,c,d=byte(v,1,4);return a+b*256+c*65536+d*16777216 end
local length=u32();if length>16777216 then invalid()end;local program=take(length)
local count=u8();if count>64 then invalid()end
${materializer?.inlinePages?'if count~=0 then invalid()end':`local chunks={};local total=0
for i=1,count do
${nativeBindings||materializer?`local name=u32();if chunks[name]then invalid()end`:`
 local n=u8();if n<1 or n>128 then invalid()end;local name=take(n)
 if not name:match('^[A-Za-z_][A-Za-z0-9_]*$')or chunks[name]then invalid()end`}
 local l=u32();total=total+l;if l<1 or total>17825792 then invalid()end;chunks[name]=take(l)
end`}
local padding=u8();if padding<32 or padding>95 then invalid()end;take(padding)
if pos~=#raw+1 then invalid()end
${hasNative ? materializer?jointBridge(materializer):nativeBindings?(preparations?preparationBridge(nativeBindings.salt,preparations):boundNativeBridge(nativeBindings.salt)):nativeBridge+"\nlocal nativeRead,nativeWrite=nil,nil" : "if count~=0 then invalid()end;local environment=(getfenv and getfenv(1))or _ENV or _G;local nativeRead,nativeWrite=nil,nil"}
`;
}
const nativeBridge = `
${nativePacketDecoder}
local host=(getfenv and getfenv(1))or _ENV or _G
local compiled,bindings={},{}
local loader,assign=host.loadstring or host.load,host.setfenv
for key,value in pairs(chunks)do
 local name,body=key,value
 bindings[name]=function(...)
  local fn=compiled[name]
  if not fn then
   if type(loader)~='function'then error('Nil native loader unavailable',0)end
   local f,e=loader(nativeBody(body))
   if type(f)~='function'then error(e or 'Nil opaque compile failed',0)end
   if type(assign)=='function'then assign(f,host)end
   fn=f;compiled[name]=fn
  end
  return fn(...)
 end
end
local environment=setmetatable({}, {
 __index=function(_,key)return bindings[key]or host[key]end,
 __newindex=function(_,key,value)if bindings[key]then error('Nil opaque entry is read-only',0)end;host[key]=value end,
 __metatable=false,
})
`;
