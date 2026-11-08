import {randomInt} from 'node:crypto';
import {packNativePackets,nativePacketDecoder} from './native-packets.mjs';
import {validateOpaqueEntry} from './opaque.mjs';

const M=2**32,valid=n=>Number.isInteger(n)&&n>0&&n<M;
const mix=(a,b)=>((a+b)%M*65599+Math.floor(a/65536)*257)%M;
const mask=(state,field)=>mix(state,field*4271);
const fold=(state,values)=>values.reduce(mix,state);
export function nativeRoute(name,salt){let route=salt;for(const byte of Buffer.from(name,'ascii'))route=mix(route,byte);return route;}
export function createNativeBindings(entries){
 const names=entries.map(({name})=>validateOpaqueEntry(name));
 if(new Set(names).size!==names.length)throw new TypeError('Duplicate native binding');
 const aliases=new Set();
 const letters='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',alphabet=letters+'0123456789_';
 const codes=names.map(()=>{let alias;do{alias=letters[randomInt(letters.length)];for(let i=randomInt(16,30);i>0;i--)alias+=alphabet[randomInt(alphabet.length)];}while(aliases.has(alias)||names.includes(alias));aliases.add(alias);return alias;});
 let salt,routes;for(let attempt=0;attempt<32;attempt++){salt=randomInt(1,M);routes=codes.map(alias=>nativeRoute(alias,salt));if(new Set(routes).size===routes.length)break;if(attempt===31)throw new RangeError('Native route allocation failed');}
 const records=names.map((name,i)=>[name,Object.freeze({alias:codes[i],route:routes[i],accessKey:randomInt(1,M),nameKey:randomInt(1,M)})]);
 return {salt,entries:new Map(records)};
}
export function validateNativeBindings(bindings,entries){
 if(!bindings||!valid(bindings.salt)||!(bindings.entries instanceof Map)||bindings.entries.size>64)throw new TypeError('Invalid native bindings');
 const routes=new Set();
 for(const [name,binding]of bindings.entries){
  validateOpaqueEntry(name);
  if(!binding||!/^[A-Za-z][A-Za-z0-9_]{16,30}$/.test(binding.alias)||!valid(binding.accessKey)||!valid(binding.nameKey)||binding.route!==nativeRoute(binding.alias,bindings.salt)||routes.has(binding.route))throw new TypeError('Invalid native binding');
  routes.add(binding.route);
 }
 if(entries&&(entries.length!==bindings.entries.size||entries.some(({name})=>!bindings.entries.has(name))))throw new TypeError('Native bindings do not match chunks');
}
export function nativeBindingFor(bindings,name){
 if(!bindings)return undefined;
 for(const [source,binding]of bindings.entries)if(source===name||binding.alias===name)return binding;
}
export function packBoundNativePackets(bytes,binding){
 if(!valid(binding?.accessKey)||!valid(binding?.nameKey))throw new TypeError('Missing native receipt keys');
 const legacy=packNativePackets(bytes),size=legacy.readUInt32LE(0),count=legacy.readUInt32LE(4);
 const out=Buffer.allocUnsafe(legacy.length+4);out.writeUInt32LE(size,0);out.writeUInt32LE(count,4);
 let state=mix(binding.accessKey,binding.nameKey),at=8,pos=12;
 out.writeUInt32LE(fold(state,[size,count]),8);
 for(let i=0;i<count;i++){
  const length=legacy.readUInt32LE(at+4);
  const fields=[0,8,12,16].map((offset,j)=>(legacy.readUInt32LE(at+offset)+mask(state,j+1))%M);
  const reverse=(legacy[at+20]+mask(state,5)%256)%256;
  out.writeUInt32LE(length,pos);fields.forEach((n,j)=>out.writeUInt32LE(n,pos+4+j*4));out[pos+20]=reverse;
  legacy.copy(out,pos+21,at+21,at+21+length);
  state=fold(state,[length,...fields,reverse,legacy[at+21],legacy[at+20+length]]);
  at+=21+length;pos+=21+length;
 }
 return out;
}

// Descriptor masks consume a VM-supplied access key and the validated name's
// constant key. Neither key is stored in the packet or route directory.
// This is a representation dependency, not cryptographic authentication.
export const nativeReceiptDecoder=`
local function nativeMix(a,b)return ((a+b)%4294967296*65599+math.floor(a/65536)*257)%4294967296 end
local function nativeMask(state,field)return nativeMix(state,field*4271)end
local function nativeReceipt(frame,key,nameKey)
 if type(frame)~='string'or #frame<12 or type(key)~='number'or type(nameKey)~='number'or key<1 or key>=4294967296 or key%1~=0 or nameKey<1 or nameKey>=4294967296 or nameKey%1~=0 then invalid()end
 local function word(at)local a,b,c,d=byte(frame,at,at+3);return a+b*256+c*65536+d*16777216 end
 local size,count,seal=word(1),word(5),word(9)
 if size<1 or size>16777216 or count<1 or count>4096 then invalid()end
 local state=nativeMix(key,nameKey)
 if nativeMix(nativeMix(state,size),count)~=seal then invalid()end
 return state,size,count
end
`;
export const boundNativePacketDecoder=nativeReceiptDecoder+nativePacketDecoder
 .replace('nativeBody(frame)','nativeBody(frame,key,nameKey)')
 .replace('local size,count=word(),word()','local state,size,count=nativeReceipt(frame,key,nameKey);pos=13')
 .replace('local offset,length,seed,multiplier,increment=word(),word(),word(),word(),word()\n  local reverse=byte(take(1))',`local length=word()
 local encoded={word(),word(),word(),word()}
 local direction=byte(take(1))
 local offset,seed,multiplier,increment=(encoded[1]-nativeMask(state,1))%4294967296,(encoded[2]-nativeMask(state,2))%4294967296,(encoded[3]-nativeMask(state,3))%4294967296,(encoded[4]-nativeMask(state,4))%4294967296
 local reverse=(direction-nativeMask(state,5)%256)%256`)
 .replace('packets[i]={offset,length,seed,multiplier,increment,reverse,take(length)}',`local data=take(length)
 state=nativeMix(state,length);for j=1,4 do state=nativeMix(state,encoded[j])end;state=nativeMix(state,direction);state=nativeMix(state,byte(data,1));state=nativeMix(state,byte(data,length))
 packets[i]={offset,length,seed,multiplier,increment,reverse,data}`);

export function boundNativeBridge(salt){
 return `${boundNativePacketDecoder}
local host=(getfenv and getfenv(1))or _ENV or _G
local loader,assign=host.loadstring or host.load,host.setfenv
local compiled,bindings={},{}
local function route(name)local value=${salt};for i=1,#name do value=nativeMix(value,byte(name,i))end;return value end
local function nativeRead(name,key,nameKey)
 if key==0 then return host[name]end
 local id=route(name);local body=chunks[id];if not body then invalid()end
 nativeReceipt(body,key,nameKey)
 local cached=bindings[id];if cached then if cached[1]~=key or cached[2]~=nameKey then invalid()end;return cached[3]end
 local function binding(...)
  local fn=compiled[id]
  if not fn then
   if type(loader)~='function'then error('Nil native loader unavailable',0)end
   local f,e=loader(nativeBody(body,key,nameKey))
   if type(f)~='function'then error(e or 'Nil opaque compile failed',0)end
   if type(assign)=='function'then assign(f,host)end
   fn=f;compiled[id]=fn
  end
  return fn(...)
 end
 bindings[id]={key,nameKey,binding};return binding
end
local function nativeWrite(name,value,key)
 if key~=0 then error('Nil opaque entry is read-only',0)end
 host[name]=value
end
local environment=host
`;
}
