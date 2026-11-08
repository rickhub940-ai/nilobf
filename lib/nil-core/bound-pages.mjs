import {createHmac} from 'node:crypto';
import {readFileSync} from 'node:fs';

const word=value=>{if(!Number.isInteger(value)||value<0||value>=2**32)throw new RangeError('Invalid page context word');const out=Buffer.alloc(4);out.writeUInt32LE(value);return out;};
// Domain 0: descriptor seed. 1: next page gate. 2: sealed section tag.
// 3: child entry key. Metadata is length-framed and uses little-endian words;
// the SHA-256 implementation itself uses the standard big-endian words.
export function boundPageMac(gate,domain,fields,body=Buffer.alloc(0)){
 if(!Buffer.isBuffer(gate)||gate.length!==16||!Number.isInteger(domain)||domain<0||domain>3||!Array.isArray(fields)||fields.length>8||!Buffer.isBuffer(body)||body.length>16777216)throw new TypeError('Invalid bound page input');
 return createHmac('sha256',gate).update(Buffer.from([domain,fields.length])).update(Buffer.concat(fields.map(word))).update(body).digest().subarray(0,16);
}
export const boundPageSeed=(gate,state,factor,add,offset,length)=>boundPageMac(gate,0,[state,factor,add,offset,length]).readUInt32LE(0);
export const boundNextGate=(gate,bytes,state,offset)=>boundPageMac(gate,1,[state,offset,bytes.length],bytes);
export const boundSectionTag=(gate,bytes,id,parent,plainLength)=>boundPageMac(gate,2,[id,parent,plainLength],bytes);
export const boundEntryKey=(gate,id,parent)=>boundPageMac(gate,3,[id,parent]).readUInt32LE(0)%4294967295+1;
export const boundPageMacRuntime=readFileSync(new URL('./bound-pages.lua',import.meta.url),'utf8');

// Same framing/algorithm; only the scratch layout and body ingestion change.
// Keep the reference template available for emitted-size comparisons.
export function boundPageMacRuntimeFor(lean=false){
 if(typeof lean!=='boolean')throw new TypeError('Invalid MAC layout');
 if(!lean)return boundPageMacRuntime;
 const schedule=boundPageMacRuntime.indexOf('  for i=16,63 do'),after=boundPageMacRuntime.indexOf('  local a,b,c,d,e,f,g,h=',schedule);
 const body="   for i=0,length-1 do local value=reader(i);if type(value)~='number'or value%1~=0 or value<0 or value>255 then invalid()end;put(inner,value)end";
 const iv=boundPageMacRuntime.match(/h=(\{[\d,]+\}),block=/)?.[1];
 if(schedule<0||after<schedule||!iv||!boundPageMacRuntime.includes(body))throw new Error('MAC optimization anchors changed');
 let source=boundPageMacRuntime.slice(0,schedule)+boundPageMacRuntime.slice(after);
 source=source.replace('words=create(256)','words=create(64)').replace('fill(s.words,0,0,256)','fill(s.words,0,0,64)')
  .replace('  for i=1,64 do\n   local x=',`  for i=1,64 do
   local at=(i-1)%16*4
   if i>16 then
    local a,b=read32(w,(i-16)%16*4),read32(w,(i-3)%16*4)
    local x=xor(rotate(a,7),rotate(a,18),shift(a,3));local y=xor(rotate(b,17),rotate(b,19),shift(b,10))
    write32(w,at,(read32(w,at)+x+read32(w,(i-8)%16*4)+y)%4294967296)
   end
   local x=`)
  .replace('K[i]+read32(w,(i-1)*4)','K[i]+read32(w,at)')
  .replace('return function(key,domain,fields,reader,length)','return function(key,domain,fields,reader,length,reader32)')
  .replace("length>0 and type(reader)~='function'", "length>0 and(type(reader)~='function'or type(reader32)~='function')")
  .replace(body,`   local at,used=0,inner.used;local block=inner.block
   while at<length do
    if used<=60 and at+4<=length then
     local value=reader32(at);if type(value)~='number'or value%1~=0 or value<0 or value>=4294967296 then invalid()end
     write32(block,used,value);used=used+4;at=at+4
    else
     local value=reader(at);if type(value)~='number'or value%1~=0 or value<0 or value>255 then invalid()end;write8(block,used,value);used=used+1;at=at+1
    end
    if used==64 then compress(inner);used=0 end
   end`)
  .replace('   digest=finish(inner)','   inner.used,inner.size=used,inner.size+length\n   digest=finish(inner)')
  .replace('outer=start();',`outer=inner;outer.h=${iv};`)
  .replace('clear(inner);clear(outer);','clear(inner);');
 if(source.includes('for i=16,63 do')||!source.includes('local at=(i-1)%16*4')||!source.includes('reader32(at)'))throw new Error('MAC optimization incomplete');
 return source;
}

// Binding is a build-time transition before dataProgram assigns final keys.
// Only prototype-owned bytes enter this pass; opaque input is never parsed.
export function bindPageProgram(program,authSlot){
 if(program.version!==3||!Number.isInteger(authSlot)||authSlot<1||authSlot>=2**31)throw new TypeError('Invalid bound page program');
 const prototypes=program.prototypes.map(p=>p.sealKey?{...p,boundPage:true}:p);
 return {...program,prototypes,pageAuthSlot:authSlot,boundPages:true};
}
