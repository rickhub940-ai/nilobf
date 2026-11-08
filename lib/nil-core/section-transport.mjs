import {randomInt} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {stateMix} from './stateful.mjs';
import {entryForGate} from './sealed-pages.mjs';
import {boundEntryKey} from './bound-pages.mjs';
import {radix85Decoder} from './radix85.mjs';
import {jointBridge} from './joint-materializer.mjs';

const M=2**32;
const word=n=>{const bytes=Buffer.alloc(4);bytes.writeUInt32LE(n);return bytes;};
const short=n=>{const bytes=Buffer.alloc(2);bytes.writeUInt16LE(n);return bytes;};
function shuffle(values){const out=[...values];for(let i=out.length-1;i>0;i--){const j=randomInt(i+1);[out[i],out[j]]=[out[j],out[i]];}return out;}
function seed(section,nonce,schema){
 let state=stateMix(stateMix(nonce,section.id,schema),section.key,schema);
 if(section.gate){const expected=schema.boundPages?boundEntryKey(section.gate,section.id,section.parent%1073741824):entryForGate(section.gate);if(expected!==section.key)throw new TypeError('Invalid transport gate');for(const byte of section.gate)state=stateMix(state,byte,schema);}
 return state;
}
function encodeSection(bytes,state,schema){
 const out=Buffer.alloc(bytes.length);
 for(let at=0;at<bytes.length;at+=4){
  const width=Math.min(4,bytes.length-at),limit=256**width;
  state=stateMix(state,at/4+1,schema);
  let plain=0;for(let j=0;j<width;j++)plain+=bytes[at+j]*256**j;
  const value=(plain+state)%limit;
  for(let j=0;j<width;j++)out[at+j]=Math.floor(value/256**j)%256;
  state=stateMix(state,plain,schema);
 }return out;
}

// Transport descriptors contain ranges/nonces, never section entry keys or
// page gates. Body opening is delegated to the corresponding VM open operation.
// This reversible encoding is not a cryptographic secrecy/authentication claim.
export function packSectionTransport(blob,plan,schema,{compactTransport=false}={}){
 if(typeof compactTransport!=='boolean')throw new TypeError('Invalid compact transport mode');
 if(!Buffer.isBuffer(blob)||schema?.version!==5||schema.sectionTransport!==true||!Buffer.isBuffer(plan?.prefix)||!Array.isArray(plan.sections)||!plan.sections.length||plan.sections.length>4096||!blob.subarray(0,plan.prefix.length).equals(plan.prefix))throw new TypeError('Missing section transport plan');
 const base=12+plan.prefix.length+plan.sections.length*(compactTransport?14:20);
 const locations=new Map(),payload=[];let physical=base,logical=plan.prefix.length;
 for(const [i,section]of plan.sections.entries()){
  if(section.id!==i+1||section.header!==logical||section.offset!==logical+8||section.length<(schema.compactPrototypeMetadata?11:34)||blob.readUInt32LE(logical)!==section.parent||blob.readUInt32LE(logical+4)!==section.length||section.offset+section.length>blob.length||!Number.isInteger(section.key)||section.key<1||section.key>=M||Boolean(section.gate)!==Boolean(section.parent>=2147483648))throw new TypeError('Invalid section transport range');
  logical+=8+section.length;
 }if(logical!==blob.length)throw new TypeError('Incomplete section transport plan');
 for(const [rank,section]of shuffle(plan.sections).entries()){
  const nonce=randomInt(M),bytes=encodeSection(blob.subarray(section.offset,section.offset+section.length),seed(section,nonce,schema),schema);
  locations.set(section.id,{physical,nonce,rank:rank+1});payload.push(bytes);physical+=bytes.length;
 }
 const directory=plan.sections.flatMap(section=>{
  const at=locations.get(section.id);return compactTransport?[word(section.parent),word(section.length),short(at.rank),word(at.nonce)]:[word(section.header),word(section.parent),word(section.length),word(at.physical),word(at.nonce)];
 });
 return Buffer.concat([word(blob.length),word(plan.prefix.length),word(plan.sections.length),plan.prefix,...directory,...payload],physical);
}

export function sectionTransportDecoder(schema,{alphabet85,fastTransport=false,hasNative=false,materializer,compactTransport=false}={}){
 if(typeof compactTransport!=='boolean')throw new TypeError('Invalid compact transport mode');
 if(schema?.version!==5||schema.sectionTransport!==true||!alphabet85||hasNative&&(!materializer?.inlinePages||!materializer?.entries?.length))throw new TypeError('Section transport requires V5 inline native pages');
 const base=schema.family===0?'(a+b)':schema.family===1?'(a*3+b)':'(a+5*b)',side=schema.family===0?'a':schema.family===1?'b':'((a+b)%modulus)';
 const mix=`return (${base}%modulus*${schema.multiplier}+math.floor(${side}/${2**schema.shift})*${schema.gain})%modulus`;
 let source=readFileSync(new URL('./section-transport.lua',import.meta.url),'utf8')
  .replace('__RADIX__',()=>radix85Decoder(alphabet85,{bufferOutput:fastTransport}))
  .replace('__INPUT__',()=>fastTransport?`local physicalLength=packedBuffer and packedLength or #data
local function physical8(at)if packedBuffer then return packedRead8(packedBuffer,at)end;return byte(data,at+1)end
local function physical32(at)if packedBuffer then return packedRead32(packedBuffer,at)end;local a,b,c,d=byte(data,at+1,at+4);return a+b*256+c*65536+d*16777216 end`:`local physicalLength=#data
local function physical8(at)return byte(data,at+1)end
local function physical32(at)local a,b,c,d=byte(data,at+1,at+4);return a+b*256+c*65536+d*16777216 end`)
  .replace('__MIX__',()=>mix);
 if(schema.boundPages){
  const old='local a,b,c,d=byte(gate,1,4);if(a+b*256+c*65536+d*16777216)%4294967295+1~=key then invalid()end';
  if(!source.includes(old))throw new Error('Bound transport entry anchor changed');
  // openPrototype already derives the full gate/id/parent key before this
  // transport reader is constructed. Section authentication then checks bytes.
  source=source.replace(old,'');
 }
 if(compactTransport){
  const first=source.indexOf('local payloadAt='),last=source.indexOf('local cachedMetadata',first);
  if(first<0||last<0)throw new Error('Compact transport anchors changed');
  source=source.slice(0,first)+`local payloadAt=12+prefixLength+count*14
if payloadAt>physicalLength then invalid()end
local transportSections,order={},{};local logical=prefixLength
for id=1,count do
 local at=12+prefixLength+(id-1)*14
 local parent,length=physical32(at),physical32(at+4)
 local rank=physical8(at+8)+physical8(at+9)*256;local nonce=physical32(at+10)
 if length<34 or logical+8+length>logicalLength or rank<1 or rank>count or order[rank]then invalid()end
 local section={logical,parent,length,0,nonce};transportSections[id]=section;order[rank]=section
 logical=logical+8+length
end
if logical~=logicalLength then invalid()end
local finish=payloadAt
for rank=1,count do
 local section=order[rank];if not section or finish+section[3]>physicalLength then invalid()end
 section[4]=finish;finish=finish+section[3];order[rank]=nil
end
if physicalLength-finish>3 then invalid()end
for at=finish,physicalLength-1 do if physical8(at)~=0 then invalid()end end
`+source.slice(last);
 }
 if(schema.compactPrototypeMetadata)source=source.replaceAll('length<34','length<11');
 return source+'\n'+(hasNative?jointBridge(materializer):"local environment=(getfenv and getfenv(1))or _ENV or _G;local nativeRead,nativeWrite=nil,nil")+'\n';
}
