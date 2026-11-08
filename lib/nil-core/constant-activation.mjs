import {constantEncoding} from './numeric-constants.mjs';
import {bitWidth,packBitFields} from './bit-fields.mjs';
// A location becomes meaningful through a consuming record's operand seal.
// All algorithms remain public; this is not a secret/authentication boundary.
const M=2**32;
const word=n=>{const b=Buffer.alloc(4);b.writeUInt32LE(n);return b;};
const mask=(key,i)=>(Math.floor(key/256**((i-1)%4))+(i%251)*17)%256;
export function packActivatedConstants(values,keys,entryKey,mix,shuffle,{binaryIntegers=false,bitPacked=false,metrics}={}){
 if(typeof bitPacked!=='boolean')throw new TypeError('Invalid constant bit layout');
 const rows=values.map((value,i)=>{
  const {tag,raw}=constantEncoding(value,binaryIntegers);
  const encoded=Buffer.from(raw);for(let j=0;j<raw.length;j++)encoded[j]=(raw[j]+mask(keys[i],j+1))%256;
  return {i,tag,raw,encoded,key:keys[i],offset:0};
 });
 let length=0;const payload=[];
 for(const row of shuffle(rows)){row.offset=length;length+=row.encoded.length;payload.push(row.encoded);}
 const addressBits=bitPacked?bitWidth(length)+3:32,lengthBits=bitPacked?bitWidth(length):32,fields=[];
 const descriptors=rows.map(row=>{
  const packed=row.offset*8+row.tag;
  if(packed>=M)throw new RangeError('Activated constant address limit');
  let seal=mix(mix(mix(row.key,row.tag),row.offset),row.raw.length);
  for(const byte of row.raw)seal=mix(seal,byte);
  let state=mix(mix(row.key,entryKey),row.i+1);
  return Buffer.concat([packed,row.raw.length,seal].map((plain,j)=>{
   const bits=[addressBits,lengthBits,32][j];
   if(plain>=2**bits)throw new RangeError('Constant bit field overflow');
   state=mix(state,j+1);const encoded=(plain+state)%2**bits;state=mix(state,plain);
   if(bitPacked){fields.push({value:encoded,bits});return Buffer.alloc(0);}return word(encoded);
  }));
 });
 const directory=bitPacked?packBitFields(fields):Buffer.concat(descriptors);
 if(metrics){metrics.descriptorLegacyBytes=(metrics.descriptorLegacyBytes??0)+rows.length*12;metrics.descriptorStoredBytes=(metrics.descriptorStoredBytes??0)+directory.length;}
 if(bitPacked)return Buffer.concat([word(length),directory,...payload]);
 return Buffer.concat([...descriptors,word(length),...payload]);
}

export const activatedConstantDirectory=String.raw`
  p.cache={};p.constantDirectory=position
  need(p.constantCount*12);position=position+p.constantCount*12
  local pool=range();p.constantStart,p.constantLength=pool[1],pool[2]
`;

export const activatedConstantRuntime=String.raw`
 local function constant(frame,slot,ticket,access,resolveNative)
  ready(frame);local p=frame.prototype
  if type(slot)~='number'or slot%1~=0 or slot<1 or slot>p.constantCount or type(ticket)~='number'or ticket%1~=0 or ticket<0 or ticket>=modulus then invalid()end
  local ctx=contexts[frame.bank]
  local operandSeal=mix(mix(mix(frame.key,frame.cursor),ctx.guard),frame.slot)
  for i=1,4 do operandSeal=mix(operandSeal,frame.raw[i])end
  local key=(ticket-mix(operandSeal,slot))%modulus;if key==0 then invalid()end
  local commitment=mix(mix(key,p.entryKey),slot)
  local cached=p.cache[slot];if cached then
   if cached[1]~=commitment then invalid()end
   if resolveNative then if type(cached[2])~='string'or type(nativeRead)~='function'then invalid()end;return nativeRead(cached[2],access,key)end
   return cached[2]
  end
  local at=p.constantDirectory+(slot-1)*12
  local state=mix(mix(key,p.entryKey),slot);local descriptor={}
  for i=1,3 do
   state=mix(state,i);local value=(p.reader32(at+(i-1)*4)-state)%modulus
   descriptor[i]=value;state=mix(state,value)
  end
  local tag=descriptor[1]%8;local offset=floor(descriptor[1]/8);local length=descriptor[2]
  if tag>4 or offset>p.constantLength or length>p.constantLength-offset or tag<3 and length~=0 then invalid()end
  local seal=mix(mix(mix(key,tag),offset),length);local value=nil
  if tag==1 then value=false elseif tag==2 then value=true
  elseif tag>=3 then
   local parts,block={},{}
   for j=1,length do
    local v=(p.reader8(p.constantStart+offset+j-1)-floor(key/256^((j-1)%4))-(j%251)*17)%256
    seal=mix(seal,v);block[#block+1]=string.char(v)
    if #block==4096 then parts[#parts+1]=table.concat(block);block={}end
   end
   parts[#parts+1]=table.concat(block);value=table.concat(parts)
   if tag==3 then value=tonumber(value);if not value or value~=value or value==math.huge or value==-math.huge then invalid()end end
  end
  if seal~=descriptor[3]then invalid()end
  p.cache[slot]={commitment,value}
  if resolveNative then if type(value)~='string'or type(nativeRead)~='function'then invalid()end;return nativeRead(value,access,key)end
  return value
 end
`;

export const bitActivatedConstantDirectory=String.raw`
  p.cache={};p.constantLength=u32();if p.constantLength>16777216 then invalid()end
  p.constantAddressBits=fieldBits(p.constantLength)+3;p.constantLengthBits=fieldBits(p.constantLength)
  p.constantRecordBits=p.constantAddressBits+p.constantLengthBits+32;p.constantDirectory=position
  local directorySize=floor((p.constantCount*p.constantRecordBits+7)/8)
  need(directorySize);packedTail(read8,position,p.constantCount*p.constantRecordBits);position=position+directorySize
  p.constantStart=position;need(p.constantLength);position=position+p.constantLength
`;

const descriptorStart=activatedConstantRuntime.indexOf('  local at=p.constantDirectory+');
const descriptorEnd=activatedConstantRuntime.indexOf('  local tag=descriptor[1]',descriptorStart);
if(descriptorStart<0||descriptorEnd<descriptorStart)throw new Error('Constant bit descriptor reader anchor changed');
export const bitActivatedConstantRuntime=activatedConstantRuntime.slice(0,descriptorStart)+String.raw`
  local at=(slot-1)*p.constantRecordBits
  local state=mix(mix(key,p.entryKey),slot);local descriptor={}
  for i=1,3 do
   local bits=i==1 and p.constantAddressBits or i==2 and p.constantLengthBits or 32
   state=mix(state,i)
   local value=(packedBits(p.reader8,p.constantDirectory,at,bits,p.reader32)-state)%2^bits
   descriptor[i]=value;state=mix(state,value);at=at+bits
  end
`+activatedConstantRuntime.slice(descriptorEnd);
