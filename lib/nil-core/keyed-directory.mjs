import {randomInt} from 'node:crypto';
import {stateMix} from './stateful.mjs';
import {bitWidth,packBitFields} from './bit-fields.mjs';

const M=2**32;
// Descriptor authorization uses the transfer key, not the prototype entry key.
// This is reversible VM encoding; the interpreter still contains its rules.
export function directoryMask(key,id,pc,bank,ctx,profile){
 return stateMix(stateMix(stateMix(stateMix(key,id,profile),pc,profile),ctx.guard,profile),bank,profile);
}

export function packKeyedRecords(records,id,contexts,profile,{narrow=false,bitPacked=false}={}){
 if(typeof bitPacked!=='boolean'||bitPacked&&!narrow)throw new TypeError('Bit directories require narrow records');
 if(!Number.isInteger(id)||id<1||id>4096||!Array.isArray(contexts)||contexts.length<2||contexts.length>4||!Array.isArray(records)||records.length<1||records.length%contexts.length!==0)throw new TypeError('Invalid keyed record directory');
 if(records.some(r=>!Buffer.isBuffer(r.bytes)||!Number.isInteger(r.key)||r.key<1||r.key>=M))throw new TypeError('Invalid keyed record');
 const total=records.reduce((n,r)=>n+r.bytes.length,0);
 const directoryWidth=narrow?(total<=1024?2:total<=262144?3:4):4,directoryBits=bitPacked?bitWidth(total*64-1):directoryWidth*8,limit=2**directoryBits;
 const descriptors=Array(records.length),order=[...records.keys()];
 for(let i=order.length-1;i>0;i--){const j=randomInt(i+1);[order[i],order[j]]=[order[j],order[i]];}
 const payload=[];let offset=0;
 for(const index of order){
  const record=records[index],width=record.bytes.length;
  if(width<6||width>=64||offset+width>16777216)throw new RangeError('Invalid keyed record range');
  const bank=index%contexts.length+1,pc=Math.floor(index/contexts.length)*5+1;
  const descriptor=offset*64+width;
  descriptors[index]=(descriptor+directoryMask(record.key,id,pc,bank,contexts[bank-1],profile))%limit;
  payload.push(record.bytes);offset+=width;
 }
 const length=Buffer.alloc(4);length.writeUInt32LE(offset);
 const directory=bitPacked?packBitFields(descriptors.map(value=>({value,bits:directoryBits}))):Buffer.alloc(records.length*directoryWidth);
 if(!bitPacked)descriptors.forEach((value,index)=>directory.writeUIntLE(value,index*directoryWidth,directoryWidth));
 return Buffer.concat([length,directory,...payload]);
}

export function keyedInstructionDirectory(source,{narrow=false,bitPacked=false}={}){
 if(typeof bitPacked!=='boolean'||bitPacked&&!narrow)throw new TypeError('Bit directories require narrow records');
 source=source.replaceAll('\r\n','\n');
 const scan=/p\.offsets=\{\}\n  for i=1,p\.instructionCount do local n=u8\(\);if n<(6|37) or n>(45|44|38) then invalid\(\)end;need\(n\);local offsets=\{position\};position=position\+n;for bank=2,contextCount do local width=u8\(\);if width<(6|37) or width>(45|44|38) then invalid\(\)end;need\(width\);offsets\[bank\]=position;position=position\+width end;p\.offsets\[\(i-1\)\*5\+1\]=offsets end/;
 const match=scan.exec(source);
 if(!match)throw new Error('Keyed instruction directory scan changed');
 source=source.replace(scan,`p.recordLength=u32();p.recordDirectory=position
  if p.recordLength<p.instructionCount*contextCount*${match[1]} or p.recordLength>p.instructionCount*contextCount*${match[2]} then invalid()end
  ${bitPacked?'p.directoryBits=fieldBits(p.recordLength*64-1);p.directoryLimit=2^p.directoryBits':narrow?'p.directoryWidth=p.recordLength<=1024 and 2 or p.recordLength<=262144 and 3 or 4;p.directoryLimit=256^p.directoryWidth':''}
  local directorySize=${bitPacked?'floor((p.instructionCount*contextCount*p.directoryBits+7)/8)':`p.instructionCount*contextCount*${narrow?'p.directoryWidth':'4'}`}
  need(directorySize);${bitPacked?'packedTail(read8,position,p.instructionCount*contextCount*p.directoryBits);':''}position=position+directorySize
  p.recordStart=position;need(p.recordLength);position=position+p.recordLength`);
 const fetch='  local offsets=frame.prototype.offsets[frame.cursor];if not offsets then invalid()end\n  local ctx=contexts[frame.bank];local offset=offsets[frame.bank];local p,key=frame.prototype,frame.key';
 if(!source.includes(fetch))throw new Error('Keyed instruction directory fetch changed');
 source=source.replace(fetch,`  local p,key=frame.prototype,frame.key
  if not hasInstruction(p,frame.cursor)then invalid()end
  local ctx=contexts[frame.bank]`);
 const uncached='  if not record then';
 if(!source.includes(uncached))throw new Error('Keyed record cache boundary changed');
 source=source.replace(uncached,`${uncached}
  ${bitPacked?'local stored=packedBits(p.reader8,p.recordDirectory,((frame.cursor-1)/5*contextCount+frame.bank-1)*p.directoryBits,p.directoryBits,p.reader32)':`local directoryAt=p.recordDirectory+((frame.cursor-1)/5*contextCount+frame.bank-1)*${narrow?'p.directoryWidth':'4'}\n  ${narrow?'local stored=p.reader8(directoryAt)+p.reader8(directoryAt+1)*256;if p.directoryWidth>=3 then stored=stored+p.reader8(directoryAt+2)*65536 end;if p.directoryWidth==4 then stored=stored+p.reader8(directoryAt+3)*16777216 end':''}`}
  local descriptor=(${narrow?'stored':'p.reader32(directoryAt)'}-mix(mix(mix(mix(key,frame.id),frame.cursor),ctx.guard),frame.bank))%${narrow?'p.directoryLimit':'modulus'}
  local recordWidth=descriptor%64;local relative=floor(descriptor/64)
  if recordWidth<${match[1]} or recordWidth>${match[2]} or relative+recordWidth>p.recordLength then invalid()end
  local offset=p.recordStart+relative`);
 source=source.replaceAll('p.reader8(offset-1)','recordWidth');
 source=source.replace(/frame\.prototype\.offsets\[(target|nextPc|ticket\[5\])\]/g,(_,pc)=>`hasInstruction(frame.prototype,${pc})`);
 if(/\.offsets\[/.test(source))throw new Error('Unhandled keyed instruction directory read');
 const anchor=' local function witness(value)';
 if(!source.includes(anchor))throw new Error('Keyed instruction membership scope changed');
 return source.replace(anchor,` local function hasInstruction(p,pc)
  return type(pc)=='number'and pc>=1 and pc%5==1 and pc<=p.instructionCount*5-4
 end
${anchor}`);
}
