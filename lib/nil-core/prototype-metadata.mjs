import {stateMix} from './stateful.mjs';

const DOMAIN=0x4d31b7a9;
const M=2**32;

// Metadata is size encoding, not a secret-key cipher. The active prototype
// key/id selects the field rotation and chains each decoded byte into the next.
export function packPrototypeMetadata(p,id,key,profile,order){
 if(!Array.isArray(order)||order.length!==7||new Set(order).size!==7||order.some(n=>n<0||n>6||!Number.isInteger(n)))throw new TypeError('Invalid prototype field order');
 const mix=(a,b)=>stateMix(a,b,profile);
 let state=mix(mix(key,id),DOMAIN),index=0;
 const bytes=[];
 const emit=value=>{
  if(!Number.isInteger(value)||value<0||value>=M)throw new RangeError('Invalid prototype metadata integer');
  do{
   let plain=value%128;value=Math.floor(value/128);if(value)plain+=128;
   index++;state=mix(state,index);
   bytes.push((plain+state%256)%256);state=mix(state,plain);
  }while(value);
 };
 const values=[p.parameters,p.vararg?1:0,p.registers,p.cells,p.upvalues.length,p.constants.length,p.code.length];
 for(let i=0;i<7;i++)emit(values[order[(i+key%7)%7]]);
 for(const [kind,slot]of p.upvalues){
  if((kind!==0&&kind!==1)||!Number.isInteger(slot)||slot<1||slot>8192)throw new RangeError('Invalid compact upvalue');
  emit(slot*2+kind);
 }
 const seal=Buffer.alloc(4);seal.writeUInt32LE(mix(state,index));
 return Buffer.concat([Buffer.from(bytes),seal]);
}

export function compactPrototypeReader(source,order){
 source=source.replaceAll('\r\n','\n');
 const sealed=source.includes('  p={sealKey=gate};p.parent,p.parameters,p.vararg=');
 const start=source.indexOf(sealed?'  p={sealKey=gate};p.parent,p.parameters,p.vararg=':'  p={};p.parent,p.parameters,p.vararg=');
 const last='  p.constantCount=u32();totalConstants=totalConstants+p.constantCount;if totalConstants>65536 then invalid()end';
 const tail=source.indexOf(last,start),end=tail+last.length;
 if(start<0||tail<start)throw new Error('Compact prototype metadata reader anchor changed');
 const prefix=`  local metadataState=mix(mix(key,id),${DOMAIN});local metadataIndex=0
  local function metadataInteger()
   local value,power=0,1
   for width=1,5 do
    metadataIndex=metadataIndex+1;metadataState=mix(metadataState,metadataIndex)
    local plain=(u8()-metadataState%256)%256;metadataState=mix(metadataState,plain)
    local digit=plain%128
    if width==5 and digit>15 then invalid()end
    value=value+digit*power
    if plain<128 then if width>1 and digit==0 then invalid()end;return value end
    power=power*128
   end
   invalid()
  end
  local metadataOrder={${order.map(n=>n+1).join(',')}};local metadataValues={}
  for field=1,7 do metadataValues[metadataOrder[(field-1+key%7)%7+1]]=metadataInteger()end
  p={${sealed?'sealKey=gate,':''}parent=section[1],parameters=metadataValues[1],vararg=metadataValues[2],registers=metadataValues[3],cells=metadataValues[4],upCount=metadataValues[5],constantCount=metadataValues[6],instructionCount=metadataValues[7]}
  if p.vararg>1 or p.registers>65535 or p.cells>8192 or p.parameters>p.cells or p.upCount>8192 or p.constantCount>65536 or p.instructionCount<1 or p.instructionCount>100000 then invalid()end
  p.vararg=p.vararg==1;p.up={}
  local parent=prototypes[p.parent]
  for i=1,p.upCount do
   local descriptor=metadataInteger();local kind,slot=descriptor%2,floor(descriptor/2)
   if slot<1 or not parent or slot>(kind==0 and parent.cells or parent.upCount)then invalid()end
   p.up[i]={kind,slot}
  end
  if u32()~=mix(metadataState,metadataIndex)then invalid()end;p.entryKey=key
  totalConstants=totalConstants+p.constantCount;if totalConstants>65536 then invalid()end
`;
 source=source.slice(0,start)+prefix+source.slice(end);
 const count='  p.instructionCount=u32();totalInstructions=';
 if(!source.includes(count))throw new Error('Compact prototype instruction count anchor changed');
 return source.replace(count,'  totalInstructions=');
}
