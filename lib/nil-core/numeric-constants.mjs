// Only compiler-owned pools reach this codec; opaque inputs are not parsed.
// Binary words are selected only when shorter than the decimal representation.
export function constantEncoding(value,binaryIntegers=false){
 const tag=value===null?0:value===false?1:value===true?2:typeof value==='number'?3:typeof value==='string'?4:-1;
 if(tag<0)throw new TypeError('Invalid VM constant');
 if(binaryIntegers&&tag===3&&Number.isInteger(value)&&value>=10000&&value<2**32){
  const raw=Buffer.alloc(4);raw.writeUInt32LE(value);return {tag:5,raw};
 }
 return {tag,raw:tag>=3?Buffer.from(tag===3?String(value):value,'latin1'):Buffer.alloc(0)};
}
export const binaryConstantRuntime=String.raw`elseif tag==5 then
   local r=p.constantData[slot];if r[2]~=4 then invalid()end
   local seal=mix(key,tag);value=0
   for j=0,3 do
    local v=(p.reader8(r[1]+j)-floor(key/256^j)-((j+1)%251)*17)%256
    value=value+v*256^j;seal=mix(seal,v)
   end
   if seal~=p.constantSeals[slot]then invalid()end
  else`;
export const activatedBinaryConstantRuntime=String.raw`elseif tag==5 then
   if length~=4 then invalid()end;value=0
   for j=0,3 do
    local v=(p.reader8(p.constantStart+offset+j)-floor(key/256^j)-((j+1)%251)*17)%256
    value=value+v*256^j;seal=mix(seal,v)
   end
  elseif tag>=3 then`;
