// Size encoding only. Fields are little-endian, tightly packed; the owning
// record/directory supplies its existing mask, seal and authorization state.
export function bitWidth(maximum){
 if(!Number.isInteger(maximum)||maximum<0||maximum>0xffffffff)throw new RangeError('Invalid bit field bound');
 return Math.max(1,Math.ceil(Math.log2(maximum+1)));
}

export function packBitFields(fields){
 let total=0;
 for(const {value,bits}of fields){
  if(!Number.isInteger(bits)||bits<1||bits>32||!Number.isInteger(value)||value<0||value>=2**bits)throw new RangeError('Invalid bit field');
  total+=bits;
 }
 const out=Buffer.alloc(Math.ceil(total/8));let cursor=0;
 for(const {value,bits}of fields){
  let used=0;
  while(used<bits){
   const shift=cursor%8,width=Math.min(8-shift,bits-used);
   const digit=Math.floor(value/2**used)%2**width;
   out[Math.floor(cursor/8)]|=digit<<shift;cursor+=width;used+=width;
  }
 }
 return out;
}

// Byte-aligned 8/16/24/32-bit fields still use only 1/2/3/4 reads. Unaligned
// 32-bit fields use at most five byte reads; no per-bit loop or large shifts.
export const bitFieldRuntime=String.raw`
 local function packedBits(reader,base,at,width,wordReader)
  local offset,shift=base+floor(at/8),at%8;local span=floor((width+shift+7)/8)
  local value,start=0,0
  if span>=4 and wordReader then value=wordReader(offset);start=4 end
  for i=start,span-1 do value=value+reader(offset+i)*256^i end
  return floor(value/2^shift)%2^width
 end
 local function fieldBits(n)
  local bits=1;while n>=2^bits do bits=bits+1 end;return bits
 end
 local function packedTail(reader,base,count)
  local used=count%8
  if used~=0 and floor(reader(base+floor(count/8))/2^used)~=0 then invalid()end
 end
`;

export function operandBitWidths(p,count,environmentReflection=false){
 return [p.registers,p.cells,p.upvalues.length,p.constants.length,2*(p.code.length-1),count,100000,3,environmentReflection?14:13].map(bitWidth);
}

export function branchCoordinate(target,pc){
 if(target===0)return 0; // Absent operand, omitted by the record bitmap.
 const delta=(target-pc)/5;
 if(!Number.isInteger(delta)||target<1)throw new RangeError('Invalid branch coordinate');
 return delta>=0?delta*2:-delta*2-1;
}

export const bitPrototypeWidths=String.raw`
  p.operandBits={fieldBits(p.registers),fieldBits(p.cells),fieldBits(p.upCount),fieldBits(p.constantCount),fieldBits(2*(p.instructionCount-1)),fieldBits(count),17,2,4}
`;

export const bitRecordReader=String.raw`
  local slot=(encoded-(floor(key/128)+ctx.salt)%256)*masks.inverse%256
  local format=ctx.formats[slot];if not format then invalid()end
  local bitReader,wordReader=__BIT_READER__,__WORD_READER__
  local bitBase,bitCursor=position,0
  for i=1,8 do
   if bits%2==1 then
    local width,role=32,0
    if i<=4 then role=floor(format/16^((i-1-key%4)%4))%16;width=p.operandBits[role];if not width then invalid()end end
    if bitBase+floor((bitCursor+width+7)/8)+4>limit then invalid()end
    local value=packedBits(bitReader,bitBase,bitCursor,width,wordReader)
    if i<=4 then
     local base=raw[i];value=(value-base)%2^width
     if role==5 then local delta=floor(value/2);if value%2==1 then delta=-delta-1 end;value=frame.cursor+delta*5 end
     value=(base+value)%modulus
    end
    raw[i]=value;bitCursor=bitCursor+width
   end
   bits=floor(bits/2);stamp=mix(stamp,raw[i])
  end
  packedTail(bitReader,bitBase,bitCursor)
  position=bitBase+floor((bitCursor+7)/8)
`;
