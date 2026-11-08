const codes=Object.freeze({r:1,l:2,u:3,k:4,g:4,j:5,p:6,i:7,a:8,b:9});
export function operandWidths(p,count){
 return [p.registers,p.cells,p.upvalues.length,p.constants.length,p.code.length*5,count,100000,3,13].map(n=>n<256?1:n<65536?2:3);
}
export function operandFormat(roles,ctx){
 return roles.reduce((n,role,i)=>{
  if(!codes[role])throw new TypeError('Unsupported narrow operand role');
  return n+codes[role]*16**ctx.order[i];
 },0);
}
export function narrowOperandWord(value,width){
 const b=Buffer.alloc(width);b.writeUIntLE(value%256**width,0,width);return b;
}
// Reconstruct canonical masked words before the original stamp, semantic fold,
// receipt, mutation and transfer logic. Only their stored representation changes.
export const narrowRecordReader=String.raw`
  local slot=(encoded-(floor(key/128)+ctx.salt)%256)*masks.inverse%256
  local format=ctx.formats[slot];if not format then invalid()end
  for i=1,8 do
   if bits%2==1 then
    local width=4;local role=0
    if i<=4 then role=floor(format/16^((i-1-key%4)%4))%16;width=p.operandWidths[role];if not width then invalid()end end
    if position+width>limit then invalid()end
    local value
    if width==4 then value=p.reader32(position)
    elseif width==2 then value=p.reader16(position)
    elseif width==1 then value=p.reader8(position)
    else value=p.reader16(position)+p.reader8(position+2)*65536 end
    if i<=4 then local base=raw[i];value=(base+(value-base)%256^width)%modulus end
    raw[i]=value;position=position+width
   end
   bits=floor(bits/2);stamp=mix(stamp,raw[i])
  end
`;
export const narrowPrototypeWidths=String.raw`
  local function operandWidth(n)if n<256 then return 1 elseif n<65536 then return 2 else return 3 end end
  p.operandWidths={operandWidth(p.registers),operandWidth(p.cells),operandWidth(p.upCount),operandWidth(p.constantCount),operandWidth(p.instructionCount*5),operandWidth(count),3,1,1}
`;
