import { LIMITS } from './opcodes.mjs';

export function serializeNil(program, { opcodeMap } = {}) {
  if (![2,3].includes(program?.version) || !Array.isArray(program.prototypes) ||
      program.prototypes.length < 1 || program.prototypes.length > LIMITS.prototypes) {
    throw new TypeError('Nil invalid program');
  }
  const protectedLayout = program.version === 3;
  const parts = [Buffer.from('STBC'), Buffer.from([program.version])];
  let bytes = 5;
  function push(buffer) {
    bytes += buffer.length;
    if (bytes > LIMITS.blobBytes) throw new RangeError('Nil bytecode size limit exceeded');
    parts.push(buffer);
  }
  function u8(value) {
    if (!Number.isInteger(value) || value < 0 || value > 255) throw new RangeError('Nil byte out of range');
    push(Buffer.from([value]));
  }
  function u32(value) {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new RangeError('Nil operand out of range');
    const buffer = Buffer.allocUnsafe(4); buffer.writeUInt32LE(value); push(buffer);
  }
  function string(value, layout, slot) {
    const buffer = Buffer.from(value, 'latin1');
    if (layout) for (let j=0;j<buffer.length;j++) buffer[j]=(buffer[j]+constantMask(layout,slot,j+1))%256;
    u32(buffer.length); push(buffer);
  }
  u32(program.prototypes.length); u32(program.root);
  for (const prototype of program.prototypes) {
    u32(prototype.parent); u32(prototype.parameters); u8(prototype.vararg ? 1 : 0);
    u32(prototype.registers); u32(prototype.cells); u32(prototype.upvalues.length);
    for (const [kind, index] of prototype.upvalues) { u8(kind); u32(index); }
    const layout = protectedLayout ? prototype.layout : null;
    if (protectedLayout) {
      if (!layout || !Number.isInteger(layout.seedA) || layout.seedA<1 || layout.seedA>65535 ||
          !Number.isInteger(layout.seedB) || layout.seedB<1 || layout.seedB>65535 ||
          !Array.isArray(layout.order) || layout.order.length!==4 || new Set(layout.order).size!==4 ||
          layout.order.some(n=>!Number.isInteger(n)||n<1||n>4) || ![0,1].includes(layout.opLast)) throw new TypeError('Invalid protected instruction layout');
      u32(layout.seedA);u32(layout.seedB);for(const slot of layout.order)u8(slot);u8(layout.opLast);
    }
    u32(prototype.constants.length);
    for (const [index,constant] of prototype.constants.entries()) {
      if (constant === null) u8(0);
      else if (constant === false) u8(1);
      else if (constant === true) u8(2);
      else if (typeof constant === 'number') { u8(3); string(String(constant),layout,index+1); }
      else if (typeof constant === 'string') { u8(4); string(constant,layout,index+1); }
      else throw new TypeError('Nil unsupported constant');
    }
    u32(prototype.code.length);
    for (const [index,instruction] of prototype.code.entries()) {
      if (!Array.isArray(instruction) || instruction.length !== 5) throw new TypeError('Nil invalid instruction width');
      const [op, ...operands] = instruction;
      let mapped = opcodeMap ? opcodeMap[op] : op;
      if (!layout) { u8(mapped);for(const operand of operands)u32(operand); }
      else {
        mapped=(mapped+layout.seedA+(index+1)*layout.seedB)%256;
        const stored=[];
        operands.forEach((operand,slot)=>{
          if(!Number.isInteger(operand)||operand<0||operand>0xffffffff)throw new RangeError('Nil operand out of range');
          stored[layout.order[slot]-1]=(operand+operandMask(layout,index+1,slot+1))%4294967296;
        });
        if (!layout.opLast)u8(mapped);
        for(const value of stored)u32(value);
        if (layout.opLast)u8(mapped);
      }
    }
  }
  return Buffer.concat(parts, bytes);
}

export function operandMask(layout, instruction, slot) {
  return (layout.seedA*(instruction+slot*layout.seedB)+layout.seedB*slot*257)%4294967296;
}
export function constantMask(layout, slot, offset) {
  return (layout.seedA+slot*layout.seedB+offset*(layout.seedA%251+1))%256;
}

export function quoteLuaBytes(bytes) {
  const parts = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) parts[i] = `\\${String(bytes[i]).padStart(3, '0')}`;
  return `"${parts.join('')}"`;
}
