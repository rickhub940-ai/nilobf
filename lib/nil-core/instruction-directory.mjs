// Changes only the derived address directory. Record bytes and transfer seals
// retain their wire format; a directory entry never authorizes an edge.
export function denseInstructionDirectory(source) {
  source = source.replace(/\r\n/g, '\n');
  const allocation = 'p.offsets={}';
  const scan = /for i=1,p\.instructionCount do local n=u8\(\);if n<(6|37) or n>(45|44|38) then invalid\(\)end;need\(n\);local offsets=\{position\};position=position\+n;for bank=2,contextCount do local width=u8\(\);if width<(6|37) or width>(45|44|38) then invalid\(\)end;need\(width\);offsets\[bank\]=position;position=position\+width end;p\.offsets\[\(i-1\)\*5\+1\]=offsets end/;
  const match = scan.exec(source);
  if (!source.includes(allocation) || !match) throw new Error('Instruction directory scan changed');
  source = source.replace(allocation, 'p.offsets=createBuffer(p.instructionCount*contextCount*4)');
  source = source.replace(scan, `for i=1,p.instructionCount do
   local base=(i-1)*contextCount*4;local n=u8()
   if n<${match[1]} or n>${match[2]} then invalid()end;need(n)
   buffer.writeu32(p.offsets,base,position);position=position+n
   for bank=2,contextCount do local width=u8()
    if width<${match[3]} or width>${match[4]} then invalid()end;need(width)
    buffer.writeu32(p.offsets,base+(bank-1)*4,position);position=position+width
   end
  end`);
  const oldFetch = '  local offsets=frame.prototype.offsets[frame.cursor];if not offsets then invalid()end\n  local ctx=contexts[frame.bank];local offset=offsets[frame.bank];local p,key=frame.prototype,frame.key';
  if (!source.includes(oldFetch)) throw new Error('Instruction directory fetch changed');
  source = source.replace(oldFetch, `  local p,key=frame.prototype,frame.key
  if not hasInstruction(p,frame.cursor)then invalid()end
  local ctx=contexts[frame.bank]
  local offset=readBuffer32(p.offsets,((frame.cursor-1)/5*contextCount+frame.bank-1)*4)`);
  // All remaining directory reads are membership checks in guarded corridors.
  const membership = /frame\.prototype\.offsets\[(target|nextPc|ticket\[5\])\]/g;
  source = source.replace(membership, (_, pc) => `hasInstruction(frame.prototype,${pc})`);
  if (/\.offsets\[/.test(source)) throw new Error('Unhandled instruction directory read');
  const anchor = ' local function witness(value)';
  if (!source.includes(anchor)) throw new Error('Instruction membership scope changed');
  source = source.replace(anchor, ` local function hasInstruction(p,pc)
  return type(pc)=='number'and pc>=1 and pc%5==1 and pc<=p.instructionCount*5-4
 end
${anchor}`);
  return source;
}
