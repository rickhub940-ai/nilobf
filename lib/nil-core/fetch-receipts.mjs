import {OP,LIMITS} from './opcodes.mjs';
import {PRIVATE_ARITHMETIC,PRIVATE_CAPTURE,PRIVATE_RECEIVE} from './private-ops.mjs';
import {validateFetchContracts} from './fetch-contracts.mjs';
import {analyzeDataflow} from './dataflow.mjs';

// Lower only the existing proven arithmetic intrinsic after fragment fusion.
// A receipt carries actual values; receiver records contain neither source
// registers nor the selected operation. No opaque/native byte enters this pass.
export function lowerValueReceipts(program){
 const contracts=validateFetchContracts(program);let count=0;
 const prototypes=program.prototypes.map((p,index)=>{
  const pairs=contracts.filter(c=>c.prototype===index+1&&c.kind!=='value-receipt');
  if(!pairs.length)return p;
  if(p.registers+2>LIMITS.registers)throw new RangeError('Value receipt register limit');
  const code=p.code.map(r=>[...r]);
  for(const proof of pairs){
   const at=(proof.producer-1)/5,to=(proof.consumer-1)/5,writer=code[at],consumer=code[to];
   if(writer[0]!==PRIVATE_ARITHMETIC||writer[2]!==1||writer[3]!==2||consumer[0]!==OP.BINARY||consumer[4]!==0)throw new TypeError('Noncanonical value receipt source');
   code[at]=[PRIVATE_CAPTURE,writer[1],consumer[2],consumer[3],proof.consumer];
   code[to]=[PRIVATE_RECEIVE,consumer[1],0,0,0];count++;
  }
  const out={...p,registers:p.registers+2,code};
  if(p.dataflow)out.dataflow=analyzeDataflow(out,program.fragments);
  return out;
 });
 const out={...program,prototypes,stats:{...program.stats,valueReceiptPairs:count}};
 validateFetchContracts(out);
 return out;
}

export const receiptFetch=String.raw`
  if record.slot==ctx.receipt[1]then
   local ticket=frame.pendingReceipt
   if not ticket or ticket[1]~=frame or ticket[2]~=frame.cursor or ticket[4]~=frame.receiptEpoch or ticket[10]~=false then invalid()end
   if ticket[8]~=mix(mix(mix(ticket[9],ticket[3]),mix(ticket[2],ticket[4])),mix(mix(witness(ticket[6]),witness(ticket[7])),ticket[5]))or ticket[5]~=1 and ticket[5]~=2 then invalid()end
   ticket[10]=true;frame.pendingReceipt=nil
   local leftSlot,rightSlot=p.registers-1,p.registers
   if leftSlot<1 then invalid()end
   registers[leftSlot],registers[rightSlot]=ticket[6],ticket[7]
   local raw={};for i=1,8 do raw[i]=record.raw[i]end
   raw[(ctx.order[2]+key%4)%4+1]=(leftSlot+record.masks[ctx.domains[2]])%modulus
   raw[(ctx.order[3]+key%4)%4+1]=(rightSlot+record.masks[ctx.domains[3]])%modulus
   raw[(ctx.order[4]+key%4)%4+1]=(ticket[5]+record.masks[ctx.domains[4]])%modulus
   local slot=ctx.receipt[2]
   local encoded=(slot*(2*(key%128)+1)+(floor(key/128)+ctx.salt)%256)%256
   local semantic=mix(mix(key,ctx.guard),slot);for i=1,6 do semantic=mix(semantic,raw[i])end
   local nextPc=frame.cursor+5;local domain=ctx.domains[7]
   raw[7]=(raw[7]-mix(record.semantic,(nextPc+domain)%modulus)+mix(semantic,(nextPc+domain)%modulus))%modulus
   local stamp=mix(mix(key,ctx.guard),encoded);for i=1,8 do stamp=mix(stamp,raw[i])end
   frame.raw,frame.semantic,frame.stamp=raw,semantic,stamp
   frame.receiptActive=true;dispatchHandler=ctx.handlers[slot]
   for i=1,10 do ticket[i]=nil end
   if type(dispatchHandler)~='function'then invalid()end
  elseif frame.pendingReceipt and record.slot~=ctx.receipt[3]then invalid()end
`;
export const receiptHelper=String.raw`
 local function captureReceipt(frame,target,condition,left,right)
  ready(frame)
  if frame.pendingReceipt or frame.receiptActive or not frame.prototype.offsets[target]or target==frame.cursor then invalid()end
  frame.receiptEpoch=frame.receiptEpoch+1
  local epoch=frame.receiptEpoch
  local operation=condition and 1 or 2
  local seal=mix(mix(mix(frame.history,frame.cursor),mix(target,epoch)),mix(mix(witness(left),witness(right)),operation))
  frame.pendingReceipt={frame,target,frame.cursor,epoch,operation,left,right,seal,frame.history,false}
 end
`;

