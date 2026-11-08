import {OP, LIMITS} from './opcodes.mjs';
import {instructionEffects} from './dataflow.mjs';
import {PRIVATE_DESCRIPTOR, PRIVATE_CAPTURE, PRIVATE_RECEIVE} from './private-ops.mjs';
import {selectCfgResultLinks, resultLinkGraph, proveResultRegion} from './result-link-cfg.mjs';
import {resultConsumerSlots} from './result-protocol.mjs';

const arithmetic=new Set([OP.BINARY,OP.UNARY]);
const corridorOps=new Set([OP.CONST,OP.GETL,OP.GETUP,OP.JUMP]);
const terminal=new Set([OP.RETURN,OP.TAILCALL,256,258,PRIVATE_DESCRIPTOR]);
const inputSlots=row=>row[0]===OP.BINARY?[2,3]:row[0]===OP.UNARY?[2]:[];
const ordinary=row=>arithmetic.has(row[0])&&(row[0]===OP.BINARY?row[4]>=1&&row[4]<=13:row[3]>=1&&row[3]<=3);
const successor=(row,index)=>row[0]===OP.JUMP?(row[1]-1)/5:index+1;
function predecessors(p){
 const out=Array.from({length:p.code.length},()=>[]);
 p.code.forEach((row,i)=>{
  const [op,a,b,c,d]=row;
  const targets=terminal.has(op)?[]:op===OP.JUMP?[(a-1)/5]:op===OP.FORNEXT?[(c-1)/5]:[i+1,...([OP.JF,OP.JT,OP.JNIL].includes(op)?[(b-1)/5]:op===OP.FORCHECK?[(d-1)/5]:[])];
  for(const target of new Set(targets)){
   if(target===p.code.length)continue;
   if(!Number.isInteger(target)||target<0||target>=p.code.length)throw new TypeError('Invalid result link edge');
   out[target].push(i);
  }
 });return out;
}

// A bounded exclusive corridor, not SSA. Only owned arithmetic results are
// forwarded. No calls, branch, native fragment or instruction writer may occur
// between producer and receiver. The ordinary IR remains available for audits.
export function selectResultLinkCandidates(p,fragments,{cfg=false,semanticReceipts=false}={}){
  if(cfg)return selectCfgResultLinks(p,fragments,{semanticReceipts});
  const pred=predecessors(p),links=[],claimed=new Set();
  for(let i=0;i<p.code.length;i++){
   const producer=p.code[i];if(!ordinary(producer))continue;
   const register=producer[1],corridor=[],visited=new Set([i]);let previous=i,j=i+1;
   for(let steps=0;steps<8;steps++){
    if(!Number.isInteger(j)||j<=0||j>=p.code.length||visited.has(j)||pred[j].length!==1||pred[j][0]!==previous)break;
    visited.add(j);
    const row=p.code[j],slots=inputSlots(row).filter(slot=>row[slot]===register);
    if(ordinary(row)&&slots.length&&!claimed.has(j)){
     links.push(Object.freeze({producer:i*5+1,consumer:j*5+1,register,slots:Object.freeze(slots),corridor:Object.freeze(corridor)}));claimed.add(j);break;
    }
    if(!corridorOps.has(row[0]))break;
    const effect=instructionEffects(row,fragments);
    if(effect.reads.includes(register)||effect.writes.includes(register))break;
    corridor.push(j*5+1);previous=j;j=successor(row,j);
   }
  }
  return links;
}
export function activateResultLinks(program,{cfg=false,semanticReceipts=false}={}){
 if(typeof cfg!=='boolean')throw new TypeError('Invalid CFG result link mode');
 if(typeof semanticReceipts!=='boolean'||semanticReceipts&&!cfg)throw new TypeError('Semantic receipts require CFG proofs');
 if(program?.version!==5)throw new TypeError('Result links require data V5');
 let pairs=0,forwarded=0,branches=0,joins=0,maxHops=0,copies=0,branchConsumers=0,indexConsumers=0;
 const prototypes=program.prototypes.map(p=>{
  if(p.resultLinks!==undefined)throw new TypeError('Result links already lowered');
  const links=selectResultLinkCandidates(p,program.fragments,{cfg,semanticReceipts});
  if(!links.length)return p;
  // Existing value receipts already reserve two temporary slots; lifetimes
  // cannot overlap because their private writers/receivers break the corridor.
  const reuse=p.code.some(row=>row[0]===PRIVATE_CAPTURE||row[0]===PRIVATE_RECEIVE);
  const registers=p.registers+(reuse?0:1);
  if(registers>LIMITS.registers)throw new RangeError('Result link register limit');
  pairs+=links.length;forwarded+=links.reduce((n,link)=>n+link.slots.length,0);
  branchConsumers+=links.filter(link=>link.kind==='branch').length;indexConsumers+=links.filter(link=>link.kind==='index').length;
  branches+=links.reduce((n,link)=>n+(link.branches??0),0);joins+=links.reduce((n,link)=>n+(link.joins??0),0);
  copies+=links.reduce((n,link)=>n+(link.copies?.length??0),0);
  maxHops=Math.max(maxHops,...links.map(link=>link.maxHops??link.corridor.length+1));
  return {...p,registers,resultRegister:registers,resultLinks:Object.freeze(links)};
 });
 const out={...program,prototypes,resultPathReceipts:cfg,semanticReceipts,stats:{...program.stats,resultLinkPairs:pairs,resultLinkOperands:forwarded,resultLinkBranches:branches,resultLinkJoins:joins,resultLinkCopies:copies,resultLinkMaxHops:maxHops,resultBranchConsumers:branchConsumers,resultIndexConsumers:indexConsumers}};
 validateResultLinks(out);return out;
}

// Recheck at serialization, so stale links after relocation cannot be emitted.
export function validateResultLinks(program){
 let count=0;
 for(const p of program.prototypes){
  if(!p.resultLinks?.length)continue;
  const pred=predecessors(p),producers=new Set(),consumers=new Set(),corridors=new Set();
  const graph=p.resultLinks.some(link=>link.mode==='cfg')?resultLinkGraph(p,program.fragments):null;
  const endpoints=new Set(p.resultLinks.flatMap(link=>[link.producer,link.consumer]));
  if(p.resultRegister!==p.registers)throw new TypeError('Invalid result temporary');
  for(const link of p.resultLinks){
   const a=(link.producer-1)/5,b=(link.consumer-1)/5,source=p.code[a],receiver=p.code[b];
   if(!Number.isInteger(a)||!Number.isInteger(b)||b<=0||b===a||!ordinary(source??[])||!resultConsumerSlots(receiver,program.semanticReceipts).length||producers.has(a)||consumers.has(b)||source[1]!==link.register||!Number.isInteger(link.register)||link.register<1||link.register>=p.resultRegister||!Array.isArray(link.corridor)||link.corridor.length>7)throw new TypeError('Invalid result link contract');
   const slots=resultConsumerSlots(receiver,program.semanticReceipts).filter(slot=>receiver[slot]===link.register);
   if(link.mode!=='cfg'&&(!slots.length||JSON.stringify(slots)!==JSON.stringify(link.slots)))throw new TypeError('Invalid result link inputs');
   if(link.mode==='cfg'){
    if(program.resultPathReceipts!==true)throw new TypeError('CFG results require path receipts');
    const proof=proveResultRegion(p,a,program.fragments,graph,{semanticReceipts:program.semanticReceipts===true});
    if(!proof||['consumer','register','maxHops','branches','joins','kind'].some(field=>proof[field]!==link[field])||['slots','copies','corridor','edges'].some(field=>JSON.stringify(proof[field])!==JSON.stringify(link[field])))throw new TypeError('Stale CFG result proof');
    for(const pc of link.corridor){const j=(pc-1)/5;if(corridors.has(j)||endpoints.has(pc))throw new TypeError('Overlapping CFG result region');corridors.add(j);}
    producers.add(a);consumers.add(b);count++;continue;
   }
   if(link.mode!==undefined)throw new TypeError('Unknown result proof mode');
   let previous=a;const visited=new Set([a]);
   for(const pc of [...link.corridor,link.consumer]){
    const j=(pc-1)/5;
    if(!Number.isInteger(j)||j<=0||j>=p.code.length||visited.has(j)||j!==successor(p.code[previous],previous)||pred[j].length!==1||pred[j][0]!==previous)throw new TypeError('Result receiver bypasses producer');
    visited.add(j);previous=j;
    if(j===b)continue;
    const row=p.code[j],effect=instructionEffects(row,program.fragments);
    if(!corridorOps.has(row[0])||effect.reads.includes(link.register)||effect.writes.includes(link.register)||corridors.has(j))throw new TypeError('Invalid result link corridor');
    corridors.add(j);
   }
   producers.add(a);consumers.add(b);count++;
  }
 }
 return count;
}

export function resultLinkFields(p){
 const fields=new Map();
 const at=pc=>{if(!fields.has(pc))fields.set(pc,{incoming:0,outgoing:0,slots:[]});return fields.get(pc);};
 for(const link of p.resultLinks??[]){
  at(link.producer).outgoing=link.consumer;
  Object.assign(at(link.consumer),{incoming:link.producer,slots:link.slots});
  for(const pc of link.corridor)at(pc).outgoing=2147483648+link.producer;
 }return fields;
}

export const resultLinkHelper=String.raw`
 local function publishResult(frame,target,value)
  ready(frame)
  if frame.pendingResult or frame.resultActive or target==frame.cursor or not frame.prototype.offsets[target]then invalid()end
  frame.resultEpoch=frame.resultEpoch+1
  local epoch=frame.resultEpoch
  local seal=mix(mix(mix(frame.history,frame.cursor),mix(target,epoch)),witness(value))
  frame.pendingResult={frame,frame.cursor,target,frame.cursor+5,epoch,value,seal,frame.history,false,0}
 end
`;

export const resultLinkFetch=String.raw`
  local incoming=ctx.result[record.slot]and(record.raw[5]-record.masks[ctx.domains[5]])%modulus or 0
  local ticket=frame.pendingResult
  if incoming~=0 then
   if not ticket or ticket[1]~=frame or ticket[2]~=incoming or ticket[3]~=frame.cursor or ticket[4]~=frame.cursor or ticket[5]~=frame.resultEpoch or ticket[9]~=false then invalid()end
   if ticket[7]~=mix(mix(mix(ticket[8],ticket[2]),mix(ticket[3],ticket[5])),witness(ticket[6]))then invalid()end
   ticket[9]=true;frame.pendingResult=nil
   local temporary=p.registers;registers[temporary]=ticket[6]
   local raw={};for i=1,8 do raw[i]=frame.raw[i]end
   local changed=0
   for logical=2,ctx.result[record.slot]do
    local at=(ctx.order[logical]+key%4)%4+1;local domain=ctx.domains[logical]
    if(raw[at]-record.masks[domain])%modulus==0 then raw[at]=(temporary+record.masks[domain])%modulus;changed=changed+1 end
   end
   if changed==0 then invalid()end
   local semantic=mix(mix(key,ctx.guard),record.slot);for i=1,6 do semantic=mix(semantic,raw[i])end
   local nextPc=frame.cursor+5;local domain=ctx.domains[7]
   raw[7]=(raw[7]-mix(frame.semantic,(nextPc+domain)%modulus)+mix(semantic,(nextPc+domain)%modulus))%modulus
   local stamp=mix(mix(key,ctx.guard),record.encoded);for i=1,8 do stamp=mix(stamp,raw[i])end
   frame.raw,frame.semantic,frame.stamp=raw,semantic,stamp;frame.resultActive=true
   for i=1,10 do ticket[i]=nil end
  elseif ticket then
   local marker=(record.raw[6]-record.masks[ctx.domains[6]])%modulus
   if ticket[1]~=frame or ticket[4]~=frame.cursor or ticket[3]==frame.cursor or marker~=2147483648+ticket[2]then invalid()end
  end
`;

const replaceOnce=(source,anchor,replacement)=>{
 const at=source.indexOf(anchor);
 if(at<0||source.indexOf(anchor,at+anchor.length)>=0)throw new Error('Result receipt runtime anchor changed');
 return source.slice(0,at)+replacement+source.slice(at+anchor.length);
};

// The frame carries an empty token rather than the receipt's value/history.
// The weak-key vault value never references its token or frame directly. This
// reduces ordinary frame snapshot exposure; AST instrumentation can still see
// the vault and every operation. It is not a secret outside the runtime host.
export function resultLinkRuntime({pathReceipts=false,semanticReceipts=false}={}){
 if(typeof semanticReceipts!=='boolean'||semanticReceipts&&!pathReceipts)throw new TypeError('Semantic receipts require path receipts');
 if(!pathReceipts)return {helper:resultLinkHelper,fetch:resultLinkFetch,retire:'frame.pendingResult,frame.resultActive=nil,nil;',frameFields:',resultEpoch=0'};
 let helper=resultLinkHelper;
 helper=replaceOnce(helper,'frame.pendingResult={frame,frame.cursor,target,frame.cursor+5,epoch,value,seal,frame.history,false,0}',`local token={};frame.pendingResult=token
  resultTickets[token]={frame.resultOwner,frame.cursor,target,frame.cursor+5,epoch,value,seal,frame.history,false,0,seal,frame.history}`);
 helper+=String.raw`
 local function retireResult(frame)
  local token=frame.pendingResult;local ticket=token and resultTickets[token]
  if ticket then for i=1,12 do ticket[i]=nil end;resultTickets[token]=nil end
  frame.pendingResult,frame.resultActive,frame.resultOwner=nil,nil,nil
 end
`;
 let fetch=replaceOnce(resultLinkFetch,'local ticket=frame.pendingResult',`local token=frame.pendingResult
  local ticket=token and resultTickets[token]
  if token and(not ticket or ticket[12]~=frame.history)then invalid()end`);
 fetch=fetch.replaceAll('ticket[1]~=frame','ticket[1]~=frame.resultOwner');
 fetch=replaceOnce(fetch,'ticket[9]=true;frame.pendingResult=nil','ticket[9]=true;resultTickets[token]=nil;frame.pendingResult=nil');
 fetch=replaceOnce(fetch,'local changed=0',`raw[5]=(mix(ticket[11],witness(ticket[6]))+record.masks[ctx.domains[5]])%modulus
   local changed=0`);
 fetch=replaceOnce(fetch,'for i=1,10 do ticket[i]=nil end','for i=1,12 do ticket[i]=nil end');
 if(semanticReceipts){
  fetch=replaceOnce(fetch,'for logical=2,ctx.result[record.slot]do','for logical=1,ctx.result[record.slot]do');
  const edge='raw[7]=(raw[7]-mix(frame.semantic,(nextPc+domain)%modulus)+mix(semantic,(nextPc+domain)%modulus))%modulus';
  fetch=replaceOnce(fetch,edge,edge+String.raw`
   if ctx.resultBranch[record.slot]then
    local secondPc=(raw[(ctx.order[2]+key%4)%4+1]-record.masks[ctx.domains[2]])%modulus
    if secondPc~=nextPc then
     local other=ctx.domains[8]
     raw[8]=(raw[8]-mix(frame.semantic,(secondPc+other)%modulus)+mix(semantic,(secondPc+other)%modulus))%modulus
    end
   end`);
  helper+=String.raw`
 local function consumeSemanticResult(frame,registers,first,second)
  if frame.resultActive then
   local slot=frame.prototype.registers
   if first~=slot and second~=slot then invalid()end
   registers[slot]=nil;frame.resultActive=nil
  end
 end
`;
 }
 const transfer=String.raw`
  if frame.pendingResult then
   local ticket=resultTickets[frame.pendingResult]
   if not ticket then invalid()end
   local expected=frame.cursor==ticket[2]and frame.cursor+5 or frame.cursor
   if ticket[1]~=frame.resultOwner or ticket[5]~=frame.resultEpoch or ticket[12]~=frame.history or ticket[4]~=expected or frame.cursor==ticket[2]and nextPc~=frame.cursor+5 or ticket[10]>=8 then invalid()end
   ticket[10]=ticket[10]+1;ticket[4]=nextPc
   ticket[11]=mix(ticket[11],mix(mix(frame.cursor,nextPc),mix(frame.stamp,witness(result))))
   ticket[12]=mix(frame.history,mix(frame.stamp,witness(result)))
  end
  frame.history=mix(frame.history,mix(frame.stamp,witness(result)))`;
 return {helper,fetch,transfer,prefix:'local resultTickets=setmetatable({},{__mode="k"})\n',retire:'retireResult(frame);',frameFields:',resultEpoch=0,resultOwner={}'};
}
