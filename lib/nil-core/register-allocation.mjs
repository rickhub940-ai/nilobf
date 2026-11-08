import {OP,OPERAND_ROLES} from './opcodes.mjs';
import {privateRoles} from './private-ops.mjs';
import {instructionEffects} from './dataflow.mjs';
import {randomInt} from 'node:crypto';

// CFG liveness followed by closed-interval allocation. The interval hull is
// deliberately conservative across loops/joins. Cells/upvalues are never
// remapped: closures capture reference cells, not temporary registers.
const TERMINAL=new Set([OP.RETURN,OP.TAILCALL]);
const UNCONDITIONAL=new Set([OP.JUMP,OP.FORNEXT]);
const rolesFor=op=>privateRoles.get(op)??OPERAND_ROLES[op-1];
const BUDGET=4_000_000;

function allocate(p){
 const code=p.code;
 const effects=code.map(row=>instructionEffects(row));
 if(effects.some(e=>e.instructionWrite)||code.some(row=>!rolesFor(row[0])))return null;
 const leaders=new Set([0]);
 const edges=code.map((row,i)=>{
  const targets=rolesFor(row[0]).flatMap((role,j)=>role==='j'?[(row[j+1]-1)/5]:[]);
  if(targets.some(n=>!Number.isInteger(n)||n<0||n>=code.length))throw new RangeError('Invalid register allocation branch');
  for(const n of targets)leaders.add(n);
  if((targets.length||TERMINAL.has(row[0]))&&i+1<code.length)leaders.add(i+1);
  if(!TERMINAL.has(row[0])&&!UNCONDITIONAL.has(row[0])&&i+1<code.length)targets.push(i+1);
  return [...new Set(targets)];
 });
 const starts=[...leaders].sort((a,b)=>a-b);
 // Bound compiler memory/work for adversarial or very large source programs.
 if(starts.length*Math.max(1,p.registers)>BUDGET)return null;
 const owners=new Int32Array(code.length),blocks=starts.map((start,i)=>({start,end:starts[i+1]??code.length,use:new Set(),def:new Set(),incoming:new Set(),outgoing:new Set(),predecessors:[],successors:[]}));
 for(const [index,b]of blocks.entries()){
  for(let at=b.start;at<b.end;at++){
   owners[at]=index;
   const e=effects[at];
   for(const r of e.reads)if(!b.def.has(r))b.use.add(r);
   for(const r of e.mustWrites??e.writes)b.def.add(r);
  }
 }
 for(const [index,b]of blocks.entries()){
  b.successors=[...new Set(edges[b.end-1].map(at=>owners[at]))];
  for(const target of b.successors)blocks[target].predecessors.push(index);
 }
 const queue=blocks.map((_,i)=>i),queued=new Uint8Array(blocks.length);queued.fill(1);
 let work=0;
 while(queue.length){
  const index=queue.pop(),b=blocks[index];queued[index]=0;
  const outgoing=new Set();
  for(const next of b.successors)for(const r of blocks[next].incoming){if(++work>BUDGET)return null;outgoing.add(r);}
  const incoming=new Set(b.use);
  for(const r of outgoing){if(++work>BUDGET)return null;if(!b.def.has(r))incoming.add(r);}
  const changed=incoming.size!==b.incoming.size||[...incoming].some(r=>!b.incoming.has(r));
  b.outgoing=outgoing;b.incoming=incoming;
  if(changed)for(const pred of b.predecessors)if(!queued[pred]){queue.push(pred);queued[pred]=1;}
 }
 const first=new Int32Array(p.registers+1);first.fill(code.length);
 const last=new Int32Array(p.registers+1);last.fill(-1);
 const touch=(r,at)=>{
  if(!Number.isInteger(r)||r<1||r>p.registers)throw new RangeError('Invalid register allocation operand');
  first[r]=Math.min(first[r],at);last[r]=Math.max(last[r],at);
 };
 for(const b of blocks){
  for(const r of b.incoming)touch(r,b.start);
  for(const r of b.outgoing)touch(r,b.end-1);
  for(let at=b.start;at<b.end;at++){
   // Distinct operands in one instruction stay distinct, including fused
   // internal dependencies and read-before-write behavior.
   rolesFor(code[at][0]).forEach((role,j)=>{if(role==='r')touch(code[at][j+1],at);});
  }
 }
 const intervals=[];
 for(let r=1;r<=p.registers;r++)if(last[r]>=0)intervals.push({r,first:first[r],last:last[r]});
 intervals.sort((a,b)=>a.first-b.first||a.last-b.last||a.r-b.r);
 // End-position heap makes interval retirement O(log live registers).
 const active=[],free=[],mapping=new Int32Array(p.registers+1);let slots=0;
 const push=item=>{let at=active.length;active.push(item);while(at){const parent=(at-1)>>1;if(active[parent].last<=item.last)break;active[at]=active[parent];at=parent;}active[at]=item;};
 const pop=()=>{const top=active[0],tail=active.pop();if(active.length){let at=0;while(at*2+1<active.length){let child=at*2+1;if(child+1<active.length&&active[child+1].last<active[child].last)child++;if(active[child].last>=tail.last)break;active[at]=active[child];at=child;}active[at]=tail;}return top;};
 for(const interval of intervals){
  while(active.length&&active[0].last<interval.first)free.push(pop().slot);
  const slot=free.length?free.pop():++slots;mapping[interval.r]=slot;push({last:interval.last,slot});
 }
 const physical=Array.from({length:slots+1},(_,i)=>i);
 for(let i=slots;i>1;i--){const j=randomInt(1,i+1);[physical[i],physical[j]]=[physical[j],physical[i]];}
 const rows=code.map(row=>{const out=[...row];rolesFor(row[0]).forEach((role,j)=>{if(role==='r')out[j+1]=physical[mapping[row[j+1]]];});return out;});
 return {...p,registers:slots,code:rows};
}

export function compactProgramRegisters(program){
 if(![2,3].includes(program?.version)||!Array.isArray(program.prototypes)||program.fragments?.size)throw new TypeError('Register allocation requires unfused canonical or lowered bytecode');
 let before=0,after=0,skipped=0;
 const prototypes=program.prototypes.map(p=>{
  before+=p.registers;const allocated=allocate(p);if(!allocated)skipped++;
  const result=allocated??p;after+=result.registers;return result;
 });
 return {...program,prototypes,stats:{...program.stats,registerAllocation:Object.freeze({before,after,skipped})}};
}
