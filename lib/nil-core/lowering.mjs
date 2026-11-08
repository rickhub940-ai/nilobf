import { randomInt } from 'node:crypto';
import { OP, OPERAND_ROLES, LIMITS } from './opcodes.mjs';
import {hasRegisterDependency} from './dataflow.mjs';
import {privateRoles} from './private-ops.mjs';
const rolesFor=op=>privateRoles.get(op)??OPERAND_ROLES[op-1];

export function permutation(size) {
  const list = Array.from({ length: size }, (_, i) => i + 1);
  for (let i = size - 1; i > 0; i--) {
    const j = randomInt(i + 1); [list[i], list[j]] = [list[j], list[i]];
  }
  return [0, ...list];
}
function fused(left, right) {
  const [op,a,b] = left;
  if (op === OP.CONST && right[0] === OP.CONST && a !== right[1]) return [OP.CONSTPAIR,a,b,right[1],right[2]];
  if (op === OP.CONST && right[0] === OP.NEWL && right[2] === a) return [OP.CONSTNEWL,a,b,right[1],0];
  if (op === OP.CONST && right[0] === OP.SETL && right[2] === a) return [OP.CONSTSETL,a,b,right[1],0];
  if (op === OP.CONST && right[0] === OP.GETTABLE && right[3] === a) return [OP.CONSTGETTABLE,a,b,right[1],right[2]];
  if (op === OP.GETL && right[0] === OP.GETTABLE && right[2] === a) return [OP.GETLGETTABLE,a,b,right[1],right[3]];
  return null;
}

// Preserve both original writes and never merge across a branch entry. All
// relocated targets retain the VM's instruction-coordinate representation.
export function lowerNil(program, { fuse = true, permute = true, flatten = true, dependentFusion = false } = {}) {
  if (program?.version !== 2) throw new TypeError('Lowering expects canonical STBC v2');
  let merged = 0, instructions = 0, transfers = 0;
  const prototypes = program.prototypes.map(p => {
    const targets = new Set();
    for (const row of p.code) rolesFor(row[0])?.forEach((role,i) => { if (role === 'j') targets.add(row[i+1]); });
    const relocated = new Map(), code = [];
    const rate = randomInt(80,101);
    for (let i = 0; i < p.code.length; i++) {
      relocated.set(i*5+1,code.length*5+1);
      const next = p.code[i+1];
      const combined = fuse && next && !targets.has((i+1)*5+1) && (!dependentFusion||hasRegisterDependency(p.code[i],next)) && randomInt(100)<rate ? fused(p.code[i],next) : null;
      if (combined) { code.push(combined); merged++; i++; }
      else code.push([...p.code[i]]);
    }
    const registers = permute ? permutation(p.registers) : [0,...Array.from({length:p.registers},(_,i)=>i+1)];
    const constants = permute ? permutation(p.constants.length) : [0,...Array.from({length:p.constants.length},(_,i)=>i+1)];
    const values = new Array(p.constants.length);
    p.constants.forEach((v,i) => { values[constants[i+1]-1]=v; });
    for (const row of code) rolesFor(row[0]).forEach((role,i) => {
      const slot=i+1;
      if (role==='j') { if (!relocated.has(row[slot])) throw new Error('Invalid fusion branch target'); row[slot]=relocated.get(row[slot]); }
      else if (role==='r') row[slot]=registers[row[slot]];
      else if (role==='k'||role==='g') row[slot]=constants[row[slot]];
    });
    const scrambled=flatten ? relocateBlocks(code) : {code,transfers:0};
    transfers+=scrambled.transfers;instructions += scrambled.code.length;
    if(instructions>LIMITS.instructions)throw new RangeError('Lowered instruction limit exceeded');
    return {...p,code:scrambled.code,constants:values,layout:{seedA:randomInt(1,65536),seedB:randomInt(1,65536),order:permutation(4).slice(1),opLast:randomInt(2)}};
  });
  return {...program,version:3,prototypes,stats:{...program.stats,instructions,originalInstructions:program.stats.instructions,fusedInstructions:merged,insertedControlTransfers:transfers}};
}

function relocateBlocks(code) {
  const terminal=new Set([OP.RETURN,OP.TAILCALL,OP.JUMP,OP.FORNEXT]);
  const boundary=new Set([0]);
  code.forEach((row,i)=>{
    let branch=false;
    rolesFor(row[0]).forEach((role,slot)=>{if(role==='j'){boundary.add((row[slot+1]-1)/5);branch=true;}});
    if((branch||terminal.has(row[0]))&&i+1<code.length)boundary.add(i+1);
  });
  const starts=[...boundary].sort((a,b)=>a-b);
  if(starts.some(n=>!Number.isInteger(n)||n<0||n>=code.length))throw new Error('Invalid block entry');
  const blocks=starts.map((start,i)=>({start,end:starts[i+1]??code.length}));
  for(let i=blocks.length-1;i>1;i--){const j=randomInt(1,i+1);[blocks[i],blocks[j]]=[blocks[j],blocks[i]];}
  const positions=new Map(),output=[];let transfers=0;
  for(const block of blocks){
    for(let i=block.start;i<block.end;i++){positions.set(i*5+1,output.length*5+1);output.push([...code[i]]);}
    if(!terminal.has(code[block.end-1][0])&&block.end<code.length){output.push([OP.JUMP,block.end*5+1,0,0,0]);transfers++;}
  }
  for(const row of output)rolesFor(row[0]).forEach((role,i)=>{if(role==='j'){
    if(!positions.has(row[i+1]))throw new Error('Missing relocated block target');row[i+1]=positions.get(row[i+1]);
  }});
  return {code:output,transfers};
}
