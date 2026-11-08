import {OP, OPERAND_ROLES} from './opcodes.mjs';
import {privateRoles, PRIVATE_ARITHMETIC, PRIVATE_SELECT, PRIVATE_DESCRIPTOR,PRIVATE_CAPTURE,PRIVATE_RECEIVE} from './private-ops.mjs';
import {instructionEffects} from './dataflow.mjs';

const terminal = new Set([OP.RETURN, OP.TAILCALL, 256, 258, PRIVATE_DESCRIPTOR]);
const rolesFor = (op, fragments) => fragments?.get?.(op)?.roles ?? fragments?.[op]?.roles ?? privateRoles.get(op) ?? (op===256?['g']:op===257?['i']:op===258?[]:OPERAND_ROLES[op-1]);

// j on PRIVATE_ARITHMETIC denotes a write destination, not an executable edge.
// CFG edges and write/read dependencies must remain separate.
function successors(row, index, count) {
  const [op,a,b,c,d] = row;
  if(terminal.has(op))return [];
  if(op===OP.JUMP)return [(a-1)/5];
  if(op===OP.FORNEXT)return [(c-1)/5];
  return [...new Set([index+1,...([OP.JF,OP.JT,OP.JNIL].includes(op)?[(b-1)/5]:op===OP.FORCHECK?[(d-1)/5]:[])])].filter(i=>i<count);
}

/** A restricted, linear producer/consumer proof, not whole-program SSA.
 * The producer must dominate the consumer through an exclusive corridor of
 * relocation JUMPs. It rejects unsupported shapes rather than guessing.
 * Contracts stay compiler-side; no producer table is emitted into Lua.
 */
export function validateFetchContracts(program) {
  const contracts=[];
  for(const [prototype,p] of program.prototypes.entries()){
    const writers=p.code.map((row,index)=>({row,index})).filter(({row})=>row[0]===PRIVATE_ARITHMETIC||row[0]===PRIVATE_CAPTURE);
    const templates=p.code.flatMap((row,index)=>row[0]===PRIVATE_RECEIVE||row[0]===OP.BINARY&&row[4]===0?[index]:[]);
    if(!writers.length&&!templates.length)continue;
    const predecessors=Array.from({length:p.code.length},()=>[]);
    p.code.forEach((row,index)=>successors(row,index,p.code.length).forEach(target=>{
      if(!Number.isInteger(target)||target<0||target>=p.code.length)throw new TypeError('Invalid fetch contract edge');
      predecessors[target].push(index);
    }));
    const consumers=new Set();
    for(const {row,index} of writers){
      const receipt=row[0]===PRIVATE_CAPTURE;
      const [,condition,yes,no,targetPc]=row,target=(targetPc-1)/5,consumer=p.code[target];
      if(receipt){
        if(row.slice(1,4).some(r=>!Number.isInteger(r)||r<1||r>p.registers-2))throw new TypeError('Invalid receipt capture registers');
      }else if(!Number.isInteger(condition)||condition<1||condition>p.registers||!Number.isInteger(yes)||!Number.isInteger(no)||yes<1||yes>2||no<1||no>2||yes===no)throw new TypeError('Invalid fetch contract producer');
      if(!Number.isInteger(target)||target<=0||!consumer||consumers.has(target)||(receipt?consumer[0]!==PRIVATE_RECEIVE||consumer.slice(2).some(n=>n!==0):consumer[0]!==OP.BINARY||consumer[4]!==0))throw new TypeError('Invalid fetch contract consumer');
      if((receipt?[consumer[1]]:consumer.slice(1,4)).some(r=>!Number.isInteger(r)||r<1||r>(receipt?p.registers-2:p.registers)))throw new TypeError('Invalid fetch contract registers');
      consumers.add(target);
      let previous=index,cursor=index+1;
      const visited=new Set(),corridor=[];
      while(cursor!==target){
        if(!Number.isInteger(cursor)||cursor<=0||cursor>=p.code.length||visited.has(cursor)||predecessors[cursor].length!==1||predecessors[cursor][0]!==previous||p.code[cursor][0]!==OP.JUMP)throw new TypeError('Fetch contract producer does not exclusively reach consumer');
        visited.add(cursor);corridor.push(cursor*5+1);previous=cursor;cursor=(p.code[cursor][1]-1)/5;
      }
      if(predecessors[target].length!==1||predecessors[target][0]!==previous)throw new TypeError('Fetch contract consumer bypasses producer');
      // Check direct register definitions. Values from earlier blocks remain
      // unresolved and are reported; this corridor proof never invents a def.
      const inputs=receipt?row.slice(2,4):consumer.slice(2,4);
      const definitions=new Map(),needed=new Set([condition,...inputs]);
      // A diagnostic scan is bounded even on very large straight-line input.
      for(let i=index-1,scanned=0;i>=0&&needed.size&&scanned<1024;i--,scanned++){
        const effect=instructionEffects(p.code[i],program.fragments);
        for(const register of effect.writes)if(needed.has(register)){definitions.set(register,i*5+1);needed.delete(register);}
        if(predecessors[i].length!==1||predecessors[i][0]!==i-1)break;
        if([OP.JUMP,OP.FORNEXT].includes(p.code[i][0]))break;
      }
      contracts.push(Object.freeze({prototype:prototype+1,...(receipt?{kind:'value-receipt'}:{}),producer:index*5+1,consumer:targetPc,condition,conditionDefinition:definitions.get(condition)??null,inputs:Object.freeze(inputs.map(register=>Object.freeze({register,definition:definitions.get(register)??null}))),operand:4,choices:Object.freeze(receipt?[1,2]:[yes,no]),corridor:Object.freeze(corridor)}));
    }
    if(templates.some(index=>!consumers.has(index)))throw new TypeError('Fetch contract template has no producer');
    // No other operation may refer to the invalid operator template as a write
    // destination; runtime permits only this proven BINARY operand mutation.
    for(const row of p.code)if(row[0]!==PRIVATE_ARITHMETIC){
      const roles=rolesFor(row[0],program.fragments);
      if(!roles)throw new TypeError('Unknown fetch contract operation');
      if(row[0]===PRIVATE_SELECT&&consumers.has((row[4]-1)/5))throw new TypeError('Fetch contract has a competing operand writer');
    }
  }
  return Object.freeze(contracts);
}
