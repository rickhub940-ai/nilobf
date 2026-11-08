import {OP,OPERAND_ROLES} from './opcodes.mjs';
import {privateRoles,PRIVATE_GET,PRIVATE_DENY,PRIVATE_INIT,PRIVATE_CAP,PRIVATE_SELECT,PRIVATE_OPEN,PRIVATE_SPAN,PRIVATE_ARITHMETIC,PRIVATE_DESCRIPTOR,PRIVATE_CAPTURE,PRIVATE_RECEIVE} from './private-ops.mjs';

// Register use/definition positions, not just operand types. Reference mutations
// are effects even when they do not define a new register value.
const access={
 CONST:[[],[1]],GETG:[[],[1]],SETG:[[1],[]],GETL:[[],[1]],SETL:[[2],[]],NEWL:[[2],[]],
 GETUP:[[],[1]],SETUP:[[2],[]],MOVE:[[2],[1]],GETTABLE:[[2,3],[1]],SETTABLE:[[1,2,3],[]],
 NEWTABLE:[[],[1]],PACK:[[],[1]],ONE:[[1,2],[]],MANY:[[1,2],[]],ITEM:[[2],[1]],
 CALL:[[2,3],[1]],VARARG:[[],[1]],RETURN:[[1],[]],JUMP:[[],[]],JF:[[1],[]],JT:[[1],[]],JNIL:[[1],[]],
 CLOSURE:[[],[1]],UNARY:[[2],[1]],BINARY:[[2,3],[1]],APPEND:[[1,2],[]],FORPREP:[[1,2,3],[1,2,3]],
 FORCHECK:[[1,2,3],[]],FORNEXT:[[1,2],[1]],TAILCALL:[[1,2],[]],CALL1:[[2,3],[1]],CALLVOID:[[1,2],[]],
 CONSTPAIR:[[],[1,3]],CONSTNEWL:[[],[1]],CONSTSETL:[[],[1]],CONSTGETTABLE:[[4],[1,3]],GETLGETTABLE:[[4],[1,3]],
};
const calls=new Set([OP.CALL,OP.CALL1,OP.CALLVOID,OP.TAILCALL]);
const metamethods=new Set([OP.GETG,OP.SETG,OP.GETTABLE,OP.SETTABLE,OP.UNARY,OP.BINARY,OP.APPEND,OP.CONSTGETTABLE,OP.GETLGETTABLE]);
const names=Object.keys(OP);
export function instructionEffects(row,fragments){
 if(row[0]===PRIVATE_CAPTURE)return {reads:row.slice(1,4),writes:[],localDependency:[],call:false,mayYield:false,mayThrow:true,readsMemory:true,writesMemory:true,capture:false,branch:false,terminal:false,valuePack:false,instructionWrite:{target:row[4],operands:[2,3,4],condition:row[1]}};
 if(row[0]===PRIVATE_RECEIVE)return {reads:[],writes:[row[1]],localDependency:[],call:false,mayYield:true,mayThrow:true,readsMemory:true,writesMemory:true,capture:false,branch:false,terminal:false,valuePack:false};
 if(row[0]===PRIVATE_DESCRIPTOR)return {reads:[],writes:[],localDependency:[],call:false,mayYield:false,mayThrow:true,readsMemory:true,writesMemory:false,capture:false,branch:false,terminal:true,valuePack:true};
 const fragment=fragments?.get?.(row[0]);if(fragment){
  const reads=new Set(),writes=new Set();let memoryWrite=false,mayYield=false;
  function expr(v){if(!v)return;if(v.reg!==undefined)reads.add(row[v.reg+1]);if(v.unary||v.binary)mayYield=true;if(v.value)expr(v.value);if(v.left)expr(v.left);if(v.right)expr(v.right);}
  function statements(list){for(const s of list){expr(s.value);if(s.branch){expr(s.branch.condition);statements(s.branch.yes);statements(s.branch.no);}else if(s.write==='reg')writes.add(row[s.field+1]);else if(s.write)memoryWrite=true;}}
  statements(fragment.statements);
  return {reads:[...reads],writes:[...writes],...(fragment.kind==='diamond'?{mustWrites:[]}:{}),localDependency:[],call:false,mayYield,mayThrow:true,readsMemory:true,writesMemory:memoryWrite,capture:false,branch:false,terminal:false,valuePack:false};
 }
 if(privateRoles.has(row[0]))return {reads:row[0]===PRIVATE_OPEN?row.slice(2,4):row[0]===PRIVATE_SPAN?[row[2]]:row[0]===PRIVATE_SELECT?row.slice(1,4):[PRIVATE_DENY,PRIVATE_INIT,PRIVATE_ARITHMETIC].includes(row[0])?[row[1]]:[],writes:[PRIVATE_GET,PRIVATE_CAP,PRIVATE_OPEN,PRIVATE_SPAN].includes(row[0])?[row[1]]:[],localDependency:[],call:row[0]===PRIVATE_CAP,mayYield:false,mayThrow:true,readsMemory:true,writesMemory:[PRIVATE_INIT,PRIVATE_SELECT,PRIVATE_OPEN,PRIVATE_SPAN,PRIVATE_ARITHMETIC].includes(row[0]),capture:[PRIVATE_OPEN,PRIVATE_SPAN].includes(row[0]),branch:false,terminal:false,valuePack:false,...(row[0]===PRIVATE_ARITHMETIC?{instructionWrite:{target:row[4],operand:4,choices:[row[2],row[3]],condition:row[1]}}:{})};
 if(row[0]===257||row[0]===258)return {reads:[],writes:[],localDependency:[],call:true,mayYield:false,mayThrow:true,readsMemory:true,writesMemory:true,capture:false,branch:false,terminal:row[0]===258,valuePack:false};
 if(row[0]===256)return {reads:[],writes:[],localDependency:[],call:true,mayYield:true,mayThrow:true,readsMemory:true,writesMemory:false,capture:false,branch:false,terminal:true,valuePack:true};
 const op=row[0],entry=access[names[op-1]];if(!entry||!OPERAND_ROLES[op-1])throw new TypeError('Unknown dataflow instruction');
 const reads=entry[0].map(i=>row[i]),writes=entry[1].map(i=>row[i]);
 // Fused table gets consume the value written by their first operation.
 const localDependency=[OP.CONSTGETTABLE,OP.GETLGETTABLE].includes(op)?[row[1]]:[];
 const capture=op===OP.CLOSURE,branch=OPERAND_ROLES[op-1].includes('j'),terminal=[OP.RETURN,OP.TAILCALL].includes(op);
 return {reads,writes,localDependency,call:calls.has(op),mayYield:calls.has(op)||metamethods.has(op),mayThrow:calls.has(op)||metamethods.has(op)||[OP.FORPREP,OP.FORCHECK,OP.FORNEXT].includes(op),
  readsMemory:[OP.GETG,OP.GETL,OP.GETUP,OP.GETTABLE,OP.ITEM,OP.CONSTGETTABLE,OP.GETLGETTABLE,OP.ONE,OP.MANY,OP.APPEND].includes(op),
  writesMemory:[OP.SETG,OP.SETL,OP.NEWL,OP.SETUP,OP.SETTABLE,OP.ONE,OP.MANY,OP.APPEND,OP.CONSTNEWL,OP.CONSTSETL].includes(op),capture,branch,terminal,
  valuePack:[OP.PACK,OP.ONE,OP.MANY,OP.CALL,OP.VARARG,OP.RETURN,OP.TAILCALL,OP.CALL1,OP.CALLVOID,OP.APPEND].includes(op)};
}
export function hasRegisterDependency(left,right){const defined=new Set(instructionEffects(left).writes);return instructionEffects(right).reads.some(r=>defined.has(r));}

// Block-local def/use links are sufficient for the bounded fusion pass. This is
// deliberately not advertised as whole-program SSA or alias analysis.
export function analyzeDataflow(prototype,fragments){
 const leaders=new Set([1]);
 prototype.code.forEach((row,i)=>{const pc=i*5+1,e=instructionEffects(row,fragments);(fragments?.get?.(row[0])?.roles??privateRoles.get(row[0])??(row[0]===256?['g']:row[0]===257?['i']:row[0]===258?[]:OPERAND_ROLES[row[0]-1])).forEach((role,j)=>{if(role==='j')leaders.add(row[j+1]);});if((e.branch||e.terminal)&&i+1<prototype.code.length)leaders.add(pc+5);});
 const annotations=[],definitions=new Map();let block=0;
 prototype.code.forEach((row,i)=>{const pc=i*5+1;if(leaders.has(pc)){block++;definitions.clear();}const effects=instructionEffects(row,fragments),uses=effects.reads.map(register=>({register,definition:definitions.get(register)??null}));annotations.push({pc,block,...effects,uses});(effects.mustWrites??effects.writes).forEach(r=>definitions.set(r,pc));});
 return {blocks:block,annotations};
}
