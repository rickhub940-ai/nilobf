import {randomInt} from 'node:crypto';
import {OP,OPERAND_ROLES} from './opcodes.mjs';
import {instructionEffects} from './dataflow.mjs';
import {privateRoles,PRIVATE_SELECT,PRIVATE_ARITHMETIC} from './private-ops.mjs';
import {buildEffectGraph} from './effect-graph.mjs';
import {selectResultLinkCandidates} from './result-links.mjs';
const eligible=new Set([OP.CONST,OP.GETL,OP.SETL,OP.NEWL,OP.GETUP,OP.SETUP,OP.MOVE,OP.UNARY,OP.BINARY]);
const roleFor=(op,fragments)=>fragments?.get?.(op)?.roles??privateRoles.get(op)??OPERAND_ROLES[op-1]??[];
function flow(p,fragments){
 const next=p.code.map((r,i)=>{
  if([OP.RETURN,OP.TAILCALL].includes(r[0]))return [];
  if(r[0]===OP.JUMP)return [(r[1]-1)/5];if(r[0]===OP.FORNEXT)return [(r[3]-1)/5];
  return [...new Set([i+1,...([OP.JF,OP.JT,OP.JNIL].includes(r[0])?[(r[2]-1)/5]:r[0]===OP.FORCHECK?[(r[4]-1)/5]:[])])].filter(j=>j<p.code.length);
 });
 const before=p.code.map(()=>new Set()),after=p.code.map(()=>new Set());let changed=true;
 while(changed){changed=false;for(let i=p.code.length-1;i>=0;i--){const effects=instructionEffects(p.code[i],fragments),out=new Set(next[i].flatMap(j=>[...before[j]])),input=new Set([...out].filter(r=>!(effects.mustWrites??effects.writes).includes(r)));effects.reads.forEach(r=>input.add(r));if(input.size!==before[i].size||[...input].some(r=>!before[i].has(r)))changed=true;before[i]=input;after[i]=out;}}
 const leaders=new Set([0]);p.code.forEach((row,i)=>{roleFor(row[0],fragments).forEach((r,j)=>{if(r==='j')leaders.add((row[j+1]-1)/5);});if(next[i].length!==1||next[i][0]!==i+1)leaders.add(i+1);});
 return {after,leaders};
}
function fragment(rows,live,{preciseBudget=false,chargeFirst=false}={}){
 const fields=[],temps=new Map(),statements=[];let definitions=0,dependent=false;
 const field=(role,value)=>{let index=fields.findIndex(f=>f.role===role&&f.value===value);if(index<0){index=fields.length;fields.push({role,value});}return index;};
 const read=r=>{if(temps.has(r)){dependent=true;return {temp:temps.get(r)};}return {reg:field('r',r)};};
 for(const [index,[op,a,b,c,d]]of rows.entries()){
  if(preciseBudget&&(chargeFirst||index>0))statements.push({spend:1});
  if(op===OP.JUMP&&preciseBudget)continue;
  let expression;
  if(op===OP.CONST)expression={constant:field('k',b)};
  else if(op===OP.GETL)expression={cell:field('l',b)};
  else if(op===OP.GETUP)expression={up:field('u',b)};
  else if(op===OP.MOVE)expression=read(b);
  else if(op===OP.UNARY)expression={unary:c,value:read(b)};
  else if(op===OP.BINARY)expression={binary:d,left:read(b),right:read(c)};
  else if([OP.SETL,OP.NEWL,OP.SETUP].includes(op)){
   statements.push({write:op===OP.SETUP?'up':op===OP.NEWL?'newCell':'cell',field:field(op===OP.SETUP?'u':'l',a),value:read(b)});continue;
  }else return null;
  statements.push({define:++definitions,value:expression});temps.set(a,definitions);
 }
 for(const [reg,temp]of temps)if(live.has(reg))statements.push({write:'reg',field:field('r',reg),value:{temp}});
 if(!dependent||fields.length>4||fields.filter(f=>f.role==='k').length>2)return null;
 return {roles:fields.map(f=>f.role),values:fields.map(f=>f.value),statements,cost:rows.length};
}

function graphDiamonds(p,graph,define,{preciseBudget=false,protectedRows=new Set()}={}){
 const consumed=new Set(),replacements=new Map(),proofs=[];
 const mutationTargets=new Set(p.code.filter(row=>[PRIVATE_SELECT,PRIVATE_ARITHMETIC].includes(row[0])).map(row=>(row[4]-1)/5));
 const path=(start,merge,header)=>{
  const indices=[],visited=new Set();let block=start,previous=header;
  while(block!==merge){
   const info=graph.blocks[block];
   if(!info||visited.has(block)||visited.size>=16||info.predecessors.length!==1||info.predecessors[0]!==previous||!graph.dominators[block].has(header)||info.successors.length!==1)return null;
   visited.add(block);
   for(let index=info.start;index<info.end;index++){
    const row=p.code[index];
    if(protectedRows.has(index)||consumed.has(index)||mutationTargets.has(index)||row[0]!==OP.JUMP&&!eligible.has(row[0])||row[0]===OP.BINARY&&row[4]===0||indices.length>=48)return null;
    indices.push(index);
   }
   previous=block;block=info.successors[0];
  }
  return indices;
 };
 for(let index=0;index<p.code.length;index++){
  const row=p.code[index];if(![OP.JF,OP.JT,OP.JNIL].includes(row[0])||protectedRows.has(index)||consumed.has(index)||mutationTargets.has(index)||!graph.nodes[index].reachable)continue;
  const header=graph.blockAt[index],merge=graph.immediatePostdom[header];
  if(merge===null||merge===header||merge>=graph.blocks.length||graph.blocks[header].end-1!==index||graph.successors[index].length!==2)continue;
  const fallthrough=graph.blockAt[index+1],target=graph.blockAt[(row[2]-1)/5];
  const yes=path(row[0]===OP.JF?fallthrough:target,merge,header),no=path(row[0]===OP.JF?target:fallthrough,merge,header);
  if(!yes||!no||!yes.length&&!no.length||yes.some(i=>no.includes(i)))continue;
  // The emitted transfer replaces an original final JUMP. Without one on
  // both paths, moving its budget charge can change effects at exhaustion.
  if(preciseBudget&&(!yes.length||!no.length||p.code[yes.at(-1)][0]!==OP.JUMP||p.code[no.at(-1)][0]!==OP.JUMP))continue;
  const all=new Set([...yes,...no]),mergeIndex=graph.blocks[merge].start;
  // Require an actual branch-written cell/upvalue reaching a consumer at or
  // after the merge. A conditional with only cosmetic control does not qualify.
  const consumers=[];
  for(const node of graph.nodes)if(node.reachable&&!all.has((node.pc-1)/5)&&graph.dominators[node.block].has(merge))for(const use of node.uses){
   if(!/^(cell|up):/.test(use.resource)||use.definitions.length<2)continue;
   const producers=use.definitions.filter(def=>typeof def==='number'&&all.has((def-1)/5)&&graph.nodes[(def-1)/5].writes.includes(use.resource));
   if(producers.length)consumers.push({resource:use.resource,consumer:node.pc,producers});
  }
  if(!consumers.length)continue;
  const live=new Set([...graph.liveIn[mergeIndex]].filter(key=>key.startsWith('r:')).map(key=>Number(key.slice(2))));
  const reduce=indices=>{const rows=preciseBudget?indices.slice(0,-1).map(i=>p.code[i]):indices.map(i=>p.code[i]).filter(r=>r[0]!==OP.JUMP);return rows.length?fragment(rows,live,{preciseBudget,chargeFirst:preciseBudget}):{roles:[],values:[],statements:[]};};
  const positive=reduce(yes),negative=reduce(no);if(!positive||!negative)continue;
  const fields=[{role:'r',value:row[1]}];
  function rebase(f){
   const positions=f.roles.map((role,i)=>{let at=fields.findIndex(field=>field.role===role&&field.value===f.values[i]);if(at<0){at=fields.length;fields.push({role,value:f.values[i]});}return at;});
   const expression=n=>{const out={...n};for(const key of ['reg','cell','up','constant'])if(n[key]!==undefined)out[key]=positions[n[key]];for(const key of ['value','left','right'])if(n[key])out[key]=expression(n[key]);return out;};
   return f.statements.map(s=>s.spend?s:({...s,...(s.field!==undefined?{field:positions[s.field]}:{}),value:expression(s.value)}));
  }
  const yesStatements=rebase(positive),noStatements=rebase(negative);
  if(fields.length>4||fields.filter(field=>field.role==='k').length>2)continue;
  const definition={kind:'diamond',roles:fields.map(field=>field.role),cost:1+Math.max(yes.length,no.length),...(preciseBudget?{preciseBudget:true}:{}),statements:[{branch:{condition:{reg:0},mode:row[0]===OP.JNIL?'nil':'truthy',yes:yesStatements,no:noStatements,yesCost:yes.length,noCost:no.length}}]};
  const op=define(definition);if(!op)continue;
  replacements.set(index,{row:[op,...fields.map(field=>field.value),...Array(4-fields.length).fill(0)],target:mergeIndex*5+1});
  consumed.add(index);for(const item of all)consumed.add(item);
  proofs.push({head:index*5+1,merge:mergeIndex*5+1,yes:yes.map(i=>i*5+1),no:no.map(i=>i*5+1),consumers});
 }
 if(!replacements.size)return {prototype:p,proofs,removed:0};
 const code=[],relocated=new Map();
 for(let index=0;index<p.code.length;index++){
  const replacement=replacements.get(index);
  if(replacement){relocated.set(index*5+1,code.length*5+1);code.push(replacement.row,[OP.JUMP,replacement.target,0,0,0]);}
  else if(!consumed.has(index)){relocated.set(index*5+1,code.length*5+1);code.push([...p.code[index]]);}
 }
 for(const row of code)roleFor(row[0],define.fragments).forEach((role,j)=>{if(role==='j'){const target=relocated.get(row[j+1]);if(target===undefined)throw new Error('Effect graph consumed an externally addressed instruction');row[j+1]=target;}});
 return {prototype:{...p,code},proofs,removed:p.code.length-code.length};
}
/** Compose actual value computations; no decoy operations or identity masks.
 * The caller selects compiler-owned prototypes. Register
 * liveness preserves every value crossing a fragment or CFG boundary.
 */
export function fuseMaterializerProgram(program,firstNativePrototype,{effectGraph=false,resultLinks=false,cfgResultLinks=false,semanticReceipts=false,preciseBudget=false}={}){
 if(typeof cfgResultLinks!=='boolean'||cfgResultLinks&&!resultLinks)throw new TypeError('CFG results require result links');
 if(typeof semanticReceipts!=='boolean'||semanticReceipts&&!cfgResultLinks)throw new TypeError('Semantic receipts require CFG proofs');
 const fragments=new Map(),byShape=new Map(),used=new Set(program.prototypes.flatMap(p=>p.code.map(r=>r[0])));let removed=0;
 const graphs=[],diamondProofs=[];let diamondRemoved=0,reservedResultPairs=0;
 const define=definition=>{const shape=JSON.stringify(definition);let op=byShape.get(shape);if(!op&&fragments.size>=192)return null;if(!op){do{op=randomInt(1024,2**32);}while(used.has(op));used.add(op);fragments.set(op,definition);byShape.set(shape,op);}return op;};
 define.fragments=fragments;
 const prototypes=program.prototypes.map((p,index)=>{
  if(index<firstNativePrototype)return p;
  const before=cfgResultLinks&&resultLinks&&!p.packetDescriptor?selectResultLinkCandidates(p,fragments,{cfg:true,semanticReceipts}).slice(0,4):[];
  const preserved=new Set(before.flatMap(link=>[link.producer,link.consumer,...link.corridor]).map(pc=>(pc-1)/5));
  if(effectGraph){const graph=buildEffectGraph(program,index),result=graphDiamonds(p,graph,define,{preciseBudget,protectedRows:preserved});graphs.push(graph.summary);diamondProofs.push(...result.proofs.map(proof=>({prototype:index+1,...proof})));diamondRemoved+=result.removed;p=result.prototype;}
  // Preserve at most four proven arithmetic corridors per owned preparation
  // prototype. Other fragments retain their existing fusion. Final links are
  // proved again after relocation, descriptor packing and data lowering.
  const reserved=resultLinks&&!p.packetDescriptor?selectResultLinkCandidates(p,fragments,{cfg:cfgResultLinks,semanticReceipts}).slice(0,4):[];
  const protectedRows=new Set(reserved.flatMap(link=>[link.producer,link.consumer,...link.corridor]).map(pc=>(pc-1)/5));reservedResultPairs+=reserved.length;
  const {after,leaders}=flow(p,fragments),code=[],relocated=new Map(),templates=new Set(p.code.filter(r=>[PRIVATE_SELECT,PRIVATE_ARITHMETIC].includes(r[0])).map(r=>(r[4]-1)/5));
  for(let i=0;i<p.code.length;){
   let chosen=null,length=0;const maximum=randomInt(3,8);
   for(let n=1;n<=maximum&&i+n<=p.code.length;n++){
    if(protectedRows.has(i+n-1)||templates.has(i+n-1)||!eligible.has(p.code[i+n-1][0])||(n>1&&leaders.has(i+n-1)))break;
    if(n>1){const f=fragment(p.code.slice(i,i+n),after[i+n-1],{preciseBudget});if(f){chosen=f;length=n;}}
   }
   relocated.set(i*5+1,code.length*5+1);
   if(chosen){const definition={roles:chosen.roles,statements:chosen.statements,cost:chosen.cost,...(preciseBudget?{preciseBudget:true}:{})},shape=JSON.stringify(definition);let op=byShape.get(shape);
    if(!op&&fragments.size>=192){code.push([...p.code[i]]);i++;continue;}
    if(!op){do{op=randomInt(1024,2**32);}while(used.has(op));used.add(op);fragments.set(op,definition);byShape.set(shape,op);}
    code.push([op,...chosen.values,...Array(4-chosen.values.length).fill(0)]);removed+=length-1;i+=length;}
   else{code.push([...p.code[i]]);i++;}
  }
  for(const row of code)roleFor(row[0],fragments).forEach((role,j)=>{if(role==='j'){const target=relocated.get(row[j+1]);if(!target)throw new Error('Fragment consumed a branch entry');row[j+1]=target;}});
  return {...p,code};
 });
 const graphSummary=effectGraph?{prototypes:graphs.length,nodes:graphs.reduce((n,g)=>n+g.nodes,0),blocks:graphs.reduce((n,g)=>n+g.blocks,0),definitionEdges:graphs.reduce((n,g)=>n+g.definitionEdges,0),crossBlockUses:graphs.reduce((n,g)=>n+g.crossBlockUses,0),mergeUses:graphs.reduce((n,g)=>n+g.mergeUses,0),captureUses:graphs.reduce((n,g)=>n+g.captureUses,0),controlDependencies:graphs.reduce((n,g)=>n+g.controlDependencies,0),diamondRegions:diamondProofs.length,diamondRemovedInstructions:diamondRemoved}:undefined;
 return {...program,fragments,prototypes,...(effectGraph?{effectGraph:{summary:graphSummary,graphs,proofs:diamondProofs}}:{}),stats:{...program.stats,instructions:prototypes.reduce((n,p)=>n+p.code.length,0),materializerFragments:fragments.size,materializerRemovedInstructions:removed+diamondRemoved,reservedResultPairs}};
}

const unary=['','-','not ','#'],binary=['','+','-','*','/','%','^','..','==','~=','<','<=','>','>='];
export function fragmentSemantic(f,key1,key2){
 const args=['a','b','c','d'],keys=new Map();f.roles.forEach((role,i)=>{if(role==='k')keys.set(i,keys.size?key2:key1);});
 function expression(n){
  if(n.temp)return 'v'+n.temp;
  if(n.constant!==undefined)return `constant(frame,${args[n.constant]},${keys.get(n.constant)})`;
  if(n.reg!==undefined)return `registers[${args[n.reg]}]`;
  if(n.cell!==undefined)return `cells[${args[n.cell]}].v`;
  if(n.up!==undefined)return `upvalues[${args[n.up]}].v`;
  if(n.unary)return `(${unary[n.unary]}${expression(n.value)})`;
  if(n.binary)return `(${expression(n.left)}${binary[n.binary]}${expression(n.right)})`;
  throw new TypeError('Invalid fragment expression');
 }
 const charge=cost=>`budget[1]=budget[1]-${cost};if budget[1]<0 then error('Nil instruction budget exceeded',0)end;`;
 const statements=list=>list.map(s=>s.spend?charge(s.spend):s.branch?`if ${s.branch.mode==='nil'?expression(s.branch.condition)+'==nil':expression(s.branch.condition)} then ${f.preciseBudget?'':charge(s.branch.yesCost)}${statements(s.branch.yes)}else ${f.preciseBudget?'':charge(s.branch.noCost)}${statements(s.branch.no)}end;`:s.define?`local v${s.define}=${expression(s.value)};`:s.write==='reg'?`registers[${args[s.field]}]=${expression(s.value)};`:s.write==='newCell'?`cells[${args[s.field]}]={v=${expression(s.value)}};`:`${s.write==='cell'?'cells':'upvalues'}[${args[s.field]}].v=${expression(s.value)};`).join('');
 return (f.kind==='diamond'||f.preciseBudget?'':charge(f.cost-1))+statements(f.statements);
}
