import {OP} from './opcodes.mjs';
import {instructionEffects} from './dataflow.mjs';
import {PRIVATE_GET,PRIVATE_INIT,PRIVATE_OPEN,PRIVATE_SPAN,PRIVATE_SELECT,PRIVATE_ARITHMETIC,PRIVATE_DESCRIPTOR,PRIVATE_CAPTURE,PRIVATE_RECEIVE} from './private-ops.mjs';

const terminals=new Set([OP.RETURN,OP.TAILCALL,256,258,PRIVATE_DESCRIPTOR]);
const equal=(a,b)=>a.size===b.size&&[...a].every(value=>b.has(value));
const union=sets=>new Set(sets.flatMap(set=>[...set]));
const intersection=sets=>sets.length?new Set([...sets[0]].filter(value=>sets.every(set=>set.has(value)))):new Set();
const pc=index=>index*5+1;

// Operand write destinations are memory effects, not executable CFG edges.
export function effectSuccessors(row,index,count){
 const target=value=>{const result=(value-1)/5;if(!Number.isInteger(result)||result<0||result>=count)throw new TypeError('Invalid effect graph target');return result;};
 if(terminals.has(row[0]))return [];
 if(row[0]===OP.JUMP)return [target(row[1])];
 if(row[0]===OP.FORNEXT)return [target(row[3])];
 const next=index+1<count?[index+1]:[];
 if([OP.JF,OP.JT,OP.JNIL].includes(row[0]))next.push(target(row[2]));
 else if(row[0]===OP.FORCHECK)next.push(target(row[4]));
 return [...new Set(next)];
}

function resources(row,p,program,fragments,index,escapedCells){
 const effects=instructionEffects(row,fragments),reads=new Set(effects.reads.filter(r=>r>0).map(r=>'r:'+r)),writes=new Set(effects.writes.filter(r=>r>0).map(r=>'r:'+r)),weak=new Set();
 const readCell=slot=>{reads.add('binding:'+slot);reads.add('cell:'+slot);};
 const writeCell=(slot,fresh=false)=>{if(fresh)writes.add('binding:'+slot);else reads.add('binding:'+slot);writes.add('cell:'+slot);};
 const readUp=slot=>reads.add('up:'+slot);
 const writeUp=slot=>{writes.add('up:'+slot);for(let i=1;i<=p.upvalues.length;i++)if(i!==slot)weak.add('up:'+i);};
 const [op,a,b,c]=row;
 if(op===OP.GETL||op===OP.GETLGETTABLE)readCell(b);
 else if(op===PRIVATE_DESCRIPTOR)readCell(a);
 else if(op===OP.SETL)writeCell(a);
 else if(op===OP.NEWL)writeCell(a,true);
 else if(op===OP.CONSTNEWL)writeCell(c,true);
 else if(op===OP.CONSTSETL)writeCell(c);
 else if(op===OP.GETUP)readUp(b);
 else if(op===OP.SETUP)writeUp(a);
 if(op===OP.CLOSURE){
  const child=program.prototypes[b-1];if(!child)throw new TypeError('Missing effect graph closure');
  for(const [kind,slot]of child.upvalues)if(kind===0)readCell(slot);else readUp(slot);
  weak.add('heap:*');
 }
 const fragment=fragments?.get?.(op);
 if(fragment){
  const expr=n=>{if(!n)return;if(n.cell!==undefined)readCell(row[n.cell+1]);if(n.up!==undefined)readUp(row[n.up+1]);if(n.value)expr(n.value);if(n.left)expr(n.left);if(n.right)expr(n.right);};
  const visit=statements=>{for(const s of statements){expr(s.value);if(s.branch){expr(s.branch.condition);visit(s.branch.yes);visit(s.branch.no);}else if(s.write==='cell'||s.write==='newCell')writeCell(row[s.field+1],s.write==='newCell');else if(s.write==='up')writeUp(row[s.field+1]);}};
  visit(fragment.statements);
  if(fragment.kind==='diamond'){for(const resource of writes){weak.add(resource);}writes.clear();}
 }
 if([OP.GETG,OP.GETTABLE,OP.CONSTGETTABLE,OP.GETLGETTABLE,OP.ITEM,OP.ONE,OP.MANY,OP.APPEND].includes(op))reads.add('heap:*');
 if([OP.SETG,OP.SETTABLE,OP.NEWTABLE,OP.PACK,OP.ONE,OP.MANY,OP.APPEND,OP.VARARG].includes(op))weak.add('heap:*');
 if(op===PRIVATE_GET)reads.add('private:*');
 if(op===PRIVATE_INIT)weak.add('private:*');
 if(op===PRIVATE_OPEN){reads.add('section:*');weak.add('permit:*');}
 if(op===PRIVATE_SPAN){reads.add('permit:*');weak.add('span:*');}
 if(op===PRIVATE_SELECT||op===PRIVATE_ARITHMETIC||op===PRIVATE_CAPTURE)writes.add('record:'+row[4]);
 if(op===PRIVATE_RECEIVE)reads.add('record:'+pc(index));
 if(op===OP.BINARY&&row[4]===0||op===OP.MOVE&&row[2]===0)reads.add('record:'+pc(index));
 // Unknown calls/metamethods may mutate captured cells/upvalues and heap. They
 // are MAY definitions: retaining earlier definitions prevents optimistic
 // substitution. Binding generations/closure aliases are not full heap SSA.
 if(effects.call||effects.mayYield){reads.add('heap:*');weak.add('heap:*');for(const slot of escapedCells)weak.add('cell:'+slot);for(let i=1;i<=p.upvalues.length;i++)weak.add('up:'+i);}
 return {...effects,reads,writes,weak};
}

function lattice(blocks,reachable,start,reverse,spend){
 const universe=new Set([...reachable]),sets=blocks.map((_,id)=>id===start?new Set([start]):new Set(universe));
 let changed=true;
 while(changed){changed=false;for(const id of reachable){if(id===start)continue;spend();const neighbours=(reverse?blocks[id].successors:blocks[id].predecessors).filter(n=>reachable.has(n));const next=intersection(neighbours.map(n=>sets[n]));next.add(id);if(!equal(next,sets[id])){sets[id]=next;changed=true;}}}
 return sets;
}

export function buildEffectGraph(program,prototypeIndex,{maxWork=1000000,maxEdges=250000}={}){
 const p=program.prototypes[prototypeIndex];if(!p?.code.length||p.code.length>20000)throw new RangeError('Effect graph instruction limit');
 let work=0;const spend=()=>{if(++work>maxWork)throw new RangeError('Effect graph analysis limit');};
 const successors=p.code.map((row,index)=>effectSuccessors(row,index,p.code.length));
 const predecessors=p.code.map(()=>[]);successors.forEach((edges,index)=>edges.forEach(next=>predecessors[next].push(index)));
 const leaders=new Set([0]);successors.forEach((edges,index)=>{if(edges.length!==1||edges[0]!==index+1){edges.forEach(next=>leaders.add(next));if(index+1<p.code.length)leaders.add(index+1);}});
 const starts=[...leaders].sort((a,b)=>a-b),blockAt=new Array(p.code.length);
 const blocks=starts.map((start,id)=>{const end=starts[id+1]??p.code.length;for(let i=start;i<end;i++)blockAt[i]=id;return {id,start,end,predecessors:[],successors:[]};});
 if(blocks.length>2048)throw new RangeError('Effect graph block limit');
 for(const block of blocks)block.successors=[...new Set(successors[block.end-1].map(next=>blockAt[next]))];
 for(const block of blocks)for(const next of block.successors)blocks[next].predecessors.push(block.id);
 const reachable=new Set(),todo=[0];while(todo.length){const id=todo.pop();if(reachable.has(id))continue;reachable.add(id);todo.push(...blocks[id].successors);}
 const dominators=lattice(blocks,reachable,0,false,spend);
 const exit=blocks.length,augmented=[...blocks.map(block=>({...block,predecessors:[],successors:block.successors.length?block.successors:[exit]})),{id:exit,predecessors:[],successors:[]}];
 for(const block of augmented)for(const next of block.successors)augmented[next].predecessors.push(block.id);
 const canExit=new Set(),reverseTodo=[exit];while(reverseTodo.length){const id=reverseTodo.pop();if(canExit.has(id))continue;canExit.add(id);reverseTodo.push(...augmented[id].predecessors);}
 // Regions that can flow into a nonterminating SCC do not have the finite exit
 // proof needed by diamond lowering. Keep them out of that proof domain.
 let closed=true;while(closed){closed=false;for(const id of [...canExit])if(id!==exit&&augmented[id].successors.some(next=>!canExit.has(next))){canExit.delete(id);closed=true;}}
 const postdominators=lattice(augmented,canExit,exit,true,spend);
 const immediatePostdom=blocks.map(block=>{
  if(!canExit.has(block.id))return null;
  const candidates=[...postdominators[block.id]].filter(id=>id!==block.id);
  return candidates.find(id=>candidates.every(other=>other===id||postdominators[id].has(other)))??null;
 });
 const controls=blocks.map(()=>new Set());
 for(const block of blocks)if(block.successors.length>1&&canExit.has(block.id))for(const next of block.successors)for(const id of postdominators[next])if(id!==exit&&!postdominators[block.id].has(id))controls[id].add(block.id);
 const escapedCells=new Set(program.prototypes.filter(child=>child.parent===prototypeIndex+1).flatMap(child=>child.upvalues.filter(([kind])=>kind===0).map(([,slot])=>slot)));
 const effects=p.code.map((row,index)=>resources(row,p,program,program.fragments,index,escapedCells)),keys=new Set(effects.flatMap(e=>[...e.reads,...e.writes,...e.weak]));
 if(keys.size*(blocks.length+1)>1000000)throw new RangeError('Effect graph state limit');
 const entry=new Map([...keys].map(key=>[key,new Set(['entry:'+key])])),before=blocks.map(()=>new Map()),after=blocks.map(()=>new Map());
 const sameMap=(a,b)=>a.size===b.size&&[...a].every(([key,value])=>b.has(key)&&equal(value,b.get(key)));
 const apply=(state,e,id)=>{for(const key of e.writes){spend();state.set(key,new Set([id]));}for(const key of e.weak){spend();state.set(key,new Set([...(state.get(key)??[]),id]));}};
 const queue=[0],queued=new Set(queue);
 while(queue.length){spend();const id=queue.shift();queued.delete(id);if(!reachable.has(id))continue;const block=blocks[id],incoming=new Map();
  if(id===0)for(const [key,defs]of entry)incoming.set(key,new Set(defs));
  for(const pred of block.predecessors)for(const [key,defs]of after[pred]){spend();incoming.set(key,new Set([...(incoming.get(key)??[]),...defs]));}
  const outgoing=new Map(incoming);for(let i=block.start;i<block.end;i++)apply(outgoing,effects[i],pc(i));
  before[id]=incoming;
  if(!sameMap(outgoing,after[id])){after[id]=outgoing;for(const next of block.successors)if(!queued.has(next)){queue.push(next);queued.add(next);}}
 }
 const nodes=[],edges=[];let merges=0,crossBlock=0,captures=0;
 for(const block of blocks){const state=new Map(before[block.id]);for(let index=block.start;index<block.end;index++){
  const e=effects[index],uses=[];
  if(reachable.has(block.id))for(const key of e.reads){const definitions=[...(state.get(key)??new Set(['entry:'+key]))];uses.push({resource:key,definitions});if(definitions.length>1)merges++;
   for(const definition of definitions){if(edges.length>=maxEdges)throw new RangeError('Effect graph edge limit');edges.push({from:definition,to:pc(index),resource:key});if(typeof definition==='number'&&blockAt[(definition-1)/5]!==block.id)crossBlock++;}
  }
  if(e.capture)captures+=uses.filter(use=>!use.resource.startsWith('r:')).length;
  nodes[index]={pc:pc(index),block:block.id,reachable:reachable.has(block.id),uses,writes:[...e.writes],mayWrites:[...e.weak],call:e.call,mayYield:e.mayYield,mayThrow:e.mayThrow};apply(state,e,pc(index));
 }}
 const liveIn=p.code.map(()=>new Set()),liveOut=p.code.map(()=>new Set());let changed=true;
 while(changed){changed=false;for(let i=p.code.length-1;i>=0;i--){spend();const e=effects[i],out=union(successors[i].map(next=>liveIn[next])),input=new Set([...out].filter(key=>!e.writes.has(key)));for(const key of e.reads)input.add(key);if(!equal(input,liveIn[i])||!equal(out,liveOut[i])){liveIn[i]=input;liveOut[i]=out;changed=true;}}}
 return {prototype:prototypeIndex+1,blocks,blockAt,successors,predecessors,reachable,dominators,postdominators,immediatePostdom,controls,nodes,edges,liveIn,liveOut,summary:{prototype:prototypeIndex+1,nodes:nodes.length,blocks:blocks.length,reachableBlocks:reachable.size,definitionEdges:edges.length,mergeUses:merges,crossBlockUses:crossBlock,captureUses:captures,unknownCalls:effects.filter(e=>e.call).length,controlDependencies:controls.reduce((n,set)=>n+set.size,0),work}};
}
