import {OP} from './opcodes.mjs';
import {instructionEffects} from './dataflow.mjs';
import {effectSuccessors} from './effect-graph.mjs';
import {resultConsumerSlots, resultConsumerKind} from './result-protocol.mjs';

const arithmetic = new Set([OP.BINARY, OP.UNARY]);
const branches = new Set([OP.JF, OP.JT, OP.JNIL]);
const corridorOps = new Set([OP.CONST, OP.GETL, OP.GETUP, OP.MOVE, OP.NEWL, OP.SETL, OP.JUMP, ...branches]);
const ordinary = row => arithmetic.has(row?.[0]) && (row[0] === OP.BINARY ? row[4] >= 1 && row[4] <= 13 : row[3] >= 1 && row[3] <= 3);
const inputs = row => row[0] === OP.BINARY ? [2, 3] : [2];
const pc = index => index * 5 + 1;

export function resultLinkGraph(p, fragments) {
  const successors = p.code.map((row, index) => effectSuccessors(row, index, p.code.length));
  const predecessors = p.code.map(() => []), mutationTargets = new Set();
  successors.forEach((edges, index) => edges.forEach(next => predecessors[next].push(index)));
  for (const row of p.code) {
    const write = instructionEffects(row, fragments).instructionWrite;
    if (write) mutationTargets.add((write.target - 1) / 5);
  }
  const reachable = new Set(), todo = p.code.length ? [0] : [];
  while(todo.length){const index=todo.pop();if(reachable.has(index))continue;reachable.add(index);todo.push(...successors[index]);}
  return {successors, predecessors, mutationTargets, reachable};
}

// Bounded region proof, not whole-program SSA. Every path must terminate at
// the same arithmetic use of the producer's value, possibly via MOVE or owned
// local cells. Cells are distinct boxes allocated by make/NEWL, not user table
// fields or external upvalues. Incoming edges from outside would bypass the
// producer. Enumerate bounded path states instead of merging MAY definitions
// optimistically. No calls, SETUP, heap writes or record writes are admitted.
export function proveResultRegion(p, producer, fragments, graph = resultLinkGraph(p, fragments), {semanticReceipts=false}={}) {
  const source = p.code[producer];
  if (!ordinary(source) || !graph.reachable.has(producer) || graph.mutationTargets.has(producer) || graph.successors[producer].length !== 1 || graph.successors[producer][0] !== producer + 1) return null;
  const register = source[1], members = new Set(), visiting = new Set(), memo = new Map(), copies = new Set();
  let consumer = null, consumerSlots = null, failed = false, work = 0;
  function visit(index, registers, cells) {
    if(++work>256){failed=true;return 0;}
    if (failed || index === producer || visiting.has(index) || graph.mutationTargets.has(index)) { failed = true; return 0; }
    const key=index+':'+[...registers].sort((a,b)=>a-b).join(',')+':'+[...cells].sort((a,b)=>a-b).join(',');
    if (memo.has(key)) return memo.get(key);
    const row = p.code[index];
    const slots=resultConsumerSlots(row,semanticReceipts).filter(slot=>registers.has(row[slot]));
    if (slots.length) {
      if (consumer !== null && (consumer !== index || JSON.stringify(consumerSlots)!==JSON.stringify(slots))) failed = true;
      consumer = index;consumerSlots=slots;return 0;
    }
    if (!row || !corridorOps.has(row[0]) && !(semanticReceipts && [OP.PACK,OP.NEWTABLE].includes(row[0])) || !members.has(index) && members.size >= 7) { failed = true; return 0; }
    const effect = instructionEffects(row, fragments);
    if (effect.call || effect.mayYield || effect.writesMemory && ![OP.SETL,OP.NEWL].includes(row[0]) || effect.capture || effect.instructionWrite || !graph.successors[index].length) { failed = true; return 0; }
    registers=new Set(registers);cells=new Set(cells);
    const assign=(set,at,value)=>{if(value){set.add(at);copies.add(index);}else set.delete(at);};
    if(row[0]===OP.MOVE)assign(registers,row[1],registers.has(row[2]));
    else if(row[0]===OP.SETL||row[0]===OP.NEWL)assign(cells,row[1],registers.has(row[2]));
    else if(row[0]===OP.GETL)assign(registers,row[1],cells.has(row[2]));
    else if([OP.CONST,OP.GETUP,OP.PACK,OP.NEWTABLE].includes(row[0]))registers.delete(row[1]);
    members.add(index); visiting.add(index);
    const depth = 1 + Math.max(...graph.successors[index].map(next=>visit(next,registers,cells)));
    visiting.delete(index); memo.set(key, depth); return depth;
  }
  const depth = visit(producer + 1,new Set([register]),new Set());
  if (failed || consumer === null || depth > 7) return null;
  const allowed = new Set([producer, ...members]);
  for (const index of [...members, consumer]) if (!graph.predecessors[index].length || graph.predecessors[index].some(previous => !allowed.has(previous))) return null;
  const corridor = [...members].sort((a, b) => a - b);
  return Object.freeze({
    mode: 'cfg', ...(semanticReceipts?{kind:resultConsumerKind(p.code[consumer])}:{}), producer: pc(producer), consumer: pc(consumer), register,
    slots: Object.freeze(consumerSlots), copies: Object.freeze([...copies].sort((a,b)=>a-b).map(pc)),
    corridor: Object.freeze(corridor.map(pc)), maxHops: depth + 1,
    branches: corridor.filter(index => graph.successors[index].length === 2).length,
    joins: [...members, consumer].filter(index => graph.predecessors[index].length > 1).length,
    edges: Object.freeze([producer, ...corridor].flatMap(index => graph.successors[index].map(next => Object.freeze([pc(index), pc(next)])))),
  });
}

export function selectCfgResultLinks(p, fragments, {semanticReceipts=false}={}) {
  const graph = resultLinkGraph(p, fragments), candidates = [];
  for (let index = 0; index < p.code.length; index++) {
    const proof = proveResultRegion(p, index, fragments, graph, {semanticReceipts});
    if (proof) candidates.push(proof);
  }
  // Prefer existing branch regions; do not introduce branches to meet a quota.
  const priority=link=>link.kind==='branch'?2:link.kind==='index'?1:0;
  candidates.sort((a, b) => priority(b)-priority(a) || b.branches - a.branches || b.copies.length - a.copies.length || a.producer - b.producer);
  const selected = [], producers = new Set(), consumers = new Set(), corridors = new Set(), endpoints = new Set();
  for (const link of candidates) {
    if (producers.has(link.producer) || consumers.has(link.consumer) || corridors.has(link.producer) || corridors.has(link.consumer) || link.corridor.some(at => corridors.has(at) || endpoints.has(at))) continue;
    selected.push(link); producers.add(link.producer); consumers.add(link.consumer);
    endpoints.add(link.producer); endpoints.add(link.consumer); link.corridor.forEach(at => corridors.add(at));
  }
  return selected;
}
