import {effectSuccessors} from './effect-graph.mjs';
import {PRIVATE_OPEN, PRIVATE_SELECT, PRIVATE_ARITHMETIC, PRIVATE_CAPTURE} from './private-ops.mjs';

/** Build-time classification, not recovery or a security score. A fixed key
 * capsule may still be inside a gate-dependent sealed page. Counting it says
 * the target-key equation is independent of application results once opened. */
export function analyzeEmulationSurface(program) {
  const out={instructions:0,edges:0,fixedTargetKeyEdges:0,resultGatedTargetKeyEdges:0,receiptConsumerEdges:0,sealedPrototypes:0,pageOpenInstructions:0,recordMutationInstructions:0};
  for(const p of program.prototypes){
    if(p.sealKey)out.sealedPrototypes++;
    const consumers=new Set((p.resultLinks??[]).map(link=>link.consumer));
    p.code.forEach((row,index)=>{
      const edges=effectSuccessors(row,index,p.code.length).length;
      out.instructions++;out.edges+=edges;
      if(row[0]===257)out.resultGatedTargetKeyEdges+=edges;
      else out.fixedTargetKeyEdges+=edges;
      if(consumers.has(index*5+1))out.receiptConsumerEdges+=edges;
      if(row[0]===PRIVATE_OPEN)out.pageOpenInstructions++;
      if([PRIVATE_SELECT,PRIVATE_ARITHMETIC,PRIVATE_CAPTURE].includes(row[0]))out.recordMutationInstructions++;
    });
  }
  return Object.freeze(out);
}
