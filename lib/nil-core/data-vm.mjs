import {randomBytes,randomInt} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {denseInstructionDirectory} from './instruction-directory.mjs';
import {packKeyedRecords,keyedInstructionDirectory} from './keyed-directory.mjs';
import {operandWidths,operandFormat,narrowOperandWord,narrowRecordReader,narrowPrototypeWidths} from './narrow-records.mjs';
import {OP,OPERAND_ROLES,LIMITS} from './opcodes.mjs';
import {statefulProgram,stateMix} from './stateful.mjs';
import {analyzeDataflow} from './dataflow.mjs';
import {validateNativeBindings,nativeBindingFor} from './bound-native.mjs';
import {privateRoles,PRIVATE_GET,PRIVATE_DENY,PRIVATE_INIT,PRIVATE_CAP,PRIVATE_SELECT,PRIVATE_OPEN,PRIVATE_SPAN,PRIVATE_ARITHMETIC,PRIVATE_DESCRIPTOR,PRIVATE_CAPTURE,PRIVATE_RECEIVE} from './private-ops.mjs';
import {receiptFetch,receiptHelper} from './fetch-receipts.mjs';
import {validateFetchContracts} from './fetch-contracts.mjs';
import {validateResultLinks,resultLinkFields,resultLinkRuntime} from './result-links.mjs';
import {sealRecord,recordActivation} from './record-activation.mjs';
import {sealLaneRecord,laneBufferActivation,retireLaneBuffer,byteInverse,specializeLaneReads} from './lane-buffer.mjs';
import {fragmentSemantic} from './materializer-fragments.mjs';
import {entryForGate,sealPage,sealedPageRuntime} from './sealed-pages.mjs';
import {packActivatedConstants,activatedConstantDirectory,activatedConstantRuntime,bitActivatedConstantDirectory,bitActivatedConstantRuntime} from './constant-activation.mjs';
import {consumerHandlerPlan,validateConsumerRecipes,consumerRecipeIndex,consumerRecipeOperands,consumerRecipeSemantic,consumerRecipeRole,scheduleConsumerOperands} from './consumer-handlers.mjs';
import {boundEntryKey,boundSectionTag} from './bound-pages.mjs';
import {constantEncoding,binaryConstantRuntime,activatedBinaryConstantRuntime} from './numeric-constants.mjs';
import {resultConsumerSlots} from './result-protocol.mjs';
import {packPrototypeMetadata,compactPrototypeReader} from './prototype-metadata.mjs';
import {packBitFields,branchCoordinate,operandBitWidths,bitFieldRuntime,bitPrototypeWidths,bitRecordReader} from './bit-fields.mjs';
import {specializeSealedFetch} from './sealed-fetch.mjs';

const M=2**32,schemas=new WeakMap(),nativePlans=new WeakMap(),transportPlans=new WeakMap(),word=n=>{const b=Buffer.alloc(4);b.writeUInt32LE(n);return b;};
const nonce=()=>randomInt(1,M),freeze=a=>Object.freeze(a);
// Private v5 fragment ID, never used as a delivered slot or a v4 opcode.
export const NATIVE_STEP=257,NATIVE_FINISH=258;
const FORWARD=256,rolesFor=(op,fragments)=>fragments?.get?.(op)?.roles??fragments?.[op]?.roles??privateRoles.get(op)??(op===FORWARD?['g']:op===NATIVE_STEP?['i']:op===NATIVE_FINISH?[]:OPERAND_ROLES[op-1]);
export const dataSchema=blob=>schemas.get(blob);
export const dataNativeBindings=blob=>nativePlans.get(blob);
export const dataTransportPlan=blob=>transportPlans.get(blob);
export function dataProgram(program,{nativeBindings}={}){
 if(nativeBindings)validateNativeBindings(nativeBindings);
 let forwards=0,unreachable=0;
 const prototypes=program.prototypes.map(p=>{
  const constants=[...p.constants],code=p.code.map(row=>[...row]),aliasSlots=new Map();
  for(const row of code){
   const op=row[0],slot=op===OP.GETG||op===OP.SETG?2:op===FORWARD?1:0;if(!slot)continue;
   const original=constants[row[slot]-1],binding=nativeBindingFor(nativeBindings,original);if(!binding||binding.alias===original)continue;
   const key=`${row[slot]}:${binding.alias}`;let replacement=aliasSlots.get(key);
   if(!replacement){replacement=constants.length+1;constants.push(binding.alias);aliasSlots.set(key,replacement);}
   row[slot]=replacement;
  }
  const used=new Set();for(const row of code)rolesFor(row[0],program.fragments).forEach((role,i)=>{if(role==='k'||role==='g')used.add(row[i+1]);});
  const mapping=new Map(),compact=[];for(const slot of [...used].sort((a,b)=>a-b)){mapping.set(slot,compact.length+1);compact.push(constants[slot-1]);}
  for(const row of code)rolesFor(row[0],program.fragments).forEach((role,i)=>{if(role==='k'||role==='g')row[i+1]=mapping.get(row[i+1]);});
  constants.splice(0,constants.length,...compact);
  const [get,pack,args,many,tail]=code,bound=nativeBindingFor(nativeBindings,constants[get?.[2]-1]);
  if(!bound&&code.length>=5&&p.parameters===0&&p.vararg&&get[0]===OP.GETG&&pack[0]===OP.PACK&&args[0]===OP.VARARG&&many[0]===OP.MANY&&tail[0]===OP.TAILCALL&&many[1]===pack[1]&&many[2]===args[1]&&tail[1]===get[1]&&tail[2]===pack[1]){forwards++;unreachable+=code.length-5;return {...p,constants,code:[[FORWARD,get[2],0,0,0]]};}
  return {...p,constants,code};
 });
 const p=statefulProgram({...program,prototypes,stats:{...program.stats,instructions:prototypes.reduce((n,p)=>n+p.code.length,0),fusedInstructions:program.stats.fusedInstructions+forwards*4,forwardFragments:forwards,removedUnreachableInstructions:unreachable}});
 return {...p,version:5,prototypes:p.prototypes.map((proto,index)=>({...proto,...(proto.sealKey?{layout:{...proto.layout,keys:[program.boundPages?boundEntryKey(proto.sealKey,index+1,proto.parent):entryForGate(proto.sealKey),...proto.layout.keys.slice(1)]}}:{}),dataflow:analyzeDataflow(proto,program.fragments)}))};
}
function shuffle(list){const out=[...list];for(let i=out.length-1;i>0;i--){const j=randomInt(i+1);[out[i],out[j]]=[out[j],out[i]];}return out;}
function byteMask(key,i){return (Math.floor(key/256**((i-1)%4))+(i%251)*17)%256;}
function targets(row,pc){const [op,a,b,c,d]=row;if(op===OP.RETURN||op===OP.TAILCALL||op===FORWARD||op===NATIVE_FINISH||op===PRIVATE_DESCRIPTOR)return [];if(op===OP.JUMP)return [a];if(op===OP.FORNEXT)return [c];return [...new Set([pc+5,...([OP.JF,OP.JT,OP.JNIL].includes(op)?[b]:op===OP.FORCHECK?[d]:[])])];}
export function serializeData(program,{contextCount=2,mixProfile,nativeBindings,externalEntry=false,compactRecords=false,batchSpans=false,fastCipher=false,sealedRecords=false,sectionTransport=false,activatedConstants=false,consumerHandlers=false,sharedHandlers=false,denseMetadata=false,identityWitness=false,leanRuntime=false,keyedDirectory=false,narrowRecords=false,compactPrototypeMetadata=false,bitPackedRecords=false,bitPackedConstants=false,bufferLanes=false}={}){
 if(typeof bufferLanes!=='boolean'||bufferLanes&&(!sealedRecords||!keyedDirectory||!bitPackedRecords))throw new TypeError('Buffer lanes require sealed keyed bit records');
 if(typeof bitPackedConstants!=='boolean'||bitPackedConstants&&!activatedConstants)throw new TypeError('Bit constants require activated constants');
 if(typeof bitPackedRecords!=='boolean'||bitPackedRecords&&(!narrowRecords||!keyedDirectory||!compactRecords))throw new TypeError('Bit records require narrow keyed records');
 if(typeof compactPrototypeMetadata!=='boolean'||compactPrototypeMetadata&&(!keyedDirectory||!compactRecords))throw new TypeError('Compact prototypes require keyed compact records');
 if(typeof narrowRecords!=='boolean'||narrowRecords&&(!keyedDirectory||!compactRecords))throw new TypeError('Narrow records require compact keyed records');
 if(typeof keyedDirectory!=='boolean'||keyedDirectory&&denseMetadata)throw new TypeError('Keyed directory requires its own metadata layout');
 if(typeof leanRuntime!=='boolean'||leanRuntime&&(!compactRecords||!fastCipher||!sectionTransport||!batchSpans))throw new TypeError('Lean records require compact inline delivery');
 if(typeof identityWitness!=='boolean')throw new TypeError('Invalid identity witness mode');
 if(typeof denseMetadata!=='boolean')throw new TypeError('Invalid dense metadata mode');
 if(typeof sharedHandlers!=='boolean')throw new TypeError('Invalid shared handler mode');
 if(typeof consumerHandlers!=='boolean')throw new TypeError('Invalid consumer handler mode');
 if(typeof activatedConstants!=='boolean')throw new TypeError('Invalid constant activation mode');
 if(typeof sectionTransport!=='boolean'||sectionTransport&&externalEntry)throw new TypeError('Section transport requires a normal V5 entry');
 if(typeof sealedRecords!=='boolean')throw new TypeError('Invalid record activation mode');
 if(typeof compactRecords!=='boolean')throw new TypeError('Invalid record encoding mode');
 if(typeof batchSpans!=='boolean')throw new TypeError('Invalid span reader mode');
 if(typeof fastCipher!=='boolean')throw new TypeError('Invalid cipher arithmetic mode');
 if(nativeBindings)validateNativeBindings(nativeBindings);
 if(program?.version!==5||!Array.isArray(program.prototypes)||program.prototypes.length<1||program.prototypes.length>LIMITS.prototypes||!Number.isInteger(contextCount)||contextCount<2||contextCount>4)throw new TypeError('Invalid data VM program');
 const fetchContracts=validateFetchContracts(program);
 const resultLinkCount=validateResultLinks(program);
 if(program.semanticReceipts!==undefined&&typeof program.semanticReceipts!=='boolean')throw new TypeError('Invalid semantic receipt mode');
 if(program.semanticReceipts&&!program.resultPathReceipts)throw new TypeError('Semantic receipts require path proofs');
 const resultOpenTargets=program.semanticReceipts?program.prototypes.map(p=>(p.resultLinks??[]).map(link=>link.consumer)):undefined;
 if(program.boundPages&&(!fastCipher||!sectionTransport||!batchSpans||!Number.isInteger(program.pageAuthSlot)||program.pageAuthSlot<1||program.pageAuthSlot>=2**31))throw new TypeError('Invalid bound page delivery');
 const presentOps=program.prototypes.flatMap(p=>p.code.map(row=>row[0]));
 if(presentOps.includes(PRIVATE_CAPTURE))presentOps.push(OP.BINARY);
 const usedOps=[...new Set(presentOps)].sort((a,b)=>a-b);
 if(usedOps.length>255||usedOps.some(op=>!rolesFor(op,program.fragments)))throw new TypeError('Invalid data VM operation');
 if(batchSpans&&!usedOps.includes(PRIVATE_SPAN))throw new TypeError('Batch spans require inline pages');
 const handlerRecipes=consumerHandlers?consumerHandlerPlan(program,usedOps):undefined;
 const labels=shuffle(Array.from({length:255},(_,i)=>i+1)).slice(0,handlerRecipes?.length??usedOps.length);
 const profile=mixProfile?{family:mixProfile.family,multiplier:mixProfile.multiplier,gain:mixProfile.gain,shift:mixProfile.shift}:{family:randomInt(3),multiplier:randomInt(8,32768)*2+1,gain:randomInt(17,65536),shift:randomInt(8,21)};
 if(![0,1,2].includes(profile.family)||!Number.isInteger(profile.multiplier)||profile.multiplier<17||profile.multiplier>65535||profile.multiplier%2!==1||!Number.isInteger(profile.gain)||profile.gain<17||profile.gain>65535||!Number.isInteger(profile.shift)||profile.shift<8||profile.shift>20)throw new TypeError('Invalid data VM mixer');
 const contexts=[];
 for(let i=0;i<contextCount;i++){
  let slots=shuffle(labels);
  if(i&&labels.length>1){let attempts=0;while(slots.some((n,j)=>n===contexts[i-1].slots[j])&&attempts++<32)slots=shuffle(labels);if(slots.some((n,j)=>n===contexts[i-1].slots[j]))slots=contexts[i-1].slots.map((_,j)=>contexts[i-1].slots[(j+1)%labels.length]);}
  contexts.push(freeze({slots:freeze(slots),domains:freeze(Array.from({length:9},nonce)),order:freeze(shuffle([0,1,2,3])),guard:nonce(),opcodeSalt:randomInt(256)}));
 }
 if(typeof externalEntry!=='boolean')throw new TypeError('Invalid external entry mode');
 const gates=program.prototypes.flatMap(p=>p.code.filter(r=>r[0]===NATIVE_STEP));if(gates.length&&!externalEntry)throw new TypeError('Native preparation requires external entry');
 const recordStorage={...(bufferLanes?{laneWords:0,laneTailRecords:0,additionalEnvelopeBytes:0}:{}),records:0,omittedWords:0,expandedBytes:0,storedBytes:0,paddingBytes:0,bitOperandSavedBytes:0,bitDirectorySavedBytes:0,...(narrowRecords?{narrowWordSavedBytes:0,directorySavedBytes:0,directoryBytes:0}:{})};
 let potentialIntegers=0,potentialSavedBytes=0;
 if(leanRuntime)for(const p of program.prototypes)for(const value of p.constants)if(typeof value==='number'&&Number.isInteger(value)&&value>=10000&&value<M){potentialIntegers++;potentialSavedBytes+=String(value).length-4;}
 // Pay for the extra emitted decoder only when the payload saving exceeds a
 // conservative presentation allowance. Small pools keep the old dialect.
 const binaryIntegers=leanRuntime&&potentialSavedBytes>1024;
 const constantStorage={potentialIntegers,potentialSavedBytes,binaryIntegers:binaryIntegers?potentialIntegers:0,savedBytes:binaryIntegers?potentialSavedBytes:0};
 const prototypeStorage={legacyBytes:0,storedBytes:0,savedBytes:0};
 const prototypeFieldOrder=compactPrototypeMetadata?freeze(shuffle([0,1,2,3,4,5,6])):undefined;
 const schema=freeze({version:5,externalEntry,compactRecords,batchSpans,fastCipher,sealedRecords,sectionTransport,activatedConstants,consumerHandlers,sharedHandlers,denseMetadata,identityWitness,leanRuntime,keyedDirectory,narrowRecords,binaryIntegers,bitPackedRecords,bitPackedConstants,bufferLanes,compactPrototypeMetadata,prototypeFieldOrder,prototypeStorage,registerAllocation:program.stats?.registerAllocation,boundPages:program.boundPages===true,...(program.boundPages?{pageAuthSlot:program.pageAuthSlot}:{}),resultPathReceipts:program.resultPathReceipts===true,semanticReceipts:program.semanticReceipts===true,...(resultOpenTargets?{resultOpenTargets:freeze(resultOpenTargets.map(freeze))}:{}),...(handlerRecipes?{handlerRecipes}:{}),resultLinkCount,recordStorage,constantStorage,signature:randomBytes(randomInt(16,33)).toString('hex'),contextCount,usedOps:freeze(usedOps),contexts:freeze(contexts),...profile,...(program.fragments?.size?{fragments:freeze(Object.fromEntries(program.fragments))}:{}),...(fetchContracts.length?{fetchContractCount:fetchContracts.length}:{})});
 const mix=(a,b)=>stateMix(a,b,profile),fold=(key,values)=>values.reduce(mix,key),mask=(key,ctx,j)=>mix(key,ctx.domains[j]);
 if(!Number.isInteger(program.root)||program.root<1||program.root>program.prototypes.length)throw new RangeError('Invalid data VM root');
 const parts=[Buffer.from(schema.signature,'hex'),word(program.prototypes.length),word(program.root),word(externalEntry?0:program.prototypes[program.root-1].layout.keys[0])];
 const transportSections=[];
 let total=parts.reduce((n,p)=>n+p.length,0);const push=b=>{total+=b.length;if(total>LIMITS.blobBytes)throw new RangeError('Data VM bytecode size limit exceeded');parts.push(b);};
 for(const [id,p]of program.prototypes.entries()){
  const resultFields=resultLinkFields(p),widths=narrowRecords?(bitPackedRecords?operandBitWidths(p,program.prototypes.length,program.environmentReflection??false):operandWidths(p,program.prototypes.length)):undefined;
  const chunks=[],u32=n=>{if(!Number.isInteger(n)||n<0||n>=M)throw new RangeError('Data VM operand out of range');chunks.push(word(n));},u8=n=>chunks.push(Buffer.from([n]));
  if(p.layout.keys.length!==p.code.length||p.layout.constantKeys.length!==p.constants.length||p.code.length<1||[...p.layout.keys,...p.layout.constantKeys].some(n=>!Number.isInteger(n)||n<1||n>=M))throw new TypeError('Invalid data VM layout');
  const legacyHeaderBytes=33+p.upvalues.length*5;
  prototypeStorage.legacyBytes+=legacyHeaderBytes;
  if(compactPrototypeMetadata){
   const metadata=packPrototypeMetadata(p,id+1,p.layout.keys[0],profile,prototypeFieldOrder);
   chunks.push(metadata);prototypeStorage.storedBytes+=metadata.length;
  }else{
   u32(p.parent);u32(p.parameters);u8(p.vararg?1:0);u32(p.registers);u32(p.cells);u32(p.upvalues.length);
   for(const [kind,slot]of p.upvalues){u8(kind);u32(slot);}u32(p.layout.keys[0]);u32(p.constants.length);
   prototypeStorage.storedBytes+=legacyHeaderBytes;
  }
  if(activatedConstants)chunks.push(packActivatedConstants(p.constants,p.constants.map((value,i)=>nativeBindingFor(nativeBindings,value)?.nameKey??p.layout.constantKeys[i]),p.layout.keys[0],mix,shuffle,{binaryIntegers,bitPacked:bitPackedConstants,metrics:constantStorage}));
  else for(const [i,value]of p.constants.entries()){
   const {tag,raw}=constantEncoding(value,binaryIntegers);u8(tag);
   if(tag>=3){const key=nativeBindingFor(nativeBindings,value)?.nameKey??p.layout.constantKeys[i],encoded=Buffer.from(raw);for(let j=0;j<raw.length;j++)encoded[j]=(raw[j]+byteMask(key,j+1))%256;u32(fold(key,[tag,...raw]));u32(encoded.length);chunks.push(encoded);}
  }
  if(!compactPrototypeMetadata)u32(p.code.length);const recordPackets=[];
  for(const [i,row]of p.code.entries()){
   if(row.length!==5||row.slice(1).some(n=>!Number.isInteger(n)||n<0||n>=M))throw new TypeError('Invalid data VM instruction');
   const op=row[0],recipeIndex=handlerRecipes?consumerRecipeIndex(handlerRecipes,row):usedOps.indexOf(op);
   const operands=handlerRecipes?consumerRecipeOperands(handlerRecipes[recipeIndex],row.slice(1)):row.slice(1);
   if(op===NATIVE_STEP&&(!Number.isInteger(p.gates?.[i])||p.gates[i]<0||p.gates[i]>=M))throw new TypeError('Missing native packet witness');
   if(op===PRIVATE_SELECT){const template=p.code[(operands[3]-1)/5];if(!template||template[0]!==OP.MOVE||template[1]!==template[2])throw new TypeError('Invalid mutable instruction template');}
   if([OP.GETG,OP.SETG,FORWARD].includes(op)){const name=p.constants[operands[op===FORWARD?0:1]-1],binding=nativeBindingFor(nativeBindings,name);if(binding&&name!==binding.alias)throw new TypeError('Call dataProgram with nativeBindings before serialization');}
   const key=p.layout.keys[i],ks=rolesFor(op,program.fragments).flatMap((role,j)=>role==='k'||role==='g'?[operands[j]]:[]);
   const ck=ks.map(k=>nativeBindingFor(nativeBindings,p.constants[k-1])?.nameKey??p.layout.constantKeys[k-1]);if(ck.some(k=>!k))throw new RangeError('Invalid data VM constant key');while(ck.length<2)ck.push(0);
   if([OP.GETG,OP.SETG,FORWARD].includes(op)){const name=p.constants[operands[op===FORWARD?0:1]-1];ck[1]=nativeBindingFor(nativeBindings,name)?.accessKey??0;}
   if(op===OP.CLOSURE){const child=program.prototypes[operands[1]-1];if(child?.parent!==id+1)throw new RangeError('Invalid data VM child');ck[0]=child.layout.keys[0];}
   const link=resultFields.get(i*5+1);
   if(link){
    if(link.incoming)ck[0]=link.incoming;
    if(link.outgoing)ck[1]=link.outgoing;
    for(const slot of link.slots)operands[slot-1]=0;
   }
   const successors=targets(row,i*5+1);if(successors.some(pc=>pc<1||pc>p.code.length*5||pc%5!==1))throw new RangeError('Invalid data VM successor');
   for(const ctx of contexts){
    const slot=ctx.slots[recipeIndex],stored=Array(8).fill(0);
    operands.forEach((n,j)=>{const physical=(ctx.order[j]+key%4)%4;stored[physical]=(n+mask(key,ctx,j))%M;});
    const operandSeal=activatedConstants?fold(key,[i*5+1,ctx.guard,slot,...stored.slice(0,4)]):0;
    ck.forEach((n,j)=>stored[4+j]=(n+(activatedConstants&&j<ks.length?mix(operandSeal,ks[j]):0)+mask(key,ctx,4+j))%M);
    const recordBase=program.boundPages||keyedDirectory?fold(key,[id+1,i*5+1,ctx.guard]):mix(key,ctx.guard);
    const semantic=fold(recordBase,[slot,...stored.slice(0,6)]);
    const edges=[0,0];successors.forEach((pc,j)=>{const target=p.layout.keys[(pc-1)/5];if(!target)throw new RangeError('Missing data VM successor');edges[j]=(target+mix(semantic,(pc+ctx.domains[6+j])%M)+(op===NATIVE_STEP?mix(p.gates[i],ctx.domains[6+j]):0))%M;});
    edges.forEach((n,j)=>stored[6+j]=(n+mask(key,ctx,6+j))%M);
    const odd=2*(key%128)+1,add=(Math.floor(key/128)+ctx.opcodeSalt)%256,encodedOp=(slot*odd+add)%256;
    const stamp=fold(recordBase,[encodedOp,...stored]),padding=randomBytes(leanRuntime||compactPrototypeMetadata?0:randomInt(0,8));
    let bitmap=0;const present=[],bitFields=[];
    if(compactRecords){
     operands.forEach((n,j)=>{if(n!==0)bitmap|=1<<((ctx.order[j]+key%4)%4);});
     [...ck,...edges].forEach((n,j)=>{if(n!==0)bitmap|=1<<(4+j);});
     const physicalWidths=Array(4).fill(4),physicalBits=Array(4),physicalByteWidths=Array(4).fill(4);const byteWidths=bitPackedRecords?operandWidths(p,program.prototypes.length):widths;
     if(narrowRecords)rolesFor(op,program.fragments).forEach((role,j)=>{const index={r:1,l:2,u:3,k:4,g:4,j:5,p:6,i:7,a:8,b:9}[role]-1,width=widths[index],physical=(ctx.order[j]+key%4)%4;const plain=bitPackedRecords&&role==='j'?branchCoordinate(operands[j],i*5+1):operands[j];if(plain>=(bitPackedRecords?2**width:256**width))throw new RangeError('Narrow operand out of range');physicalWidths[physical]=width;physicalByteWidths[physical]=byteWidths[index];if(bitPackedRecords)physicalBits[physical]=(plain+mask(key,ctx,j))%2**width;});
     stored.forEach((n,j)=>{if(bitmap&(1<<j)){if(bitPackedRecords){const bits=j<4?physicalWidths[j]:32;bitFields.push({value:j<4?physicalBits[j]:n,bits,legacyBytes:j<4?physicalByteWidths[j]:4});}else present.push(narrowRecords&&j<4?narrowOperandWord(n,physicalWidths[j]):word(n));}});
    }
    const operandBytes=bitPackedRecords?packBitFields(bitFields):Buffer.concat(present);
    if(narrowRecords)recordStorage.narrowWordSavedBytes+=(bitPackedRecords?bitFields.length:present.length)*4-operandBytes.length;
    if(bitPackedRecords)recordStorage.bitOperandSavedBytes+=bitFields.reduce((n,f)=>n+f.legacyBytes,0)-operandBytes.length;
    const data=Buffer.concat([Buffer.from(compactRecords?[encodedOp,bitmap]:[encodedOp]),...(compactRecords?[operandBytes]:stored.map(word)),word((stamp+mask(key,ctx,8))%M),padding]);
    recordStorage.records++;recordStorage.paddingBytes+=padding.length;recordStorage.omittedWords+=compactRecords?8-(bitPackedRecords?bitFields.length:present.length):0;
    recordStorage.expandedBytes+=38+padding.length;recordStorage.storedBytes+=(keyedDirectory?4:1)+data.length;
    if(bufferLanes){recordStorage.laneWords+=Math.ceil(data.length/4);if(data.length%4)recordStorage.laneTailRecords++;}
    const bytes=sealedRecords?(bufferLanes?sealLaneRecord:sealRecord)(data,key,i*5+1,ctx,mix,program.boundPages||keyedDirectory?id+1:undefined):data;
    if(keyedDirectory)recordPackets.push({bytes,key});else{u8(data.length);chunks.push(bytes);}
   }
  }
  if(keyedDirectory){const packed=packKeyedRecords(recordPackets,id+1,contexts,profile,{narrow:narrowRecords,bitPacked:bitPackedRecords});chunks.push(packed);if(narrowRecords){const directoryBytes=packed.length-4-recordPackets.reduce((n,r)=>n+r.bytes.length,0);recordStorage.directoryBytes+=directoryBytes;if(bitPackedRecords){const payloadBytes=recordPackets.reduce((n,r)=>n+r.bytes.length,0);recordStorage.bitDirectorySavedBytes+=recordPackets.length*(payloadBytes<=1024?2:payloadBytes<=262144?3:4)-directoryBytes;}recordStorage.directorySavedBytes+=recordPackets.length*4-directoryBytes;}recordStorage.storedBytes+=packed.length-recordPackets.reduce((n,r)=>n+r.bytes.length+4,0);}
  if(p.pageBytes!==undefined){if(!p.sealKey||!usedOps.includes(PRIVATE_SPAN)||!Buffer.isBuffer(p.pageBytes)||p.pageBytes.length<1||p.pageBytes.length>8192)throw new TypeError('Invalid page span');u32(p.pageBytes.length);chunks.push(p.pageBytes);}
  const raw=Buffer.concat(chunks),key=p.layout.keys[0];let encoded;
  if(p.sealKey){if(!usedOps.includes(PRIVATE_OPEN)||key!==(program.boundPages?boundEntryKey(p.sealKey,id+1,p.parent):entryForGate(p.sealKey))||p.parent===0||program.boundPages&&!p.boundPage)throw new TypeError('Invalid sealed page');encoded=sealPage(raw,p.sealKey);if(program.boundPages)encoded=Buffer.concat([encoded,boundSectionTag(p.sealKey,encoded,id+1,p.parent,raw.length)]);}
  else{encoded=Buffer.from(raw);for(let j=0;j<raw.length;j++)encoded[j]=(raw[j]+byteMask(key,j+1))%256;}
  const header=total,parent=p.parent+(p.sealKey?2**31:0)+(p.pageBytes?2**30:0);
  push(word(parent));push(word(encoded.length));
  if(sectionTransport)transportSections.push(freeze({id:id+1,header,offset:total,length:encoded.length,parent,key,...(p.sealKey?{gate:Buffer.from(p.sealKey)}:{})}));
  push(encoded);
 }
 prototypeStorage.savedBytes=prototypeStorage.legacyBytes-prototypeStorage.storedBytes;
 freeze(prototypeStorage);freeze(recordStorage);freeze(constantStorage);const blob=Buffer.concat(parts,total);schemas.set(blob,schema);if(nativeBindings)nativePlans.set(blob,nativeBindings);
 if(sectionTransport)transportPlans.set(blob,freeze({prefix:Buffer.from(blob.subarray(0,Buffer.from(schema.signature,'hex').length+12)),sections:freeze(transportSections)}));
 return blob;
}

function operandCheck(role,value,activatedConstants=false){
 if(role==='r')return `${value}<1 or ${value}>frame.prototype.registers`;
 if(role==='l')return `${value}<1 or ${value}>frame.prototype.cells`;
 if(role==='u')return `${value}<1 or ${value}>frame.prototype.upCount`;
 if(role==='k'||role==='g')return `${value}<1 or ${value}>frame.prototype.constantCount`+(role==='g'&&!activatedConstants?` or frame.prototype.tags[${value}]~=4`:'');
 if(role==='j')return `${value}<1 or ${value}>frame.prototype.instructionCount*5 or ${value}%5~=1`;
 if(role==='p')return `${value}<1 or ${value}>count or sections[${value}][1]~=frame.id`;
 return `${value}<1 or ${value}>${{i:100000,a:3,b:13}[role]}`;
}
export function dataRuntime(schema,{recordCacheLimit=0,nativeCipher=false}={}){
 if(schema.bufferLanes!==undefined&&(typeof schema.bufferLanes!=='boolean'||schema.bufferLanes&&(!schema.sealedRecords||!schema.keyedDirectory||!schema.bitPackedRecords)))throw new TypeError('Invalid buffer lane schema');
 if(schema.bitPackedConstants!==undefined&&(typeof schema.bitPackedConstants!=='boolean'||schema.bitPackedConstants&&!schema.activatedConstants))throw new TypeError('Invalid constant bit schema');
 if(schema.bitPackedRecords!==undefined&&(typeof schema.bitPackedRecords!=='boolean'||schema.bitPackedRecords&&(!schema.narrowRecords||!schema.keyedDirectory||!schema.compactRecords)))throw new TypeError('Invalid bit record schema');
 if(schema?.leanRuntime!==undefined&&(typeof schema.leanRuntime!=='boolean'||schema.leanRuntime&&!nativeCipher))throw new TypeError('Lean runtime requires native cipher');
 if(schema?.binaryIntegers!==undefined&&(typeof schema.binaryIntegers!=='boolean'||schema.binaryIntegers&&!schema.leanRuntime))throw new TypeError('Binary constants require lean runtime');
 if(schema?.boundPages&&(!nativeCipher||!Number.isInteger(schema.pageAuthSlot)||schema.pageAuthSlot<1))throw new TypeError('Bound pages require native cipher and auth capability');
 if(typeof nativeCipher!=='boolean'||nativeCipher&&!schema?.usedOps?.includes(PRIVATE_OPEN))throw new TypeError('Native cipher requires sealed pages');
 if(!Number.isInteger(recordCacheLimit)||recordCacheLimit!==0&&(recordCacheLimit<16||recordCacheLimit>4096))throw new RangeError('Record cache limit must be zero or 16..4096');
 if(schema?.version!==5||!schema.contexts||schema.contextCount!==schema.contexts.length||schema.contextCount<2||schema.contextCount>4||!/^[a-f0-9]{32,64}$/.test(schema.signature))throw new TypeError('Missing data VM delivery schema');
 if(schema.activatedConstants!==undefined&&typeof schema.activatedConstants!=='boolean')throw new TypeError('Invalid constant activation mode');
 if(schema.consumerHandlers!==undefined&&typeof schema.consumerHandlers!=='boolean')throw new TypeError('Invalid consumer handler mode');
 if(schema.sharedHandlers!==undefined&&typeof schema.sharedHandlers!=='boolean')throw new TypeError('Invalid shared handler mode');
 if(schema.denseMetadata!==undefined&&typeof schema.denseMetadata!=='boolean')throw new TypeError('Invalid dense metadata mode');
 if(schema.compactPrototypeMetadata!==undefined&&(typeof schema.compactPrototypeMetadata!=='boolean'||schema.compactPrototypeMetadata&&(!schema.keyedDirectory||!schema.compactRecords||!Array.isArray(schema.prototypeFieldOrder)||schema.prototypeFieldOrder.length!==7||new Set(schema.prototypeFieldOrder).size!==7||schema.prototypeFieldOrder.some(n=>!Number.isInteger(n)||n<0||n>6))))throw new TypeError('Invalid compact prototype metadata');
 if(schema.resultPathReceipts!==undefined&&typeof schema.resultPathReceipts!=='boolean')throw new TypeError('Invalid result path receipt mode');
 if(schema.semanticReceipts!==undefined&&(typeof schema.semanticReceipts!=='boolean'||schema.semanticReceipts&&!schema.resultPathReceipts))throw new TypeError('Invalid semantic receipt delivery mode');
 if(schema.identityWitness!==undefined&&typeof schema.identityWitness!=='boolean')throw new TypeError('Invalid identity witness mode');
 if(![0,1,2].includes(schema.family)||!Number.isInteger(schema.multiplier)||schema.multiplier<17||schema.multiplier>65535||schema.multiplier%2!==1||!Number.isInteger(schema.gain)||schema.gain<17||schema.gain>65535||!Number.isInteger(schema.shift)||schema.shift<8||schema.shift>20||!Array.isArray(schema.usedOps)||!schema.usedOps.length||new Set(schema.usedOps).size!==schema.usedOps.length||schema.usedOps.some(op=>!rolesFor(op,schema.fragments)))throw new TypeError('Invalid data VM delivery profile');
 if(schema.consumerHandlers)validateConsumerRecipes(schema.handlerRecipes,schema.usedOps);
 if(schema.usedOps.includes(PRIVATE_ARITHMETIC)&&!schema.usedOps.includes(OP.BINARY))throw new TypeError('Missing fetch arithmetic consumer');
 if(schema.keyedDirectory!==undefined&&(typeof schema.keyedDirectory!=='boolean'||schema.keyedDirectory&&schema.denseMetadata))throw new TypeError('Invalid keyed metadata mode');
 if(schema.narrowRecords!==undefined&&(typeof schema.narrowRecords!=='boolean'||schema.narrowRecords&&(!schema.keyedDirectory||!schema.compactRecords)))throw new TypeError('Invalid narrow record mode');
 const receipts=schema.usedOps.includes(PRIVATE_CAPTURE);
 const resultLinks=(schema.resultLinkCount??0)>0;
 const resultRuntime=resultLinkRuntime({pathReceipts:schema.resultPathReceipts===true,semanticReceipts:schema.semanticReceipts===true});
 if(receipts!==schema.usedOps.includes(PRIVATE_RECEIVE)||receipts&&!schema.usedOps.includes(OP.BINARY))throw new TypeError('Missing value receipt consumer');
 for(const ctx of schema.contexts)if(!Array.isArray(ctx.slots)||ctx.slots.length!==(schema.consumerHandlers?schema.handlerRecipes.length:schema.usedOps.length)||new Set(ctx.slots).size!==ctx.slots.length||ctx.slots.some(n=>!Number.isInteger(n)||n<1||n>255)||!Array.isArray(ctx.domains)||ctx.domains.length!==9||ctx.domains.some(n=>!Number.isInteger(n)||n<1||n>=M)||!Array.isArray(ctx.order)||ctx.order.length!==4||new Set(ctx.order).size!==4||ctx.order.some(n=>!Number.isInteger(n)||n<0||n>3)||!Number.isInteger(ctx.guard)||ctx.guard<1||ctx.guard>=M||!Number.isInteger(ctx.opcodeSalt)||ctx.opcodeSalt<0||ctx.opcodeSalt>255)throw new TypeError('Invalid data VM delivery context');
 const original=readFileSync(new URL('./runtime.lua',import.meta.url),'utf8'),start=original.indexOf('if op == 1 then'),end=original.indexOf('else invalid() end',start),body=original.slice(start,end),headers=[...body.matchAll(/\b(?:if|elseif) op == (\d+) then/g)];
 const definitions=new Map(headers.map((h,i)=>[+h[1],body.slice(h.index+h[0].length,headers[i+1]?.index??body.length)]));
 const sharedBodies=[],sharedKeys=[],allocatedKeys=new Set();
 const bankFields=schema.contexts.map(ctx=>{
  const handlers=(schema.consumerHandlers?schema.handlerRecipes:schema.usedOps.map(op=>({op,selector:null}))).map((recipe,index)=>{
   const {op}=recipe;
   if(schema.sharedHandlers&&sharedBodies[index])return `[${ctx.slots[index]}]=sharedHandlers[${sharedKeys[index]}]`;
   const hc=schema.sharedHandlers?{order:ctx.order.map((_,j)=>`handlerOrder[${j+1}]`),domains:ctx.domains.map((_,j)=>`handlerDomains[${j+1}]`)}:ctx;
   const roles=rolesFor(op,schema.fragments),names=['a','b','c','d'];
   const reads=Object.fromEntries(roles.flatMap((role,j)=>consumerRecipeRole(recipe,j)?[]:[[names[j],`${names[j]}=(frame.raw[(${hc.order[j]}+frame.key%4)%4+1]-frame.masks[${hc.domains[j]}])%modulus;if ${operandCheck(role,names[j],schema.activatedConstants)} then invalid()end;`]]));
   const declarations=shuffle(roles.flatMap((_,j)=>consumerRecipeRole(recipe,j)?[]:[`local ${names[j]}=(frame.raw[(${hc.order[j]}+frame.key%4)%4+1]-frame.masks[${hc.domains[j]}])%modulus;`])).join('');
   const checks=roles.flatMap((role,j)=>consumerRecipeRole(recipe,j)?[]:[operandCheck(role,names[j],schema.activatedConstants)]).concat(op===OP.VARARG?['not frame.prototype.vararg']:[]).join(' or ')||'false';
   const unused=Array.from({length:4},(_,j)=>j).filter(j=>j>=roles.length||consumerRecipeRole(recipe,j)).map(j=>`if frame.raw[(${hc.order[j]}+frame.key%4)%4+1]~=mix(frame.key,${hc.domains[j]})then invalid()end;`).join('');
   const key1=`(frame.raw[5]-frame.masks[${hc.domains[4]}])%modulus`,key2=`(frame.raw[6]-frame.masks[${hc.domains[5]}])%modulus`;
   let semantic=(consumerRecipeSemantic(recipe)??definitions.get(op)??'').replace(/constants\[b\]/g,`constant(frame,b,${key1})`).replace(/constants\[d\]/g,`constant(frame,d,${key2})`).replace('local child, captured = prototypes[b], {}',`local child, captured = openPrototype(b,${key1}), {}`).replace(/\bremaining\b/g,'budget[1]');
   if(op===OP.GETG)semantic=`local name=constant(frame,b,${key1});local access=${key2};if nativeRead then registers[a]=nativeRead(name,access,${key1})else if access~=0 then invalid()end;registers[a]=environment[name]end`;
   else if(op===OP.SETG)semantic=`local name=constant(frame,b,${key1});local access=${key2};if nativeWrite then nativeWrite(name,registers[a],access)else if access~=0 then invalid()end;environment[name]=registers[a]end`;
   if(schema.fragments?.[op])semantic=fragmentSemantic(schema.fragments[op],key1,key2);
   else if(op===PRIVATE_GET)semantic='registers[a]=privateValues[b];if type(registers[a])~="function"then invalid()end';
   else if(op===PRIVATE_DENY)semantic="error('Nil opaque entry is read-only',0)";
   else if(op===PRIVATE_INIT)semantic='local values=registers[a];if type(values)~="table"then invalid()end;for i=1,values.n do if type(values[i])~="function"then invalid()end;if not privateValues[i]then privateValues[i]=values[i]end end';
   else if(op===PRIVATE_CAP)semantic='if type(nativeRead)~="function"then invalid()end;registers[a]=nativeRead(b);if type(registers[a])~="function"then invalid()end';
   else if(op===PRIVATE_SELECT)semantic='local source=c;if registers[a]then source=b end;writeOperand(frame,d,source)';
   else if(op===PRIVATE_ARITHMETIC)semantic='local operation=c;if registers[a]then operation=b end;writeOperator(frame,d,operation)';
   else if(op===PRIVATE_CAPTURE)semantic='captureReceipt(frame,d,registers[a],registers[b],registers[c])';
   else if(op===PRIVATE_RECEIVE)semantic='invalid()';
   else if(op===PRIVATE_DESCRIPTOR)semantic=`local data=constant(frame,b,${key1});local state=cells[a].v
    if type(data)~="string"or #data~=36 or type(state)~="number"or state%1~=0 or state<0 or state>=modulus then invalid()end
    local values={};for i=1,9 do local x,y,z,w=byte(data,(i-1)*4+1,i*4);values[i]=x+y*256+z*65536+w*16777216 end
    local cost=values[9];local seedModulus=65536;if cost>=2147483648 then cost=cost-2147483648;seedModulus=modulus end
    if cost<1 or cost>100000 then invalid()end;budget[1]=budget[1]-(cost-1);if budget[1]<0 then error('Nil instruction budget exceeded',0)end
    return false,pack(values[1],values[2],(state*values[3]+values[4])%seedModulus,values[5],values[6],values[7],values[8])`;
   else if(op===PRIVATE_OPEN)semantic='local id=registers[b];if type(id)~="number"or id%1~=0 or not sections[id]or sections[id][1]~=frame.id or not sections[id][4]then invalid()end;local child=openPrototype(id,registers[c]);local captured={};for i=1,child.upCount do local ref=child.up[i];captured[i]=ref[1]==0 and cells[ref[2]]or upvalues[ref[2]]end;registers[a]=make(id,captured)'+(schema.usedOps.includes(PRIVATE_SPAN)?';frame.permits[id]=true':'');
   else if(op===PRIVATE_SPAN)semantic='local id=registers[b];if type(id)~="number"or id%1~=0 or not frame.permits[id]or not sections[id]or sections[id][1]~=frame.id or not sections[id][5]or type(nativeRead)~="function"then invalid()end;local child=prototypes[id];if not child or not child.span or not child.spanAvailable then invalid()end;frame.permits[id]=nil;local span=child.span;local active=true;registers[a]=nativeRead(function(at)if not active or not child.spanAvailable or type(at)~="number"or at%1~=0 or at<1 or at>span[2]then invalid()end;return child.reader8(span[1]+at-1)end,span[2],function()if not active then invalid()end;active=false;child.releaseSpan()end);if type(registers[a])~="table"then invalid()end';
   if(schema.boundPages&&op===PRIVATE_DESCRIPTOR)semantic=semantic.replace('(state*values[3]+values[4])%seedModulus','pageWord(boundPageMac(frame.prototype.sealKey,0,{state,values[3],values[4],values[1],values[2]},nil,0),1)');
   if(schema.boundPages&&op===PRIVATE_OPEN)semantic=semantic.replace(';frame.permits[id]=true',';issueChildPermit(frame,id,child)');
   if(schema.boundPages&&op===PRIVATE_SPAN)semantic=semantic.replace('frame.permits[id]=nil;local span=child.span','consumeChildPermit(frame,id,child);local span=child.span');
   if(op===PRIVATE_SPAN&&schema.batchSpans){
    const suffix=');if type(registers[a])~="table"then invalid()end';
    if(!semantic.endsWith(suffix))throw new Error('Span reader anchor changed');
    semantic=semantic.slice(0,-suffix.length)+`,function(at,width,stride)
     if not active or not child.spanAvailable or type(at)~="number"or at%1~=0 or type(width)~="number"or width%1~=0 or width<1 or width>4096 or stride~=1 and stride~=-1 then invalid()end
     local last=at+(width-1)*stride;if at<1 or at>span[2]or last<1 or last>span[2]then invalid()end
     local first=at;if last<first then first=last end
     return child.readerSpan(span[1]+first-1,width)
    end`+suffix;
   }
   if(op===NATIVE_STEP)semantic='if type(nativeRead)~="function"then invalid()end;local digest=nativeRead(a);if type(digest)~="number"or digest<0 or digest>=modulus or digest%1~=0 then invalid()end;transfer(frame,pc,frame.cursor+5,nil,digest,true);'+(recordCacheLimit?'':'frame.raw={};')+'return nil';
   else if(op===NATIVE_FINISH)semantic='if type(nativeWrite)~="function"then invalid()end;return false,pack(nativeWrite())';
   else if(op===OP.RETURN)semantic='return false,registers[a]';
   else if(op===OP.TAILCALL)semantic='return true,registers[a],registers[b]';
   else if(op===FORWARD)semantic=`local name=constant(frame,a,${key1});local access=${key2};local target;if nativeRead then target=nativeRead(name,access,${key1})else if access~=0 then invalid()end;target=environment[name]end;budget[1]=budget[1]-4;if budget[1]<0 then error('Nil instruction budget exceeded',0)end;return true,target,varargs`;
   if(schema.activatedConstants&&op===OP.GETG)semantic=`local access=${key2};if nativeRead then registers[a]=constant(frame,b,${key1},access,true)else local name=constant(frame,b,${key1});if type(name)~="string"or access~=0 then invalid()end;registers[a]=environment[name]end`;
   if(schema.activatedConstants&&op===OP.SETG)semantic=semantic.replace(';local access=',';if type(name)~="string"then invalid()end;local access=');
   if(schema.activatedConstants&&op===FORWARD)semantic=`local access=${key2};local target;if nativeRead then target=constant(frame,a,${key1},access,true)else local name=constant(frame,a,${key1});if type(name)~="string"or access~=0 then invalid()end;target=environment[name]end;budget[1]=budget[1]-4;if budget[1]<0 then error('Nil instruction budget exceeded',0)end;return true,target,varargs`;
   if(receipts&&op===OP.BINARY)semantic=semantic.replace('local left, right = registers[b], registers[c]',`local left, right = registers[b], registers[c]
    if frame.receiptActive then
     if b~=frame.prototype.registers-1 or c~=frame.prototype.registers then invalid()end
     registers[b],registers[c]=nil,nil;frame.receiptActive=nil
    end`);
   if(resultLinks&&[OP.BINARY,OP.UNARY].includes(op)){
    const anchor=op===OP.BINARY?'local left, right = registers[b], registers[c]':'local value = registers[b]';
    const checks=op===OP.BINARY?'b~=frame.prototype.registers and c~=frame.prototype.registers':'b~=frame.prototype.registers';
    if(!semantic.includes(anchor))throw new Error('Result consumer anchor changed');
    semantic=semantic.replace(anchor,anchor+`\nif frame.resultActive then if ${checks} then invalid()end;registers[frame.prototype.registers]=nil;frame.resultActive=nil end`);
    semantic+=`\nlocal target=${key2};if target~=0 then if target>=2147483648 then invalid()end;publishResult(frame,target,registers[a])end`;
   }
   if(resultLinks&&schema.semanticReceipts){
    if([OP.JF,OP.JT,OP.JNIL].includes(op)){
     const condition=op===OP.JF?'not predicate':op===OP.JT?'predicate':'predicate==nil';
     semantic=`local predicate=registers[a];consumeSemanticResult(frame,registers,a,nil);if ${condition} then pc=b end`;
    }else if(op===OP.GETTABLE){
     semantic='local object,index=registers[b],registers[c];consumeSemanticResult(frame,registers,c,nil);registers[a]=object[index]';
    }
   }
   let first='frame.cursor+5',second='nil';if(op===OP.JUMP)first='a';else if(op===OP.FORNEXT)first='c';else if([OP.JF,OP.JT,OP.JNIL].includes(op))second='b';else if(op===OP.FORCHECK)second='d';
   const ending=[OP.RETURN,OP.TAILCALL,FORWARD,NATIVE_STEP,NATIVE_FINISH,PRIVATE_DESCRIPTOR].includes(op)?'':`transfer(frame,pc,${first},${second},registers[${roles.length?'a':'1'}]);return nil`;
   const contextRead=schema.sharedHandlers?'local handlerContext=contexts[frame.bank];local handlerOrder,handlerDomains=handlerContext.order,handlerContext.domains;':'';
   let generated;
   if(schema.consumerHandlers){
    const scheduled=scheduleConsumerOperands(`local pc=frame.cursor+5;${semantic}\n${ending}`,reads);
    generated=`function(frame,registers,cells,upvalues,varargs)ready(frame);${contextRead}local ${Object.keys(reads).length?Object.keys(reads).join(','):'unusedOperand'};${op===OP.VARARG?'if not frame.prototype.vararg then invalid()end;':''}${unused}${scheduled.source}\nend`;
   }else{
    generated=`function(frame,registers,cells,upvalues,varargs)ready(frame);${contextRead}${declarations}if ${checks} then invalid()end;${unused}local pc=frame.cursor+5;${semantic}\n${ending}\nend`;
   }
   if(schema.sharedHandlers){let key;do{key=randomInt(1,2147483648);}while(allocatedKeys.has(key));allocatedKeys.add(key);sharedKeys[index]=key;sharedBodies[index]=`[${key}]=${generated}`;return `[${ctx.slots[index]}]=sharedHandlers[${key}]`;}
   return `[${ctx.slots[index]}]=${generated}`;
  });
  const zeros=Array(4);ctx.order.forEach((physical,j)=>zeros[physical]=ctx.domains[j]);
  const resultRecipes=schema.consumerHandlers?schema.handlerRecipes:schema.usedOps.map(op=>({op,selector:null}));
  const resultLimit=op=>op===OP.BINARY?3:op===OP.UNARY?2:schema.semanticReceipts&&op===OP.GETTABLE?3:schema.semanticReceipts&&[OP.JF,OP.JT,OP.JNIL].includes(op)?1:0;
  const receiptFields=(receipts||resultLinks||schema.sharedHandlers?`order={${ctx.order.join(',')}},`:'')+(receipts?`receipt={${ctx.slots[schema.usedOps.indexOf(PRIVATE_RECEIVE)]},${ctx.slots[schema.usedOps.indexOf(OP.BINARY)]},${ctx.slots[schema.usedOps.indexOf(OP.JUMP)]??0}},`:'')+(resultLinks?`result={${resultRecipes.flatMap((recipe,index)=>resultLimit(recipe.op)?[`[${ctx.slots[index]}]=${resultLimit(recipe.op)}`]:[]).join(',')}},`:'');
  const semanticFields=schema.semanticReceipts?`resultBranch={${resultRecipes.flatMap((recipe,index)=>[OP.JF,OP.JT,OP.JNIL].includes(recipe.op)?[`[${ctx.slots[index]}]=true`]:[]).join(',')}},`:'';
  const formats=schema.narrowRecords?`formats={${(schema.consumerHandlers?schema.handlerRecipes:schema.usedOps.map(op=>({op}))).map((r,index)=>`[${ctx.slots[index]}]=${operandFormat(rolesFor(r.op,schema.fragments),ctx)}`).join(',')}},`:"";
  return `{${formats}guard=${ctx.guard},salt=${ctx.opcodeSalt},domains={${ctx.domains.join(',')}},${receiptFields}${semanticFields}${schema.compactRecords?`zero={${zeros.join(',')}},`:''}${schema.usedOps.includes(PRIVATE_SELECT)?`mutable={${ctx.slots[schema.usedOps.indexOf(OP.MOVE)]},${ctx.order[1]}},`:''}${schema.usedOps.includes(PRIVATE_ARITHMETIC)?`arithmetic={${ctx.slots[schema.usedOps.indexOf(OP.BINARY)]},${ctx.order[3]}},`:''}handlers={${shuffle(handlers).join(',')}}}`;
 }).join(',');
 const base=schema.family===0?'(a+b)':schema.family===1?'(a*3+b)':'(a+5*b)',side=schema.family===0?'a':schema.family===1?'b':'((a+b)%modulus)';
 const mixing=`return (${base}%modulus*${schema.multiplier}+floor(${side}/${2**schema.shift})*${schema.gain})%modulus`;
 let lazy=readFileSync(new URL('./lazy-prototypes.lua',import.meta.url),'utf8');
 if(schema.activatedConstants){
  const start=lazy.indexOf('  p.tags,p.constantData,p.constantSeals,p.cache='),end=lazy.indexOf('  p.instructionCount=',start);
  if(start<0||end<start)throw new Error('Constant directory anchors changed');
  lazy=lazy.slice(0,start)+(schema.bitPackedConstants?bitActivatedConstantDirectory:activatedConstantDirectory)+'\n'+lazy.slice(end);
 }
 if(schema.usedOps.includes(PRIVATE_OPEN)){
  lazy=lazy.replace('local parent=u32();local r=range()', 'local parent=u32();local sealed=parent>=2147483648;if sealed then parent=parent-2147483648 end;local r=range()')
   .replace('sections[id]={parent,r[1],r[2]}','sections[id]={parent,r[1],r[2],sealed}')
   .replace('if id<1 or id>count or key<1 or key>=modulus or key%1~=0 then invalid()end','if type(id)~=\'number\'or id<1 or id>count or id%1~=0 then invalid()end;local gate=nil;if sections[id][4]then gate=key;key=pageEntry(gate)elseif type(key)~=\'number\'then invalid()end;if key<1 or key>=modulus or key%1~=0 then invalid()end')
   .replace('if p.entryKey~=key then invalid()end;return p','if p.entryKey~=key or sections[id][4]and p.sealKey~=gate then invalid()end;return p');
  const begin=lazy.indexOf('  local keyBytes='),end=lazy.indexOf('  local function read8(offset)',begin);
  if(begin<0||end<begin)throw new Error('Sealed prototype anchors changed');
  const old=lazy.slice(begin,end).replace('  local decoded=native and createBuffer(length)or {};','  decoded=native and createBuffer(length)or {};');
  lazy=lazy.slice(0,begin)+'  local decoded;if section[4]then decoded,length=openSealed(section,gate)else\n'+old+'  end\n'+lazy.slice(end);
  lazy=lazy.replace('p={};p.parent','p={sealKey=gate};p.parent');
  let cipher=sealedPageRuntime({fastCipher:schema.fastCipher??false,nativeCipher});
  if(schema.leanRuntime){
   const first=cipher.indexOf('  if nativeWords then for round=1,32 do'),slow=cipher.indexOf('\n  else for round=1,32 do',first),end=cipher.indexOf('\n  if at+8<=length then',slow);
   if(first<0||slow<first||end<slow)throw new Error('Lean native cipher anchors changed');
   // Keep the existing wide-number primitive probe. A lean artifact requires
   // its successful result instead of shipping two complete round loops.
   cipher=cipher.slice(0,first)+cipher.slice(first,slow).replace('  if nativeWords then for round=1,32 do','  for round=1,32 do')+cipher.slice(end);
   cipher=cipher.replace('local nativeWords=ok and valid','if not(ok and valid)then invalid()end');
  }
  if(schema.boundPages){
   const entry="local function pageEntry(key)if type(key)~='string'or #key~=16 then invalid()end;return pageWord(key,1)%4294967295+1 end";
   const length='local length=section[3]-8;if length<34 then invalid()end';
   if(!cipher.includes(entry)||!cipher.includes(length))throw new Error('Bound cipher anchors changed');
   cipher=cipher.replace(entry,"local function pageEntry(key,id,parent)if type(key)~='string'or #key~=16 then invalid()end;return pageWord(boundPageMac(key,3,{id,parent},nil,0),1)%4294967295+1 end")
    .replace(length,`local length=section[3]-24;if length<34 then invalid()end
 local tag=boundPageMac(key,2,{section[6],section[1],length},function(i)return read8(section[2]+i)end,length+8${schema.leanRuntime?',function(i)return read32(section[2]+i)end':''})
 local difference=0;for i=0,15 do difference=bit32.bor(difference,bit32.bxor(read8(section[2]+8+length+i),byte(tag,i+1)))end
 if difference~=0 then invalid()end`);
   if(!cipher.includes('local decoded=createBuffer(length)')||!cipher.includes(' return decoded,length\nend'))throw new Error('Bound cipher lifetime anchors changed');
   cipher=cipher.replace('local decoded=createBuffer(length)','local decoded=createBuffer(length)\n local ok,result=pcall(function()')
    .replace(' return decoded,length\nend',` end)
 for i=1,4 do keys[i]=nil end;for i=1,32 do leftRounds[i],rightRounds[i]=nil,nil end
 if not ok then clearPageSpan(decoded,0,length);error(result,0)end
 return decoded,length
end`);
   lazy=lazy.replace('key=pageEntry(gate)','key=pageEntry(gate,id,sections[id][1])');
  }
  lazy=cipher+'\n'+lazy;
 }
 if(schema.usedOps.includes(PRIVATE_SPAN)){
  if(!schema.usedOps.includes(PRIVATE_OPEN))throw new TypeError('Span requires page opening');
  lazy=lazy.replace('if sealed then parent=parent-2147483648 end;local r=range()','if sealed then parent=parent-2147483648 end;local inline=parent>=1073741824;if inline then parent=parent-1073741824;if not sealed then invalid()end end;local r=range()')
   .replace('sections[id]={parent,r[1],r[2],sealed}','sections[id]={parent,r[1],r[2],sealed,inline}')
   .replace('if p.entryKey~=key or sections[id][4]and p.sealKey~=gate then invalid()end;return p','if p.entryKey~=key or sections[id][4]and p.sealKey~=gate then invalid()end;if sections[id][5]and not p.spanAvailable then p.reloadSpan()end;return p')
   .replace('  if position~=length then invalid()end',`  if section[5]then p.span=range();if p.span[2]<1 or p.span[2]>8192 then invalid()end;p.spanAvailable=true
   p.releaseSpan=function()if not p.spanAvailable then invalid()end;p.spanAvailable=false;if native then clearPageSpan(decoded,p.span[1],p.span[2])else decoded=sub(decoded,1,p.span[1])end end
   p.reloadSpan=function()decoded=openSealed(section,gate);p.spanAvailable=true end
  end
  if position~=length then invalid()end`);
 }
 if(schema.boundPages){
  const at='sections[id]={parent,r[1],r[2],sealed,inline}';
  if(!lazy.includes(at))throw new Error('Bound child directory anchor changed');
  lazy=lazy.replace(at,'sections[id]={parent,r[1],r[2],sealed,inline,id}');
 }
 if(schema.externalEntry)lazy=lazy.replace('local rootKey=u32();if rootKey==0 then invalid()end','local storedRoot=u32();local rootKey=entryOverride;if storedRoot~=0 or type(rootKey)~="number"or rootKey<1 or rootKey>=modulus or rootKey%1~=0 then invalid()end');
 if(schema.batchSpans){
  if(!schema.usedOps.includes(PRIVATE_SPAN))throw new TypeError('Batch spans require inline pages');
  lazy=lazy.replace('  p.reader8,p.reader32=read8,read32',`  p.readerSpan=function(offset,width)
   if native then if type(buffer.readstring)~="function"then return nil end;return buffer.readstring(decoded,offset,width)end
   return sub(decoded,offset+1,offset+width)
  end
  p.reader8,p.reader32=read8,read32`);
 }
 if(schema.sectionTransport){
  if(!lazy.includes('local section=sections[id];local length=section[3]')||!lazy.includes('  local function read8(offset)'))throw new Error('Section source reader anchors changed');
  lazy=lazy.replace('local section=sections[id];local length=section[3]',`local section=sections[id];local length=section[3]
  local sourceRead8,sourceRead32,closeSource=blob.openSection(id,key,${schema.usedOps.includes(PRIVATE_OPEN)?'gate':'nil'})`)
   .replace('read8(section[2]+j-1)','sourceRead8(section[2]+j-1)')
   .replace('  local function read8(offset)','  closeSource()\n  local function read8(offset)')
   .replace('if position~=#blob then invalid()end','if position~=blobLength then invalid()end');
  if(schema.usedOps.includes(PRIVATE_OPEN)){
   if(!lazy.includes('local function openSealed(section,key)')||!lazy.includes('decoded,length=openSealed(section,gate)'))throw new Error('Sealed section source anchors changed');
   lazy=lazy.replace('local function openSealed(section,key)','local function openSealed(section,key,sourceRead8,sourceRead32)\n local read8,read32=sourceRead8,sourceRead32')
    .replace('decoded,length=openSealed(section,gate)','decoded,length=openSealed(section,gate,sourceRead8,sourceRead32)')
    .replace('p.reloadSpan=function()decoded=openSealed(section,gate);p.spanAvailable=true end',`p.reloadSpan=function()
     local sourceRead8,sourceRead32,closeSource=blob.openSection(id,key,gate)
     decoded=openSealed(section,gate,sourceRead8,sourceRead32);closeSource();p.spanAvailable=true
    end`);
  }
 }
 if(schema.boundPages){
  const initial='decoded,length=openSealed(section,gate,sourceRead8,sourceRead32)';
  const reload='decoded=openSealed(section,gate,sourceRead8,sourceRead32);closeSource();p.spanAvailable=true';
  if(!lazy.includes(initial)||!lazy.includes(reload))throw new Error('Bound page cleanup anchors changed');
  // Always retire the section reader on authenticated-open failure. The old
  // prototype buffer remains live until a replacement has opened successfully.
  lazy=lazy.replace(initial,`local ok,data,width=pcall(openSealed,section,gate,sourceRead8,sourceRead32)
   if not ok then closeSource();error(data,0)end;decoded,length=data,width\n`)
   .replace(reload,`local ok,data=pcall(openSealed,section,gate,sourceRead8,sourceRead32);closeSource()
     if not ok then error(data,0)end
     local previous=decoded;decoded=data;clearPageSpan(previous,0,buffer.len(previous));p.spanAvailable=true`);
 }
 lazy=lazy.replace('p.offsets[(i-1)*5+1]=position;position=position+n','local offsets={position};position=position+n;for bank=2,contextCount do local width=u8();if width<37 or width>44 then invalid()end;need(width);offsets[bank]=position;position=position+width end;p.offsets[(i-1)*5+1]=offsets');
 let runtime=readFileSync(new URL('./runtime-v5.lua',import.meta.url),'utf8');
 if(schema.bitPackedRecords||schema.bitPackedConstants)runtime=runtime.replace(' __PROTOTYPES__',bitFieldRuntime+'\n __PROTOTYPES__');
 if(schema.identityWitness){
  const anchor=' local function witness(value)',old="elseif kind=='table'then return 7 elseif kind=='function'then return 11 elseif kind=='thread'then return 13";
  if(!runtime.includes(anchor)||!runtime.includes(old))throw new Error('Object witness anchor changed');
  runtime=runtime.replace(anchor,` local identities=setmetatable({},{__mode='k'});local identitySequence=0
 local function objectWitness(value,tag)
  local id=identities[value]
  if not id then
   if identitySequence>=modulus-1 then error('Nil identity budget exceeded',0)end
   identitySequence=identitySequence+1;id=identitySequence;identities[value]=id
  end
  return mix(id,tag)
 end
${anchor}`).replace(old,"elseif kind=='table'then return objectWitness(value,7)elseif kind=='function'then return objectWitness(value,11)elseif kind=='thread'then return objectWitness(value,13)");
 }
 if(schema.activatedConstants){
  const start=runtime.indexOf(' local function constant('),end=runtime.indexOf(' local function inverse(',start);
  if(start<0||end<start)throw new Error('Constant consumer anchors changed');
  runtime=runtime.slice(0,start)+(schema.bitPackedConstants?bitActivatedConstantRuntime:activatedConstantRuntime)+'\n'+runtime.slice(end);
  if(schema.consumerHandlers){
   runtime=runtime.replace('  local cached=p.cache[slot];if cached then',
    '  local cache=frame.consumerCache\n  local cached=p.scalarCache[slot]or cache and cache[slot];if cached then')
    .replace('  p.cache[slot]={commitment,value}',"  if type(value)=='string'then if not cache then cache={};frame.consumerCache=cache end;cache[slot]={commitment,value}else p.scalarCache[slot]={commitment,value}end");
   lazy=lazy.replace('p.cache={};p.constantDirectory=position','p.scalarCache={};p.constantDirectory=position');
  }
  runtime=runtime.replace('  frame.masks,frame.raw,frame.semantic,frame.stamp=', '  frame.slot=record.slot\n  frame.masks,frame.raw,frame.semantic,frame.stamp=');
 }
 if(schema.binaryIntegers){
  runtime=runtime.replaceAll('\r\n','\n');lazy=lazy.replaceAll('\r\n','\n');
  if(schema.activatedConstants){
   if(!runtime.includes('if tag>4 or')||!runtime.includes('elseif tag>=3 then'))throw new Error('Lean activated constants anchors changed');
   runtime=runtime.replace('if tag>4 or','if tag>5 or').replace('elseif tag>=3 then',activatedBinaryConstantRuntime);
  }else{
   const anchor="if tag==0 then return nil elseif tag==1 then value=false elseif tag==2 then value=true\n  else";
   if(!lazy.includes('if tag>4 then invalid()end')||!runtime.includes(anchor))throw new Error('Lean constants anchors changed');
   lazy=lazy.replace('if tag>4 then invalid()end','if tag>5 then invalid()end');
   runtime=runtime.replace(anchor,anchor.slice(0,-4)+binaryConstantRuntime);
  }
 }
 if(schema.activatedConstants||schema.consumerHandlers||schema.denseMetadata)runtime=runtime.replace(' local storage=native and fromBuffer(blob)or blob',' if not native then invalid()end\n local storage=native and fromBuffer(blob)or blob');
 if(schema.sectionTransport){
  runtime=runtime.replace("type(blob)~='string'or #blob>16777216 or sub(blob,1,#signature)~=signature", "type(blob)~='table'or type(blob.length)~='number'or blob.length<34 or blob.length>16777216 or blob.length%1~=0 or type(blob.read8)~='function'or type(blob.read32)~='function'or type(blob.openSection)~='function'")
   .replace('local storage=native and fromBuffer(blob)or blob','local blobLength=blob.length;local storage=nil')
   .replace('local function read8(offset)if native then return readBuffer8(storage,offset)end;return byte(storage,offset+1)end','local function read8(offset)return blob.read8(offset)end')
   .replace('local function read32(offset)if native then return readBuffer32(storage,offset)end;local a,b,c,d=byte(storage,offset+1,offset+4);return a+b*256+c*65536+d*16777216 end','local function read32(offset)return blob.read32(offset)end')
   .replace(' local position=#signature',' for i=1,#signature do if read8(i-1)~=byte(signature,i)then invalid()end end\n local position=#signature')
   .replaceAll('#blob','blobLength');
 }
 if(receipts||resultLinks)runtime=runtime.replace('local function open(frame)',(resultLinks?resultRuntime.prefix??'':'')+'local function open(frame,registers)')
  .replace('local handler=open(frame)','local handler=open(frame,registers)');
 if(schema.semanticReceipts&&resultLinks){
  if(!Array.isArray(schema.resultOpenTargets)||schema.resultOpenTargets.flat().length!==schema.resultLinkCount||schema.resultOpenTargets.some(p=>!Array.isArray(p)||new Set(p).size!==p.length||p.some(pc=>!Number.isInteger(pc)||pc<1||pc%5!==1)))throw new TypeError('Invalid result opening targets');
  const targets=schema.resultOpenTargets.flatMap((pcs,i)=>pcs.length?[`[${i+1}]={${pcs.map(pc=>`[${pc}]=true`).join(',')}}`]:[]).join(',');
  runtime=runtime.replace('local function open(frame,registers)',`local resultOpenTargets={${targets}}
 local function open(frame,registers)`);
  const anchor='  local offsets=frame.prototype.offsets[frame.cursor]';
  if(!runtime.includes(anchor))throw new Error('Semantic receipt opening anchor changed');
  runtime=runtime.replace(anchor,`  local expected=resultOpenTargets[frame.id]
  if expected and expected[frame.cursor]then
   local token=frame.pendingResult;local ticket=token and resultTickets[token]
   if not ticket or ticket[1]~=frame.resultOwner or ticket[3]~=frame.cursor or ticket[4]~=frame.cursor or ticket[5]~=frame.resultEpoch or ticket[9]~=false or ticket[12]~=frame.history then invalid()end
  end
${anchor}`);
 }
 if(receipts)runtime=runtime
  .replace('  __PATCH_FETCH__','  local dispatchHandler=record.handler\n  __PATCH_FETCH__')
  .replace('return record.handler','return dispatchHandler');
 if(schema.compactRecords){
  lazy=lazy.replaceAll('n<37 or n>44','n<6 or n>45').replaceAll('width<37 or width>44','width<6 or width>45');
  const start=runtime.indexOf('  local encoded=p.reader8(offset);local raw={}'),end=runtime.indexOf('  local slot=',start);
  if(start<0||end<start)throw new Error('Record fetch anchors changed');
  runtime=runtime.slice(0,start)+`  local encoded=p.reader8(offset);local raw={}
  local bits=p.reader8(offset+1);local position=offset+2;local limit=offset+p.reader8(offset-1)
  for i=1,4 do raw[(i-1+key%4)%4+1]=masks[ctx.zero[i]]end
  for i=5,8 do raw[i]=masks[ctx.domains[i]]end
  local stamp=mix(mix(key,ctx.guard),encoded)
  for i=1,8 do
   if bits%2==1 then if position+4>limit then invalid()end;raw[i]=p.reader32(position);position=position+4 end
   bits=floor(bits/2);stamp=mix(stamp,raw[i])
  end
  if position+4>limit or limit-position-4>7 or (p.reader32(position)-masks[ctx.domains[9]])%modulus~=stamp then invalid()end
`+runtime.slice(end);
  if(schema.leanRuntime){
   lazy=lazy.replaceAll('n<6 or n>45','n<6 or n>38').replaceAll('width<6 or width>45','width<6 or width>38');
   runtime=runtime.replace('position+4>limit or limit-position-4>7','position+4~=limit');
  }
 }
 if(schema.narrowRecords){
  const loopStart=runtime.indexOf('  for i=1,8 do\n   if bits%2==1 then'),loopEnd=runtime.indexOf('  if position+4',loopStart);
  if(loopStart<0||loopEnd<0)throw new Error('Narrow record reader anchors changed');
  const reader=schema.bitPackedRecords?bitRecordReader.replaceAll('__BIT_READER__',schema.sealedRecords?'active8':'p.reader8').replaceAll('__WORD_READER__',schema.sealedRecords?'active32':'p.reader32'):narrowRecordReader;
  runtime=runtime.slice(0,loopStart)+reader+runtime.slice(loopEnd);
  const anchor='  p.instructionCount=u32();';
  const end=lazy.indexOf('  p.offsets={}',lazy.indexOf(anchor));if(end<0)throw new Error('Narrow prototype widths anchor changed');
  lazy=lazy.slice(0,end)+(schema.bitPackedRecords?bitPrototypeWidths:narrowPrototypeWidths)+lazy.slice(end);
  if(!schema.bitPackedRecords)lazy=lazy.replace('  p.reader8,p.reader32=read8,read32','  p.reader16=function(offset)if native then return buffer.readu16(decoded,offset)end;return read8(offset)+read8(offset+1)*256 end\n  p.reader8,p.reader32=read8,read32');
 }
 if(schema.sealedRecords){
  const anchor='  local encoded=p.reader8(offset);local raw={}';
  if(!runtime.includes(anchor))throw new Error('Record activation anchor changed');
  // Length prefixes remain transport metadata. Instruction bytes are opened
  // only with the active transfer key, never by the prototype reader alone.
  runtime=runtime.replace(anchor,(schema.bufferLanes?laneBufferActivation:recordActivation)+'\n'+anchor)
   .replaceAll('p.reader8(offset)', 'active8(offset)')
   .replaceAll('p.reader8(offset+1)', 'active8(offset+1)')
   .replaceAll('p.reader32(offset+1+(i-1)*4)', 'active32(offset+1+(i-1)*4)')
   .replaceAll('p.reader32(offset+33)', 'active32(offset+33)')
   .replaceAll('p.reader32(position)', 'active32(position)')
   .replaceAll('p.reader16(position)', 'active16(position)')
   .replaceAll('p.reader8(position', 'active8(position');
  if(schema.narrowRecords&&!schema.bitPackedRecords)runtime=runtime.replace('local active8,active32=view.read8,view.read32','local active8,active32=view.read8,view.read32;local function active16(at)return active8(at)+active8(at+1)*256 end');
  const slotAt=runtime.lastIndexOf('  local slot=');if(slotAt<0)throw new Error('Record activation retirement anchor changed');
  runtime=runtime.slice(0,slotAt)+(schema.bufferLanes?retireLaneBuffer:'  for i=1,width do active[i]=nil end;view.offset=nil\n')+runtime.slice(slotAt);
 }
 if(schema.compactPrototypeMetadata){
  lazy=compactPrototypeReader(lazy,schema.prototypeFieldOrder).replaceAll('r[2]<34','r[2]<11').replaceAll('length<34','length<11');
 }
 const retireConstants=schema.consumerHandlers?'local cache=frame.consumerCache;if cache then for slot,entry in pairs(cache)do entry[1],entry[2]=nil,nil;cache[slot]=nil end;frame.consumerCache=nil end;':'';
 const retireView=retireConstants+((recordCacheLimit||schema.sealedRecords)?'frame.raw,frame.masks,frame.semantic,frame.stamp,frame.openHistory,frame.openBank=nil,nil,nil,nil,nil,nil':'');
 const retireFrame=retireConstants+(schema.boundPages?'retireChildPermits(frame);':'')+(receipts?'frame.pendingReceipt,frame.receiptActive=nil,nil;':'')+(resultLinks?resultRuntime.retire:'')+(schema.sealedRecords?'frame.activation=nil;':'')+((recordCacheLimit||schema.sealedRecords)?'frame.raw,frame.masks,frame.records,frame.maskCache,frame.prototype,frame.patches,frame.operatorPatches,frame.permits=nil,nil,nil,nil,nil,nil,nil,nil;frame.phase=2;':'');
 if(resultLinks)runtime=runtime.replace('  frame.history=mix(frame.history,mix(frame.stamp,witness(result)))',resultRuntime.transfer??`  if frame.pendingResult then
   local ticket=frame.pendingResult
   local expected=frame.cursor==ticket[2]and frame.cursor+5 or frame.cursor
   if ticket[1]~=frame or ticket[4]~=expected or frame.cursor==ticket[2]and nextPc~=frame.cursor+5 or ticket[10]>=8 then invalid()end
   ticket[10]=ticket[10]+1;ticket[4]=nextPc
  end
  frame.history=mix(frame.history,mix(frame.stamp,witness(result)))`);
 let rendered=runtime
  .replace('__RECORD_LOOKUP__',()=>schema.sealedRecords?'local records={}':recordCacheLimit?`local index=(frame.cursor-1)/5%${recordCacheLimit}+1
  local records=frame.records[index]
  if not records or records.cursor~=frame.cursor then records={cursor=frame.cursor};frame.records[index]=records end`:
  'local records=frame.records[frame.cursor];if not records then records={};frame.records[frame.cursor]=records end')
  .replace('__RECORD_MASKS__',()=>(recordCacheLimit||schema.sealedRecords)?`local masks={};for i=1,9 do local domain=ctx.domains[i];masks[domain]=mix(key,domain)end;masks.inverse=inverse(2*(key%128)+1)`:
  `local cached=frame.maskCache[key];if not cached then cached={};frame.maskCache[key]=cached end
  local masks=cached[frame.bank]
  if not masks then masks={};for i=1,9 do local domain=ctx.domains[i];masks[domain]=mix(key,domain)end;masks.inverse=inverse(2*(key%128)+1);cached[frame.bank]=masks end`)
  .replace('__RETIRE_VIEW__',()=>retireView)
  .replaceAll('__RETIRE_FRAME__',()=>retireFrame)
  .replace('__SIGNATURE__',()=> '"'+Buffer.from(schema.signature,'hex').toJSON().data.map(n=>'\\'+String(n).padStart(3,'0')).join('')+'"')
  .replace('__MIX__',()=>mixing).replace('__COUNT__',()=>String(schema.contextCount)).replace('__PROTOTYPES__',()=>lazy).replace('contexts={__BANKS__}',()=>`${schema.sharedHandlers?'local sharedHandlers={'+shuffle(sharedBodies).join(',')+'};':''}contexts={${bankFields}}`)
  .replace('__PATCH_FETCH__',()=>(schema.usedOps.includes(PRIVATE_SELECT)?`
  local source=frame.patches[frame.cursor]
  if source then
   if record.slot~=ctx.mutable[1]then invalid()end
   local raw={};for i=1,8 do raw[i]=record.raw[i]end
   local physical=ctx.mutable[2];raw[(physical+key%4)%4+1]=(source+record.masks[ctx.domains[2]])%modulus
   local semantic=mix(mix(key,ctx.guard),record.slot);for i=1,6 do semantic=mix(semantic,raw[i])end
   local nextPc=frame.cursor+5;local domain=ctx.domains[7]
   raw[7]=(raw[7]-mix(record.semantic,(nextPc+domain)%modulus)+mix(semantic,(nextPc+domain)%modulus))%modulus
   local stamp=mix(mix(key,ctx.guard),record.encoded);for i=1,8 do stamp=mix(stamp,raw[i])end
   frame.raw,frame.semantic,frame.stamp=raw,semantic,stamp;frame.patches[frame.cursor]=nil
  end`:'')+(schema.usedOps.includes(PRIVATE_ARITHMETIC)?`
  local operation=frame.operatorPatches[frame.cursor]
  if record.slot==ctx.arithmetic[1]then
   local physical=ctx.arithmetic[2];local at=(physical+key%4)%4+1
   local original=(record.raw[at]-record.masks[ctx.domains[4]])%modulus
   if original==0 then
    if not operation or operation<1 or operation>2 or operation%1~=0 then invalid()end
    local raw={};for i=1,8 do raw[i]=record.raw[i]end
    raw[at]=(operation+record.masks[ctx.domains[4]])%modulus
    local semantic=mix(mix(key,ctx.guard),record.slot);for i=1,6 do semantic=mix(semantic,raw[i])end
    local nextPc=frame.cursor+5;local domain=ctx.domains[7]
    raw[7]=(raw[7]-mix(record.semantic,(nextPc+domain)%modulus)+mix(semantic,(nextPc+domain)%modulus))%modulus
    local stamp=mix(mix(key,ctx.guard),record.encoded);for i=1,8 do stamp=mix(stamp,raw[i])end
    frame.raw,frame.semantic,frame.stamp=raw,semantic,stamp;frame.operatorPatches[frame.cursor]=nil
   elseif operation then invalid()end
  elseif operation then invalid()end`:'')+(receipts?receiptFetch:'')+(resultLinks?resultRuntime.fetch:'') )
  .replace('__PATCH_HELPER__',()=>(schema.usedOps.includes(PRIVATE_SELECT)?`
 local function writeOperand(frame,target,source)
  ready(frame);if not frame.prototype.offsets[target]or frame.patches[target]then invalid()end
  frame.patches[target]=source
 end`:'')+(schema.usedOps.includes(PRIVATE_ARITHMETIC)?`
 local function writeOperator(frame,target,operation)
  ready(frame);if not frame.prototype.offsets[target]or frame.operatorPatches[target]or type(operation)~="number"or operation%1~=0 or operation<1 or operation>2 then invalid()end
  frame.operatorPatches[target]=operation
 end`:'')+(receipts?receiptHelper:'')+(resultLinks?resultRuntime.helper:'') )
  .replace('__FRAME_PATCH__',()=>(schema.usedOps.includes(PRIVATE_SELECT)?',patches={}':'')+(schema.usedOps.includes(PRIVATE_SPAN)?',permits={}':'')+(schema.boundPages?',childOwner={},childEpoch=0':'')+(schema.usedOps.includes(PRIVATE_ARITHMETIC)?',operatorPatches={}':'')+(receipts?',receiptEpoch=0':'')+(resultLinks?resultRuntime.frameFields:''));
 if(schema.boundPages){
  const prefix=`if type(nativeRead)~='function'then invalid()end
 local boundPageMac=nativeRead(${schema.pageAuthSlot});if type(boundPageMac)~='function'then invalid()end
`;
  if(!rendered.includes(' local totalConstants,totalInstructions=0,0')||!rendered.includes(' local function inverse('))throw new Error('Bound runtime scope anchors changed');
  // Before pageEntry/openPrototype, so every reference captures this binding.
  const start=rendered.indexOf('local bxor,shiftLeft,shiftRight=bit32.bxor');
  if(start<0)throw new Error('Bound native cipher anchor changed');
  rendered=rendered.slice(0,start)+prefix+rendered.slice(start);
  rendered=rendered.replace(' local function inverse(',` local function recordBase(key,guard,frame)return mix(mix(mix(key,frame.id),frame.cursor),guard)end
 local function inverse(`).replaceAll('mix(key,ctx.guard)','recordBase(key,ctx.guard,frame)');
  const permits=` local childTickets=setmetatable({},{__mode='k'})
 local function eraseChildTicket(token)
  local ticket=childTickets[token];if ticket then for i=1,6 do ticket[i]=nil end;childTickets[token]=nil end
 end
 local function issueChildPermit(frame,id,child)
  if frame.childEpoch>=modulus-1 then invalid()end
  local previous=frame.permits[id];if previous then eraseChildTicket(previous)end
  frame.childEpoch=frame.childEpoch+1;local token={}
  childTickets[token]={frame.childOwner,id,child,child.sealKey,frame.cursor,frame.childEpoch};frame.permits[id]=token
 end
 local function consumeChildPermit(frame,id,child)
  local token=frame.permits[id];local ticket=childTickets[token]
  if not ticket or ticket[1]~=frame.childOwner or ticket[2]~=id or ticket[3]~=child or ticket[4]~=child.sealKey or not frame.prototype.offsets[ticket[5]]or ticket[6]<1 or ticket[6]>frame.childEpoch then invalid()end
  frame.permits[id]=nil;eraseChildTicket(token)
 end
 local function retireChildPermits(frame)
  for id,token in pairs(frame.permits)do eraseChildTicket(token);frame.permits[id]=nil end
  frame.childOwner,frame.childEpoch=nil,nil
 end
`;
  if(!rendered.includes(' local privateValues={}'))throw new Error('Bound child vault anchor changed');
  rendered=rendered.replace(' local privateValues={}',permits+' local privateValues={}');
 }
 if(schema.keyedDirectory&&!schema.boundPages){
  const anchor=' local function inverse(';
  if(!rendered.includes(anchor))throw new Error('Keyed record context anchor changed');
  rendered=rendered.replace(anchor,' local function recordBase(key,guard,frame)return mix(mix(mix(key,frame.id),frame.cursor),guard)end\n'+anchor).replaceAll('mix(key,ctx.guard)','recordBase(key,ctx.guard,frame)');
 }
 if(schema.bufferLanes){
  const inverse=' local function inverse(odd)local result=1;for i=1,3 do result=result*(2-odd*result)%256 end;return result end';
  if(!rendered.includes(inverse))throw new Error('Byte inverse specialization anchor changed');
  rendered=rendered.replace(inverse,byteInverse);
 }
 const delivered=schema.keyedDirectory?keyedInstructionDirectory(rendered,{narrow:schema.narrowRecords,bitPacked:schema.bitPackedRecords}):schema.denseMetadata?denseInstructionDirectory(rendered):rendered;
 const optimized=schema.sealedRecords?specializeSealedFetch(delivered):delivered;
 return schema.bufferLanes?specializeLaneReads(optimized):optimized;
}
