import {randomInt,randomBytes} from 'node:crypto';
import {compileLuaToNil} from './compiler.mjs';
import {lowerNil} from './lowering.mjs';
import {OP,OPERAND_ROLES,LIMITS} from './opcodes.mjs';
import {packNativePackets} from './native-packets.mjs';
import {PRIVATE_GET,PRIVATE_DENY,PRIVATE_INIT,PRIVATE_CAP,PRIVATE_DESCRIPTOR,privateRoles} from './private-ops.mjs';
import {fuseMaterializerProgram} from './materializer-fragments.mjs';
import {sampleGate} from './sealed-pages.mjs';
import {quoteLuaBytes} from './format.mjs';
import {nativeLifetimeRuntime} from './native-lifetime.mjs';
import {validateFetchContracts} from './fetch-contracts.mjs';
import {createObjectProtocol,objectProtocolBridge} from './object-protocol.mjs';
import {validateObjectProtocolContracts} from './object-protocol-contracts.mjs';
import {compressNativeBytes} from './native-compression.mjs';
import {analyzeDataflow} from './dataflow.mjs';
import {lowerValueReceipts} from './fetch-receipts.mjs';
import {encodeWordFeedbackBlock} from './word-feedback.mjs';
import {boundPageSeed,boundNextGate,bindPageProgram} from './bound-pages.mjs';
import {compactProgramRegisters} from './register-allocation.mjs';

const M=2**32,plans=new WeakMap(),mix=(a,b)=>((a+b)%M*65599+Math.floor(a/65536)*257)%M;
const mask=(state,field)=>mix(state,field*4271);
function digest(bytes){let a=1,b=0;for(const value of bytes){a+=value;b+=a;}return (b%65521)*65536+a%65521;}
function shuffle(a){a=[...a];for(let i=a.length-1;i>0;i--){const j=randomInt(i+1);[a[i],a[j]]=[a[j],a[i]];}return a;}
export const materializerPlan=blob=>plans.get(blob);
export const attachMaterializer=(blob,plan)=>{plans.set(blob,plan);return blob;};

// Only compiler-owned straight-line packet descriptors may use this terminal
// superinstruction. Native bodies and arbitrary user/wire functions are untouched.
export function packDescriptorPrototypes(program){
 let removed=0,count=0;
 const prototypes=program.prototypes.map(p=>{
  if(!p.packetDescriptor)return p;
  if(p.parameters!==1||p.vararg||p.upvalues.length||!Buffer.isBuffer(p.sealKey)||p.sealKey.length!==16||p.packetDescriptor.length!==8||p.packetDescriptor.some(v=>!Number.isInteger(v)||v<0||v>=M))throw new Error('Invalid descriptor prototype');
  const cost=p.code.reduce((n,row)=>n+(program.fragments.get(row[0])?.cost??1),0);
  if(cost<1||cost>100000)throw new Error('Invalid descriptor instruction cost');
  const bytes=Buffer.alloc(36);[...p.packetDescriptor,cost+(p.fullWordSeed?2147483648:0)].forEach((v,i)=>bytes.writeUInt32LE(v,i*4));
  removed+=p.code.length-1;count++;
  const packed={...p,packetDescriptor:undefined,registers:0,cells:1,constants:[bytes.toString('latin1')],code:[[PRIVATE_DESCRIPTOR,1,1,0,0]],...(p.layout?.keys?{layout:{keys:[p.layout.keys[0]],constantKeys:[p.layout.constantKeys[0]]}}:{})};
  if(p.dataflow)packed.dataflow=analyzeDataflow(packed,program.fragments);
  return packed;
 });
 return {...program,prototypes,stats:{...program.stats,instructions:prototypes.reduce((n,p)=>n+p.code.length,0),packedDescriptorCount:count,packedDescriptorRemovedInstructions:removed}};
}

// A physical linked layout. Next-node addresses consume the actual preceding
// plaintext digest. The linked walk and descriptor arithmetic are VM code.
function packRegion(bytes,packetLayout){
 const raw=packNativePackets(bytes,packetLayout),count=raw.readUInt32LE(4),records=[];let at=8;
 for(let i=0;i<count;i++){
  const length=raw.readUInt32LE(at+4);
  records.push({offset:raw.readUInt32LE(at),length,seed:raw.readUInt32LE(at+8),multiplier:raw.readUInt32LE(at+12),increment:raw.readUInt32LE(at+16),reverse:raw[at+20],cipher:raw.subarray(at+21,at+21+length)});at+=21+length;
 }
 const order=shuffle([0,1,2,3,4,5,6]),physical=shuffle(records),initial=randomInt(1,M),id=randomInt(1,M);
 let size=16;for(const p of physical){p.position=size+1;size+=28+p.length;}
 const frame=Buffer.alloc(size);frame.writeUInt32LE(bytes.length,0);frame.writeUInt32LE(count,4);
 const logical=[...records].sort((a,b)=>a.offset-b.offset);frame.writeUInt32LE((logical[0].position+mask(initial,8))%M,8);frame.writeUInt32LE(mix(mix(initial,bytes.length),count),12);
 let state=initial;
 for(let i=0;i<logical.length;i++){
  const p=logical[i],nextState=mix(state,digest(bytes.subarray(p.offset,p.offset+p.length)));
  const values=[p.offset,p.length,p.seed,p.multiplier,p.increment,p.reverse,logical[i+1]?.position??0];
  values.forEach((v,j)=>frame.writeUInt32LE((v+mask(j===6?nextState:state,j+1))%M,p.position-1+order[j]*4));
  p.cipher.copy(frame,p.position-1+28);state=nextState;
 }
 return {id,frame,initial,order,size:bytes.length,count,finalState:state};
}

function packSealedRegion(bytes,packetLayout,wordFeedback=false,nonlinearFeedback=false,boundPages=false){
 const raw=packNativePackets(bytes,packetLayout),count=raw.readUInt32LE(4),records=[];let at=8;
 for(let i=0;i<count;i++){const length=raw.readUInt32LE(at+4);records.push({offset:raw.readUInt32LE(at),length,multiplier:raw.readUInt32LE(at+12),increment:raw.readUInt32LE(at+16),reverse:raw[at+20],factor:randomInt(8,32768)*2+1,add:randomInt(nonlinearFeedback?M:65536)});at+=21+length;}
 records.sort((a,b)=>a.offset-b.offset);
 const initial=randomInt(1,M),id=randomInt(1,M),starter=randomBytes(16),physical=shuffle(records);let size=16;
 for(const p of physical){p.position=size+1;size+=p.length;}
 const frame=Buffer.alloc(size);frame.writeUInt32LE(bytes.length,0);frame.writeUInt32LE(count,4);frame.writeUInt32LE(randomInt(M),8);frame.writeUInt32LE(mix(mix(initial,bytes.length),count),12);
 let state=initial,gate=starter;
 for(const p of records){p.sealKey=gate;p.seed=boundPages?boundPageSeed(gate,state,p.factor,p.add,p.offset,p.length):(state*p.factor+p.add)%(nonlinearFeedback?M:65536);let seed=p.seed;const plain=bytes.subarray(p.offset,p.offset+p.length);
  if(wordFeedback){const encoded=encodeWordFeedbackBlock(plain,seed,p.multiplier,p.increment,p.offset,p.reverse,nonlinearFeedback);encoded.bytes.copy(frame,p.position-1);seed=encoded.state;}
  else for(let j=0;j<p.length;j++){seed=(seed*p.multiplier+p.increment)%65536;frame[p.position-1+(p.reverse?p.length-1-j:j)]=(plain[j]+Math.floor(seed/256))%256;}
  state=mix(state,digest(plain));if(nonlinearFeedback)state=mix(state,seed);gate=boundPages?boundNextGate(gate,plain,state,p.offset):sampleGate(plain,state);
 }
 return {id,frame,initial,size:bytes.length,count,finalState:state,starter,records,pageIds:[],wordFeedback,nonlinearFeedback};
}

function sourceFor(p,n,select,open,span,arithmetic){
 const methods=p.objectProtocol?.methods;
 const field=index=>`(word(${p.id},position+${p.order[index]*4})-base-${(index+1)*4271*65599%M})%4294967296`;
 // Family selection changes real block boundaries and the accumulation path.
 // Byte kernels are bounded to 4096 bytes and have separate stream/write jobs.
 const lane=randomInt(2),width=arithmetic?`${arithmetic}(state%2==${lane},3072,state%1025)`:lane?'2048+state%2049':'4096-state%1025';
 return `local function ${n}(...)
 if not cache${n} then
  local state=${p.initial};${p.inline?`local size=${p.size};local count=${p.count}`:`local size=word(${p.id},1);local count=word(${p.id},5)
  if size~=${p.size} or count~=${p.count} or word(${p.id},13)~=${mix(mix(p.initial,p.size),p.count)}then reject()end`}
  ${p.records?`local gate=${quoteLuaBytes(p.starter)};local pages={${p.pageIds.join(',')}}`:`local position=(word(${p.id},9)-${mask(p.initial,8)})%4294967296`}
  local output=allocate(size${p.codec?`,${p.decodedSize}${p.codec===2?',true':p.codec===3?',3':''}`:''});local consumed=0;local visited={}
  for packet=1,count do
   local base=(state*65599+floor(state/65536)*257)%4294967296
   ${p.records?`local descriptor=${open}(pages[packet],gate);local offset,length,seed,multiplier,increment,reverse,position=descriptor(state)`:`local offset=${field(0)};local length=${field(1)};local seed=${field(2)};local multiplier=${field(3)};local increment=${field(4)};local reverse=${field(5)}`}
   ${p.inline?`local source=${span}(pages[packet]);if position~=1 or visited[pages[packet]]then reject()end;visited[pages[packet]]=true`:'if position<17 or visited[position]then reject()end;visited[position]=true'}
   if offset~=consumed or length<1 or length>8192 or offset+length>size or seed>${p.nonlinearFeedback?'4294967295':'65535'} or multiplier<1 or multiplier>65535 or multiplier%2~=1 or increment<1 or increment>65535 or increment%2~=1 or reverse>1 then reject()end
   local done=0;local a=1;local b=0
   while done<length do
    local width=${width};if width>length-done then width=length-done end
    ${p.wordFeedback?'if width<length-done then width=width-width%4 end':''}
    local stride=${select}(reverse==1,-1,1);local input=position+${p.records?0:28}+done
    if stride==-1 then input=position+${p.records?0:28}+length-done-1 end
    ${methods?`local nextSeed,transaction=output[${methods.prepare}](output,source,input,stride,width,offset+done,seed,multiplier,increment)
    local receipt=output[${methods.apply}](output,transaction)
    local sum,weighted${p.wordFeedback?',nextSeed':''}=output[${methods.commit}](output,receipt)
    seed=nextSeed`:`seed=stream(output,seed,multiplier,increment,width)
    local sum,weighted=apply(output,${p.inline?'source':p.id},input,stride,width,offset+done)`}
    b=b+width*a+weighted;a=a+sum;done=done+width
   end
   state=(base+((b%65521)*65536+a%65521)*65599)%4294967296;${p.nonlinearFeedback?'state=(state*65599+floor(state/65536)*257+seed*65599)%4294967296;':''}consumed=consumed+length
   ${p.records?`if packet<count then gate=${methods?`output[${methods.key}]`:'key'}(output,offset,length,state${p.boundPages?',gate':''})end`:`base=(state*65599+floor(state/65536)*257)%4294967296;position=${field(6)}`}
  end
  if ${p.records?'':'position~=0 or '}consumed~=size or state~=${p.finalState}then reject()end
  cache${n}=${methods?`output[${methods.compile}]`:'compile'}(output)
 end
 return cache${n}(...)
end`;
}

/** Merge native preparation prototypes into the wire, before lazy serialization.
 * No native byte ever enters the source parser. Private reads become values,
 * never global names or a name -> route -> preparation-factory lookup.
 */
export function jointMaterializer(wire,entries,{target='lua51',pageGates=true,inlinePages=false,fetchTransitions=false,objectProtocol=false,effectGraph=false,onEffectGraph,nativeCompression=false,packedDescriptors=false,streamMasks=false,valueReceipts=false,resultLinks=false,cfgResultLinks=false,semanticReceipts=false,semanticRegions=false,packetLayout,wordFeedback=false,batchSpans=false,nonlinearFeedback=false,compressionMode='greedy',entropyCoding=false,entropyStreams=false,boundPages=false,leanRuntime=false,compactRegisters=false}={}){
 if(typeof compactRegisters!=='boolean')throw new TypeError('Invalid register allocation mode');
 if(typeof leanRuntime!=='boolean')throw new TypeError('Invalid lean runtime mode');
 if(typeof boundPages!=='boolean'||boundPages&&(!pageGates||!inlinePages||!objectProtocol||!packedDescriptors||!wordFeedback||!nonlinearFeedback||!batchSpans))throw new TypeError('Bound pages require inline packed word-feedback pages');
 if(typeof semanticRegions!=='boolean')throw new TypeError('Invalid semantic region mode');
 if(typeof effectGraph!=='boolean')throw new TypeError('Invalid effect graph mode');
 effectGraph=effectGraph||semanticRegions;
 if(typeof cfgResultLinks!=='boolean'||cfgResultLinks&&!resultLinks)throw new TypeError('CFG results require result links');
 if(typeof semanticReceipts!=='boolean'||semanticReceipts&&!cfgResultLinks)throw new TypeError('Semantic receipts require CFG result links');
 if(typeof resultLinks!=='boolean')throw new TypeError('Invalid result link reservation mode');
 if(wire.version!==3||wire.root!==1||!entries.length)throw new TypeError('Invalid joint materializer input');
 if(typeof pageGates!=='boolean')throw new TypeError('Invalid page gate mode');
 if(typeof inlinePages!=='boolean'||inlinePages&&!pageGates)throw new TypeError('Inline pages require page gates');
 if(typeof fetchTransitions!=='boolean')throw new TypeError('Invalid fetch transition mode');
 if(typeof objectProtocol!=='boolean'||objectProtocol&&(!inlinePages||!pageGates))throw new TypeError('Object protocol requires joint inline pages');
 if(typeof wordFeedback!=='boolean'||wordFeedback&&(!objectProtocol||!batchSpans))throw new TypeError('Word feedback requires object protocol and batch spans');
 if(typeof nonlinearFeedback!=='boolean'||nonlinearFeedback&&(!wordFeedback||!pageGates))throw new TypeError('Nonlinear feedback requires word feedback and page gates');
 if(!['greedy','balanced'].includes(compressionMode)||compressionMode!=='greedy'&&!nativeCompression)throw new TypeError('Invalid native compression mode');
 if(typeof entropyStreams!=='boolean'||entropyStreams&&!entropyCoding)throw new TypeError('Stream entropy requires entropy coding');
 if(typeof entropyCoding!=='boolean'||entropyCoding&&(!nativeCompression||!wordFeedback))throw new TypeError('Entropy coding requires compression and word feedback');
 if(typeof effectGraph!=='boolean'||effectGraph&&!objectProtocol)throw new TypeError('Effect graph materialization requires object protocol');
 if(typeof nativeCompression!=='boolean'||nativeCompression&&!objectProtocol)throw new TypeError('Native compression requires object protocol');
 if(typeof packedDescriptors!=='boolean'||packedDescriptors&&!pageGates)throw new TypeError('Packed descriptors require sealed pages');
 if(typeof streamMasks!=='boolean'||streamMasks&&!objectProtocol)throw new TypeError('Stream masks require object protocol');
 if(typeof valueReceipts!=='boolean'||valueReceipts&&!fetchTransitions)throw new TypeError('Value receipts require fetch transitions');
 if(onEffectGraph!==undefined&&(typeof onEffectGraph!=='function'||!effectGraph))throw new TypeError('Effect graph callback requires graph mode');
 const protocol=objectProtocol?createObjectProtocol({wordFeedback,nonlinearFeedback,boundPages,leanRuntime}):undefined;
 const blocks=entries.map(e=>nativeCompression?compressNativeBytes(e.bytes,{mode:compressionMode,entropyCoding,entropyStreams}):{bytes:e.bytes,decodedSize:e.bytes.length,codec:0});
 const regions=blocks.map(block=>({...((pageGates?packSealedRegion:packRegion)(block.bytes,packetLayout,wordFeedback,nonlinearFeedback,boundPages)),decodedSize:block.decodedSize,codec:block.codec}));while(new Set(regions.map(p=>p.id)).size!==regions.length)regions.forEach(p=>p.id=randomInt(1,M));
 for(const p of regions){p.inline=inlinePages;p.objectProtocol=protocol;p.boundPages=boundPages;}
 const pages=shuffle(regions.flatMap((region,index)=>(region.records??[]).map((record,packet)=>({region,index,record,packet}))));pages.forEach((page,index)=>page.region.pageIds[page.packet]=wire.prototypes.length+regions.length+index+1);
 const names=objectProtocol?['allocate','reject','floor',...(boundPages?['auth']:[])]:[...(inlinePages?[]:['word']),'allocate','stream','apply','compile','reject','floor',...(pageGates?['key']:[])],ids=shuffle(Array.from({length:99999},(_,i)=>i+1)).slice(0,names.length);
 const capNames=new Map(names.map((name,i)=>[name,'C'+randomBytes(12).toString('hex')]));
 const locals=names.map(name=>`local ${name}=${capNames.get(name)}`).join(';');
 const instructionSelect='S'+randomBytes(12).toString('hex'),instructionOpen='P'+randomBytes(12).toString('hex'),instructionSpan='D'+randomBytes(12).toString('hex'),instructionArithmetic=fetchTransitions?'A'+randomBytes(12).toString('hex'):undefined,funcs=regions.map((p,i)=>sourceFor(p,'v'+i,instructionSelect,instructionOpen,instructionSpan,instructionArithmetic));
 const source=`${locals};${regions.map((_,i)=>'local cachev'+i).join(';')};${funcs.join('\n')};return ${regions.map((_,i)=>'v'+i).join(',')}`;
 const objectContracts=protocol?validateObjectProtocolContracts(source,protocol,regions.length):[];
 const mat=lowerNil(compileLuaToNil(source,{target,instructionSelect,instructionOpen,instructionSpan,instructionArithmetic}),{fuse:false});
 if(mat.prototypes.length!==regions.length+1)throw new Error('Unexpected preparation prototype structure');
 const root=wire.prototypes[0],mr=mat.prototypes[0],cut=mr.code.findIndex(row=>row[0]===OP.RETURN);
 if(cut<0||mr.code.slice(0,cut).some(row=>(privateRoles.get(row[0])??OPERAND_ROLES[row[0]-1]).includes('j')))throw new Error('Materializer initializer is not straight line');
 const capSlots=new Map(names.map((name,i)=>[capNames.get(name),ids[i]])),privateSlots=new Map(entries.map((e,i)=>[e.name,i+1]));
 const remapMat=(p,index)=>{
  const isRoot=index===0;
  const code=p.code.map(row=>{const out=[...row];(privateRoles.get(out[0])??OPERAND_ROLES[out[0]-1]).forEach((role,j)=>{if(isRoot){if(role==='r')out[j+1]+=root.registers;if(role==='l')out[j+1]+=root.cells;if(role==='k'||role==='g')out[j+1]+=root.constants.length;}if(role==='p')out[j+1]+=wire.prototypes.length-1;});return out;});
  return {...p,parent:p.parent===0?0:p.parent===1?1:p.parent+wire.prototypes.length-1,upvalues:p.upvalues.map(([kind,slot])=>[kind,kind===0&&p.parent===1?slot+root.cells:slot]),code};
 };
 const material=mat.prototypes.map(remapMat),prefix=[...material[0].code.slice(0,cut),[PRIVATE_INIT,material[0].code[cut][1],0,0,0]],shift=prefix.length*5;
 const wireCode=root.code.map(row=>{const out=[...row];(privateRoles.get(out[0])??OPERAND_ROLES[out[0]-1]).forEach((role,j)=>{if(role==='j')out[j+1]+=shift;});return out;});
 const pagePrototypes=pages.map(({region,record:p,index})=>{const compiled=lowerNil(compileLuaToNil(`return function(state)local seed=(state*${p.factor}+${p.add})%${nonlinearFeedback?M:65536};return ${p.offset},${p.length},seed,${p.multiplier},${p.increment},${p.reverse},${inlinePages?1:p.position} end`,{target}),{fuse:true,flatten:false}).prototypes[1],end=compiled.code.findIndex(r=>r[0]===OP.RETURN);return {...compiled,parent:wire.prototypes.length+index+1,sealKey:p.sealKey,fullWordSeed:nonlinearFeedback,packetDescriptor:[p.offset,p.length,p.factor,p.add,p.multiplier,p.increment,p.reverse,inlinePages?1:p.position],...(inlinePages?{pageBytes:region.frame.subarray(p.position-1,p.position-1+p.length)}:{}),code:compiled.code.slice(0,end+1)};});
 const combined=[{...root,constants:[...root.constants,...mr.constants],registers:root.registers+mr.registers,cells:root.cells+mr.cells,code:[...prefix,...wireCode]},...wire.prototypes.slice(1),...material.slice(1),...pagePrototypes];
 combined.forEach((p,index)=>{p.code=p.code.map(row=>{
  if(row[0]!==OP.GETG&&row[0]!==OP.SETG)return row;
  const name=p.constants[row[2]-1];
  if(privateSlots.has(name))return [row[0]===OP.GETG?PRIVATE_GET:PRIVATE_DENY,row[1],row[0]===OP.GETG?privateSlots.get(name):0,0,0];
  if(capSlots.has(name))return [PRIVATE_CAP,row[1],capSlots.get(name),0,0];
  return row;
 });});
 if(combined.some(p=>p.registers>LIMITS.registers||p.cells>LIMITS.cells))throw new RangeError('Joint materializer frame limit');
 const assembled={...wire,prototypes:combined,stats:{...wire.stats,prototypes:combined.length,instructions:combined.reduce((n,p)=>n+p.code.length,0)}};
 const allocated=compactRegisters?compactProgramRegisters(assembled):assembled;
 const fused=fuseMaterializerProgram(allocated,semanticRegions?0:wire.prototypes.length,{effectGraph,resultLinks,cfgResultLinks,semanticReceipts,preciseBudget:semanticRegions});
 const packed=packedDescriptors?packDescriptorPrototypes(fused):fused;
 let program=valueReceipts?lowerValueReceipts(packed):packed;
 if(boundPages)program=bindPageProgram(program,ids[names.indexOf('auth')]);
 const fetchContracts=validateFetchContracts(program);
 if(onEffectGraph)onEffectGraph(Object.freeze({summary:Object.freeze(program.effectGraph.summary),prototypes:Object.freeze(program.effectGraph.graphs),regions:Object.freeze(program.effectGraph.proofs)}));
 return {program,plan:{ids:Object.fromEntries(names.map((name,i)=>[name,ids[i]])),regions,entries,inlinePages,objectProtocol:protocol,nativeCompression:blocks.some(block=>block.codec),nativeEntropy:blocks.some(block=>block.codec>=2),nativeStreams:blocks.some(block=>block.codec===3),nativeBlocks:blocks.some(block=>block.codec===1||block.codec===2),streamMasks},summary:{mode:'joint-ir',inlinePages,fetchTransitions,objectProtocol,packedDescriptors,streamMasks,valueReceipts,valueReceiptPairs:program.stats.valueReceiptPairs??0,packedDescriptorCount:program.stats.packedDescriptorCount??0,packedDescriptorRemovedInstructions:program.stats.packedDescriptorRemovedInstructions??0,objectContracts:objectContracts.length,fetchContracts:fetchContracts.length,...(nativeCompression?{compression:{codec:blocks.some(b=>b.codec===3)?'lz4-stream-huffman':blocks.some(b=>b.codec===2)?'lz4-huffman':'lz4-block',originalBytes:entries.reduce((n,e)=>n+e.bytes.length,0),storedBytes:blocks.reduce((n,b)=>n+b.bytes.length,0),greedyBytes:blocks.reduce((n,b)=>n+(b.greedyBytes??b.bytes.length),0),lz4Bytes:blocks.reduce((n,b)=>n+(b.lz4Bytes??b.bytes.length),0),parseSavedBytes:blocks.reduce((n,b)=>n+(b.parseSavedBytes??0),0),entropySavedBytes:blocks.reduce((n,b)=>n+(b.entropySavedBytes??0),0),compressedRegions:blocks.filter(b=>b.codec).length,entropyRegions:blocks.filter(b=>b.codec>=2).length,streamRegions:blocks.filter(b=>b.codec===3).length,streamSavedBytes:blocks.reduce((n,b)=>n+(b.streamSavedBytes??0),0)}}:{}),...(effectGraph?{effectGraph:program.effectGraph.summary,effectGraphStage:valueReceipts?'before-descriptor-and-receipt-lowering':'before-descriptor-packing'}:{}),prototypes:mat.prototypes.length-1,kernelLimit:4096,packets:regions.reduce((n,r)=>n+r.count,0),sealedPages:pages.length,fragments:program.fragments.size,removedInstructions:program.stats.materializerRemovedInstructions}};
}

// These primitives do not parse descriptors, traverse packets, choose native
// bindings or advance the descriptor state. Those operations live in VM IR.
export function jointBridge(plan,{batchSpans=plan.batchSpans??false}={}){
 if(typeof batchSpans!=='boolean'||batchSpans&&!plan.inlinePages)throw new TypeError('Invalid batch span bridge');
 if(plan.objectProtocol)return objectProtocolBridge(plan,{batchSpans});
 const id=plan.ids;
 return `
local host=(getfenv and getfenv(1))or _ENV or _G
local loader,assign=host.loadstring or host.load,host.setfenv
local floor=math.floor
${nativeLifetimeRuntime}
local owners=setmetatable({},{__mode='k'})
local binary=type(buffer)=='table'and type(buffer.create)=='function'and type(buffer.fromstring)=='function'and type(buffer.readu8)=='function'and type(buffer.writeu8)=='function'and type(buffer.tostring)=='function'
local create,from,read,write,to
if binary then create,from,read,write,to=buffer.create,buffer.fromstring,buffer.readu8,buffer.writeu8,buffer.tostring end
${plan.inlinePages?"local inputs=setmetatable({},{__mode='k'})":"local storage={};if binary then for key,body in pairs(chunks)do storage[key]=from(body)end end"}
local function integer(n,low,high)if type(n)~='number'or n%1~=0 or n<low or n>high then invalid()end end
local function owned(output)local state=owners[output];if not state then invalid()end;return state end
local function retireOutput(output,state)
 owners[output]=nil
 if binary then clearNativeBuffer(state.data,0,state.size)end
 clearNativePieces(state.pieces);clearNativePieces(state.starts);clearNativePieces(state.mask)
 state.data,state.pieces,state.starts,state.mask=nil,nil,nil,nil;state.size,state.cursor,state.pending=0,0,nil
end
local capabilities={
 [${id.floor}]=math.floor,
 [${id.reject}]=invalid,
 ${id.key?`[${id.key}]=function(output,offset,length,seed)
  local state=owned(output);integer(length,1,state.size);integer(offset,0,state.size-length);integer(seed,0,4294967295);if state.pending or offset+length>state.cursor then invalid()end
  local cursor=seed;local values={};for i=0,15 do local at=offset+(cursor+i*997)%length;local value
   if binary then value=read(state.data,at)else local low,high=1,#state.starts;while low<high do local middle=floor((low+high+1)/2);if state.starts[middle]<=at then low=middle else high=middle-1 end end;value=byte(state.pieces[low],at-state.starts[low]+1)end
   seed=((seed+value+i*4271)%4294967296*65599+floor(seed/65536)*257)%4294967296;values[i+1]=char((value+floor(seed/256^(i%4)))%256)
  end;return concat(values)
 end,`:''}
 ${id.word?`[${id.word}]=function(region,at)local body=chunks[region];if not body then invalid()end;integer(at,1,#body-3);local a,b,c,d=byte(body,at,at+3);return a+b*256+c*65536+d*16777216 end,`:''}
 [${id.allocate}]=function(size)integer(size,1,16777216);local output={};owners[output]={size=size,cursor=0,pieces={},starts={},mask={},data=binary and create(size)or nil};return output end,
 [${id.stream}]=function(output,seed,multiplier,increment,width)
  local state=owned(output);integer(width,1,4096);integer(seed,0,65535);integer(multiplier,1,65535);integer(increment,1,65535)
  if state.pending then invalid()end
  for i=1,width do seed=(seed*multiplier+increment)%65536;state.mask[i]=floor(seed/256)end
  state.pending=width;return seed
 end,
 [${id.apply}]=function(output,region,at,stride,width,destination)
  local state=owned(output);${plan.inlinePages?'local input=inputs[region];if not input then invalid()end;local length=input.size':'local body=chunks[region];if not body then invalid()end;local length=#body;local input=storage[region]'}
  integer(width,1,4096);integer(destination,0,state.size-width);integer(at,1,length);if stride~=1 and stride~=-1 then invalid()end
  integer(at+(width-1)*stride,1,length);if state.pending~=width or destination~=state.cursor then invalid()end
  ${plan.inlinePages?`if input[4]<width or input[7]and input[7]~=output then invalid()end
  if input[5]then if at~=input[5]or stride~=input[6]then invalid()end
  elseif at~=(stride==1 and 1 or length)then invalid()end
  input[7]=output`:''}
  ${batchSpans?`local window=input.batch and input.batch(at,width,stride)or nil
  if window~=nil and (type(window)~='string'or #window~=width)then invalid()end`:''}
  local sum,weighted=0,0;local block={}
  for i=1,width do
   local position=at+(i-1)*stride;local v=((${plan.inlinePages?(batchSpans?'window and byte(window,stride==1 and i or width-i+1)or input.reader(position)':'input.reader(position)'):'binary and read(input,position-1)or byte(body,position)'})-state.mask[i])%256
   state.mask[i]=nil;sum=sum+v;weighted=weighted+sum
   if binary then write(state.data,destination+i-1,v)else block[i]=char(v)end
  end
  if not binary then state.starts[#state.pieces+1]=destination;state.pieces[#state.pieces+1]=concat(block)end
  ${plan.inlinePages?`input[4]=input[4]-width;input[5]=at+width*stride;input[6]=stride
  if input[4]==0 then local release=input.release;inputs[region]=nil;input.reader=nil;input.release=nil;${batchSpans?'input.batch=nil;':''}input[7]=nil;release()end`:''}
  state.pending=nil;state.cursor=state.cursor+width;return sum,weighted
 end,
 [${id.compile}]=function(output)
  local state=owned(output);if state.pending or state.cursor~=state.size then invalid()end
  if type(loader)~='function'then retireOutput(output,state);error('Nil native loader unavailable',0)end
  local source=binary and to(state.data)or concat(state.pieces);retireOutput(output,state)
  local fn,e=loader(source);source=nil;if type(fn)~='function'then error(e or 'Nil opaque compile failed',0)end
  if type(assign)=='function'then assign(fn,host)end;return fn
 end
}
local function nativeRead(slot,key,release${batchSpans?',batch':''})${plan.inlinePages?`if type(slot)=='function'then integer(key,1,8192);if type(release)~='function'${batchSpans?"or batch~=nil and type(batch)~='function'":''}then invalid()end;local input={};inputs[input]={size=key,reader=slot,release=release,${batchSpans?'batch=batch,':''}[4]=key};return input end;`:''}if key==0 then return host[slot]end;local value=capabilities[slot];if not value then invalid()end;return value end
local nativeWrite=nil
local environment=host
`;
}
