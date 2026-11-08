import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, randomInt } from 'node:crypto';
import { compileLuaToNil } from './nil-core/compiler.mjs';
import { serializeNil } from './nil-core/format.mjs';
import { LIMITS } from './nil-core/opcodes.mjs';
import { DEFAULT_OPAQUE_ENTRY, validateOpaqueEntry, opaqueSourceBytes, normalizeOpaqueChunks } from './nil-core/opaque.mjs';
import { randomOpcodeMap, validateOpcodeMap, packContainer, containerDecoder, randomizeDispatcher } from './nil-core/container.mjs';
import { lowerNil } from './nil-core/lowering.mjs';
import { OP } from './nil-core/opcodes.mjs';
import { renameRunnerBindings } from './nil-core/presentation.mjs';
import { flattenRunnerFunctions, compactRunnerTokens } from './nil-core/runner-flow.mjs';
import { liftRunnerHelpers, poolRunnerPrimitives, concealRunnerStrings, normalizeRunnerMethods, shuffleRunnerFields, randomNumericKey, renameFrameFields } from './nil-core/runner-object.mjs';
import { randomRadix85Alphabet, encodeRadix85, quoteRadix85 } from './nil-core/radix85.mjs';
import {statefulProgram,serializeStateful,statefulSchema,statefulRuntime} from './nil-core/stateful.mjs';
import {dataProgram,serializeData,dataSchema,dataRuntime,dataNativeBindings,dataTransportPlan} from './nil-core/data-vm.mjs';
import {prepareNative} from './nil-core/native-preparation.mjs';
import {concealInternalDiagnostics} from './nil-core/diagnostics.mjs';
import {createNativeBindings,validateNativeBindings} from './nil-core/bound-native.mjs';
import {jointMaterializer,materializerPlan,attachMaterializer} from './nil-core/joint-materializer.mjs';
import {activateResultLinks} from './nil-core/result-links.mjs';
import {packSectionTransport,sectionTransportDecoder} from './nil-core/section-transport.mjs';
import {fuseMaterializerProgram} from './nil-core/materializer-fragments.mjs';

export { compileLuaToNil, serializeNil };
const runtime = readFileSync(new URL('./nil-core/runtime.lua', import.meta.url), 'utf8');
function containsOwnLoop(node){
  if(['ForNumericStatement','ForGenericStatement','WhileStatement','RepeatStatement'].includes(node.type))return true;
  for(const value of Object.values(node)){
    const children=Array.isArray(value)?value:[value];
    for(const child of children)if(child&&typeof child==='object'&&child.type!=='FunctionDeclaration'&&containsOwnLoop(child))return true;
  }
  return false;
}

export function leadingMarkerComment(source) {
  if (!source.startsWith('--')) return '';
  const opening = /^--\[(=*)\[/.exec(source);
  if (opening) {
    const close = `]${opening[1]}]`;
    const end = source.indexOf(close, opening[0].length);
    if (end < 0) throw new SyntaxError('Unterminated leading marker comment');
    return source.slice(0, end + close.length);
  }
  return source.split(/\r\n|\n|\r/, 1)[0];
}

export function buildNilWrapper(blob, { markerComment = '', diagnostics='opaque', onDiagnostics, onStructure, recordCacheLimit=0, scopeAliases=false, fastTransport=false, requireBuffer=false, requireBit32=false, callableEntry=false, compactTransport=false, nativeCipher=false, maxSteps = 1_000_000, opaqueChunks, dispatchFamily, schema=dataSchema(blob)??statefulSchema(blob), nativeBindings=dataNativeBindings(blob), materializer=materializerPlan(blob), opcodeMap = [0,...Array.from({length:Object.keys(OP).length},(_,i)=>i+1)] } = {}) {
  if(!Number.isInteger(recordCacheLimit)||recordCacheLimit!==0&&(recordCacheLimit<16||recordCacheLimit>4096||schema?.version!==5))throw new RangeError('Record cache limit requires V5 and zero or 16..4096');
  if(typeof scopeAliases!=='boolean')throw new TypeError('Invalid alias mode');
  if(typeof requireBuffer!=='boolean')throw new TypeError('Invalid buffer requirement');
  if(typeof callableEntry!=='boolean')throw new TypeError('Invalid callable entry mode');
  if(typeof compactTransport!=='boolean'||compactTransport&&!schema?.sectionTransport)throw new TypeError('Compact transport requires section transport');
  if(typeof nativeCipher!=='boolean'||nativeCipher&&(!requireBuffer||!requireBit32||schema?.version!==5))throw new TypeError('Native cipher requires V5 buffer and bit32 guards');
  if(schema?.bufferLanes&&(!requireBuffer||!requireBit32))throw new TypeError('Buffer lanes require buffer and bit32 guards');
  if(schema?.denseMetadata&&!requireBuffer)throw new TypeError('Dense metadata requires buffer');
  if(typeof requireBit32!=='boolean'||requireBit32&&!requireBuffer)throw new TypeError('Bit32 requirement needs buffer');
  if(schema?.boundPages&&(!nativeCipher||!requireBuffer||!requireBit32||!materializer?.objectProtocol?.boundPages))throw new TypeError('Bound page guards and protocol required');
  if(schema?.leanRuntime&&(!nativeCipher||materializer?.objectProtocol?.leanRuntime!==true))throw new TypeError('Lean runtime delivery/protocol mismatch');
  if(materializer?.objectProtocol?.wordFeedback&&!requireBit32)throw new TypeError('Word feedback requires buffer and bit32 guards');
  if (!Buffer.isBuffer(blob) || blob.length > LIMITS.blobBytes) throw new TypeError('Invalid bytecode buffer');
  if (!Number.isInteger(maxSteps) || maxSteps < 1 || maxSteps > 1_000_000_000) throw new RangeError('Invalid maxSteps');
  if (typeof markerComment !== 'string' || (markerComment && leadingMarkerComment(markerComment) !== markerComment)) {
    throw new TypeError('markerComment must be a single Lua comment');
  }
  validateOpcodeMap(opcodeMap);
  const entries = normalizeOpaqueChunks(opaqueChunks);
  if(schema?.version===5&&entries.length&&!nativeBindings&&!materializer)throw new TypeError('V5 native binding plan required');
  if(nativeBindings)validateNativeBindings(nativeBindings,entries);
  if(!['opaque','development'].includes(diagnostics)||onDiagnostics!==undefined&&typeof onDiagnostics!=='function'||onStructure!==undefined&&typeof onStructure!=='function')throw new TypeError('Invalid diagnostic options');
  const preparations=nativeBindings?new Map(entries.map(({name,bytes})=>{const binding=nativeBindings.entries.get(name);return [binding.route,prepareNative(bytes,binding)];})):undefined;
  if(onStructure)onStructure(Object.freeze({wire:schema,materializer:materializer?.summary,native:Object.freeze(Object.fromEntries([...(preparations??[])].map(([route,p])=>[route,Object.freeze({schema:p.schema,steps:p.steps})])))}));
  if(schema?.sectionTransport&&(nativeBindings||entries.length&&!materializer?.inlinePages))throw new TypeError('Section transport requires inline V5 materialization');
  const packed = schema?.sectionTransport?packSectionTransport(blob,dataTransportPlan(blob),schema,{compactTransport}):packContainer(blob, entries, opcodeMap,{nativeBindings,preparations,materializer});
  const alphabet85=randomRadix85Alphabet();
  const usedFieldKeys=new Set();
  const dataKey=randomNumericKey(usedFieldKeys),runKey=randomNumericKey(usedFieldKeys);
  const letters='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let entry;do{entry=letters[randomInt(letters.length)]+letters[randomInt(letters.length)]+letters[randomInt(letters.length)];}while(['and','end','for','nil','not'].includes(entry));
  usedFieldKeys.add(entry);const handlerFields=[];
  const dispatcher = schema?.version===5?dataRuntime(schema,{recordCacheLimit,nativeCipher}):randomizeDispatcher(schema?statefulRuntime(schema,{inline:true}):runtime, opcodeMap, { dispatchFamily,objectName:'state',handlerFields,usedFieldKeys,stateful:!!schema,lazyPrototypes:!!schema?.lazyPrototypes });
  const placeholder='__PACKED_LITERAL_'+randomBytes(12).toString('hex');
  const bitNames="'bxor','band','extract','byteswap'"+(materializer?.objectProtocol?.nonlinearFeedback||schema?.bufferLanes?",'lrotate'":'')+(materializer?.nativeEntropy||nativeCipher?",'rshift'":'')+(nativeCipher?",'lshift'":'')+(schema?.boundPages?",'rrotate','bnot','bor'":'');
  const bufferGuard=requireBuffer?`local required=buffer;if type(required)~='table'then error('Nil buffer unavailable',0)end;for _,name in ipairs({'create','fromstring','readu8','readu32','writeu8','readstring','tostring'${schema?.bufferLanes?",'readbits','writebits'":''}${requireBit32||schema?.denseMetadata?",'writeu32'":''}${requireBit32?",'fill'":''}${requireBit32&&materializer?.nativeCompression?",'len','copy','readu16'":schema?.boundPages?",'len'":''}${materializer?.nativeEntropy?",'writeu16'":''}${schema?.narrowRecords&&!schema?.bitPackedRecords&&!(requireBit32&&materializer?.nativeCompression)?",'readu16'":''}})do if type(required[name])~='function'then error('Nil buffer unavailable',0)end end;${requireBit32?`local bits=bit32;if type(bits)~='table'then error('Nil bit32 unavailable',0)end;for _,name in ipairs({${bitNames}})do if type(bits[name])~='function'then error('Nil bit32 unavailable',0)end end;`:''}`:'';
  const runField=`[${runKey}]=function(state,...)
${bufferGuard}
local data=state[${dataKey}]
${schema?.sectionTransport?sectionTransportDecoder(schema,{alphabet85,materializer,fastTransport,compactTransport,hasNative:entries.length>0}):containerDecoder(entries.length > 0,{alphabet85,nativeBindings,preparations,materializer,fastTransport})}
local factory=(function()\n${dispatcher}\nend)()
return factory(program,environment,${maxSteps},nativeRead,nativeWrite)(...)
end`;
  const entryField=`${entry}=function(state)return function(...)return state[${runKey}](state,...)end end`;
  const fields=[runField,...(callableEntry?[]:[entryField]),...handlerFields];
  for(let i=fields.length-1;i>0;i--){const j=randomInt(i+1);[fields[i],fields[j]]=[fields[j],fields[i]];}
  // Keep the packed body in the same object as its decoder and use an entry
  // factory method. Native payload bytes are never parsed by these passes.
  const metatable=callableEntry?`{__call=function(state,...)return state[${runKey}](state,...)end,__metatable=false}`:'{}';
  const source=`return setmetatable({${fields.join(',')},[${dataKey}]=${placeholder}},${metatable});`;
  const normalized=normalizeRunnerMethods(diagnostics==='opaque'?concealInternalDiagnostics(source,onDiagnostics):source);
  // Lifting/flattening rely on globally unique binding identities. Reuse
  // disjoint-scope aliases only after those structural transforms finish.
  const renamed=renameRunnerBindings(schema?renameFrameFields(normalized,{usedFieldKeys}):normalized);
  // Keep five-argument handlers and six-argument transfers in place so
  // their hot-path contract survives helper lifting and the later flattening selection.
  const lifted=liftRunnerHelpers(renamed,{runKey,usedFieldKeys,minStatements:schema?.leanRuntime?8:schema?2:1,include:node=>schema?.version!==5||node.parameters.length!==5&&node.parameters.length!==6&&!node.body.some(containsOwnLoop)});
  const concealed=concealRunnerStrings(lifted.source,{usedFieldKeys,alphabet85,denseMetadata:schema?.denseMetadata??false});
  const pooled=poolRunnerPrimitives(concealed,{usedFieldKeys});
  // Preserve v5's hot data consumers and transfer functions as direct code.
  // Applying presentation state machines to every operand read/handler made
  // their small operations more expensive than the VM state they consume.
  const flattened=flattenRunnerFunctions(shuffleRunnerFields(pooled.source),{include:node=>schema?.version===5?
    (!schema.leanRuntime||node.body.length>=8)&&node.parameters.length!==5&&node.parameters.length!==6&&!node.body.some(containsOwnLoop):
    !schema||!(node.body.length===3&&node.body[0].type==='LocalStatement'&&node.body[1].type==='ForNumericStatement'&&node.body[2].type==='ReturnStatement')});
  const rendered=compactRunnerTokens(renameRunnerBindings(flattened.source,{scopeAliases}));
  if(rendered.split(placeholder).length!==2)throw new Error('Packed literal placeholder changed');
  const runner=rendered.replace(placeholder,()=>quoteRadix85(encodeRadix85(packed,alphabet85))).replace(/;$/,'')+(callableEntry?'(...);':`:${entry}()(...);`);
  return [
    ...(markerComment ? [markerComment] : []),
    runner,
    '',
  ].join('\n');
}

/** Keep a native chunk byte-for-byte; compile only the independent wire source. */
export function wrapOpaqueLuaSourceAsNil(source, options = {}) {
  const bytes = opaqueSourceBytes(source);
  const entryName = validateOpaqueEntry(options.entryName ?? DEFAULT_OPAQUE_ENTRY);
  const wireSource = options.wireSource ?? `return ${entryName}(...)`;
  if (options.opaqueChunks !== undefined) throw new TypeError('Use wrapLuaSourceAsNil for multiple opaque chunks');
  const markerComment = options.markerComment ?? leadingMarkerComment(bytes.toString('utf8'));
  return wrapLuaSourceAsNil(wireSource, {
    ...options, markerComment, opaqueChunks: new Map([[entryName, bytes]]),
  });
}

export function wrapLuaSourceAsNil(source, options = {}) {
  for(const option of ['leanRuntime','boundPages','resultLinks','cfgResultLinks','sealedRecords','sectionTransport','semanticRegions','activatedConstants','consumerHandlers'])if(options[option]!==undefined&&(typeof options[option]!=='boolean'||options[option]&&(options.vmVersion??5)!==5))throw new TypeError(`${option} requires data V5`);
  if(options.cfgResultLinks&&!options.resultLinks)throw new TypeError('CFG results require result links');
  if(options.sectionTransport&&normalizeOpaqueChunks(options.opaqueChunks).length&&(options.nativeMode!=='joint'||options.inlinePages===false))throw new TypeError('Section transport requires joint inline native pages');
  if(options.valueReceipts!==undefined&&(typeof options.valueReceipts!=='boolean'||options.valueReceipts&&((options.vmVersion??5)!==5||options.nativeMode!=='joint'||options.fetchTransitions!==true||!normalizeOpaqueChunks(options.opaqueChunks).length)))throw new TypeError('Value receipts require joint V5 fetch transitions');
  if(options.packedDescriptors!==undefined&&(typeof options.packedDescriptors!=='boolean'||options.packedDescriptors&&((options.vmVersion??5)!==5||options.nativeMode!=='joint'||options.pageGates===false||!normalizeOpaqueChunks(options.opaqueChunks).length)))throw new TypeError('Packed descriptors require joint sealed V5 pages');
  if(options.streamMasks!==undefined&&(typeof options.streamMasks!=='boolean'||options.streamMasks&&((options.vmVersion??5)!==5||options.nativeMode!=='joint'||options.objectProtocol!==true)))throw new TypeError('Stream masks require joint V5 object protocol');
  if(options.recordCacheLimit!==undefined&&(!Number.isInteger(options.recordCacheLimit)||options.recordCacheLimit!==0&&(options.recordCacheLimit<16||options.recordCacheLimit>4096||(options.vmVersion??5)!==5)))throw new RangeError('Record cache limit requires V5 and zero or 16..4096');
  if(options.nativeCompression!==undefined&&(typeof options.nativeCompression!=='boolean'||options.nativeCompression&&((options.vmVersion??5)!==5||options.nativeMode!=='joint'||options.objectProtocol!==true)))throw new TypeError('Native compression requires joint V5 object protocol');
  if(options.onEffectGraph!==undefined&&(typeof options.onEffectGraph!=='function'||options.effectGraph!==true&&options.semanticRegions!==true))throw new TypeError('Effect graph callback requires graph mode');
  if(options.effectGraph!==undefined&&(typeof options.effectGraph!=='boolean'||options.effectGraph&&((options.vmVersion??5)!==5||options.nativeMode!=='joint'||options.objectProtocol!==true)))throw new TypeError('Effect graph requires joint V5 object protocol');
  if(options.objectProtocol!==undefined&&(typeof options.objectProtocol!=='boolean'||options.objectProtocol&&((options.vmVersion??5)!==5||options.nativeMode!=='joint'||options.inlinePages===false||options.pageGates===false||!normalizeOpaqueChunks(options.opaqueChunks).length)))throw new TypeError('Object protocol requires joint inline V5 native materialization');
  if(options.fastCipher!==undefined&&(typeof options.fastCipher!=='boolean'||options.fastCipher&&(options.vmVersion??5)!==5))throw new TypeError('Cipher arithmetic mode requires V5');
  if(options.compactRecords!==undefined&&(typeof options.compactRecords!=='boolean'||options.compactRecords&&(options.vmVersion??5)!==5))throw new TypeError('Compact records require V5');
  if(options.batchSpans!==undefined&&(typeof options.batchSpans!=='boolean'||options.batchSpans&&((options.vmVersion??5)!==5||options.nativeMode!=='joint'||options.inlinePages===false||!normalizeOpaqueChunks(options.opaqueChunks).length)))throw new TypeError('Batch spans require joint inline V5 pages');
  if(options.fetchTransitions!==undefined&&(typeof options.fetchTransitions!=='boolean'||options.fetchTransitions&&((options.vmVersion??5)!==5||options.nativeMode!=='joint'||!normalizeOpaqueChunks(options.opaqueChunks).length)))throw new TypeError('Fetch transitions require joint V5 native materialization');
  if(options.vmVersion!==undefined&&![4,5].includes(options.vmVersion))throw new TypeError('Unknown VM version');
  if((options.vmVersion??5)===5){
    if(options.nativeMode!==undefined&&!['joint','packet'].includes(options.nativeMode))throw new TypeError('Unknown native preparation mode');
    const jointEntries=normalizeOpaqueChunks(options.opaqueChunks);
    // Joint materialization remains explicit until resistance/cost gates pass.
    // The standalone opaque wrapper retains the established packet default.
    if(jointEntries.length&&options.nativeMode==='joint'){
      const wire=lowerNil(compileLuaToNil(source,options),{dependentFusion:true});
      const joint=jointMaterializer(wire,jointEntries,{...options,inlinePages:options.inlinePages??true});joint.plan.summary=Object.freeze(joint.summary);
      joint.plan.batchSpans=options.batchSpans??false;
      const compiled=dataProgram(joint.program),program=options.resultLinks?activateResultLinks(compiled,{cfg:options.cfgResultLinks??false}):compiled;
      if(options.resultLinks)joint.plan.summary=Object.freeze({...joint.summary,resultLinkPairs:program.stats.resultLinkPairs,resultLinkOperands:program.stats.resultLinkOperands});
      const blob=attachMaterializer(serializeData(program,{contextCount:options.contextCount??2,compactRecords:options.compactRecords??false,batchSpans:options.batchSpans??false,fastCipher:options.fastCipher??false,sealedRecords:options.sealedRecords??false,sectionTransport:options.sectionTransport??false,activatedConstants:options.activatedConstants??false,consumerHandlers:options.consumerHandlers??false,leanRuntime:options.leanRuntime??false}),joint.plan);
      return buildNilWrapper(blob,{...options,markerComment:options.markerComment??leadingMarkerComment(source)});
    }
    const entries=normalizeOpaqueChunks(options.opaqueChunks),nativeBindings=entries.length?createNativeBindings(entries):undefined;
    let lowered=lowerNil(compileLuaToNil(source,options),{dependentFusion:true});
    if(options.semanticRegions){
      lowered=fuseMaterializerProgram(lowered,0,{effectGraph:true,resultLinks:options.resultLinks??false,cfgResultLinks:options.cfgResultLinks??false,preciseBudget:true});
      if(options.onEffectGraph)options.onEffectGraph(Object.freeze({summary:Object.freeze(lowered.effectGraph.summary),prototypes:Object.freeze(lowered.effectGraph.graphs),regions:Object.freeze(lowered.effectGraph.proofs)}));
    }
    const compiled=dataProgram(lowered,{nativeBindings}),program=options.resultLinks?activateResultLinks(compiled,{cfg:options.cfgResultLinks??false}):compiled;
    return buildNilWrapper(serializeData(program,{contextCount:options.contextCount??2,nativeBindings,compactRecords:options.compactRecords??false,fastCipher:options.fastCipher??false,sealedRecords:options.sealedRecords??false,sectionTransport:options.sectionTransport??false,activatedConstants:options.activatedConstants??false,consumerHandlers:options.consumerHandlers??false}),{...options,nativeBindings,markerComment:options.markerComment??leadingMarkerComment(source)});
  }
  const program = statefulProgram(lowerNil(compileLuaToNil(source, options)));
  const opcodeMap = randomOpcodeMap();
  return buildNilWrapper(serializeStateful(program, { opcodeMap }), {
    ...options, opcodeMap, markerComment: options.markerComment ?? leadingMarkerComment(source),
  });
}

