import {readFileSync} from 'node:fs';
import {randomInt} from 'node:crypto';
import {nativeLifetimeRuntime,nativeBufferLifetimeRuntime} from './native-lifetime.mjs';
import {nativeBlockRuntime,nativeBufferBlockRuntime} from './native-compression.mjs';
import {wordFeedbackRuntime} from './word-feedback.mjs';
import {nativeEntropyRuntime} from './native-entropy.mjs';
import {nativeStreamsRuntime} from './native-entropy-streams.mjs';
import {boundPageMacRuntimeFor} from './bound-pages.mjs';
import luaparse from 'luaparse';

const runtime=readFileSync(new URL('./object-protocol.lua',import.meta.url),'utf8');
// The transaction is a closed, compiler-owned record. Derive its erasure
// schema from this generated bridge, rather than handing it to host pairs.
// Opaque payload bytes never enter this parser. A new nonliteral access must
// get an explicit lifetime design instead of silently escaping cleanup.
function closeOperationLifetime(source){
 const ast=luaparse.parse(source,{luaVersion:'5.1',scope:true,encodingMode:'pseudo-latin1'}),fields=new Set();
 function walk(node){
  if(!node||typeof node!=='object')return;
  if(node.base?.type==='Identifier'&&node.base.isLocal===true&&node.base.name==='operation'){
   if(node.type==='MemberExpression')fields.add(node.identifier.name);
   if(node.type==='IndexExpression'){
    if(node.index.type!=='StringLiteral'||!/^[A-Za-z_][A-Za-z0-9_]*$/.test(node.index.value))throw new Error('Dynamic operation fields require an explicit cleanup contract');
    fields.add(node.index.value);
   }
  }
  for(const value of Object.values(node))if(Array.isArray(value))value.forEach(walk);else if(value&&typeof value==='object')walk(value);
 }
 walk(ast);
 if(!fields.size||!source.includes('clearNativePieces(operation)')||!source.includes('clearNativePieces(state.operation)'))throw new Error('Operation cleanup anchors changed');
 const keys=[...fields].sort();
 const erase=`local function clearNativeOperation(operation)${keys.map(k=>'operation.'+k).join(',')}=${keys.map(()=> 'nil').join(',')} end\n`;
 return source.replace('local function owned(',erase+'local function owned(')
  .replaceAll('clearNativePieces(operation)','clearNativeOperation(operation)')
  .replaceAll('clearNativePieces(state.operation)','clearNativeOperation(state.operation)');
}
export function createObjectProtocol({wordFeedback=false,nonlinearFeedback=false,boundPages=false,leanRuntime=false}={}){
 if(typeof leanRuntime!=='boolean'||leanRuntime&&!wordFeedback)throw new TypeError('Lean protocol requires word feedback');
 if(typeof wordFeedback!=='boolean')throw new TypeError('Invalid word feedback mode');
 if(typeof nonlinearFeedback!=='boolean'||nonlinearFeedback&&!wordFeedback)throw new TypeError('Nonlinear feedback requires word feedback');
 if(typeof boundPages!=='boolean'||boundPages&&(!wordFeedback||!nonlinearFeedback))throw new TypeError('Bound pages require nonlinear word feedback');
 const used=new Set(),methods={};
 for(const name of ['prepare','apply','commit','key','compile']){
  let key;do{key=randomInt(1,2**31);}while(used.has(key));used.add(key);methods[name]=key;
 }
 return Object.freeze({version:1,wordFeedback,nonlinearFeedback,boundPages,leanRuntime,methods:Object.freeze(methods)});
}

// Opaque payload bytes never pass through this template or a source parser.
export function objectProtocolBridge(plan,{batchSpans=false}={}){
 const protocol=plan.objectProtocol;
 if(plan.sessionOwnership!==undefined&&typeof plan.sessionOwnership!=='boolean')throw new TypeError('Invalid session ownership mode');
 if(plan.streamMasks!==undefined&&typeof plan.streamMasks!=='boolean')throw new TypeError('Invalid stream mask mode');
 if(!plan.inlinePages||protocol?.version!==1||typeof batchSpans!=='boolean')throw new TypeError('Invalid object materializer protocol');
 const keys=['prepare','apply','commit','key','compile'].map(name=>protocol.methods?.[name]);
 if(keys.some(key=>!Number.isInteger(key)||key<1||key>=2**31)||new Set(keys).size!==keys.length||['allocate','floor','reject'].some(name=>!Number.isInteger(plan.ids?.[name])||plan.ids[name]<1))throw new TypeError('Invalid object protocol keys');
 const feedback=protocol.wordFeedback===true;
 const replacements={
 MASK_RUNTIME:!feedback&&plan.streamMasks?`local function advanceMask(seed,multiplier,increment,width)
  local factor,bias=1,0
  while width>0 do
   if width%2==1 then factor=factor*multiplier%65536;bias=(bias*multiplier+increment)%65536 end
   increment=increment*(multiplier+1)%65536;multiplier=multiplier*multiplier%65536;width=floor(width/2)
  end
  return (seed*factor+bias)%65536
 end`:'',
 PREPARE_MASK:feedback?'operation.seed,operation.multiplier,operation.increment=seed,multiplier,increment;return seed,token':plan.streamMasks?'operation.seed,operation.multiplier,operation.increment=seed,multiplier,increment;return advanceMask(seed,multiplier,increment,width),token':'for i=1,width do seed=(seed*multiplier+increment)%65536;state.mask[i]=floor(seed/256)end;return seed,token',
 SEED_LIMIT:feedback?'4294967295':'65535',COMMIT_SEED:feedback?'local nextSeed=operation.nextSeed;integer(nextSeed,0,4294967295);':'',RETURN_SEED:feedback?',nextSeed':'',
 WINDOW_SEED:plan.streamMasks?'local seed,multiplier,increment=operation.seed,operation.multiplier,operation.increment':'',
 DECODE_MASK:plan.streamMasks?'seed=(seed*multiplier+increment)%65536;local value=(encoded-floor(seed/256))%256':'local value=(encoded-state.mask[i])%256;state.mask[i]=nil',
 CLEAR_MASK:plan.streamMasks?'':'clearNativePieces(state.mask);',MASK_FIELD:plan.streamMasks?'':'mask={},',
 LIFETIME:protocol.leanRuntime?nativeBufferLifetimeRuntime:nativeLifetimeRuntime,BATCH:batchSpans?'batch':'nil',BATCH_ARGUMENT:batchSpans?',batch':'',BATCH_CHECK:batchSpans?'or batch~=nil and type(batch)~="function"':'',ALLOCATE:plan.ids.allocate,FLOOR:plan.ids.floor,REJECT:plan.ids.reject,...Object.fromEntries(Object.entries(protocol.methods).map(([name,key])=>[name.toUpperCase(),key]))};
 if(plan.nativeEntropy&&(!plan.nativeCompression||!feedback))throw new TypeError('Entropy decoder requires buffer word protocol');
 const blockNeeded=plan.nativeBlocks!==false;
 const streamDecode=plan.nativeStreams?'if state.entropy==3 then return expandNativeStreams(state.data,state.size,state.decodedSize)end;':'';
 const entropyDecode=plan.nativeEntropy?blockNeeded?streamDecode+'if state.entropy then local expanded=expandNativeEntropy(state.data,state.size);local ok,result=pcall(expandNativeBlock,expanded,buffer.len(expanded),state.decodedSize);buffer.fill(expanded,0,0,buffer.len(expanded));if not ok then error(result,0)end;return result end;':streamDecode+'invalid();':'';
 let template=runtime.replace('__COMPRESSION_RUNTIME__',plan.nativeCompression?(blockNeeded?(feedback?nativeBufferBlockRuntime:nativeBlockRuntime):'')+(plan.nativeEntropy?'\n'+nativeEntropyRuntime:'')+(plan.nativeStreams?'\n'+nativeStreamsRuntime:''):'').replace('__DECOMPRESS__',plan.nativeCompression?`if state.decodedSize then ${entropyDecode}${blockNeeded?`return expandNativeBlock(${feedback?'state.data':'binary and state.data or concat(state.pieces)'},state.size,state.decodedSize)`:'invalid()'}end;`:'');
 if(plan.nativeEntropy){
  if(!template.includes('[__ALLOCATE__]=function(size,decodedSize)')||!template.includes('decodedSize=decodedSize,cursor=0'))throw new Error('Entropy allocation anchors changed');
  template=template.replace('[__ALLOCATE__]=function(size,decodedSize)','[__ALLOCATE__]=function(size,decodedSize,entropy)\n  if entropy~=nil and(type(entropy)~="boolean"or not decodedSize)then invalid()end')
   .replace('decodedSize=decodedSize,cursor=0','decodedSize=decodedSize,entropy=entropy,cursor=0');
 }
 if(plan.nativeStreams){
  if(!plan.nativeEntropy)throw new TypeError('Stream decoder requires entropy');
  template=template.replace('type(entropy)~=\"boolean\"or not decodedSize','type(entropy)~=\"boolean\"and entropy~=3 or not decodedSize');
 }
 if(feedback){
  const first=template.indexOf('local binary='),last=template.indexOf('local function integer(',first);
  if(first<0||last<0)throw new Error('Buffer-only protocol anchor changed');
  template=template.slice(0,first)+'local binary=true\nlocal create,read,write,to=buffer.create,buffer.readu8,buffer.writeu8,buffer.tostring\n'+template.slice(last);
  template=template.replace('data=binary and create(size)or nil','data=create(size)').replace('return binary and to(state.data)or concat(state.pieces)','return to(state.data)');
  const keyStart=template.indexOf('  if binary then value=read(state.data,at)'),keyEnd=template.indexOf('\n  seed=',keyStart);
  if(keyStart<0||keyEnd<0)throw new Error('Buffer-only key anchor changed');
  template=template.slice(0,keyStart)+'  value=read(state.data,at)'+template.slice(keyEnd);
 }
 if(feedback){const first=template.indexOf('local function executeWindow('),last=template.indexOf('methods[__APPLY__]',first);if(first<0||last<0)throw new Error('Word kernel template changed');template=template.slice(0,first)+wordFeedbackRuntime(protocol.nonlinearFeedback)+template.slice(last);}
 if(protocol.boundPages){
  if(!feedback||!protocol.nonlinearFeedback||!Number.isInteger(plan.ids.auth)||plan.ids.auth<1)throw new TypeError('Invalid bound page capability');
  const first=template.indexOf('methods[__KEY__]='),last=template.indexOf('methods[__COMPILE__]=',first);
  if(first<0||last<0||!template.includes('local methods={}'))throw new Error('Bound page protocol anchors changed');
  template=template.slice(0,first)+`methods[__KEY__]=function(output,offset,length,seed,gate)
 local state=owned(output,0);local version=state.version
 integer(length,1,state.size);integer(offset,0,state.size-length);integer(seed,0,4294967295)
 if offset+length~=state.cursor or version<=1 then invalid()end
 local result=boundPageMac(gate,1,{seed,offset,length},function(i)return read(state.data,offset+i)end,length${protocol.leanRuntime?',function(i)return buffer.readu32(state.data,offset+i)end':''})
 if owners[output]~=state or state.phase~=0 or state.version~=version then invalid()end
 return result
end
`+template.slice(last);
  template=template.replace('local methods={}',boundPageMacRuntimeFor(protocol.leanRuntime??false)+'\nlocal methods={}')
   .replace('local capabilities={','local capabilities={\n [__AUTH__]=boundPageMac,');
  replacements.AUTH=plan.ids.auth;
 }
 if(protocol.leanRuntime){
  const fields='pieces={},starts={},',clear='clearNativePieces(state.pieces);clearNativePieces(state.starts);';
  if(!feedback||!template.includes(fields)||!template.includes(clear))throw new Error('Lean allocation anchors changed');
  template=template.replace(fields,'').replace(clear,'').replace('if binary and state.data then','if state.data then').replace('local binary=true\n','');
  if(/state\.(pieces|starts)\b/.test(template))throw new Error('Legacy allocation remains live');
 }
 if(plan.sessionOwnership){
  // Weak-key values are strong in Luau. No input value may point back to the
  // output key through an owner -> leases -> input -> owner retention cycle.
  const comparisons=template.match(/input\.owner(?:==|~=)output/g)??[];
  if(comparisons.length!==4||!template.includes('input.owner,input.pending=output,token')||!template.includes('owners[output]={size=size,'))throw new Error('Session ownership anchors changed');
  template=template.replace(/input\.owner(==|~=)output/g,(_,op)=>'input.owner'+op+'state.ownerIdentity')
   .replace('input.owner,input.pending=output,token','input.owner,input.pending=state.ownerIdentity,token')
   .replace('owners[output]={size=size,','owners[output]={ownerIdentity={},size=size,')
   .replace('state.data=nil;state.size,state.cursor=0,0','state.data,state.ownerIdentity=nil,nil;state.size,state.cursor=0,0');
 }
 return closeOperationLifetime(template.replace(/__([A-Z_]+)__/g,(_,name)=>{
  if(!(name in replacements))throw new Error('Unknown object protocol template field '+name);
  return String(replacements[name]);
 }));
}
