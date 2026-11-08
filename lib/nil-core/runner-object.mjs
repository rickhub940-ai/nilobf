import luaparse from 'luaparse';
import {randomInt} from 'node:crypto';
import {randomRadix85Alphabet,encodeRadix85,quoteRadix85} from './radix85.mjs';

const options={luaVersion:'5.1',ranges:true,scope:true,comments:false,encodingMode:'pseudo-latin1'};
const keywords=new Set('and break do else elseif end false for function if in local nil not or repeat return then true until while pc'.split(' '));
const letters='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
function walk(node,visit){if(!node||typeof node!=='object')return;visit(node);for(const value of Object.values(node))if(Array.isArray(value))value.forEach(n=>walk(n,visit));else if(value&&typeof value==='object')walk(value,visit);}
function splice(source,start,end,edits){let result='',pos=start;for(const e of edits.filter(e=>e.start>=start&&e.end<=end).sort((a,b)=>a.start-b.start)){if(e.start<pos)throw new Error('Overlapping runner object edits');result+=source.slice(pos,e.start)+e.text;pos=e.end;}return result+source.slice(pos,end);}
function descendants(node,fn){for(const value of Object.values(node))if(Array.isArray(value))value.forEach(n=>{if(n&&typeof n==='object')fn(n);});else if(value&&typeof value==='object')fn(value);}

export function randomMethodKey(used){for(;;){const key=letters[randomInt(letters.length)]+letters[randomInt(letters.length)];if(!keywords.has(key)&&!used.has(key)){used.add(key);return key;}}}
export function randomNumericKey(used){const available=Array.from({length:128},(_,i)=>i).filter(n=>!used.has(n));if(!available.length)throw new RangeError('Runner numeric slots exhausted');const key=available[randomInt(available.length)];used.add(key);return key;}

// Only owned VM/frame schema fields are renamed. External host capabilities,
// standard libraries, user table keys and metamethod names retain their keys.
export function renameFrameFields(source,{usedFieldKeys}){
 const names=new Set('parameters upCount registers cells vararg tags constantData constantSeals constantDirectory constantStart constantLength cache consumerCache scalarCache instructionCount offsets recordLength recordDirectory recordStart directoryWidth directoryLimit operandWidths formats entryKey parent prototype cursor key history phase values openHistory window maskCache scratch workingMasks semantic reader8 reader16 reader32 readerSpan bank openBank raw stamp guard salt domains handlers masks inverse records patches encoded slot handler mutable sealKey permits span spanAvailable releaseSpan reloadSpan arithmetic operatorPatches zero pendingReceipt receiptActive receiptEpoch receipt pendingResult resultActive resultEpoch resultOwner result activation bytes offset read8 read32 length openSection ownerIdentity childOwner childEpoch'.split(' '));
 for(const name of ['up','operandBits','directoryBits','constantAddressBits','constantLengthBits','constantRecordBits','storage'])names.add(name);
 const ast=luaparse.parse(source,options),mapping=new Map(),edits=[];
 // This input is exclusively the generated runner, before binding renaming;
 // opaque user bytes never enter it. Infer the closed materializer contracts
 // from their owned local aliases as well as the frame schema. Keeping only
 // the historical frame list left transaction keys visible to pairs hooks.
 const ownedAliases=new Set(['state','input','operation']);
 walk(ast,n=>{
  if(n.base?.type!=='Identifier'||n.base.isLocal!==true||!ownedAliases.has(n.base.name))return;
  if(n.type==='MemberExpression'&&!n.identifier.name.startsWith('__'))names.add(n.identifier.name);
  if(n.type==='IndexExpression'&&n.index.type==='StringLiteral'&&!n.index.value.startsWith('__'))names.add(n.index.value);
 });
 walk(ast,n=>{
  if(n.type==='MemberExpression')usedFieldKeys.add(n.identifier.name);
  if(n.type==='TableKeyString')usedFieldKeys.add(n.key.name);
  if(n.type==='IndexExpression'&&n.index.type==='StringLiteral')usedFieldKeys.add(n.index.value);
 });
 const renamed=name=>{if(!mapping.has(name))mapping.set(name,randomMethodKey(usedFieldKeys));return mapping.get(name);};
 walk(ast,n=>{
  if(n.type==='MemberExpression'&&names.has(n.identifier.name)&&!(n.base.type==='Identifier'&&n.base.isLocal===false))edits.push({start:n.identifier.range[0],end:n.identifier.range[1],text:renamed(n.identifier.name)});
  if(n.type==='TableKeyString'&&names.has(n.key.name))edits.push({start:n.key.range[0],end:n.key.range[1],text:renamed(n.key.name)});
  if(n.type==='IndexExpression'&&n.index.type==='StringLiteral'&&names.has(n.index.value))edits.push({start:n.index.range[0],end:n.index.range[1],text:JSON.stringify(renamed(n.index.value))});
 });
 return splice(source,0,source.length,edits);
}

// Lower colon calls before moving functions or concealing member names. Keep
// the receiver evaluation single-valued/single-shot and preserve the final
// argument's multiple returns; replacing ':' with an index alone loses self.
export function normalizeRunnerMethods(source){
 const ast=luaparse.parse(source,options),used=new Set();walk(ast,n=>{if(n.type==='Identifier')used.add(n.name);});
 function fresh(){for(;;){const n='__r'+randomInt(0x1000000).toString(36);if(!used.has(n)){used.add(n);return n;}}}
 function visit(n){
  const nested=[];descendants(n,child=>nested.push(...visit(child)));
  if(['CallExpression','TableCallExpression','StringCallExpression'].includes(n.type)&&n.base?.type==='MemberExpression'&&n.base.indexer===':'){
   const receiver=fresh(),base=splice(source,...n.base.base.range,nested),args=n.type==='CallExpression'?n.arguments:n.type==='TableCallExpression'?[n.arguments]:[n.argument];
   const values=args.map(a=>splice(source,...a.range,nested));
   const text=`(function(${receiver},...)return ${receiver}["${n.base.identifier.name}"](${receiver},...)end)((${base})${values.length?','+values.join(','):''})`;
   return [{start:n.range[0],end:n.range[1],text}];
  }
  return nested;
 }
 return splice(source,0,source.length,visit(ast));
}

// Called after scope renaming: every local binding has a unique identifier.
// A helper may move only if its captured bindings are never reassigned.
// Captured tables/cells retain identity; mutable scalar captures remain in
// their original lexical scope. No native payload is inspected by this pass.
export function liftRunnerHelpers(source,{runKey,usedFieldKeys,minStatements=1,include=()=>true}){
 const ast=luaparse.parse(source,options),object=ast.body[0]?.arguments?.[0]?.arguments?.[0];
 if(object?.type!=='TableConstructorExpression')throw new Error('Runner object layout changed');
 const primary=object.fields.find(f=>f.type==='TableKey'&&f.key.value===runKey)?.value;
 if(primary?.type!=='FunctionDeclaration'||primary.parameters[0]?.type!=='Identifier')throw new Error('Runner entry layout changed');
 const declared=new Set(),mutable=new Set(),used=new Set();
 walk(ast,n=>{
  if(n.type==='Identifier')used.add(n.name);
  if(n.type==='LocalStatement')n.variables.forEach(v=>declared.add(v.name));
  if(n.type==='FunctionDeclaration'){n.parameters.filter(p=>p.type==='Identifier').forEach(p=>declared.add(p.name));if(n.isLocal)declared.add(n.identifier.name);}
  if(n.type==='AssignmentStatement')n.variables.filter(v=>v.type==='Identifier').forEach(v=>mutable.add(v.name));
  if(n.type==='ForNumericStatement'){declared.add(n.variable.name);mutable.add(n.variable.name);}
  if(n.type==='ForGenericStatement')n.variables.forEach(v=>{declared.add(v.name);mutable.add(v.name);});
 });
 function fresh(){for(;;){const n='__o'+randomInt(0x1000000).toString(36);if(!used.has(n)){used.add(n);return n;}}}
 function captures(fn){const own=new Set(fn.parameters.filter(p=>p.type==='Identifier').map(p=>p.name)),refs=new Set();for(const node of fn.body)walk(node,n=>{
  if(n.type==='LocalStatement')n.variables.forEach(v=>own.add(v.name));
  if(n.type==='FunctionDeclaration'){n.parameters.filter(p=>p.type==='Identifier').forEach(p=>own.add(p.name));if(n.isLocal)own.add(n.identifier.name);}
  if(n.type==='ForNumericStatement')own.add(n.variable.name);
  if(n.type==='ForGenericStatement')n.variables.forEach(v=>own.add(v.name));
  if(n.type==='Identifier'&&n.isLocal===true)refs.add(n.name);
 });return [...refs].filter(name=>declared.has(name)&&!own.has(name));}
 const fields=[],stats={lifted:0,keptMutableCaptures:0};
 function transform(fn,parentObject){
  const cap=captures(fn),eligible=include(fn)&&fn.body.length>=minStatements&&(!fn.identifier||fn.isLocal)&&cap.every(n=>!mutable.has(n))&&!cap.includes(fn.identifier?.name)&&fn.parameters.length+cap.length<28;
  const self=eligible?fresh():parentObject,nested=[];
  function visit(n){if(n.type==='FunctionDeclaration'){nested.push(transform(n,self));return;}descendants(n,visit);}
  fn.body.forEach(n=>{if(n.type==='FunctionDeclaration')nested.push(transform(n,self));else descendants(n,visit);});
  if(!eligible){if(cap.some(n=>mutable.has(n)))stats.keptMutableCaptures++;return {start:fn.range[0],end:fn.range[1],text:splice(source,...fn.range,nested)};}
  const key=randomMethodKey(usedFieldKeys),params=fn.parameters.map(p=>p.type==='Identifier'?p.name:'...');
  const body=fn.body.length?splice(source,fn.body[0].range[0],fn.body.at(-1).range[1],nested):'';
  fields.push(`${key}=function(${[self,...cap,...params].join(',')})${body}\nend`);
  const call=`return ${parentObject}["${key}"](${[parentObject,...cap,...params].join(',')})`;
  const header=fn.isLocal?`local function ${fn.identifier.name}`:'function';
  stats.lifted++;return {start:fn.range[0],end:fn.range[1],text:`${header}(${params.join(',')})${call} end`};
 }
 const edits=[];function start(n){if(n.type==='FunctionDeclaration'){edits.push(transform(n,primary.parameters[0].name));return;}descendants(n,start);}primary.body.forEach(n=>{if(n.type==='FunctionDeclaration')edits.push(transform(n,primary.parameters[0].name));else descendants(n,start);});
 const rewritten=splice(source,0,source.length,edits),delta=rewritten.length-source.length;
 const insert=object.range[1]-1+delta;
 return {source:rewritten.slice(0,insert)+','+fields.join(',')+rewritten.slice(insert),stats};
}

// Cache standard host primitives in numeric object slots, like the reference
// VM tables. Dynamic environment bindings/loaders are deliberately left live.
export function poolRunnerPrimitives(source,{usedFieldKeys}){
 const ast=luaparse.parse(source,options),object=ast.body[0]?.arguments?.[0]?.arguments?.[0];
 if(object?.type!=='TableConstructorExpression')throw new Error('Runner object layout changed');
 const safe=new Set('string table math error type tonumber tostring select unpack pairs ipairs next rawget rawset setmetatable getmetatable pcall xpcall getfenv setfenv'.split(' '));
 const slots=new Map(),fields=[],edits=[];
 function slot(code){if(slots.has(code))return slots.get(code);const key=randomNumericKey(usedFieldKeys);slots.set(code,key);fields.push(`[${key}]=${code}`);return key;}
 function visit(n,self){
  const simple=n.type==='MemberExpression'||(n.type==='IndexExpression'&&n.index.type==='StringLiteral');
  if(simple&&n.base.type==='Identifier'&&n.base.isLocal===false&&safe.has(n.base.name)){
   const key=n.type==='MemberExpression'?n.identifier.name:n.index.value;
   if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)){edits.push({start:n.range[0],end:n.range[1],text:`${self}[${slot(n.base.name+'.'+key)}]`});return;}
  }
  if(n.type==='Identifier'&&n.isLocal===false&&safe.has(n.name)){edits.push({start:n.range[0],end:n.range[1],text:`${self}[${slot(n.name)}]`});return;}
  descendants(n,child=>visit(child,self));
 }
 for(const field of object.fields)if(field.value?.type==='FunctionDeclaration'){
  const fn=field.value,self=fn.parameters[0];if(self?.type!=='Identifier')throw new Error('Object function requires a receiver');
  fn.body.forEach(n=>visit(n,self.name));
 }
 if(!fields.length)return {source,stats:{primitives:0}};
 const rewritten=splice(source,0,source.length,edits),delta=rewritten.length-source.length,insert=object.range[1]-1+delta;
 return {source:rewritten.slice(0,insert)+','+fields.join(',')+rewritten.slice(insert),stats:{primitives:fields.length}};
}

export function concealRunnerStrings(source,{usedFieldKeys,alphabet85=randomRadix85Alphabet(),denseMetadata=false}){
 if(typeof denseMetadata!=='boolean')throw new TypeError('Invalid pool directory mode');
 const ast=luaparse.parse(source,options),object=ast.body[0]?.arguments?.[0]?.arguments?.[0],edits=[];
 if(object?.type!=='TableConstructorExpression')throw new Error('Runner object layout changed');
 const reader=randomMethodKey(usedFieldKeys),storage=randomNumericKey(usedFieldKeys),strings=[],ids=new Map();
 function reference(value,self){
  if(value===alphabet85)return quoteRadix85(value);
  if(value.length<=2&&/^[\x20-\x7e]*$/.test(value))return JSON.stringify(value);
  if(!self)throw new Error('Unbound runner string pool access');
  if(!ids.has(value)){ids.set(value,strings.length+1);strings.push(value);}
  return `${self}.${reader}(${self},${ids.get(value)})`;
 }
 function visit(n,self){
  if(n.type==='StringLiteral'){edits.push({start:n.range[0],end:n.range[1],text:reference(n.value,self)});return;}
  if(n.type==='MemberExpression'&&n.identifier.name.length>2&&!n.identifier.name.startsWith('__')&&n.indexer!==':'&&!(n.base.type==='Identifier'&&n.base.isLocal===false)){
   visit(n.base,self);edits.push({start:n.base.range[1],end:n.range[1],text:'['+reference(n.identifier.name,self)+']'});return;
  }
  if(n.type==='TableKeyString'&&n.key.name.length>2&&!n.key.name.startsWith('__')&&!usedFieldKeys.has(n.key.name)){
   edits.push({start:n.key.range[0],end:n.key.range[1],text:'['+reference(n.key.name,self)+']'});visit(n.value,self);return;
  }
  descendants(n,child=>visit(child,self));
 }
 for(const field of object.fields){if(field.value?.type==='FunctionDeclaration')field.value.body.forEach(n=>visit(n,field.value.parameters[0].name));else visit(field.value,null);}
 if(!strings.length)return splice(source,0,source.length,edits);
 if(strings.length>65535||strings.some(value=>value.length>65535))throw new RangeError('Runner string pool limit exceeded');
 const mask=randomInt(1,256),header=Buffer.alloc(2+strings.length*2);header.writeUInt16LE(strings.length);
 strings.forEach((value,i)=>header.writeUInt16LE(value.length,2+i*2));
 const bytes=Buffer.concat([header,Buffer.from(strings.join(''),'latin1')]);
 for(let i=0;i<bytes.length;i++)bytes[i]=(bytes[i]+mask+(i%251))%256;
 // Decode once per object and cache each exact string. The host reader never
 // touches native payloads or modifies their byte representation.
 const fields=`[${storage}]={${quoteRadix85(encodeRadix85(bytes,alphabet85))},{},{},false},${reader}=function(object,index)
 local pool=object[${storage}];local cached=pool[3][index];if cached then return cached end
 if not pool[4] then
  local alphabet=${quoteRadix85(alphabet85)};local lookup={};for i=1,85 do lookup[string.byte(alphabet,i)]=i-1 end
  local parts={};local position=0;for i=1,#pool[1],5 do
   local value=0;for j=0,4 do value=value*85+lookup[string.byte(pool[1],i+j)] end
   for j=3,0,-1 do local byte=math.floor(value/256^j)%256;parts[#parts+1]=string.char((byte-${mask}-(position%251))%256);position=position+1 end
  end
  pool[4]=table.concat(parts);pool[1]=false
  local count=string.byte(pool[4],1)+string.byte(pool[4],2)*256;local offset=3+count*2
  for i=1,count do local size=string.byte(pool[4],i*2+1)+string.byte(pool[4],i*2+2)*256;pool[2][i]=${denseMetadata?'offset':'{offset,size}'};offset=offset+size end${denseMetadata?';pool[2][count+1]=offset':''}
 end
 ${denseMetadata?'local start=pool[2][index];cached=string.sub(pool[4],start,pool[2][index+1]-1)':'local range=pool[2][index];cached=string.sub(pool[4],range[1],range[1]+range[2]-1)'};pool[3][index]=cached;return cached end`;
 const rewritten=splice(source,0,source.length,edits),insert=object.range[1]-1+rewritten.length-source.length;
 return rewritten.slice(0,insert)+','+fields+rewritten.slice(insert);
}

export function shuffleRunnerFields(source){
 const ast=luaparse.parse(source,options),object=ast.body[0]?.arguments?.[0]?.arguments?.[0];
 if(object?.type!=='TableConstructorExpression')throw new Error('Runner object layout changed');
 const fields=[...object.fields];for(let i=fields.length-1;i>0;i--){const j=randomInt(i+1);[fields[i],fields[j]]=[fields[j],fields[i]];}
 const first=fields.findIndex(f=>f.value?.type==='FunctionDeclaration');if(first<0)throw new Error('Runner object has no functions');[fields[0],fields[first]]=[fields[first],fields[0]];
 return source.slice(0,object.range[0]+1)+fields.map(f=>source.slice(...f.range)).join(',')+source.slice(object.range[1]-1);
}
