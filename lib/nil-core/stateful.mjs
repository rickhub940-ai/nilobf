import {randomBytes,randomInt} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {OP,OPERAND_ROLES,LIMITS} from './opcodes.mjs';

const modulus=4294967296,schemas=new WeakMap();
function validMixProfile(p){return p&&[0,1,2].includes(p.family)&&Number.isInteger(p.multiplier)&&p.multiplier>=17&&p.multiplier<=65535&&p.multiplier%2===1&&Number.isInteger(p.gain)&&p.gain>=17&&p.gain<=65535&&Number.isInteger(p.shift)&&p.shift>=8&&p.shift<=20;}
export function stateMix(a,b,profile){
 const base=profile.family===0?(a+b)%modulus:profile.family===1?(a*3+b)%modulus:(a+5*b)%modulus;
 const side=profile.family===0?a:profile.family===1?b:(a+b)%modulus;
 return (base*profile.multiplier+Math.floor(side/2**profile.shift)*profile.gain)%modulus;
}
const word=n=>{const b=Buffer.alloc(4);b.writeUInt32LE(n);return b;};
const nonce=()=>randomInt(1,modulus);
function uniqueKeys(count){const used=new Set();while(used.size<count)used.add(nonce());return [...used];}
function successors(row,pc,size){
 const op=row[0];if(op===OP.RETURN||op===OP.TAILCALL)return [];
 if(op===OP.JUMP)return [row[1]];if(op===OP.FORNEXT)return [row[3]];
 const out=[pc+5];if([OP.JF,OP.JT,OP.JNIL].includes(op))out.push(row[2]);if(op===OP.FORCHECK)out.push(row[4]);
 return [...new Set(out)].filter(n=>n>=1&&n<=size&&n%5===1);
}
function byteMask(key,index){return (Math.floor(key/256**((index-1)%4))+(index%251)*17)%256;}
export function statefulProgram(program){
 if(program?.version!==3)throw new TypeError('Stateful lowering expects v3');
 return {...program,version:4,prototypes:program.prototypes.map(p=>({...p,layout:{keys:uniqueKeys(p.code.length),constantKeys:uniqueKeys(p.constants.length)}}))};
}
export function statefulSchema(blob){return schemas.get(blob);}
export function serializeStateful(program,{opcodeMap,lazyPrototypes=true,mixProfile}={}){
 if(typeof lazyPrototypes!=='boolean'||program?.version!==4||!Array.isArray(program.prototypes)||program.prototypes.length<1||program.prototypes.length>LIMITS.prototypes)throw new TypeError('Invalid stateful program');
 const signature=randomBytes(randomInt(16,33)),profile=mixProfile??{family:randomInt(3),multiplier:randomInt(8,32768)*2+1,gain:randomInt(17,65536),shift:randomInt(8,21)};
 if(!validMixProfile(profile))throw new TypeError('Invalid stateful mix profile');
 const schema=Object.freeze({version:4,signature:signature.toString('hex'),lazyPrototypes,...profile}),mix=(a,b)=>stateMix(a,b,profile),mask=(key,slot)=>mix(key,slot*65537);
 const guard=(key,values)=>{let g=key;for(const value of values)g=mix(g,value);return g;};
 const parts=[signature,word(program.prototypes.length),word(program.root)];let current=parts,total=signature.length+8;
 function push(bytes){total+=bytes.length;if(total>LIMITS.blobBytes)throw new RangeError('Stateful bytecode size limit exceeded');current.push(bytes);}
 function u32(value){if(!Number.isInteger(value)||value<0||value>=modulus)throw new RangeError('Stateful operand out of range');push(word(value));}
 function u8(value){if(!Number.isInteger(value)||value<0||value>255)throw new RangeError('Stateful byte out of range');push(Buffer.from([value]));}
 function bytes(b){u32(b.length);push(b);}
 if(lazyPrototypes){if(!program.prototypes[program.root-1]?.layout?.keys[0])throw new TypeError('Invalid stateful entry');u32(program.prototypes[program.root-1].layout.keys[0]);}
 for(const [prototypeIndex,p] of program.prototypes.entries()){
  if(lazyPrototypes)current=[];
  const layout=p.layout;if(!layout||layout.keys.length!==p.code.length||layout.constantKeys.length!==p.constants.length||layout.keys.some(k=>!Number.isInteger(k)||k<1||k>=modulus)||layout.constantKeys.some(k=>!Number.isInteger(k)||k<1||k>=modulus))throw new TypeError('Invalid stateful layout');
  u32(p.parent);u32(p.parameters);u8(p.vararg?1:0);u32(p.registers);u32(p.cells);u32(p.upvalues.length);
  for(const [kind,slot]of p.upvalues){u8(kind);u32(slot);}
  u32(layout.keys[0]);u32(p.constants.length);
  for(const [i,value]of p.constants.entries()){
   const tag=value===null?0:value===false?1:value===true?2:typeof value==='number'?3:typeof value==='string'?4:-1;u8(tag);
   if(tag>=3){const raw=Buffer.from(tag===3?String(value):value,'latin1'),key=layout.constantKeys[i];const encoded=Buffer.from(raw);for(let j=0;j<raw.length;j++)encoded[j]=(raw[j]+byteMask(key,j+1))%256;u32(guard(key,[tag,...raw]));bytes(encoded);}
  }
  u32(p.code.length);
  for(const [i,row]of p.code.entries()){
   if(!Array.isArray(row)||row.length!==5||!OPERAND_ROLES[row[0]-1])throw new TypeError('Invalid stateful instruction');
   const [op,...operands]=row;if(operands.some(n=>!Number.isInteger(n)||n<0||n>=modulus))throw new RangeError('Stateful operand out of range');
   const key=layout.keys[i],mapped=opcodeMap?opcodeMap[op]:op,rotate=key%4,reverse=Math.floor(key/4)%2,stored=Array(4);
   if(!Number.isInteger(mapped)||mapped<1||mapped>255)throw new RangeError('Invalid stateful opcode map');
   operands.forEach((v,j)=>{const slot=(rotate+(reverse?3-j:j))%4;stored[slot]=(v+mask(key,j+1))%modulus;});
   const slots=OPERAND_ROLES[op-1].flatMap((role,j)=>role==='k'||role==='g'?[operands[j]]:[]);
   const ck=[slots[0]?layout.constantKeys[slots[0]-1]:0,slots[1]?layout.constantKeys[slots[1]-1]:0];if(ck.some(k=>k===undefined))throw new RangeError('Invalid constant operand');
   if(lazyPrototypes&&op===OP.CLOSURE){const child=program.prototypes[operands[1]-1];if(!child||child.parent!==prototypeIndex+1)throw new RangeError('Invalid child prototype');ck[0]=child.layout.keys[0];}
   const next=successors(row,i*5+1,p.code.length*5);if(![OP.RETURN,OP.TAILCALL].includes(op)&&next.length===0)throw new RangeError('Missing stateful successor');
   const semantic=guard(key,[mapped,...operands,...ck]);
   const edges=[0,0];next.forEach((pc,j)=>{edges[j]=(layout.keys[(pc-1)/5]+mask(semantic,pc))%modulus;});
   const values=[...operands,...ck,...edges],stamp=guard(key,[mapped,...values]);
   const odd=2*(key%128)+1,add=Math.floor(key/128)%256;
   const data=Buffer.concat([Buffer.from([(mapped*odd+add)%256]),...stored.map(word),...ck.map((n,j)=>word((n+mask(key,j+5))%modulus)),...edges.map((n,j)=>word((n+mask(key,j+7))%modulus)),word((stamp+mask(key,9))%modulus),randomBytes(randomInt(0,8))]);
   u8(data.length);push(data);
  }
  if(lazyPrototypes){const raw=Buffer.concat(current),key=layout.keys[0],encoded=Buffer.from(raw);for(let j=0;j<raw.length;j++)encoded[j]=(raw[j]+byteMask(key,j+1))%256;current=parts;u32(p.parent);u32(encoded.length);parts.push(encoded);}
 }
 const blob=Buffer.concat(parts,total);schemas.set(blob,schema);return blob;
}

// Reuse the semantic instruction bodies while replacing their read/validate/
// transition contract. Native chunks never pass through this transformation.
export function statefulRuntime(schema,{inline=false}={}){
 if(schema?.version!==4||!/^[a-f0-9]{32,64}$/.test(schema.signature)||!validMixProfile(schema))throw new TypeError('Missing stateful delivery schema');
 const source=readFileSync(new URL('./runtime.lua',import.meta.url),'utf8'),start=source.indexOf('if op == 1 then'),end=source.indexOf('else invalid() end',start);
 const headers=[...source.slice(start,end).matchAll(/\b(?:if|elseif) op == (\d+) then/g)],body=source.slice(start,end);
 const checks=(op)=>OPERAND_ROLES[op-1].map((role,i)=>{const v=['a','b','c','d'][i];return `${v}<1 or ${role==='r'?v+'>frame.prototype.registers':role==='l'?v+'>frame.prototype.cells':role==='u'?v+'>frame.prototype.upCount':role==='k'||role==='g'?v+'>frame.prototype.constantCount'+(role==='g'?` or frame.prototype.tags[${v}]~=4`:''):role==='j'?v+'>frame.prototype.instructionCount*5 or '+v+'%5~=1':role==='p'?(schema.lazyPrototypes?v+'>count or sections['+v+'][1]~=frame.id':v+'>#prototypes or prototypes['+v+'].parent~=frame.id'):v+'>'+({i:100000,a:3,b:13}[role])}`;}).concat(Array.from({length:4-OPERAND_ROLES[op-1].length},(_,j)=>['a','b','c','d'][j+OPERAND_ROLES[op-1].length]+'~=0')).join(' or ');
 const dispatch=headers.map((h,i)=>`${i?'elseif':'if'} op == ${h[1]} then\nif ${checks(+h[1])}${+h[1]===18?' or not frame.prototype.vararg':''} then invalid()end\n`+body.slice(h.index+h[0].length,headers[i+1]?.index??body.length).replace(/constants\[b\]/g,'constant(frame,b,1)').replace(/constants\[d\]/g,'constant(frame,d,2)').replace('local child, captured = prototypes[b], {}',()=>schema.lazyPrototypes?'local child, captured = openPrototype(b,frame.values[5]), {}':'local child, captured = prototypes[b], {}')).join('')+'else invalid() end';
 const template=readFileSync(new URL('./runtime-v4.lua',import.meta.url),'utf8');
 const signature='"'+Buffer.from(schema.signature,'hex').toJSON().data.map(n=>'\\'+String(n).padStart(3,'0')).join('')+'"';
 const base=schema.family===0?'(a+b)':schema.family===1?'(a*3+b)':'(a+5*b)',side=schema.family===0?'a':schema.family===1?'b':'((a+b)%modulus)';
 const mixing=`return (${base}%modulus*${schema.multiplier}+floor(${side}/${2**schema.shift})*${schema.gain})%modulus`;
 // Slots 1..9 are fixed internal mask inputs. Share their common arithmetic
 // instead of invoking the generic mixer nine times. Exact under doubles:
 // even the largest family-1 product stays below 2^53. This does not change
 // serialized bytes or any state/key dependency.
 function masks(key,target){
  const prefix=schema.family===0?`local maskBase=(${key}*${schema.multiplier}+floor(${key}/${2**schema.shift})*${schema.gain})%modulus;`:schema.family===1?`local maskBase=(${key}*${3*schema.multiplier})%modulus;`:`local maskBase=(${key}*${schema.multiplier})%modulus;`;
  return prefix+Array.from({length:9},(_,i)=>{
   const slot=(i+1)*65537;
   const offset=schema.family===0?slot*schema.multiplier:schema.family===1?slot*schema.multiplier+Math.floor(slot/2**schema.shift)*schema.gain:5*slot*schema.multiplier;
   const dynamic=schema.family===2?`+floor((${key}+${slot})%modulus/${2**schema.shift})*${schema.gain}`:'';
   return `${target}[${i+1}]=(maskBase+${offset%modulus}${dynamic})%modulus;`;
  }).join('');
 }
 let output=template.replace('__SIGNATURE__',()=>signature).replace('__MIX__',()=>mixing).replace('__DISPATCH__',()=>dispatch).replace('__CODE_MASKS__',()=>masks('key','codeMasks')).replace('__WORKING_MASKS__',()=>masks('active','masks'));
 if(schema.lazyPrototypes){
  const begin=output.indexOf(' local count,entry=u32(),u32()'),end=output.indexOf(' local function constant(frame,slot,keyIndex)',begin);
  if(begin<0||end<begin)throw new Error('Stateful prototype reader anchors changed');
  const reader=readFileSync(new URL('./lazy-prototypes.lua',import.meta.url),'utf8');
  output=output.slice(0,begin)+reader+'\n'+output.slice(end);
  output=output.replace('local r=p.constantData[slot];','local read8=p.reader8;local r=p.constantData[slot];').replace('local offset=frame.prototype.offsets[frame.cursor];','local read8,read32=frame.prototype.reader8,frame.prototype.reader32;local offset=frame.prototype.offsets[frame.cursor];');
 }
 if(inline){
  const openHeader=' local function open(frame)\n',commitHeader=' local function commit(frame,op,a,b,c,d,nextPc,registers)\n',budgetHeader=' local remaining, make = maxSteps, nil';
  const start=output.indexOf(openHeader),middle=output.indexOf(commitHeader,start),finish=output.indexOf(budgetHeader,middle);
  if(start<0||middle<start||finish<middle)throw new Error('Stateful hot path anchors changed');
  const openBody=output.slice(start+openHeader.length,middle).replace(/\n end\n$/,'').replace('return op,values[1],values[2],values[3],values[4]','decodedOp,decodedA,decodedB,decodedC,decodedD=op,values[1],values[2],values[3],values[4]');
  const commitBody=output.slice(middle+commitHeader.length,finish).replace(/\n end\n$/,'').replace(/\bnextPc\b/g,'pc');
  output=output.slice(0,start)+output.slice(finish);
  const entry='local op,a,b,c,d=open(frame);pc=pc+5',exit='commit(frame,op,a,b,c,d,pc,registers)';
  if(output.split(entry).length!==2||output.split(exit).length!==2)throw new Error('Stateful loop anchors changed');
  output=output.replace(entry,()=>`local decodedOp,decodedA,decodedB,decodedC,decodedD;do\n${openBody}\nend;local op,a,b,c,d=decodedOp,decodedA,decodedB,decodedC,decodedD;pc=pc+5`).replace(exit,()=>`do\n${commitBody}\nend`);
 }
 return output;
}
