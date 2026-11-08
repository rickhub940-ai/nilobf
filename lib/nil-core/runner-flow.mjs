import luaparse from 'luaparse';
import { randomInt } from 'node:crypto';

const parseOptions={luaVersion:'5.1',ranges:true,comments:false,encodingMode:'pseudo-latin1'};
function children(node,visit){for(const value of Object.values(node))if(Array.isArray(value))value.forEach(n=>{if(n&&typeof n==='object')visit(n);});else if(value&&typeof value==='object')visit(value);}
function splice(source,start,end,edits){let pos=start,result='';for(const edit of edits.filter(e=>e.start>=start&&e.end<=end).sort((a,b)=>a.start-b.start)){result+=source.slice(pos,edit.start)+edit.text;pos=edit.end;}return result+source.slice(pos,end);}

// Operates on the generated, scope-renamed host runner only. Hoisted names are
// already unique, so moving declarations does not capture earlier references.
// Loop bodies keep their own declarations/cells and iteration semantics.
export function flattenRunnerFunctions(source,{include=()=>true}={}){
 const ast=luaparse.parse(source,parseOptions),used=new Set();
 function names(n){if(n.type==='Identifier')used.add(n.name);children(n,names);}names(ast);
 function fresh(){for(;;){const name='_'+randomInt(0x1000000).toString(36);if(!used.has(name)){used.add(name);return name;}}}
 const stats={functions:0,blocks:0};
 function descendants(node){const edits=[];function walk(n){if(n.type==='FunctionDeclaration'){edits.push(transform(n));return;}children(n,walk);}children(node,walk);return edits;}
 function transform(node){
  const nested=descendants(node),start=node.range[0],end=node.range[1];
  if(node.body.length<3||!include(node))return {start,end,text:splice(source,start,end,nested)};
  const hoisted=[],statements=[];
  for(const statement of node.body){
   if(statement.type==='LocalStatement'){
    hoisted.push(...statement.variables.map(v=>v.name));
    const values=statement.init.length?splice(source,statement.init[0].range[0],statement.init.at(-1).range[1],nested):statement.variables.map(()=> 'nil').join(',');
    statements.push({text:statement.variables.map(v=>v.name).join(',')+'='+values,returns:false});
   }else if(statement.type==='FunctionDeclaration'&&statement.isLocal){
    hoisted.push(statement.identifier.name);
    const edit=nested.find(e=>e.start===statement.range[0]);
    const text=edit?.text??source.slice(...statement.range);
    statements.push({text:text.replace(/^local\s+function\s+[A-Za-z_][A-Za-z0-9_]*/,statement.identifier.name+'=function'),returns:false});
   }else statements.push({text:splice(source,...statement.range,nested),returns:statement.type==='ReturnStatement'});
  }
  const groups=[];for(let i=0;i<statements.length;){const length=randomInt(1,4);groups.push(statements.slice(i,i+length));i+=length;}
  const states=new Set(),stateRange=Math.max(256,groups.length*4+1);function state(){let n;do{n=randomInt(1,stateRange);}while(states.has(n));states.add(n);return n;}
  const exit=state(),pc=fresh(),blocks=groups.map(group=>({id:state(),group}));
  for(let i=0;i<blocks.length;i++){const block=blocks[i];block.text=block.group.map(s=>s.text+';').join('');if(!block.group.at(-1).returns)block.text+=pc+'='+(blocks[i+1]?.id??exit)+';';}
  // Shuffle physical placement independently from execution order. A balanced
  // comparison tree selects blocks without a linear switch on ordinal states.
  function tree(items){if(items.length===1)return items[0].text;const pivot=items[Math.floor(items.length/2)].id;const lower=items.filter(b=>b.id<pivot),upper=items.filter(b=>b.id>=pivot);const invert=randomInt(2);return invert?`if ${pc}>=${pivot} then ${tree(upper)}else ${tree(lower)}end;`:`if ${pc}<${pivot} then ${tree(lower)}else ${tree(upper)}end;`;}
  // Sorting partitions keeps the tree balanced; branch polarity randomizes the
  // emitted order, so ordinal fallthrough is absent from the output.
  const body=(hoisted.length?'local '+hoisted.join(',')+';':'')+'local '+pc+'='+blocks[0].id+';while '+pc+'~='+exit+' do '+tree([...blocks].sort((a,b)=>a.id-b.id))+'end;';
  stats.functions++;stats.blocks+=blocks.length;
  const bodyStart=node.body[0].range[0],bodyEnd=node.body.at(-1).range[1];
  return {start,end,text:source.slice(start,bodyStart)+body+source.slice(bodyEnd,end)};
 }
 const edits=[];function root(n){if(n.type==='FunctionDeclaration'){edits.push(transform(n));return;}children(n,root);}root(ast);
 return {source:splice(source,0,source.length,edits),stats};
}

// Re-lex instead of deleting whitespace blindly: numeric literals next to '..'
// and '-' next to '-' need separators, as do adjacent names/keywords.
export function compactRunnerTokens(source,{hexNumbers=false}={}){
 const lexer=luaparse.parse(source,{...parseOptions,wait:true});const parts=[];let previous='';
 const joinedOperators=new Set(['--','..','//','==','~=','<=','>=','::','...','[[',']]']);
 for(;;){const token=lexer.lex();if(token.type===1)break;let text=source.slice(...token.range);
  // Lua 5.1 builds on Windows may parse hex through 32-bit strtoul. Keep
  // larger decimal integers unchanged rather than silently saturating them.
  if(hexNumbers&&token.type===16&&/^\d+$/.test(text)&&Number(text)<=0x7fffffff)text='0x'+Number(text).toString(16);
  if(previous){const a=previous.at(-1),b=text[0];if((/[\w]/.test(a)&&/[\w]/.test(b))||(/[\d.]/.test(a)&&b==='.')||(a==='.'&&/\d/.test(b))||joinedOperators.has(a+b))parts.push(' ');}
  parts.push(text);previous=text;
 }
 return parts.join('');
}
