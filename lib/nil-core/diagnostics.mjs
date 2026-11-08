import {randomBytes} from 'node:crypto';
import luaparse from 'luaparse';

// This pass sees only our generated runner, before identifiers are renamed.
// Compiler diagnostics may contain payload snippets or internal entry names.
// Keep those inside the compiler boundary; errors from executing user code
// remain untouched. Development output retains the original compiler detail.
function protectCompilerBoundary(source){
 const ast=luaparse.parse(source,{luaVersion:'5.1',ranges:true,encodingMode:'pseudo-latin1'}),edits=[];let compilerCalls=0,compilerErrors=0;
 function walk(node){
  if(!node||typeof node!=='object')return;
  if(node.type==='LocalStatement'&&node.variables.length===2&&node.init.length===1){
   const call=node.init[0];
   if(call.type==='CallExpression'&&call.base.type==='Identifier'&&call.base.name==='loader'){
    compilerCalls++;
    const [fn,err]=node.variables.map(v=>v.name),args=call.arguments.map(a=>source.slice(...a.range)).join(',');
    // Luau has yieldable pcall. Lua 5.1 needs a small resume/yield relay so
    // protecting compiler failures does not break interleaved compilation.
    const protectedCall=`local function __stProtectedCompile(fn,...)
 if type(coroutine.isyieldable)=='function' or _VERSION~='Lua 5.1' then return pcall(fn,...)end
 local unpackValues=table.unpack or unpack
 local function packValues(...)return {n=select('#',...),...}end
 local args=packValues(...)
 local worker=coroutine.create(function()return fn(unpackValues(args,1,args.n))end)
 local result=packValues(coroutine.resume(worker))
 while result[1] and coroutine.status(worker)~='dead' do
  if not coroutine.running()then return false,nil end
  result=packValues(coroutine.resume(worker,coroutine.yield(unpackValues(result,2,result.n))))
 end
 return unpackValues(result,1,result.n)
end`;
    edits.push({range:node.range,text:`${protectedCall};local __stCompilerOk,${fn},${err}=__stProtectedCompile(loader,${args});if not __stCompilerOk then ${err}=${fn};${fn}=nil end`});
   }
  }
  if(node.type==='CallExpression'&&node.base.type==='Identifier'&&node.base.name==='error'){
   const arg=node.arguments[0];
   if(arg?.type==='LogicalExpression'&&arg.operator==='or'&&arg.right.type==='StringLiteral'&&arg.right.value==='Nil opaque compile failed'){compilerErrors++;edits.push({range:arg.range,text:"'Nil opaque compile failed'"});}
  }
  for(const v of Object.values(node))if(Array.isArray(v))v.forEach(walk);else if(v&&typeof v==='object')walk(v);
 }
 walk(ast);
 if(compilerCalls!==compilerErrors)throw new Error('Native compiler boundary shape changed');
 for(const edit of edits.sort((a,b)=>b.range[0]-a.range[0]))source=source.slice(0,edit.range[0])+edit.text+source.slice(edit.range[1]);
 return source;
}

// Only generated wrapper literals pass here. Native bytes and user errors do not.
export function concealInternalDiagnostics(source,onDiagnostics){
 const messages=new Map(),used=new Set();
 const rendered=protectCompilerBoundary(source).replace(/(['"])(Nil [^'"\r\n]*)\1/g,(_,quote,message)=>{
  let code=messages.get(message);
  if(!code){do{code='0x'+randomBytes(6).toString('hex');}while(used.has(code));used.add(code);messages.set(message,code);}
  return quote+code+quote;
 });
 if(onDiagnostics)onDiagnostics(Object.freeze(Object.fromEntries([...messages].map(([message,code])=>[code,message]))));
 return rendered;
}
