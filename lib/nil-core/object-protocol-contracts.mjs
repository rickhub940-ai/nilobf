import luaparse from 'luaparse';

// Restricted proof for compiler-owned prepare/apply/commit corridors. This is
// not whole-program alias analysis and does not inspect opaque source bytes.
export function validateObjectProtocolContracts(source,protocol,expected){
 const ast=luaparse.parse(source,{luaVersion:'5.1'}),contracts=[];
 const same=(node,name)=>node?.type==='Identifier'&&node.name===name;
 const oneCall=statement=>statement?.init?.length===1&&statement.init[0].type==='CallExpression'?statement.init[0]:null;
 const method=call=>call?.base?.type==='IndexExpression'&&same(call.base.base,'output')&&call.base.index.type==='NumericLiteral'?call.base.index.value:null;
 const walk=(node,visit)=>{
  if(!node||typeof node!=='object')return;
  visit(node);
  for(const value of Object.values(node)){
   if(Array.isArray(value)){for(const child of value)walk(child,visit);}
   else if(value&&typeof value==='object')walk(value,visit);
  }
 };
 for(const fn of ast.body.filter(node=>node.type==='FunctionDeclaration')){
  let count=0;
  walk(fn,node=>{
   if(node.type!=='WhileStatement')return;
   const found=node.body.flatMap((statement,index)=>method(oneCall(statement))===protocol.methods.prepare?[index]:[]);
   for(const index of found){
    const prepare=node.body[index],apply=node.body[index+1],commit=node.body[index+2];
    const a=oneCall(prepare),b=oneCall(apply),c=oneCall(commit);
    if(prepare.type!=='LocalStatement'||prepare.variables.length!==2||!same(prepare.variables[0],'nextSeed')||!same(prepare.variables[1],'transaction')||a.arguments.length!==9||!same(a.arguments[0],'output')||!same(a.arguments[1],'source'))throw new TypeError('Invalid object prepare contract');
    if(apply?.type!=='LocalStatement'||apply.variables.length!==1||!same(apply.variables[0],'receipt')||method(b)!==protocol.methods.apply||b.arguments.length!==2||!same(b.arguments[0],'output')||!same(b.arguments[1],'transaction'))throw new TypeError('Invalid object apply contract');
    if(commit?.type!=='LocalStatement'||commit.variables.length!==(protocol.wordFeedback?3:2)||!same(commit.variables[0],'sum')||!same(commit.variables[1],'weighted')||protocol.wordFeedback&&!same(commit.variables[2],'nextSeed')||method(c)!==protocol.methods.commit||c.arguments.length!==2||!same(c.arguments[0],'output')||!same(c.arguments[1],'receipt'))throw new TypeError('Invalid object commit contract');
    // These tokens have one producer and one consumer in the whole materializer
    // function; no reference may escape into a cell, callback or another call.
    for(const name of ['transaction','receipt']){let references=0;walk(fn,n=>{if(same(n,name))references++;});if(references!==2)throw new TypeError('Object protocol token escapes its corridor');}
    contracts.push(Object.freeze({prototype:fn.identifier.name,prepare:index,apply:index+1,commit:index+2,tokenUses:1,receiptUses:1}));count++;
   }
  });
  if(count!==1)throw new TypeError('Object materializer requires one transaction corridor');
 }
 if(contracts.length!==expected)throw new TypeError('Missing object materializer contracts');
 return Object.freeze(contracts);
}
