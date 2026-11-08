import luaparse from 'luaparse';
import {OP} from './opcodes.mjs';
import {PRIVATE_ARITHMETIC,PRIVATE_CAPTURE,PRIVATE_RECEIVE} from './private-ops.mjs';

const unary=['','-','not ','#'];
const binary=['','+','-','*','/','%','^','..','==','~=','<','<=','>','>='];
const selectorSlot=op=>op===OP.BINARY?4:op===OP.UNARY?3:0;

// Retain the canonical slot where instruction writers need it. Other sites
// select a semantic recipe: the selector is absent from their stored operands.
// This changes the dialect, not the program's evaluation order or budget.
export function consumerHandlerPlan(program,usedOps){
 const choices=new Map(usedOps.map(op=>[op,new Set()]));
 for(const p of program.prototypes)for(const row of p.code){
  const slot=selectorSlot(row[0]);if(slot){const values=choices.get(row[0]);if(!values)throw new TypeError('Missing consumer recipe operation');values.add(row[slot]);}
 }
 // The private receipt interpreter synthesizes a BINARY instruction at fetch.
 if(program.prototypes.some(p=>p.code.some(row=>[PRIVATE_ARITHMETIC,PRIVATE_CAPTURE,PRIVATE_RECEIVE].includes(row[0]))))choices.get(OP.BINARY)?.add(0);
 const recipes=usedOps.map(op=>{
  const slot=selectorSlot(op),values=[...(choices.get(op)??[])].sort((a,b)=>a-b);
  return {op,selector:slot&&values.length&&!values.includes(0)?values[0]:null};
 });
 for(const op of usedOps){
  const slot=selectorSlot(op);if(!slot)continue;
  for(const selector of [...choices.get(op)].sort((a,b)=>a-b)){
   if(selector===0||recipes[usedOps.indexOf(op)].selector===selector)continue;
   recipes.push({op,selector});
  }
 }
 // A valid existing dialect must not become unrepresentable because semantic
 // specialization exhausted its one-byte slots. Keep generic handlers then.
 if(recipes.length>255)return Object.freeze(usedOps.map(op=>Object.freeze({op,selector:null})));
 validateConsumerRecipes(recipes,usedOps);
 return Object.freeze(recipes.map(Object.freeze));
}

export function validateConsumerRecipes(recipes,usedOps){
 if(!Array.isArray(recipes)||recipes.length<usedOps.length||recipes.length>255)throw new TypeError('Invalid consumer recipes');
 const seen=new Set();
 recipes.forEach((recipe,index)=>{
  if(!recipe||!usedOps.includes(recipe.op)||index<usedOps.length&&recipe.op!==usedOps[index])throw new TypeError('Invalid consumer recipe operation');
  const limit=recipe.op===OP.BINARY?13:recipe.op===OP.UNARY?3:0;
  if(recipe.selector!==null&&(!limit||!Number.isInteger(recipe.selector)||recipe.selector<1||recipe.selector>limit))throw new TypeError('Invalid consumer selector');
  const identity=`${recipe.op}:${recipe.selector}`;if(seen.has(identity))throw new TypeError('Duplicate consumer recipe');seen.add(identity);
 });
}

export function consumerRecipeIndex(recipes,row){
 const slot=selectorSlot(row[0]);
 const exact=slot?recipes.findIndex(recipe=>recipe.op===row[0]&&recipe.selector===row[slot]):-1;
 const index=exact<0?recipes.findIndex(recipe=>recipe.op===row[0]&&recipe.selector===null):exact;
 if(index<0)throw new TypeError('Missing consumer recipe');
 return index;
}

export function consumerRecipeOperands(recipe,operands){
 const out=[...operands];if(recipe.selector!==null)out[selectorSlot(recipe.op)-1]=0;return out;
}

export function consumerRecipeSemantic(recipe){
 if(recipe.selector===null)return null;
 if(recipe.op===OP.BINARY)return `local left, right = registers[b], registers[c]\nregisters[a]=left ${binary[recipe.selector]} right`;
 return `local value = registers[b]\nregisters[a]=${unary[recipe.selector]}value`;
}

export function consumerRecipeRole(recipe,index){
 return recipe.selector!==null&&index===selectorSlot(recipe.op)-1;
}

// Insert pure operand reads at the first consuming statement on each path.
// Only owned a/b/c/d bindings are transformed; locals, function parameters,
// field names and external capabilities keep their original semantics.
// A decoded operand is a number, so nil is a safe not-yet-consumed sentinel.
export function scheduleConsumerOperands(source,reads){
 const ast=luaparse.parse(source,{luaVersion:'5.1',ranges:true,comments:false,encodingMode:'pseudo-latin1'});
 const names=new Set(Object.keys(reads)),edits=new Map(),seenReads=new Set();
 let boundaries=0,conditionalReads=0;
 function expression(node,shadow,out){
  if(!node)return;
  switch(node.type){
   case 'Identifier':if(names.has(node.name)&&!shadow.has(node.name))out.add(node.name);break;
   case 'MemberExpression':expression(node.base,shadow,out);break;
   case 'IndexExpression':expression(node.base,shadow,out);expression(node.index,shadow,out);break;
   case 'TableConstructorExpression':for(const field of node.fields){if(field.type==='TableKey')expression(field.key,shadow,out);expression(field.value,shadow,out);}break;
   case 'FunctionDeclaration':{
    const inner=new Set(shadow);for(const parameter of node.parameters)if(parameter.type==='Identifier')inner.add(parameter.name);
    freeBody(node.body,inner,out);break;
   }
   default:for(const value of Object.values(node))if(Array.isArray(value))value.forEach(child=>{if(child?.type)expression(child,shadow,out);});else if(value?.type)expression(value,shadow,out);
  }
 }
 function freeBody(nodes,shadow,out){
  const inner=new Set(shadow);
  for(const node of nodes){
   if(node.type==='LocalStatement'){node.init.forEach(value=>expression(value,inner,out));node.variables.forEach(value=>inner.add(value.name));}
   else if(node.type==='FunctionDeclaration'){if(node.isLocal)inner.add(node.identifier.name);expression(node,inner,out);}
   else if(node.type==='ForNumericStatement'||node.type==='ForGenericStatement'){
    [node.start,node.end,node.step,...(node.iterators??[])].forEach(value=>expression(value,inner,out));
    const nested=new Set(inner);for(const variable of node.variables??[node.variable])nested.add(variable.name);freeBody(node.body,nested,out);
   }else if(node.type==='IfStatement'){for(const clause of node.clauses){expression(clause.condition,inner,out);freeBody(clause.body,new Set(inner),out);}}
   else if(node.body){expression(node.condition,inner,out);freeBody(node.body,new Set(inner),out);}
   else expression(node,inner,out);
  }
 }
 function decode(used,known,conditional,repeated){
  const missing=[...used].filter(name=>!known.has(name));if(!missing.length)return;
  const snippets=missing.map(name=>{
   const guarded=repeated||seenReads.has(name);seenReads.add(name);
   return guarded?`if ${name}==nil then ${reads[name]} end;`:reads[name];
  }).join('');
  missing.forEach(name=>known.add(name));boundaries++;if(conditional)conditionalReads+=missing.length;
  return snippets;
 }
 function insert(at,text){if(text)edits.set(at,(edits.get(at)??'')+text);}
 function prepare(node,used,known,conditional,repeated){
  insert(node.range[0],decode(used,known,conditional,repeated));
 }
 function block(nodes,input,outerShadow,conditional=false,repeated=false){
  const known=new Set(input),shadow=new Set(outerShadow);
  for(const node of nodes){
   const used=new Set();
   if(node.type==='IfStatement'){
    const continuing=new Set(known),paths=[];
    const common=new Set();
    if(node.clauses.at(-1).type==='ElseClause'){
     const reads=node.clauses.map(clause=>{
      const out=new Set(),first=clause.body[0];
      if(first?.type==='LocalStatement')first.init.forEach(value=>expression(value,shadow,out));
      else if(first&&['AssignmentStatement','CallStatement','ReturnStatement'].includes(first.type))expression(first,shadow,out);
      return out;
     });
     for(const name of reads[0])if(reads.every(path=>path.has(name)))common.add(name);
    }
    for(const [index,clause]of node.clauses.entries()){
     const conditionReads=new Set();expression(clause.condition,shadow,conditionReads);
     // Share a read only if the first statement on every path consumes it.
     // This never opens branch-specific constants or skips budget statements.
     if(index===0){for(const name of common)conditionReads.add(name);prepare(node,conditionReads,continuing,conditional,repeated);}
     else if(clause.condition){
      const snippet=decode(conditionReads,continuing,true,repeated);
      // An elseif condition is reached only after earlier conditions fail.
      // Wrap only conditions requiring a new read; do not hoist those reads.
      if(snippet){insert(clause.condition.range[0],`(function()${snippet}return (`);insert(clause.condition.range[1],') end)()');}
     }
     paths.push(block(clause.body,continuing,shadow,true,repeated));
    }
    if(node.clauses.at(-1).type!=='ElseClause')paths.push(continuing);
    for(const name of names)if(paths.every(path=>path.has(name)))known.add(name);
   }else if(['ForNumericStatement','ForGenericStatement','WhileStatement','RepeatStatement','DoStatement'].includes(node.type)){
    const conditionShadow=new Set(shadow);
    // Repeat's condition sees locals declared in its body. Other loop
    // conditions/bounds are evaluated outside the loop-variable scope.
    if(node.type==='RepeatStatement')for(const statement of node.body){
     if(statement.type==='LocalStatement')statement.variables.forEach(value=>conditionShadow.add(value.name));
     if(statement.type==='FunctionDeclaration'&&statement.isLocal)conditionShadow.add(statement.identifier.name);
    }
    [node.start,node.end,node.step,...(node.iterators??[])].forEach(value=>expression(value,shadow,used));
    expression(node.condition,conditionShadow,used);
    prepare(node,used,known,conditional,repeated);
    const inner=new Set(shadow);for(const variable of node.variables??(node.variable?[node.variable]:[]))inner.add(variable.name);
    const result=block(node.body,known,inner,conditional||node.type!=='DoStatement',repeated||node.type!=='DoStatement');
    if(node.type==='DoStatement')for(const name of result)known.add(name);
   }else{
    if(node.type==='LocalStatement')node.init.forEach(value=>expression(value,shadow,used));
    else if(node.type==='FunctionDeclaration'){
     const inner=new Set(shadow);if(node.isLocal)inner.add(node.identifier.name);expression(node,inner,used);
    }else expression(node,shadow,used);
    prepare(node,used,known,conditional,repeated);
    if(node.type==='LocalStatement')node.variables.forEach(value=>shadow.add(value.name));
    if(node.type==='FunctionDeclaration'&&node.isLocal)shadow.add(node.identifier.name);
   }
  }
  return known;
 }
 block(ast.body,new Set(),new Set());
 const pieces=[];let at=0;
 for(const [position,text]of [...edits].sort((a,b)=>a[0]-b[0])){pieces.push(source.slice(at,position),text);at=position;}
 pieces.push(source.slice(at));
 return {source:pieces.join(''),boundaries,conditionalReads};
}
