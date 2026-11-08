import luaparse from 'luaparse';
import { randomInt } from 'node:crypto';

const letters='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
const tail=letters+'0123456789';
const keywords=new Set('and break do else elseif end false for function if in local nil not or repeat return then true until while'.split(' '));
class Scope {
  constructor(parent=null){this.parent=parent;this.names=new Map();this.aliases=new Set();}
  find(name){return this.names.has(name)?this.names.get(name):this.parent?.find(name);}
  hasAlias(name){return this.aliases.has(name)||!!this.parent?.hasAlias(name);}
}

// This pass applies only to the generated VM runner, never to native/Luraph
// bodies. Resolve declarations with the AST so inner scopes, shadowing and
// repeat conditions are renamed as well as the outer wrapper parameters.
export function renameRunnerBindings(source,{scopeAliases=false}={}) {
  if(typeof scopeAliases!=='boolean')throw new TypeError('Invalid alias mode');
  const ast=luaparse.parse(source,{luaVersion:'5.1',ranges:true,comments:false,scope:scopeAliases,encodingMode:'pseudo-latin1'});
  const used=new Set([...keywords,'pc','remaining','registers','prototype','nativeBody','lookup','__nil','__nil_source']),edits=new Map();
  function collect(node){
    if(!node||typeof node!=='object')return;
    if(node.type==='Identifier')used.add(node.name);
    for(const value of Object.values(node))if(Array.isArray(value))value.forEach(collect);else if(value&&typeof value==='object')collect(value);
  }
  if(scopeAliases){for(const node of ast.globals)used.add(node.name);}else collect(ast);
  function alias(scope){
    // Large joint interpreters and four banks can exhaust the 3276 short
    // candidates, especially on the second renaming pass. Grow the space and
    // bound retries; generation must never spin when short names are full.
    let width=used.size>2048?3:randomInt(1,3);
    for(let attempt=0;;attempt++){
      if(attempt&&attempt%64===0)width++;
      let name=letters[randomInt(letters.length)];for(let i=1;i<width;i++)name+=tail[randomInt(tail.length)];
      if(!used.has(name)&&(!scopeAliases||!scope.hasAlias(name))){if(scopeAliases)scope.aliases.add(name);else used.add(name);return name;}
    }
  }
  function change(node,name){if(name&&name!==node.name)edits.set(node.range[0],{end:node.range[1],name});}
  function declare(node,scope){const name=alias(scope);scope.names.set(node.name,name);change(node,name);}
  function expr(node,scope){
    if(!node)return;
    switch(node.type){
      case 'Identifier':change(node,scope.find(node.name));break;
      case 'MemberExpression':expr(node.base,scope);break;
      case 'IndexExpression':expr(node.base,scope);expr(node.index,scope);break;
      case 'UnaryExpression':expr(node.argument,scope);break;
      case 'BinaryExpression':case 'LogicalExpression':expr(node.left,scope);expr(node.right,scope);break;
      case 'CallExpression':expr(node.base,scope);node.arguments.forEach(n=>expr(n,scope));break;
      case 'TableCallExpression':expr(node.base,scope);expr(node.arguments,scope);break;
      case 'StringCallExpression':expr(node.base,scope);expr(node.argument,scope);break;
      case 'FunctionDeclaration':fn(node,scope);break;
      case 'TableConstructorExpression':for(const field of node.fields){if(field.type==='TableKey')expr(field.key,scope);expr(field.value,scope);}break;
      case 'NumericLiteral':case 'StringLiteral':case 'BooleanLiteral':case 'NilLiteral':case 'VarargLiteral':break;
      default:throw new Error(`Unsupported generated runner expression: ${node.type}`);
    }
  }
  function fn(node,parent){
    const scope=new Scope(parent);
    if(node.identifier?.type==='MemberExpression'&&node.identifier.indexer===':'){scope.names.set('self','self');scope.aliases.add('self');}
    for(const param of node.parameters)if(param.type==='Identifier')declare(param,scope);
    body(node.body,scope);
  }
  function body(nodes,scope){for(const node of nodes){switch(node.type){
    case 'LocalStatement':node.init.forEach(n=>expr(n,scope));node.variables.forEach(n=>declare(n,scope));break;
    case 'FunctionDeclaration':if(node.isLocal)declare(node.identifier,scope);else expr(node.identifier,scope);fn(node,scope);break;
    case 'AssignmentStatement':node.variables.forEach(n=>expr(n,scope));node.init.forEach(n=>expr(n,scope));break;
    case 'CallStatement':expr(node.expression,scope);break;
    case 'ReturnStatement':node.arguments.forEach(n=>expr(n,scope));break;
    case 'DoStatement':body(node.body,new Scope(scope));break;
    case 'IfStatement':for(const clause of node.clauses){expr(clause.condition,scope);body(clause.body,new Scope(scope));}break;
    case 'WhileStatement':expr(node.condition,scope);body(node.body,new Scope(scope));break;
    case 'RepeatStatement':{const inner=new Scope(scope);body(node.body,inner);expr(node.condition,inner);break;}
    case 'ForNumericStatement':{expr(node.start,scope);expr(node.end,scope);expr(node.step,scope);const inner=new Scope(scope);declare(node.variable,inner);body(node.body,inner);break;}
    case 'ForGenericStatement':{node.iterators.forEach(n=>expr(n,scope));const inner=new Scope(scope);node.variables.forEach(n=>declare(n,inner));body(node.body,inner);break;}
    case 'BreakStatement':break;
    default:throw new Error(`Unsupported generated runner statement: ${node.type}`);
  }}}
  body(ast.body,new Scope());
  // Materialize once: repeatedly splicing the whole runner made large builds
  // allocate/copy a source-sized string for every identifier occurrence.
  const parts=[];let cursor=0;
  for(const [start,{end,name}]of [...edits].sort((a,b)=>a[0]-b[0])){
    if(start<cursor)throw new Error('Overlapping runner binding edits');
    parts.push(source.slice(cursor,start),name);cursor=end;
  }
  parts.push(source.slice(cursor));return parts.join('');
}
