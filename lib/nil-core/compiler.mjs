import luaparse from 'luaparse';
import { OP, UNARY, BINARY, LIMITS } from './opcodes.mjs';
import { PRIVATE_SELECT,PRIVATE_OPEN,PRIVATE_SPAN,PRIVATE_ARITHMETIC } from './private-ops.mjs';

function parse(source) {
  // luaparse's byte string mode preserves UTF-8 and decimal escapes exactly.
  const bytes = Buffer.from(source, 'utf8').toString('latin1');
  const options = { luaVersion: '5.1', encodingMode: 'pseudo-latin1',
    locations: true, ranges: true, comments: false };
  const ast = luaparse.parse(bytes, options);
  luaparse.parse(bytes, { ...options, wait: true });
  const tokens = [];
  for (;;) {
    const token = luaparse.lex();
    if (token.type === luaparse.tokenTypes.EOF) break;
    tokens.push(token);
  }
  // The parser omits parentheses from AST nodes. Record their token boundaries
  // so (f()) and (...) retain Lua's single-result semantics.
  const stack = [], pairs = new Map(), before = new Map(), after = new Map();
  tokens.forEach((token, index) => {
    before.set(token.range[0], index - 1);
    after.set(token.range[1], index + 1);
    if (token.value === '(') stack.push(index);
    if (token.value === ')') pairs.set(stack.pop(), index);
  });
  function expands(node) {
    if (!['CallExpression','TableCallExpression','StringCallExpression','VarargLiteral'].includes(node.type)) return false;
    const left = before.get(node.range[0]), right = after.get(node.range[1]);
    if (left !== undefined && right !== undefined && tokens[left]?.value === '(' && pairs.get(left) === right) {
      const previous = tokens[left - 1];
      const callArguments = previous && (previous.type === luaparse.tokenTypes.Identifier ||
        previous.type === luaparse.tokenTypes.StringLiteral || [')',']'].includes(previous.value));
      if (!callArguments) return false;
    }
    return true;
  }
  return { ast, expands };
}

class FunctionCompiler {
  constructor(program, parent, parameters = [], vararg = false) {
    this.program = program;
    this.parent = parent;
    this.id = program.prototypes.length + 1;
    if (this.id > LIMITS.prototypes) throw new Error('Nil prototype limit exceeded');
    this.code = []; this.constants = []; this.constantMap = new Map();
    this.scopes = [new Map()]; this.loops = [];
    this.upvalues = []; this.upMap = new Map();
    this.registers = 0; this.cells = 0;
    this.parameters = parameters.length; this.vararg = vararg;
    program.prototypes.push(this);
    for (const name of parameters) this.declare(name);
  }
  fail(node, message) {
    const location = node?.loc?.start;
    throw new SyntaxError(`Nil ${location ? `${location.line}:${location.column + 1}: ` : ''}${message}`);
  }
  reg() {
    if (++this.registers > LIMITS.registers) throw new Error('Nil register limit exceeded');
    return this.registers;
  }
  emit(op, ...operands) {
    if (++this.program.instructions > LIMITS.instructions) throw new Error('Nil instruction limit exceeded');
    const index = this.code.length;
    this.code.push([op, ...operands, ...Array(4 - operands.length).fill(0)]);
    return index;
  }
  here() { return this.code.length * 5 + 1; }
  patch(index, operand = 1, target = this.here()) { this.code[index][operand] = target; }
  declare(name) {
    if (++this.cells > LIMITS.cells) throw new Error('Nil local cell limit exceeded');
    this.scopes.at(-1).set(name, this.cells);
    return this.cells;
  }
  resolve(name, node) {
    for (let i = this.scopes.length - 1; i >= 0; i--) {
      const slot = this.scopes[i].get(name);
      if (slot !== undefined) return { kind: 'local', slot };
    }
    if (this.upMap.has(name)) return { kind: 'up', slot: this.upMap.get(name) };
    if (this.parent) {
      const outer = this.parent.resolve(name, node);
      if (outer.kind !== 'global') {
        const slot = this.upvalues.length + 1;
        if (slot > LIMITS.cells) this.fail(node, 'upvalue limit exceeded');
        this.upvalues.push([outer.kind === 'local' ? 0 : 1, outer.slot]);
        this.upMap.set(name, slot);
        return { kind: 'up', slot };
      }
    }
    if (['getfenv', 'setfenv'].includes(name)) this.fail(node, `environment reflection ${name} is unsupported`);
    return { kind: 'global', name };
  }
  constant(value) {
    const key = value === null ? 'nil' : `${typeof value}:${value}`;
    if (this.constantMap.has(key)) return this.constantMap.get(key);
    if (++this.program.constants > LIMITS.constants) throw new Error('Nil constant limit exceeded');
    if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('Nil non-finite numeric literal');
    this.constants.push(value);
    const index = this.constants.length;
    this.constantMap.set(key, index);
    return index;
  }
  literal(value) { const a = this.reg(); this.emit(OP.CONST, a, this.constant(value)); return a; }
  read(binding) {
    const a = this.reg();
    if (binding.kind === 'global') this.emit(OP.GETG, a, this.constant(binding.name));
    else this.emit(binding.kind === 'local' ? OP.GETL : OP.GETUP, a, binding.slot);
    return a;
  }
  write(binding, value) {
    if (binding.kind === 'global') this.emit(OP.SETG, value, this.constant(binding.name));
    else this.emit(binding.kind === 'local' ? OP.SETL : OP.SETUP, binding.slot, value);
  }
  list(expressions, initial = []) {
    const tuple = this.reg(); this.emit(OP.PACK, tuple);
    for (const value of initial) this.emit(OP.ONE, tuple, value);
    expressions.forEach((node, index) => {
      const multi = index === expressions.length - 1 && this.program.expands(node);
      const value = this.expr(node, multi);
      this.emit(multi ? OP.MANY : OP.ONE, tuple, value);
    });
    return tuple;
  }
  item(tuple, index) { const value = this.reg(); this.emit(OP.ITEM, value, tuple, index); return value; }
  assignedValues(expressions, count) {
    const values = [];
    expressions.forEach((node, index) => {
      const last = index === expressions.length - 1;
      const needed = count - values.length;
      if (last && needed > 1 && this.program.expands(node)) {
        const tuple = this.expr(node, true);
        for (let i = 1; i <= needed; i++) values.push(this.item(tuple, i));
      } else values.push(this.expr(node));
    });
    while (values.length < count) values.push(this.literal(null));
    return values;
  }
  callParts(node) {
    let fn, self;
    if (node.base.type === 'MemberExpression' && node.base.indexer === ':') {
      self = this.expr(node.base.base);
      fn = this.reg();
      this.emit(OP.GETTABLE, fn, self, this.literal(node.base.identifier.name));
    } else fn = this.expr(node.base);
    const args = node.type === 'TableCallExpression' ? [node.arguments] :
      node.type === 'StringCallExpression' ? [node.argument] : node.arguments;
    const tuple = this.list(args, self ? [self] : []);
    return [fn, tuple];
  }
  call(node, multi) {
    // Compiler-owned arithmetic: a pending operator is consumed by BINARY fetch.
    // Operator zero is deliberately invalid until its producer has run.
    if(node.type==='CallExpression'&&node.base.type==='Identifier'&&node.base.name===this.program.instructionArithmetic&&this.resolve(node.base.name,node).kind==='global'){
      if(multi||node.arguments.length!==3)this.fail(node,'invalid instruction arithmetic');
      const [condition,left,right]=node.arguments.map(argument=>this.expr(argument)),result=this.reg();
      this.emit(PRIVATE_ARITHMETIC,condition,1,2,this.here()+5);
      this.emit(OP.BINARY,result,left,right,0);
      return result;
    }
    if(node.type==='CallExpression'&&node.base.type==='Identifier'&&node.base.name===this.program.instructionSpan&&this.resolve(node.base.name,node).kind==='global'){
      if(node.arguments.length!==1)throw new Error('Instruction span requires one page');
      const id=this.expr(node.arguments[0]),result=this.reg();this.emit(PRIVATE_SPAN,result,id);return result;
    }
    if(node.type==='CallExpression'&&node.base.type==='Identifier'&&node.base.name===this.program.instructionOpen&&this.resolve(node.base.name,node).kind==='global'){
      if(multi||node.arguments.length!==2)this.fail(node,'invalid instruction page opening');
      const [id,key]=node.arguments.map(argument=>this.expr(argument)),result=this.reg();this.emit(PRIVATE_OPEN,result,id,key);return result;
    }
    // Only the compiler-owned preparation source enables this intrinsic.
    // The MOVE is an instruction template: its source is written at runtime.
    if (node.type === 'CallExpression' && node.base.type === 'Identifier' &&
        node.base.name === this.program.instructionSelect && this.resolve(node.base.name,node).kind === 'global') {
      if (multi || node.arguments.length !== 3) this.fail(node,'invalid instruction selection');
      const [condition,yes,no] = node.arguments.map(argument=>this.expr(argument));
      const result=this.reg();
      this.emit(PRIVATE_SELECT,condition,yes,no,this.here()+5);
      this.emit(OP.MOVE,result,result);
      return result;
    }
    const [fn, tuple] = this.callParts(node);
    const result = this.reg(); this.emit(multi ? OP.CALL : OP.CALL1, result, fn, tuple);
    return result;
  }
  closure(node, implicitSelf = false) {
    const parameters = node.parameters.filter(p => p.type !== 'VarargLiteral').map(p => p.name);
    if (implicitSelf) parameters.unshift('self');
    const child = new FunctionCompiler(this.program, this, parameters,
      node.parameters.some(p => p.type === 'VarargLiteral'));
    child.block(node.body, false);
    child.emit(OP.RETURN, child.list([]));
    const a = this.reg(); this.emit(OP.CLOSURE, a, child.id); return a;
  }
  expr(node, multi = false) {
    switch (node.type) {
      case 'NilLiteral': return this.literal(null);
      case 'BooleanLiteral': case 'NumericLiteral': case 'StringLiteral': return this.literal(node.value);
      case 'Identifier': return this.read(this.resolve(node.name, node));
      case 'VarargLiteral': {
        if (!this.vararg) this.fail(node, 'vararg outside vararg function');
        const a = this.reg(); this.emit(OP.VARARG, a);
        return multi ? a : this.item(a, 1);
      }
      case 'CallExpression': case 'TableCallExpression': case 'StringCallExpression': return this.call(node, multi);
      case 'MemberExpression': case 'IndexExpression': {
        const base = this.expr(node.base);
        const key = node.type === 'MemberExpression' ? this.literal(node.identifier.name) : this.expr(node.index);
        const a = this.reg(); this.emit(OP.GETTABLE, a, base, key); return a;
      }
      case 'FunctionDeclaration': return this.closure(node);
      case 'UnaryExpression': {
        const op = UNARY[node.operator]; if (!op) this.fail(node, `unsupported unary ${node.operator}`);
        const b = this.expr(node.argument), a = this.reg(); this.emit(OP.UNARY, a, b, op); return a;
      }
      case 'LogicalExpression': {
        const left = this.expr(node.left), a = this.reg(); this.emit(OP.MOVE, a, left);
        const skip = this.emit(node.operator === 'and' ? OP.JF : OP.JT, a, 0);
        this.emit(OP.MOVE, a, this.expr(node.right)); this.patch(skip, 2); return a;
      }
      case 'BinaryExpression': {
        const op = BINARY[node.operator]; if (!op) this.fail(node, `unsupported binary ${node.operator}`);
        const b = this.expr(node.left), c = this.expr(node.right), a = this.reg();
        this.emit(OP.BINARY, a, b, c, op); return a;
      }
      case 'TableConstructorExpression': {
        const a = this.reg(); this.emit(OP.NEWTABLE, a);
        let arrayIndex = 1;
        node.fields.forEach((field, index) => {
          if (field.type === 'TableValue') {
            if (index === node.fields.length - 1 && this.program.expands(field.value)) {
              this.emit(OP.APPEND, a, this.expr(field.value, true), arrayIndex);
            } else this.emit(OP.SETTABLE, a, this.literal(arrayIndex), this.expr(field.value));
            arrayIndex++;
          } else {
            const key = field.type === 'TableKeyString' ? this.literal(field.key.name) : this.expr(field.key);
            this.emit(OP.SETTABLE, a, key, this.expr(field.value));
          }
        });
        return a;
      }
      default: this.fail(node, `unsupported expression ${node.type}`);
    }
  }
  lvalue(node) {
    if (node.type === 'Identifier') return this.resolve(node.name, node);
    if (node.type === 'MemberExpression' || node.type === 'IndexExpression') {
      const base = this.expr(node.base);
      const key = node.type === 'MemberExpression' ? this.literal(node.identifier.name) : this.expr(node.index);
      return { kind: 'table', base, key };
    }
    this.fail(node, 'unsupported assignment target');
  }
  assign(target, value) {
    if (target.kind === 'table') this.emit(OP.SETTABLE, target.base, target.key, value);
    else this.write(target, value);
  }
  block(body, scope = true) {
    if (scope) this.scopes.push(new Map());
    for (const node of body) this.statement(node);
    if (scope) this.scopes.pop();
  }
  finishLoop(loop) {
    for (const index of loop.breaks) this.patch(index);
    this.loops.pop();
  }
  statement(node) {
    switch (node.type) {
      case 'LocalStatement': {
        const values = this.assignedValues(node.init, node.variables.length);
        // Evaluate all RHS expressions before introducing any new names.
        for (let i = 0; i < node.variables.length; i++) {
          this.emit(OP.NEWL, this.declare(node.variables[i].name), values[i]);
        }
        return;
      }
      case 'AssignmentStatement': {
        const targets = node.variables.map(v => this.lvalue(v));
        const values = this.assignedValues(node.init, targets.length);
        // Luau commits left to right; Lua 5.1 commits right to left.
        const indices = targets.map((_, index) => index);
        if (this.program.target === 'lua51') indices.reverse();
        for (const index of indices) {
          this.assign(targets[index], values[index]);
        }
        return;
      }
      case 'CallStatement': this.emit(OP.CALLVOID, ...this.callParts(node.expression)); return;
      case 'ReturnStatement': {
        const first = node.arguments[0];
        if (node.arguments.length === 1 && this.program.expands(first) && first.type !== 'VarargLiteral') {
          this.emit(OP.TAILCALL, ...this.callParts(first));
        } else this.emit(OP.RETURN, this.list(node.arguments));
        return;
      }
      case 'FunctionDeclaration': {
        if (node.isLocal) {
          const slot = this.declare(node.identifier.name);
          this.emit(OP.NEWL, slot, this.literal(null));
          this.emit(OP.SETL, slot, this.closure(node));
        } else {
          const target = this.lvalue(node.identifier);
          this.assign(target, this.closure(node, node.identifier.indexer === ':'));
        }
        return;
      }
      case 'DoStatement': this.block(node.body); return;
      case 'IfStatement': {
        const done = [];
        for (const clause of node.clauses) {
          const skip = clause.condition ? this.emit(OP.JF, this.expr(clause.condition), 0) : null;
          this.block(clause.body);
          done.push(this.emit(OP.JUMP, 0));
          if (skip !== null) this.patch(skip, 2);
        }
        done.forEach(index => this.patch(index)); return;
      }
      case 'WhileStatement': {
        const start = this.here(), loop = { breaks: [] }; this.loops.push(loop);
        const end = this.emit(OP.JF, this.expr(node.condition), 0);
        this.block(node.body); this.emit(OP.JUMP, start); this.patch(end, 2);
        this.finishLoop(loop); return;
      }
      case 'RepeatStatement': {
        const start = this.here(), loop = { breaks: [] }; this.loops.push(loop);
        this.scopes.push(new Map()); this.block(node.body, false);
        this.emit(OP.JF, this.expr(node.condition), start);
        this.scopes.pop(); this.finishLoop(loop); return;
      }
      case 'BreakStatement': {
        const loop = this.loops.at(-1); if (!loop) this.fail(node, 'break outside loop');
        loop.breaks.push(this.emit(OP.JUMP, 0)); return;
      }
      case 'ForNumericStatement': {
        const index = this.expr(node.start), limit = this.expr(node.end);
        const step = node.step ? this.expr(node.step) : this.literal(1);
        this.emit(OP.FORPREP, index, limit, step);
        const start = this.here();
        const end = this.emit(OP.FORCHECK, index, limit, step, 0);
        this.scopes.push(new Map()); const slot = this.declare(node.variable.name);
        this.emit(OP.NEWL, slot, index);
        const loop = { breaks: [] }; this.loops.push(loop); this.block(node.body);
        this.emit(OP.FORNEXT, index, step, start);
        this.patch(end, 4); this.finishLoop(loop); this.scopes.pop(); return;
      }
      case 'ForGenericStatement': {
        const values = this.list(node.iterators), fn = this.item(values, 1);
        const state = this.item(values, 2), control = this.item(values, 3);
        const start = this.here(), args = this.list([], [state, control]);
        const results = this.reg(); this.emit(OP.CALL, results, fn, args);
        this.emit(OP.ITEM, control, results, 1);
        const end = this.emit(OP.JNIL, control, 0);
        this.scopes.push(new Map());
        node.variables.forEach((variable, i) => this.emit(OP.NEWL, this.declare(variable.name), this.item(results, i + 1)));
        const loop = { breaks: [] }; this.loops.push(loop); this.block(node.body);
        this.emit(OP.JUMP, start); this.patch(end, 2); this.finishLoop(loop); this.scopes.pop(); return;
      }
      default: this.fail(node, `unsupported statement ${node.type}`);
    }
  }
  snapshot() {
    return { parent: this.parent?.id ?? 0, parameters: this.parameters, vararg: this.vararg,
      registers: this.registers, cells: this.cells, upvalues: this.upvalues,
      constants: this.constants, code: this.code };
  }
}

export function compileLuaToNil(source, { target = 'luau', instructionSelect,instructionOpen,instructionSpan,instructionArithmetic } = {}) {
  if (typeof source !== 'string') throw new TypeError('source must be a string');
  if (!['luau', 'lua51'].includes(target)) throw new TypeError('Unsupported Nil target');
  if (instructionSelect !== undefined && (typeof instructionSelect !== 'string' || !/^[A-Za-z_][A-Za-z_0-9]*$/.test(instructionSelect))) throw new TypeError('Invalid instruction intrinsic');
  if(instructionOpen!==undefined&&(typeof instructionOpen!=='string'||!/^[A-Za-z_][A-Za-z_0-9]*$/.test(instructionOpen)))throw new TypeError('Invalid instruction page intrinsic');
  if(instructionSpan!==undefined&&(typeof instructionSpan!=='string'||!/^[A-Za-z_][A-Za-z_0-9]*$/.test(instructionSpan)))throw new TypeError('Invalid instruction span intrinsic');
  if(instructionArithmetic!==undefined&&(typeof instructionArithmetic!=='string'||!/^[A-Za-z_][A-Za-z_0-9]*$/.test(instructionArithmetic)))throw new TypeError('Invalid instruction arithmetic intrinsic');
  const intrinsics=[instructionSelect,instructionOpen,instructionSpan,instructionArithmetic].filter(v=>v!==undefined);
  if(new Set(intrinsics).size!==intrinsics.length)throw new TypeError('Instruction intrinsics must be distinct');
  if (Buffer.byteLength(source, 'utf8') > LIMITS.sourceBytes) throw new RangeError('Nil source limit exceeded');
  const { ast, expands } = parse(source);
  const program = { prototypes: [], instructions: 0, constants: 0, expands, target, instructionSelect,instructionOpen,instructionSpan,instructionArithmetic };
  const root = new FunctionCompiler(program, null, [], true);
  root.block(ast.body, false); root.emit(OP.RETURN, root.list([]));
  return { version: 2, target, root: root.id, prototypes: program.prototypes.map(p => p.snapshot()),
    stats: { prototypes: program.prototypes.length, instructions: program.instructions, constants: program.constants } };
}
