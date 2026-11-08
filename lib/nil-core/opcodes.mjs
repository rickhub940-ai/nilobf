export const OP = Object.freeze(Object.fromEntries([
  'CONST','GETG','SETG','GETL','SETL','NEWL','GETUP','SETUP','MOVE',
  'GETTABLE','SETTABLE','NEWTABLE','PACK','ONE','MANY','ITEM','CALL',
  'VARARG','RETURN','JUMP','JF','JT','JNIL','CLOSURE','UNARY','BINARY',
  'APPEND','FORPREP','FORCHECK','FORNEXT','TAILCALL','CALL1','CALLVOID',
  'CONSTPAIR','CONSTNEWL','CONSTSETL','CONSTGETTABLE','GETLGETTABLE',
].map((name, index) => [name, index + 1])));

export const UNARY = Object.freeze({ '-': 1, not: 2, '#': 3 });
export const BINARY = Object.freeze({
  '+': 1, '-': 2, '*': 3, '/': 4, '%': 5, '^': 6, '..': 7,
  '==': 8, '~=': 9, '<': 10, '<=': 11, '>': 12, '>=': 13,
});
export const OPERAND_ROLES = Object.freeze([
  ['r','k'], ['r','g'], ['r','g'], ['r','l'], ['l','r'], ['l','r'],
  ['r','u'], ['u','r'], ['r','r'], ['r','r','r'], ['r','r','r'],
  ['r'], ['r'], ['r','r'], ['r','r'], ['r','r','i'], ['r','r','r'],
  ['r'], ['r'], ['j'], ['r','j'], ['r','j'], ['r','j'], ['r','p'],
  ['r','r','a'], ['r','r','r','b'], ['r','r','i'], ['r','r','r'],
  ['r','r','r','j'], ['r','r','j'], ['r','r'], ['r','r','r'], ['r','r'],
  ['r','k','r','k'], ['r','k','l'], ['r','k','l'], ['r','k','r','r'], ['r','l','r','r'],
].map(row => Object.freeze(row)));
export const LIMITS = Object.freeze({
  sourceBytes: 1024 * 1024, prototypes: 4096, instructions: 100000,
  constants: 65536, registers: 65535, cells: 8192, blobBytes: 16 * 1024 * 1024,
});
