import { OP } from './opcodes.mjs';
import { PRIVATE_GET } from './private-ops.mjs';

/** Compiler-owned entry IR. It contains no source name or environment lookup. */
export function opaqueWrapperProgram() {
  const code = [
    [PRIVATE_GET, 1, 1, 0, 0],
    [OP.PACK, 2, 0, 0, 0],
    [OP.VARARG, 3, 0, 0, 0],
    [OP.MANY, 2, 3, 0, 0],
    [OP.TAILCALL, 1, 2, 0, 0],
  ];
  return {
    version: 3, target: 'luau', root: 1,
    prototypes: [{ parent: 0, parameters: 0, vararg: true, registers: 3, cells: 0, upvalues: [], constants: [], code }],
    stats: { prototypes: 1, instructions: code.length, constants: 0, fusedInstructions: 0 },
  };
}
