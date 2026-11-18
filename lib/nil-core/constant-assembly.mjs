// Mini-VM assembly for constants. Instead of storing the (masked) bytes of a
// constant directly, each byte is materialized by a tiny stack-machine
// program at open time: chains of PUSH/ADD/SUB/MUL operations whose
// immediates are random per build, so no raw constant byte ever appears in
// the payload — not even masked. The program itself is stored as a normal
// sealed constant (tag 6), and the existing key/seal verification applies to
// the program bytes unchanged.
//
// Bytecode ops (u8):
//   1 PUSH8  imm8        -- push imm
//   2 PUSH16 imm16le     -- push imm16
//   3 ADD                -- (a + b) % 256
//   4 SUB                -- (a - b) % 256
//   5 MUL                -- (a * b) % 256
//   6 NOT                -- (255 - a)
//   7 DUP                -- duplicate top of stack
//   8 EMIT               -- pop, append byte to output
// First byte of the program is the real constant tag (3 = number, 4 = string).

import { randomInt } from 'node:crypto';

export const ASSEMBLED_TAG = 6;

const OP = Object.freeze({ PUSH8: 1, PUSH16: 2, ADD: 3, SUB: 4, MUL: 5, NOT: 6, DUP: 7, EMIT: 8 });
const mulInverse256 = a => {
  // Only odd numbers have a multiplicative inverse mod 256.
  for (let i = 1; i < 256; i += 2) if ((a * i) % 256 === 1) return i;
  return null;
};

/**
 * Build the assembly program for one constant.
 * @param {number} realTag 3 (number) or 4 (string)
 * @param {Buffer} raw the bytes of the constant as constantEncoding produced them
 */
export function buildAssembly(realTag, raw) {
  if (realTag !== 3 && realTag !== 4) throw new TypeError('Assembled constants only support tag 3/4');
  const out = [Buffer.from([realTag])];
  for (const target of raw) {
    const roll = randomInt(4);
    const r = randomInt(256);
    if (roll === 0) {
      // target = (r + imm) % 256
      out.push(Buffer.from([OP.PUSH8, r, OP.PUSH8, (target - r + 256) % 256, OP.ADD, OP.EMIT]));
    } else if (roll === 1) {
      // target = (imm - r) % 256 with imm = target + r
      out.push(Buffer.from([OP.PUSH8, (target + r) % 256, OP.PUSH8, r, OP.SUB, OP.EMIT]));
    } else if (roll === 2) {
      // target = (imm + r) % 256 with imm = target - r (same shape, different operand order)
      out.push(Buffer.from([OP.PUSH8, (target - r + 256) % 256, OP.PUSH8, r, OP.ADD, OP.EMIT]));
    } else {
      // target = (imm * odd) % 256
      const odd = 1 + 2 * randomInt(128);
      const inv = mulInverse256(odd);
      out.push(Buffer.from([OP.PUSH8, (target * inv) % 256, OP.PUSH8, odd, OP.MUL, OP.EMIT]));
    }
  }
  return Buffer.concat(out);
}

/** Evaluate an assembly program (reference evaluator, used by tests). */
export function evaluateAssembly(program) {
  if (!Buffer.isBuffer(program) || program.length < 1) throw new TypeError('Assembly must be a non-empty buffer');
  const realTag = program[0];
  if (realTag !== 3 && realTag !== 4) throw new Error('Invalid assembled constant tag');
  const stack = [];
  const output = [];
  const pop = () => {
    if (stack.length === 0) throw new Error('Assembly stack underflow');
    return stack.pop();
  };
  let i = 1;
  while (i < program.length) {
    const op = program[i];
    if (op === OP.PUSH8) {
      if (i + 1 >= program.length) throw new Error('Truncated PUSH8 immediate');
      stack.push(program[i + 1]); i += 2;
    } else if (op === OP.PUSH16) {
      if (i + 2 >= program.length) throw new Error('Truncated PUSH16 immediate');
      stack.push(program[i + 1] + program[i + 2] * 256); i += 3;
    } else if (op === OP.ADD) { const b = pop(), a = pop(); stack.push((a + b) % 256); i += 1; }
    else if (op === OP.SUB) { const b = pop(), a = pop(); stack.push((a - b + 256 * 2) % 256); i += 1; }
    else if (op === OP.MUL) { const b = pop(), a = pop(); stack.push((a * b) % 256); i += 1; }
    else if (op === OP.NOT) { stack.push((255 - pop()) % 256); i += 1; }
    else if (op === OP.DUP) { if (stack.length === 0) throw new Error('Assembly stack underflow'); stack.push(stack[stack.length - 1]); i += 1; }
    else if (op === OP.EMIT) { output.push(pop() % 256); i += 1; }
    else throw new Error(`Unknown assembly op ${op}`);
    if (stack.length > 65536 || output.length > 65536) throw new Error('Assembly resource limit exceeded');
  }
  if (stack.length !== 0) throw new Error('Assembly program ended with a non-empty stack');
  return { tag: realTag, raw: Buffer.from(output) };
}

/** Assembly stats for build logs. */
export function assemblyStats(raw, assembly) {
  return { input: raw.length, assembled: assembly.length - 1, ratio: (assembly.length - 1) / raw.length };
}
