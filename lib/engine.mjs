import { wrapLuaSourceAsNil } from './__nil.mjs';

const MAX_SOURCE_BYTES = 512 * 1024; // hard cap; API layer enforces its own limit

const GUARD = "if not game or not Instance then return end\n";

const HEADER_COMMENTS = [
  '-- This file was protected using Nil Obfuscator [https://nil.dev/]',
  '-- [NIL V5] Protected by Nil Virtualizer (https://nil.dev/)',
  '-- << Protected by Nil Engine >> [https://nil.dev/]',
  '-- Protected with Nil Obfuscator [https://nil.dev/]',
  '-- nil.dev - Protected Lua Bytecode [https://nil.dev/]',
];

/**
 * Obfuscate Lua/Luau source with the Nil VM (data V5).
 *
 * The output is a self-contained Nil VM program: no external runtime, no
 * `loadstring`, and no third-party obfuscator templates. Protection options
 * (below) all operate on the Nil instruction/data format itself.
 *
 * @param {string} sourceCode Lua source to protect.
 * @param {object} [options]
 * @param {boolean} [options.skipGuard] Do not inject the Roblox environment guard.
 * @param {object}  [options.vm] Extra options forwarded to wrapLuaSourceAsNil
 *                               (e.g. { maxSteps, keyChain, leanRuntime }).
 * @returns {string} Obfuscated Lua source.
 */
export function obfuscateLua(sourceCode, options = {}) {
  if (typeof sourceCode !== 'string' || !sourceCode.trim()) {
    throw new Error('Source code is empty');
  }
  if (Buffer.byteLength(sourceCode, 'utf8') > MAX_SOURCE_BYTES) {
    throw new Error('Source code exceeds the 512 KB limit');
  }

  // Keep scripts inert outside Roblox unless the caller opts out.
  const guarded = options.skipGuard ? sourceCode : GUARD + sourceCode;

  const wrapped = wrapLuaSourceAsNil(guarded, {
    vmVersion: 5,
    compactRecords: true,
    fastCipher: true,
    resultLinks: true,
    cfgResultLinks: true,
    sealedRecords: true,
    activatedConstants: true,
    consumerHandlers: true,
    ...options.vm,
  });

  const header = HEADER_COMMENTS[Math.floor(Math.random() * HEADER_COMMENTS.length)];
  return `${header}\n\n${wrapped.trim()}\n`;
}
