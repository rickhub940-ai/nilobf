import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { wrapLuaSourceAsNil } from './__nil.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function getTemplatePath() {
  const p1 = resolve(process.cwd(), 'template/template.lua');
  if (existsSync(p1)) return p1;
  const p2 = resolve(__dirname, '../template/template.lua');
  if (existsSync(p2)) return p2;
  throw new Error("template.lua not found in project");
}

function genToken(used, prefix = "") {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const alphanum = chars + "0123456789";
  while (true) {
    const tok = prefix + chars[Math.floor(Math.random() * chars.length)] +
      alphanum[Math.floor(Math.random() * alphanum.length)];
    if (!used.has(tok)) {
      used.add(tok);
      return tok;
    }
  }
}

export function obfuscateLua(sourceCode) {
  if (!sourceCode || !sourceCode.trim()) {
    throw new Error("Source code is empty");
  }

  // 1. Guard against non-Roblox / sandbox
  const guard = "if not game or not Instance then return end\n";
  const guardedCode = guard + sourceCode;

  // 2. Compile directly to Nil VM bytecode
  let directVm = wrapLuaSourceAsNil(guardedCode, {
    vmVersion: 5,
    compactRecords: true,
    fastCipher: true,
    resultLinks: true,
  });

  const templatePath = getTemplatePath();
  let template = readFileSync(templatePath, 'utf8');

  // 3. Dynamically identify strings in directVm
  const strRegex = /\[(=*)\[([\s\S]*?)\]\1\]/g;
  const matches = [...directVm.matchAll(strRegex)];
  if (matches.length !== 4) {
    throw new Error(`Expected 4 long strings in directVm, got ${matches.length}`);
  }

  const sortedMatches = [...matches].sort((a, b) => a[2].length - b[2].length);
  const alphMatches = sortedMatches.filter(m => m[2].length === 85);
  if (alphMatches.length !== 2) {
    throw new Error(`Expected 2 alphabet strings of length 85, got ${alphMatches.length}`);
  }

  const bytecodeMatch = sortedMatches[sortedMatches.length - 1];
  const poolMatches = sortedMatches.filter(m => m !== alphMatches[0] && m !== alphMatches[1] && m !== bytecodeMatch);
  if (poolMatches.length !== 1) {
    throw new Error(`Expected 1 pool match, got ${poolMatches.length}`);
  }
  const poolMatch = poolMatches[0];

  const s0 = alphMatches[0][2]; // Alphabet 85
  const s2 = bytecodeMatch[2];  // Bytecode payload
  const s3 = poolMatch[2];      // String pool

  // Extract r8 from template
  const r8Match = /r8=\[(=*)\[([\s\S]*?)\]\1\],/.exec(template);
  if (!r8Match) {
    throw new Error("r8 not found in Luraph template!");
  }
  const s4 = r8Match[2]; // Luraph r8

  // Unified continuous alien string:
  const unifiedAlien = s4 + s2 + s3 + s0;

  const startS4 = 1;
  const endS4 = s4.length;

  const startS2 = endS4 + 1;
  const endS2 = startS2 + s2.length - 1;

  const startS3 = endS2 + 1;
  const endS3 = startS3 + s3.length - 1;

  const startS0 = endS3 + 1;
  const endS0 = startS0 + s0.length - 1;

  // Replace all strings from end backwards
  const replacements = [
    { start: alphMatches[0].index, end: alphMatches[0].index + alphMatches[0][0].length, val: `string.sub(i.r8,${startS0},${endS0})` },
    { start: alphMatches[1].index, end: alphMatches[1].index + alphMatches[1][0].length, val: `string.sub(i.r8,${startS0},${endS0})` },
    { start: bytecodeMatch.index, end: bytecodeMatch.index + bytecodeMatch[0].length, val: `string.sub(i.r8,${startS2},${endS2})` },
    { start: poolMatch.index, end: poolMatch.index + poolMatch[0].length, val: `string.sub(i.r8,${startS3},${endS3})` }
  ];
  replacements.sort((a, b) => b.start - a.start);
  for (const r of replacements) {
    directVm = directVm.slice(0, r.start) + r.val + directVm.slice(r.end);
  }

  // 4. In Luraph template:
  template = template.replace(r8Match[0], () => `r8=[===[${unifiedAlien}]===],`);
  const oldO8Slice = "i[27](i[62](i.r8,5),i.f8,i.q8)";
  const newO8Slice = `i[27](i[62](i.r8,5,${endS4}),i.f8,i.q8)`;
  template = template.replace(oldO8Slice, () => newO8Slice);

  // 5. Helper functions & Anti-Tamper Coupling
  const usedTokens = new Set();
  const t_hA = genToken(usedTokens, "_");
  const t_hB = genToken(usedTokens, "_");
  const t_hC = genToken(usedTokens, "_");
  const t_sig = genToken(usedTokens, "_");

  const helper_hA = `${t_hA}=function(a,b)return bit32.bxor(a,b)end`;
  const helper_hB = `${t_hB}=function(a,b)return bit32.band(a,b)end`;
  const helper_hC = `${t_hC}=function(c)local e=0;if c.${t_hA}(255,255)~=0 or c.${t_hB}(12345,12345)~=12345 then e=e+1;end;local ok,r=pcall(function()local y={__sub=function(a,b)return 77 end};local z=setmetatable({},y);return z-z;end);if not ok or r~=77 then e=e+1;end;local ok2,r2=pcall(function()local t={};return({[t]=true})[t];end);if not ok2 or r2~=true then e=e+1;end;return e;end`;
  const crash_bomb = `[30]=function(...) local b={} local s=string.rep("\\255\\0\\255\\0",262144) while true do table.insert(b,s..tostring(math.random())) table.insert(b,table.concat(b)) end end`;

  // 6. Transform instruction stepping calculations:
  const propMatch = /([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)\s*\+\s*5/.exec(directVm);
  if (propMatch) {
    const propName = propMatch[2];
    const offsetFormulas = [
      "bit32.bxor(bit32.lshift(1,2),1)",
      "bit32.bxor(21,16)",
      "bit32.rshift(40,3)",
      "bit32.band(255,5)",
      "bit32.bxor(101,96)",
      "bit32.bxor(37,32)",
      "bit32.bxor(69,64)",
      "(29%8)",
      "(45%10)",
      "((31%7)+2)",
      "math.floor(25/5)",
      "bit32.bxor(bit32.lshift(2,1),1)",
    ];
    let counter = 0;
    const stepRegex = new RegExp(`([A-Za-z0-9_]+)\\.${propName}\\s*\\+\\s*5`, 'g');
    directVm = directVm.replace(stepRegex, (match, varName) => {
      const form = offsetFormulas[counter % offsetFormulas.length];
      counter++;
      return `${varName}.${propName}+bit32.bxor(${form},${t_sig})`;
    });
  }

  // 7. Extract table constructor
  const vmMatch = /return setmetatable\(\{([\s\S]*)\},\{\}\):(\w+)\(\)\(\.\.\.\);?/.exec(directVm);
  if (!vmMatch) throw new Error("VM table pattern not found");
  const entryMethod = vmMatch[2];
  const body = vmMatch[1];

  const entryRegex = new RegExp(`${entryMethod}=function\\(\\w+\\)return function\\(\\.\\.\\.\\)return \\w+\\[(\\d+)\\]\\(\\w+,\\.\\.\\.\\)end end`);
  const entrySlotMatch = entryRegex.exec(directVm);
  const validEntrySlot = entrySlotMatch ? parseInt(entrySlotMatch[1], 10) : 121;

  const newHelpers = `${helper_hA},${helper_hB},${helper_hC},${crash_bomb}`;
  const vmTableBody = `${body},${newHelpers}`;

  const r8Body = `local ${t_sig}; local c={${vmTableBody}}; ${t_sig}=c.${t_hC}(c); while ${t_sig}~=0 do local _h=${t_sig}; while _h~=0 do _h=(_h*1664525+1013904223)%4294967296; if _h==0 then _h=1 end end; end; local _slot=(${t_sig}==0) and ${validEntrySlot} or 30; return c[_slot](c,...);`;
  const r8Entry = `R8=function(i) return function(...) ${r8Body} end end,`;

  template = template.replace("if O==2 then return D;", "if O==2 then return i:R8();");
  template = template.replace("t8=function(i,...)", () => `${r8Entry}t8=function(i,...)`);

  // 8. Safe fallback for Roblox datatypes
  const robloxTypes = ['Color3', 'Rect', 'UDim', 'UDim2', 'Vector2', 'Vector3'];
  for (const name of robloxTypes) {
    template = template.replaceAll(`${name}.new`, `(${name} and ${name}.new or function(...) return {...} end)`);
  }

  // 9. Transform all "LPH" words to "NIL"
  template = template.replace("r8=[===[LPH#", "r8=[===[NIL#");
  template = template.replaceAll('"LPH:"', '"NIL:"');
  template = template.replace(/-- This file was protected using Luraph Obfuscator v15\.1 \[https:\/\/lura\.ph\/\]/,
    '-- This file was protected using Nil Obfuscator [https://nil.dev/]');

  // 10. Single line format
  const lines = template.split(/\r?\n/);
  const header = lines[0];
  const bodySingle = lines.slice(2).join(" ").trim();

  return header + "\n\n" + bodySingle;
}
