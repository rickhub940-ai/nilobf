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

function genToken(used, prefix = "_") {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const alphanum = chars + "0123456789";
  while (true) {
    const tok = prefix + chars[Math.floor(Math.random() * chars.length)] +
      alphanum[Math.floor(Math.random() * alphanum.length)] +
      alphanum[Math.floor(Math.random() * alphanum.length)];
    if (!used.has(tok)) {
      used.add(tok);
      return tok;
    }
  }
}

function randomizeSlot(numStr) {
  const n = parseInt(numStr, 10);
  if (isNaN(n)) return numStr;
  const mode = Math.floor(Math.random() * 4);
  if (mode === 0) {
    return `0x${n.toString(16)}`;
  } else if (mode === 1) {
    return `0x${n.toString(16).toUpperCase()}`;
  } else if (mode === 2 && n > 2) {
    const r = Math.floor(Math.random() * (n - 1)) + 1;
    return `0x${r.toString(16)}+0x${(n - r).toString(16)}`;
  } else {
    const add = Math.floor(Math.random() * 16) + 1;
    return `0x${(n + add).toString(16)}-0x${add.toString(16)}`;
  }
}

function randomizeIndex(obj, numStr) {
  const n = parseInt(numStr, 10);
  if (isNaN(n)) return `${obj}[${numStr}]`;
  const mode = Math.floor(Math.random() * 3);
  if (mode === 0) {
    return `${obj}[0x${n.toString(16)}]`;
  } else if (mode === 1) {
    return `${obj}[0x${n.toString(16).toUpperCase()}]`;
  } else {
    const add = Math.floor(Math.random() * 8) + 1;
    return `${obj}[0x${(n + add).toString(16)}-0x${add.toString(16)}]`;
  }
}

function parseRootFields(tableBody) {
  const n = tableBody.length;
  let i = 0;
  let paren = 0, bracket = 0, brace = 0, block = 0;
  const fieldStarts = [0];

  while (i < n) {
    const ch = tableBody[i];
    if (ch === '"' || ch === "'") {
      const q = ch;
      i++;
      while (i < n && tableBody[i] !== q) {
        if (tableBody[i] === '\\') i += 2;
        else i++;
      }
      i++;
      continue;
    }
    if (ch === '[' && tableBody.startsWith('[===[', i)) {
      const end = tableBody.indexOf(']===]', i + 5);
      if (end !== -1) { i = end + 5; continue; }
    }
    if (ch === '[' && tableBody.startsWith('[==[', i)) {
      const end = tableBody.indexOf(']==]', i + 4);
      if (end !== -1) { i = end + 4; continue; }
    }
    if (ch === '[' && tableBody.startsWith('[=[', i)) {
      const end = tableBody.indexOf(']=]', i + 3);
      if (end !== -1) { i = end + 3; continue; }
    }
    if (ch === '[' && tableBody.startsWith('[[', i)) {
      const end = tableBody.indexOf(']]', i + 2);
      if (end !== -1) { i = end + 2; continue; }
    }

    if (ch === '(') paren++;
    else if (ch === ')') paren--;
    else if (ch === '[') bracket++;
    else if (ch === ']') bracket--;
    else if (ch === '{') brace++;
    else if (ch === '}') brace--;
    else if (/[a-zA-Z_]/.test(ch)) {
      const sw = i;
      while (i < n && /[a-zA-Z0-9_]/.test(tableBody[i])) i++;
      const w = tableBody.slice(sw, i);
      if (w === 'function' || w === 'if' || w === 'do' || w === 'repeat') block++;
      else if (w === 'end' || w === 'until') block--;
      continue;
    } else if (ch === ',' && paren === 0 && bracket === 0 && brace === 0 && block === 0) {
      fieldStarts.push(i + 1);
    }
    i++;
  }

  const fields = [];
  for (let idx = 0; idx < fieldStarts.length; idx++) {
    const start = fieldStarts[idx];
    const end = (idx + 1 < fieldStarts.length) ? fieldStarts[idx + 1] - 1 : n;
    fields.push(tableBody.slice(start, end).trim());
  }
  return fields;
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

  // Generate randomized tokens for this build
  const usedTokens = new Set();
  const t_entry_method = genToken(usedTokens);
  const t_r8_entry = genToken(usedTokens);
  const t_r8_prop = genToken(usedTokens);
  const t_hA = genToken(usedTokens);
  const t_hB = genToken(usedTokens);
  const t_hC = genToken(usedTokens);
  const t_sig = genToken(usedTokens);

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

  // Unified continuous alien string
  const unifiedAlien = s4 + s2 + s3 + s0;

  const startS4 = 1;
  const endS4 = s4.length;

  const startS2 = endS4 + 1;
  const endS2 = startS2 + s2.length - 1;

  const startS3 = endS2 + 1;
  const endS3 = startS3 + s3.length - 1;

  const startS0 = endS3 + 1;
  const endS0 = startS0 + s0.length - 1;

  // Replace all strings from end backwards using randomized property name t_r8_prop
  const replacements = [
    { start: alphMatches[0].index, end: alphMatches[0].index + alphMatches[0][0].length, val: `string.sub(i.${t_r8_prop},${startS0},${endS0})` },
    { start: alphMatches[1].index, end: alphMatches[1].index + alphMatches[1][0].length, val: `string.sub(i.${t_r8_prop},${startS0},${endS0})` },
    { start: bytecodeMatch.index, end: bytecodeMatch.index + bytecodeMatch[0].length, val: `string.sub(i.${t_r8_prop},${startS2},${endS2})` },
    { start: poolMatch.index, end: poolMatch.index + poolMatch[0].length, val: `string.sub(i.${t_r8_prop},${startS3},${endS3})` }
  ];
  replacements.sort((a, b) => b.start - a.start);
  for (const r of replacements) {
    directVm = directVm.slice(0, r.start) + r.val + directVm.slice(r.end);
  }

  // 4. In Luraph template:
  // Replace r8 with randomized property name:
  template = template.replace(r8Match[0], () => `${t_r8_prop}=[===[${unifiedAlien}]===],`);
  const oldO8Slice = "i[27](i[62](i.r8,5),i.f8,i.q8)";
  const newO8Slice = `i[27](i[62](i.${t_r8_prop},5,${endS4}),i.f8,i.q8)`;
  template = template.replace(oldO8Slice, () => newO8Slice);

  // 5. Helper functions & Anti-Tamper Coupling with randomized variable tokens
  const v_ok1 = genToken(usedTokens);
  const v_r1 = genToken(usedTokens);
  const v_ok2 = genToken(usedTokens);
  const v_r2 = genToken(usedTokens);
  const v_err = genToken(usedTokens);
  const v_arg1 = genToken(usedTokens);
  const v_arg2 = genToken(usedTokens);
  const v_inst = genToken(usedTokens);

  const helper_hA = `${t_hA}=function(${v_arg1},${v_arg2})return bit32.bxor(${v_arg1},${v_arg2})end`;
  const helper_hB = `${t_hB}=function(${v_arg1},${v_arg2})return bit32.band(${v_arg1},${v_arg2})end`;
  const helper_hC = `${t_hC}=function(${v_inst})local ${v_err}=0;if ${v_inst}.${t_hA}(255,255)~=0 or ${v_inst}.${t_hB}(12345,12345)~=12345 then ${v_err}=${v_err}+1;end;local ${v_ok1},${v_r1}=pcall(function()local y={__sub=function(a,b)return 77 end};local z=setmetatable({},y);return z-z;end);if not ${v_ok1} or ${v_r1}~=77 then ${v_err}=${v_err}+1;end;local ${v_ok2},${v_r2}=pcall(function()local t={};return({[t]=true})[t];end);if not ${v_ok2} or ${v_r2}~=true then ${v_err}=${v_err}+1;end;return ${v_err};end`;

  const crash_slot = Math.floor(Math.random() * 20) + 230; // random slot 230-249
  const crash_bomb = `[${crash_slot}]=function(...) local b={} local s=string.rep("\\255\\0\\255\\0",262144) while true do table.insert(b,s..tostring(math.random())) table.insert(b,table.concat(b)) end end`;

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
    const stepRegex = new RegExp(`([A-Za-z0-9_]+)\\.${propName}\\s*\\+\\s*5`, 'g');
    directVm = directVm.replace(stepRegex, (match, varName) => {
      const form = offsetFormulas[Math.floor(Math.random() * offsetFormulas.length)];
      return `${varName}.${propName}+bit32.bxor(${form},${t_sig})`;
    });
  }

  // Convert all [num]= in directVm using randomizeSlot:
  directVm = directVm.replace(/\[(\d+)\]\s*=/g, (m, num) => `[${randomizeSlot(num)}]=`);

  // 7. Extract table constructor from directVm
  const vmMatch = /return setmetatable\(\{([\s\S]*)\},\{\}\):(\w+)\(\)\(\.\.\.\);?/.exec(directVm);
  if (!vmMatch) throw new Error("VM table pattern not found");
  const entryMethod = vmMatch[2];
  const body = vmMatch[1];

  const entryRegex = new RegExp(`${entryMethod}=function\\(\\w+\\)return function\\(\\.\\.\\.\\)return \\w+\\[(\\d+|0x[0-9a-fA-F\\+\\-]+)\\]\\(\\w+,\\.\\.\\.\\)end end`);
  const entrySlotMatch = entryRegex.exec(directVm);
  const validEntrySlot = entrySlotMatch ? entrySlotMatch[1] : "0x79";

  const newHelpers = `${helper_hA},${helper_hB},${helper_hC},${crash_bomb}`;
  const vmTableBody = `${body},${newHelpers}`;

  const v_ctx = genToken(usedTokens);
  const v_h = genToken(usedTokens);
  const v_slot = genToken(usedTokens);

  const r8Body = `local ${t_sig}; local ${v_ctx}={${vmTableBody}}; ${t_sig}=${v_ctx}.${t_hC}(${v_ctx}); while ${t_sig}~=0 do local ${v_h}=${t_sig}; while ${v_h}~=0 do ${v_h}=(${v_h}*1664525+1013904223)%4294967296; if ${v_h}==0 then ${v_h}=1 end end; end; local ${v_slot}=(${t_sig}==0) and ${validEntrySlot} or ${crash_slot}; return ${v_ctx}[${v_slot}](${v_ctx},...);`;
  const r8Entry = `${t_r8_entry}=function(i) return function(...) ${r8Body} end end,`;

  // 8. Randomize t8 and optimize dispatch for ultra-fast startup:
  const t8Regex = /t8=function\(i,\.\.\.\)([\s\S]*?)end,FR=/;
  const newT8Full = `${r8Entry}${t_entry_method}=function(i,...) local y,U,u,c,r,e,_,O,X,S,V,F,R=i:K8(); return i:${t_r8_entry}(); end,FR=`;
  template = template.replace(t8Regex, () => newT8Full);

  // Replace end call :t8()(...) with :{t_entry_method}()(...)
  template = template.replace(":t8()(...)", () => `:${t_entry_method}()(...)`);

  // 9. Safe fallback for Roblox datatypes
  const robloxTypes = ['Color3', 'Rect', 'UDim', 'UDim2', 'Vector2', 'Vector3'];
  for (const name of robloxTypes) {
    template = template.replaceAll(`${name}.new`, `(${name} and ${name}.new or function(...) return {} end)`);
  }

  // 10. Transform all "LPH" words to "NIL" outside payload
  template = template.replace(`${t_r8_prop}=[===[LPH#`, `${t_r8_prop}=[===[NIL#`);
  template = template.replaceAll('"LPH:"', '"NIL:"');
  template = template.replace(/-- This file was protected using Luraph Obfuscator v15\.1 \[https:\/\/lura\.ph\/\]/,
    '-- This file was protected using Nil Obfuscator [https://nil.dev/]');

  // 11. PARSE ROOT TABLE FIELDS, SHUFFLE WITH FISHER-YATES & RANDOMIZE ALL SLOTS AND INDICES!
  const rootMatch = /return setmetatable\(\{([\s\S]*)\},\{\}\):(\w+)\(\)\(\.\.\.\);?/.exec(template);
  if (!rootMatch) throw new Error("Root table not matched for shuffle");
  const entryCall = rootMatch[2];
  const fields = parseRootFields(rootMatch[1]);

  // Convert top-level slots [num]= using randomizeSlot
  const processedFields = fields.map(f => {
    return f.replace(/^\[(\d+)\]\s*=/, (m, num) => `[${randomizeSlot(num)}]=`);
  });

  // Full Fisher-Yates shuffle across all fields
  for (let i = processedFields.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [processedFields[i], processedFields[j]] = [processedFields[j], processedFields[i]];
  }

  // Reassemble template with shuffled fields
  template = `return setmetatable({${processedFields.join(',')}},{}):${entryCall}()(...);`;

  // 12. Deep slot and index randomization across the entire code outside alien string:
  const parts = template.split(`${t_r8_prop}=[===[`);
  const beforeAlien = parts[0];
  const afterAlienAndRest = parts[1].split("]===],");
  const alienString = afterAlienAndRest[0];
  const afterAlien = afterAlienAndRest.slice(1).join("]===],");

  const randSlotReplacer = (m, num) => `[${randomizeSlot(num)}]=`;
  const randIdxReplacer = (m, obj, num) => randomizeIndex(obj, num);

  let cleanBefore = beforeAlien.replace(/\[(\d+)\]\s*=/g, randSlotReplacer);
  cleanBefore = cleanBefore.replace(/\b([a-zA-Z_][a-zA-Z0-9_]*)\[(\d+)\]/g, randIdxReplacer);

  let cleanAfter = afterAlien.replace(/\[(\d+)\]\s*=/g, randSlotReplacer);
  cleanAfter = cleanAfter.replace(/\b([a-zA-Z_][a-zA-Z0-9_]*)\[(\d+)\]/g, randIdxReplacer);

  template = cleanBefore + `${t_r8_prop}=[===[` + alienString + `]===],` + cleanAfter;

  // Single line deliverable format
  const header = "-- This file was protected using Nil Obfuscator [https://nil.dev/]";
  return header + "\n\n" + template.trim();
}
