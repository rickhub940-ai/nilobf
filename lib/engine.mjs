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

function genDiverseToken(used) {
  const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const digits = "0123456789";
  const alphanum = letters + digits;

  const styles = [
    // Style 0: _ + 1-2 letters/digits
    () => "_" + letters[Math.floor(Math.random() * letters.length)] +
          alphanum[Math.floor(Math.random() * alphanum.length)],
    // Style 1: 1 letter + 1 digit/letter
    () => letters[Math.floor(Math.random() * letters.length)] +
          alphanum[Math.floor(Math.random() * alphanum.length)],
    // Style 2: 1 letter + _ + 1 digit/letter
    () => letters[Math.floor(Math.random() * letters.length)] + "_" +
          alphanum[Math.floor(Math.random() * alphanum.length)],
    // Style 3: _ + 2-3 chars
    () => "_" + letters[Math.floor(Math.random() * letters.length)] +
          alphanum[Math.floor(Math.random() * alphanum.length)] +
          alphanum[Math.floor(Math.random() * alphanum.length)],
    // Style 4: 2 letters
    () => letters[Math.floor(Math.random() * letters.length)] +
          letters[Math.floor(Math.random() * letters.length)],
    // Style 5: 2 letters + 1 digit
    () => letters[Math.floor(Math.random() * letters.length)] +
          letters[Math.floor(Math.random() * letters.length)] +
          digits[Math.floor(Math.random() * digits.length)],
  ];

  const reserved = new Set([
    'and','break','do','else','elseif','end','false','for','function','if','in',
    'local','nil','not','or','repeat','return','then','true','until','while',
    'self','game','task','workspace','Instance','script','math','table','string','bit32'
  ]);

  while (true) {
    const fn = styles[Math.floor(Math.random() * styles.length)];
    const tok = fn();
    if (!used.has(tok) && !reserved.has(tok)) {
      used.add(tok);
      return tok;
    }
  }
}

function randomizeSlotMath(numStr) {
  const n = parseInt(numStr, 10);
  if (isNaN(n)) return numStr;
  const patterns = [];
  patterns.push(`0x${n.toString(16)}`);
  patterns.push(`0x${n.toString(16).toUpperCase()}`);
  if (n > 2) {
    const r = Math.floor(Math.random() * (n - 1)) + 1;
    patterns.push(`0x${r.toString(16)}+0x${(n - r).toString(16)}`);
    patterns.push(`${r}+0x${(n - r).toString(16)}`);
  }
  const add = Math.floor(Math.random() * 16) + 1;
  patterns.push(`0x${(n + add).toString(16)}-0x${add.toString(16)}`);
  for (const div of [2, 3, 4, 5]) {
    if (n % div === 0 && n > div) {
      patterns.push(`${div}*0x${(n / div).toString(16)}`);
      break;
    }
  }
  return patterns[Math.floor(Math.random() * patterns.length)];
}

function randomizeIndexMath(obj, numStr) {
  const n = parseInt(numStr, 10);
  if (isNaN(n)) return `${obj}[${numStr}]`;
  const patterns = [];
  patterns.push(`${obj}[0x${n.toString(16)}]`);
  patterns.push(`${obj}[0x${n.toString(16).toUpperCase()}]`);
  if (n > 2) {
    const r = Math.floor(Math.random() * (n - 1)) + 1;
    patterns.push(`${obj}[0x${r.toString(16)}+0x${(n - r).toString(16)}]`);
  }
  const add = Math.floor(Math.random() * 8) + 1;
  patterns.push(`${obj}[0x${(n + add).toString(16)}-0x${add.toString(16)}]`);
  return patterns[Math.floor(Math.random() * patterns.length)];
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
  const t_entry_method = genDiverseToken(usedTokens);
  const t_r8_entry = genDiverseToken(usedTokens);
  const t_r8_prop = genDiverseToken(usedTokens);
  const t_hA = genDiverseToken(usedTokens);
  const t_hB = genDiverseToken(usedTokens);
  const t_hC = genDiverseToken(usedTokens);
  const t_sig = genDiverseToken(usedTokens);

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

  // Random equals count for long brackets (2 to 4)
  let eqCount = Math.floor(Math.random() * 3) + 2;
  let openBracket = `[${'='.repeat(eqCount)}[`;
  let closeBracket = `]${'='.repeat(eqCount)}]`;
  while (unifiedAlien.includes(closeBracket)) {
    eqCount++;
    openBracket = `[${'='.repeat(eqCount)}[`;
    closeBracket = `]${'='.repeat(eqCount)}]`;
  }

  template = template.replace(r8Match[0], () => `${t_r8_prop}=${openBracket}${unifiedAlien}${closeBracket},`);
  const oldO8Slice = "i[27](i[62](i.r8,5),i.f8,i.q8)";
  const newO8Slice = `i[27](i[62](i.${t_r8_prop},5,${endS4}),i.f8,i.q8)`;
  template = template.replace(oldO8Slice, () => newO8Slice);

  // 4. Helper functions & Anti-Tamper Coupling with randomized patterns and tokens
  const v_ok1 = genDiverseToken(usedTokens);
  const v_r1 = genDiverseToken(usedTokens);
  const v_ok2 = genDiverseToken(usedTokens);
  const v_r2 = genDiverseToken(usedTokens);
  const v_err = genDiverseToken(usedTokens);
  const v_arg1 = genDiverseToken(usedTokens);
  const v_arg2 = genDiverseToken(usedTokens);
  const v_inst = genDiverseToken(usedTokens);
  const v_meta = genDiverseToken(usedTokens);
  const v_obj = genDiverseToken(usedTokens);
  const v_tbl = genDiverseToken(usedTokens);

  const randA = Math.floor(Math.random() * 50000) + 1000;
  const randB = Math.floor(Math.random() * 50000) + 1000;
  const randVal = Math.floor(Math.random() * 800) + 50;

  const operators = [
    { mm: '__sub', op: '-' },
    { mm: '__add', op: '+' },
    { mm: '__mul', op: '*' },
  ];
  const chosenOp = operators[Math.floor(Math.random() * operators.length)];

  const check1 = `if ${v_inst}.${t_hA}(${randA},${randA})~=0 or ${v_inst}.${t_hB}(${randB},${randB})~=${randB} then ${v_err}=${v_err}+1;end;`;
  const check2 = `local ${v_ok1},${v_r1}=pcall(function()local ${v_meta}={${chosenOp.mm}=function(a,b)return ${randVal} end};local ${v_obj}=setmetatable({},${v_meta});return ${v_obj}${chosenOp.op}${v_obj};end);if not ${v_ok1} or ${v_r1}~=${randVal} then ${v_err}=${v_err}+1;end;`;
  const check3 = `local ${v_ok2},${v_r2}=pcall(function()local ${v_tbl}={};return({[${v_tbl}]=true})[${v_tbl}];end);if not ${v_ok2} or ${v_r2}~=true then ${v_err}=${v_err}+1;end;`;

  const checks = [check1, check2, check3];
  for (let i = checks.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [checks[i], checks[j]] = [checks[j], checks[i]];
  }

  const helper_hA = `${t_hA}=function(${v_arg1},${v_arg2})return bit32.bxor(${v_arg1},${v_arg2})end`;
  const helper_hB = `${t_hB}=function(${v_arg1},${v_arg2})return bit32.band(${v_arg1},${v_arg2})end`;
  const helper_hC = `${t_hC}=function(${v_inst})local ${v_err}=0;${checks.join('')}return ${v_err};end`;

  const crash_slot = Math.floor(Math.random() * 20) + 230;
  const bombPatterns = ["\\255\\0\\255\\0", "\\128\\64\\32\\16", "\\254\\1\\254\\1", "\\255\\255\\0\\0"];
  const bombPat = bombPatterns[Math.floor(Math.random() * bombPatterns.length)];
  const bombRep = [131072, 262144, 524288][Math.floor(Math.random() * 3)];
  const v_bmb = genDiverseToken(usedTokens);
  const v_str = genDiverseToken(usedTokens);
  const crash_bomb = `[${crash_slot}]=function(...) local ${v_bmb}={} local ${v_str}=string.rep("${bombPat}",${bombRep}) while true do table.insert(${v_bmb},${v_str}..tostring(math.random())) table.insert(${v_bmb},table.concat(${v_bmb})) end end`;

  // 5. Transform instruction stepping calculations:
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

  // Convert all [num]= in directVm
  directVm = directVm.replace(/\[(\d+)\]\s*=/g, (m, num) => `[${randomizeSlotMath(num)}]=`);

  // 6. Extract table constructor from directVm
  const vmMatch = /return setmetatable\(\{([\s\S]*)\},\{\}\):(\w+)\(\)\(\.\.\.\);?/.exec(directVm);
  if (!vmMatch) throw new Error("VM table pattern not found");
  const entryMethod = vmMatch[2];
  const body = vmMatch[1];

  const entryRegex = new RegExp(`${entryMethod}=function\\(\\w+\\)return function\\(\\.\\.\\.\\)return \\w+\\[(\\d+|0x[0-9a-fA-F\\+\\-]+)\\]\\(\\w+,\\.\\.\\.\\)end end`);
  const entrySlotMatch = entryRegex.exec(directVm);
  const validEntrySlot = entrySlotMatch ? entrySlotMatch[1] : "0x79";

  const newHelpers = `${helper_hA},${helper_hB},${helper_hC},${crash_bomb}`;
  const vmTableBody = `${body},${newHelpers}`;

  const v_ctx = genDiverseToken(usedTokens);
  const v_h = genDiverseToken(usedTokens);
  const v_slot = genDiverseToken(usedTokens);

  const randMul = [1664525, 214013, 1103515245, 134775813][Math.floor(Math.random() * 4)];
  const randInc = [1013904223, 2531011, 12345, 1][Math.floor(Math.random() * 4)];

  const r8Body = `local ${t_sig}; local ${v_ctx}={${vmTableBody}}; ${t_sig}=${v_ctx}.${t_hC}(${v_ctx}); while ${t_sig}~=0 do local ${v_h}=${t_sig}; while ${v_h}~=0 do ${v_h}=(${v_h}*${randMul}+${randInc})%4294967296; if ${v_h}==0 then ${v_h}=1 end end; end; local ${v_slot}=(${t_sig}==0) and ${validEntrySlot} or ${crash_slot}; return ${v_ctx}[${v_slot}](${v_ctx},...);`;
  const r8Entry = `${t_r8_entry}=function(i) return function(...) ${r8Body} end end,`;

  // 7. Randomize t8 and optimize dispatch for ultra-fast startup:
  const t8Regex = /t8=function\(i,\.\.\.\)([\s\S]*?)end,FR=/;
  const newT8Full = `${r8Entry}${t_entry_method}=function(i,...) local y,U,u,c,r,e,_,O,X,S,V,F,R=i:K8(); return i:${t_r8_entry}(); end,FR=`;
  template = template.replace(t8Regex, () => newT8Full);

  // Replace end call :t8()(...) with :{t_entry_method}()(...)
  template = template.replace(":t8()(...)", () => `:${t_entry_method}()(...)`);

  // 8. Safe fallback for Roblox datatypes
  const robloxTypes = ['Color3', 'Rect', 'UDim', 'UDim2', 'Vector2', 'Vector3'];
  for (const name of robloxTypes) {
    template = template.replaceAll(`${name}.new`, `(${name} and ${name}.new or function(...) return {} end)`);
  }

  // 9. Transform all "LPH" words to "NIL" outside payload
  template = template.replace(`${t_r8_prop}=${openBracket}LPH#`, `${t_r8_prop}=${openBracket}NIL#`);
  template = template.replaceAll('"LPH:"', '"NIL:"');

  // 10. Parse and shuffle root table fields
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
      if (ch === '[' && tableBody.startsWith(openBracket, i)) {
        const end = tableBody.indexOf(closeBracket, i + openBracket.length);
        if (end !== -1) { i = end + closeBracket.length; continue; }
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

  const rootMatch = /return setmetatable\(\{([\s\S]*)\},\{\}\):(\w+)\(\)\(\.\.\.\);?/.exec(template);
  if (!rootMatch) throw new Error("Root table not matched for shuffle");
  const entryCall = rootMatch[2];
  const fields = parseRootFields(rootMatch[1]);

  const processedFields = fields.map(f => {
    return f.replace(/^\[(\d+)\]\s*=/, (m, num) => `[${randomizeSlotMath(num)}]=`);
  });

  // Full Fisher-Yates shuffle across all fields
  for (let i = processedFields.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [processedFields[i], processedFields[j]] = [processedFields[j], processedFields[i]];
  }

  // 11. Random wrapper syntax pattern!
  const v_root = genDiverseToken(usedTokens);
  const wrapperPatterns = [
    () => `return setmetatable({${processedFields.join(',')}},{}):${entryCall}()(...);`,
    () => `return(setmetatable({${processedFields.join(',')}},{})):${entryCall}()(...);`,
    () => `local ${v_root}=setmetatable({${processedFields.join(',')}},{});return ${v_root}:${entryCall}()(...);`,
    () => `do local ${v_root}=setmetatable({${processedFields.join(',')}},{});return ${v_root}:${entryCall}()(...) end;`,
    () => `return(function(...)return setmetatable({${processedFields.join(',')}},{}):${entryCall}()(...)end)(...);`,
  ];
  const chosenWrapper = wrapperPatterns[Math.floor(Math.random() * wrapperPatterns.length)];
  template = chosenWrapper();

  // 12. Deep slot and index randomization across the entire code outside alien string
  const parts = template.split(`${t_r8_prop}=${openBracket}`);
  const beforeAlien = parts[0];
  const afterAlienAndRest = parts[1].split(`${closeBracket},`);
  const alienString = afterAlienAndRest[0];
  const afterAlien = afterAlienAndRest.slice(1).join(`${closeBracket},`);

  const randSlotReplacer = (m, num) => `[${randomizeSlotMath(num)}]=`;
  const randIdxReplacer = (m, obj, num) => randomizeIndexMath(obj, num);

  let cleanBefore = beforeAlien.replace(/\[(\d+)\]\s*=/g, randSlotReplacer);
  cleanBefore = cleanBefore.replace(/\b([a-zA-Z_][a-zA-Z0-9_]*)\[(\d+)\]/g, randIdxReplacer);

  let cleanAfter = afterAlien.replace(/\[(\d+)\]\s*=/g, randSlotReplacer);
  cleanAfter = cleanAfter.replace(/\b([a-zA-Z_][a-zA-Z0-9_]*)\[(\d+)\]/g, randIdxReplacer);

  template = cleanBefore + `${t_r8_prop}=${openBracket}` + alienString + `${closeBracket},` + cleanAfter;

  // 13. Randomized header comment
  const headers = [
    "-- This file was protected using Nil Obfuscator [https://nil.dev/]",
    "-- [NIL V5.1] Protected by Nil Engine (https://nil.dev/)",
    "-- << Protected by Nil Virtualizer >> [https://nil.dev/]",
    "-- Protected with Nil Obfuscator [https://nil.dev/]",
    "-- nil.dev - Protected Lua Bytecode [https://nil.dev/]"
  ];
  const header = headers[Math.floor(Math.random() * headers.length)];

  return header + "\n\n" + template.trim();
}
