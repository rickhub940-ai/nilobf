import { readFileSync } from 'node:fs';

// The next word's state consumes the actual plaintext, not a skip-ahead seed.
const rotate = (value, count) => ((value << count) | (value >>> (32 - count))) >>> 0;
export function encodeWordFeedbackBlock(plain, state, multiplier, increment, offset, reverse, nonlinearFeedback = false) {
  const out = Buffer.allocUnsafe(plain.length);
  const r = multiplier % 23 + 5, t = increment % 19 + 7;
  for (let at = 0; at < plain.length; at += 4) {
    const width = Math.min(4, plain.length - at);
    let value = 0;
    for (let j = 0; j < width; j++) value += plain[at + j] * 256 ** j;
    let key = (state * multiplier + increment + offset + at) >>> 0;
    if (nonlinearFeedback) key = (rotate(key, r) ^ rotate(state, t)) >>> 0;
    const cipher = (value ^ key) >>> 0;
    for (let j = 0; j < width; j++) out[reverse ? plain.length - 1 - at - j : at + j] = cipher >>> (j * 8) & 255;
    state = nonlinearFeedback ? ((rotate((key + value) >>> 0, t) ^ rotate(value, r) ^ state) + increment + offset + at) >>> 0 : (key + value * 257) >>> 0;
  }
  return { bytes: out, state };
}
export function encodeWordFeedback(...args) { return encodeWordFeedbackBlock(...args).bytes; }
export const wordFeedbackKernel = readFileSync(new URL('./word-feedback.lua', import.meta.url), 'utf8');
export function wordFeedbackRuntime(nonlinearFeedback = false) {
  if (!nonlinearFeedback) return wordFeedbackKernel;
  const key = 'local key=(seed*multiplier+increment+destination+cursor)%4294967296';
  const next = 'seed=(key+value*257)%4294967296';
  if (wordFeedbackKernel.split(key).length !== 3 || wordFeedbackKernel.split(next).length !== 3) throw new Error('Feedback kernel anchors changed');
  return wordFeedbackKernel
    .replace('local sum,weighted,cursor=0,0,0', 'local rotate=bit32.lrotate;local r,t=multiplier%23+5,increment%19+7\n local sum,weighted,cursor=0,0,0')
    .replaceAll(key, key + ';key=xor(rotate(key,r),rotate(seed,t))')
    .replaceAll(next, 'seed=(xor(rotate((key+value)%4294967296,t),rotate(value,r),seed)+increment+destination+cursor)%4294967296');
}
