import { obfuscateLua } from '../lib/engine.mjs';

export const config = {
  maxDuration: 60,
};

// --- Limits -----------------------------------------------------------------
// Best-effort, in-memory rate limiting. On serverless each instance keeps its
// own counters, so this throttles bursts rather than providing a hard global
// quota. Put a real edge limiter (Vercel Firewall / WAF) in front for that.
const WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = 20;
const MAX_CODE_BYTES = 256 * 1024;
const hits = new Map(); // ip -> { count, resetAt }

function clientIp(req) {
  const fwd = req.headers?.['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length) return fwd.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

function checkRateLimit(ip) {
  const now = Date.now();
  let entry = hits.get(ip);
  if (!entry || entry.resetAt <= now) {
    entry = { count: 0, resetAt: now + WINDOW_MS };
    hits.set(ip, entry);
  }
  entry.count += 1;
  if (hits.size > 4096) {
    // Bound memory: drop expired windows eagerly.
    for (const [key, value] of hits) if (value.resetAt <= now) hits.delete(key);
  }
  return { allowed: entry.count <= MAX_REQUESTS_PER_WINDOW, retryAfter: Math.ceil((entry.resetAt - now) / 1000) };
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ status: 'error', message: 'Method Not Allowed' });
  }

  const rate = checkRateLimit(clientIp(req));
  if (!rate.allowed) {
    res.setHeader('Retry-After', String(rate.retryAfter));
    return res.status(429).json({ status: 'error', message: 'Rate limit exceeded. Try again later.' });
  }

  const contentLength = Number(req.headers?.['content-length'] ?? 0);
  if (Number.isFinite(contentLength) && contentLength > MAX_CODE_BYTES) {
    return res.status(413).json({ status: 'error', message: 'Request body too large' });
  }

  try {
    let luaCode = '';
    if (typeof req.body === 'string') {
      try {
        const parsed = JSON.parse(req.body);
        luaCode = parsed.code || parsed.script || '';
      } catch {
        luaCode = req.body;
      }
    } else if (req.body && typeof req.body === 'object') {
      luaCode = req.body.code || req.body.script || '';
    }

    if (!luaCode || !luaCode.trim()) {
      return res.status(400).json({ status: 'error', message: 'Lua source code is empty' });
    }

    if (Buffer.byteLength(luaCode, 'utf8') > MAX_CODE_BYTES) {
      return res.status(413).json({ status: 'error', message: 'Lua source exceeds the 256 KB limit' });
    }

    const start = Date.now();
    const obfuscated = obfuscateLua(luaCode);
    const duration = Date.now() - start;

    return res.status(200).json({
      status: 'success',
      original_size: Buffer.byteLength(luaCode, 'utf8'),
      obfuscated_size: Buffer.byteLength(obfuscated, 'utf8'),
      duration_ms: duration,
      obfuscated
    });

  } catch (err) {
    console.error('Obfuscation error:', err);
    const message = String(err?.message ?? 'Internal obfuscation failure').slice(0, 300);
    return res.status(500).json({
      status: 'error',
      message
    });
  }
}
