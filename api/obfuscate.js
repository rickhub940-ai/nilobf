import { obfuscateLua } from '../lib/engine.mjs';

export const config = {
  maxDuration: 60,
};

export default async function handler(req, res) {
  // CORS Headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ status: 'error', message: 'Method Not Allowed' });
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

    const start = Date.now();
    const obfuscated = obfuscateLua(luaCode);
    const duration = Date.now() - start;

    return res.status(200).json({
      status: 'success',
      original_size: luaCode.length,
      obfuscated_size: obfuscated.length,
      duration_ms: duration,
      obfuscated: obfuscated
    });

  } catch (err) {
    console.error('Obfuscation error:', err);
    return res.status(500).json({
      status: 'error',
      message: err.message || 'Internal obfuscation failure'
    });
  }
}
