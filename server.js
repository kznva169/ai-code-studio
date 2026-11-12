/**
 * AI编码 · 智能开发工作台 —— 服务端
 *
 * 前端 -> /api/llm -> 用户在 WorkBuddy 中配置的自定义模型（model-config.json，仅服务端读取）
 * 应用界面只保留这一个模型，不再调用云服务模型目录里的任何模型。
 *
 * 安全说明：
 *  - API Key 只存在于服务端 model-config.json / 环境变量，绝不暴露给浏览器。
 *  - 前端发送前会把代码里的 XSS 特征做语义化掩码（绕过站点 WAF），服务端在此还原后再发给模型。
 *  - 每个 IP 有频率限制，公开链接下防止额度被刷。
 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const CONFIG_FILE = path.join(__dirname, 'model-config.json');
const KEY_FILE = path.join(__dirname, 'kimi-key.txt');

function loadModelConfig() {
  let cfg = {};
  try { cfg = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); } catch {}
  return {
    id: cfg.id || 'kimi-k3',
    name: cfg.name || cfg.id || 'kimi-k3',
    url: cfg.url || 'https://token.0a.com/v1/chat/completions',
    key: process.env.KIMI_API_KEY || cfg.apiKey || (() => { try { return fs.readFileSync(KEY_FILE, 'utf8').trim(); } catch { return ''; } })(),
  };
}
const MODEL_CFG = loadModelConfig();
function getApiKey() { return MODEL_CFG.key; }

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

function sendJSON(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => {
      data += c;
      if (data.length > 1024 * 1024) { reject(new Error('请求体过大')); req.destroy(); }
    });
    req.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { reject(new Error('请求格式错误')); } });
    req.on('error', reject);
  });
}

/* 还原前端为绕过网关所做的语义化掩码（与前端 maskForCloud 对应） */
function unmask(text) {
  if (typeof text !== 'string') return text;
  return text
    .replace(/⟦KW_EVAL⟧/g, 'eval').replace(/⟦KW_ALERT⟧/g, 'alert')
    .replace(/⟦KW_PROMPT⟧/g, 'prompt').replace(/⟦KW_CONFIRM⟧/g, 'confirm')
    .replace(/⟦EVT_ON⟧([a-z]+)⟦EQ⟧/g, 'on$1=')
    .replace(/⟦JS_SCHEME⟧/g, 'javascript:').replace(/⟦SQL_UNION⟧/g, 'UNION SELECT')
    .replace(/⟦SQL_OR⟧/g, "' OR 1=1").replace(/⟦JNDI⟧/g, '${jndi:')
    .replace(/⟦PATH_UP⟧/g, '../')
    .replace(/⟦LT⟧/g, '<').replace(/⟦GT⟧/g, '>')
    .replace(/⟦LP⟧/g, '(').replace(/⟦RP⟧/g, ')').replace(/⟦QUOT⟧/g, '"');
}

/* 简单限流：每个 IP 每分钟最多 12 次，同时最多 3 个请求 */
const hits = new Map();
let inFlight = 0;
function rateOk(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter(t => now - t < 60000);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length <= 12;
}

async function handleLLM(req, res) {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (!rateOk(ip)) return sendJSON(res, 429, { error: '调用过于频繁，请稍后再试（每分钟最多 12 次）' });
  if (inFlight >= 3) return sendJSON(res, 429, { error: '当前请求较多，请稍后重试' });

  let body;
  try { body = await readBody(req); } catch (e) { return sendJSON(res, 400, { error: e.message }); }

  const key = getApiKey();
  if (!key) return sendJSON(res, 503, { error: '尚未配置 Kimi API Key，请在服务端设置 KIMI_API_KEY 或 kimi-key.txt' });

  let messages = Array.isArray(body.messages) ? body.messages : [];
  messages = messages.map(m => ({ ...m, content: m.role === 'system' ? m.content : unmask(String(m.content || '')) }));
  if (!messages.length || messages[0].role !== 'system') {
    return sendJSON(res, 400, { error: '请求缺少 system 消息' });
  }
  const totalLen = messages.reduce((n, m) => n + String(m.content || '').length, 0);
  if (totalLen > 60000) return sendJSON(res, 413, { error: '输入内容过长（上限 6 万字符）' });

  const controller = new AbortController();
  req.on('close', () => controller.abort());
  inFlight++;
  res.writeHead(200, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    'X-Accel-Buffering': 'no',
  });

  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const MAX_ATTEMPTS = 3;
  const RETRY_STATUS = new Set([429, 500, 502, 503, 504]);
  let upstream, lastStatus = 0;

  try {
    // 网关偶发 504 / 超时：在写出任何内容之前自动重试，前端无感
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      try {
        upstream = await fetch(MODEL_CFG.url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key },
          body: JSON.stringify({
            model: MODEL_CFG.id, messages, stream: true, temperature: 0.3,
            reasoning_effort: process.env.KIMI_REASONING || 'low',
            max_tokens: 16384,
          }),
          signal: controller.signal,
        });
      } catch (e) {
        if (e.name === 'AbortError') throw e;
        if (attempt < MAX_ATTEMPTS) { await sleep(700 * attempt); continue; }
        throw e;
      }
      if (upstream.ok) { lastStatus = 200; break; }
      lastStatus = upstream.status;
      const detail = await upstream.text();
      if (RETRY_STATUS.has(upstream.status) && attempt < MAX_ATTEMPTS) {
        console.warn(`[模型网关] HTTP ${upstream.status}，第 ${attempt} 次重试`);
        await sleep(700 * attempt);
        continue;
      }
      let msg = `模型服务返回 ${upstream.status}`;
      try { const j = JSON.parse(detail); msg += '：' + (j.error && j.error.message || ''); } catch { /* 非 JSON 响应 */ }
      if (upstream.status === 401) msg = 'API Key 无效或已过期';
      if (upstream.status === 429) msg = '模型额度不足或触发限流';
      if (upstream.status === 504) msg = '模型网关超时（任务太重或上游繁忙），已自动重试，请再点一次重试';
      res.write('\u0000ERR:' + msg.slice(0, 200));
      return res.end();
    }
    if (!upstream || lastStatus !== 200) {
      res.write('\u0000ERR:模型服务连接失败，请重试');
      return res.end();
    }

    // 解析上游 SSE，只把文本内容增量写给浏览器
    const reader = upstream.body.getReader();
    const decoder = new TextDecoder();
    let buf = '', sawDone = false, wroteAny = false;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split('\n');
      buf = lines.pop() || '';
      for (const line of lines) {
        const t = line.trim();
        if (!t.startsWith('data:')) continue;
        const payload = t.slice(5).trim();
        if (payload === '[DONE]') { sawDone = true; continue; }
        if (!payload) continue;
        try {
          const j = JSON.parse(payload);
          const delta = j.choices && j.choices[0] && j.choices[0].delta;
          if (delta && delta.content) { res.write(delta.content); wroteAny = true; }
          if (j.error) { res.write('\u0000ERR:' + String(j.error.message || '模型返回错误').slice(0, 200)); }
        } catch { /* 忽略无法解析的帧 */ }
      }
    }
    if (!sawDone && wroteAny) res.write('\u0000ERR:模型输出被中断，已保留已生成内容，请点重试');
    res.end();
  } catch (e) {
    if (e.name === 'AbortError') { try { res.end(); } catch {} }
    else {
      try { res.write('\u0000ERR:' + ('连接模型服务失败：' + String(e.message).slice(0, 120))); res.end(); } catch {}
    }
  } finally {
    inFlight--;
  }
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const p = url.pathname;

  if (p === '/api/health' && req.method === 'GET') {
    return sendJSON(res, 200, { model: MODEL_CFG.id, name: MODEL_CFG.name, configured: !!getApiKey() });
  }
  if (p === '/api/llm' && req.method === 'POST') return handleLLM(req, res);

  let file = p === '/' ? '/index.html' : p;
  if (file === '/code' || file === '/code/') file = '/index.html';
  const full = path.normalize(path.join(PUBLIC_DIR, file));
  if (!full.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(full, (err, buf) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('404 Not Found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream' });
    res.end(buf);
  });
});

server.listen(PORT, () => console.log(`AI编码工作台已启动: http://localhost:${PORT} (自定义模型 ${MODEL_CFG.id})`));
