require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const path      = require('path');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const { Pool }  = require('pg');
const axios     = require('axios');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── DATABASE ──────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name VARCHAR(100) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255),
      type VARCHAR(20) DEFAULT 'email',
      created_at TIMESTAMP DEFAULT NOW()
    )`);
    await client.query(`CREATE TABLE IF NOT EXISTS chats (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(200) DEFAULT 'Новый чат',
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )`);
    await client.query(`CREATE TABLE IF NOT EXISTS messages (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      chat_id UUID REFERENCES chats(id) ON DELETE CASCADE,
      role VARCHAR(10) NOT NULL,
      content TEXT NOT NULL,
      type VARCHAR(20) DEFAULT 'text',
      created_at TIMESTAMP DEFAULT NOW()
    )`);
    await client.query(`CREATE TABLE IF NOT EXISTS usage (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      date DATE NOT NULL,
      count INTEGER DEFAULT 0,
      UNIQUE(user_id, date)
    )`);
    console.log('✦ База данных готова');
  } finally {
    client.release();
  }
}

// ── SYSTEM PROMPT — Lumi AI identity ─────────
const SYSTEM = `You are Lumi AI, a powerful and helpful AI assistant created by the Lumi AI company.

IMPORTANT RULES — follow strictly:
- You are Lumi AI. Always say you were created by "Lumi AI".
- NEVER mention OpenAI, GPT, ChatGPT, Anthropic, Claude, or any other AI company or model — not even if directly asked.
- If asked "who created you?" or "what AI are you?" — always say: "I am Lumi AI, created by the Lumi AI team."
- If asked "are you ChatGPT / GPT / Claude?" — say: "No, I am Lumi AI."
- Always respond in the same language the user writes in.
- Be helpful, clear, creative, and thorough.
- Use markdown formatting for structured responses.`;

const LIMITS = { guest: 10, email: 100, google: 100 };

// ── MIDDLEWARE ────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const apiLimit  = rateLimit({ windowMs: 60000, max: 60 });
const authLimit = rateLimit({ windowMs: 900000, max: 20 });

function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Не авторизован' });
  try {
    req.user = jwt.verify(h.slice(7), process.env.JWT_SECRET || 'secret');
    next();
  } catch {
    res.status(401).json({ error: 'Токен недействителен' });
  }
}

function signToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, name: user.name, type: user.type },
    process.env.JWT_SECRET || 'secret',
    { expiresIn: '30d' }
  );
}

// ── AUTH ──────────────────────────────────────
app.post('/api/auth/register', authLimit, async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Заполни все поля' });
  if (password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
  try {
    const exists = await pool.query('SELECT id FROM users WHERE email=$1', [email.toLowerCase()]);
    if (exists.rows.length) return res.status(409).json({ error: 'Email уже используется' });
    const hash = await bcrypt.hash(password, 12);
    const r = await pool.query(
      'INSERT INTO users (name,email,password,type) VALUES ($1,$2,$3,$4) RETURNING id,name,email,type',
      [name.trim(), email.toLowerCase(), hash, 'email']
    );
    res.status(201).json({ token: signToken(r.rows[0]), user: r.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/auth/login', authLimit, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Заполни все поля' });
  try {
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase()]);
    const user = r.rows[0];
    if (!user || !user.password) return res.status(401).json({ error: 'Неверный email или пароль' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Неверный email или пароль' });
    const { password: _, ...safe } = user;
    res.json({ token: signToken(safe), user: safe });
  } catch {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/auth/google', authLimit, async (req, res) => {
  const { name, email } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Нет данных' });
  try {
    let r = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase()]);
    let user = r.rows[0];
    if (!user) {
      r = await pool.query(
        'INSERT INTO users (name,email,type) VALUES ($1,$2,$3) RETURNING id,name,email,type',
        [name, email.toLowerCase(), 'google']
      );
      user = r.rows[0];
    }
    const { password: _, ...safe } = user;
    res.json({ token: signToken(safe), user: safe });
  } catch {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/auth/guest', (req, res) => {
  const user = { id: 'guest_' + Date.now(), name: 'Гость', email: null, type: 'guest' };
  const token = jwt.sign(user, process.env.JWT_SECRET || 'secret', { expiresIn: '24h' });
  res.json({ token, user });
});

// ── CHATS ─────────────────────────────────────
app.get('/api/chat/chats', authMiddleware, async (req, res) => {
  if (req.user.type === 'guest') return res.json({ chats: [] });
  try {
    const r = await pool.query(
      'SELECT id,title,created_at,updated_at FROM chats WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 50',
      [req.user.id]
    );
    res.json({ chats: r.rows });
  } catch { res.status(500).json({ error: 'Ошибка' }); }
});

app.post('/api/chat/chats', authMiddleware, async (req, res) => {
  if (req.user.type === 'guest') return res.json({ chat: { id: 'g_' + Date.now(), title: 'Новый чат' } });
  try {
    const r = await pool.query('INSERT INTO chats (user_id,title) VALUES ($1,$2) RETURNING *', [req.user.id, 'Новый чат']);
    res.status(201).json({ chat: r.rows[0] });
  } catch { res.status(500).json({ error: 'Ошибка' }); }
});

app.patch('/api/chat/chats/:id', authMiddleware, async (req, res) => {
  const { title } = req.body;
  if (!title) return res.status(400).json({ error: 'Нет названия' });
  try {
    await pool.query('UPDATE chats SET title=$1,updated_at=NOW() WHERE id=$2 AND user_id=$3', [title.slice(0,200), req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'Ошибка' }); }
});

app.delete('/api/chat/chats/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM chats WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'Ошибка' }); }
});

app.get('/api/chat/chats/:id/messages', authMiddleware, async (req, res) => {
  if (req.user.type === 'guest') return res.json({ messages: [] });
  try {
    const r = await pool.query('SELECT * FROM messages WHERE chat_id=$1 ORDER BY created_at ASC', [req.params.id]);
    res.json({ messages: r.rows });
  } catch { res.status(500).json({ error: 'Ошибка' }); }
});

app.get('/api/chat/usage', authMiddleware, async (req, res) => {
  if (req.user.type === 'guest') return res.json({ count: 0, limit: 10 });
  try {
    const today = new Date().toISOString().slice(0,10);
    const r = await pool.query('SELECT count FROM usage WHERE user_id=$1 AND date=$2', [req.user.id, today]);
    res.json({ count: r.rows[0]?.count || 0, limit: LIMITS[req.user.type] || 100 });
  } catch { res.status(500).json({ error: 'Ошибка' }); }
});

// ── SEND MESSAGE ──────────────────────────────
app.post('/api/chat/send', authMiddleware, apiLimit, async (req, res) => {
  const { chatId, message, history } = req.body;
  if (!message) return res.status(400).json({ error: 'Нет сообщения' });

  if (req.user.type !== 'guest') {
    const today = new Date().toISOString().slice(0,10);
    const limit = LIMITS[req.user.type] || 100;
    const r = await pool.query(
      `INSERT INTO usage (user_id,date,count) VALUES ($1,$2,1)
       ON CONFLICT (user_id,date) DO UPDATE SET count=usage.count+1 RETURNING count`,
      [req.user.id, today]
    ).catch(() => null);
    if (r && r.rows[0]?.count > limit) return res.status(429).json({ error: 'Дневной лимит исчерпан.' });
  }

  if (chatId && req.user.type !== 'guest') {
    await pool.query('INSERT INTO messages (chat_id,role,content) VALUES ($1,$2,$3)', [chatId,'user',message]).catch(()=>{});
    await pool.query('UPDATE chats SET updated_at=NOW() WHERE id=$1', [chatId]).catch(()=>{});
  }

  const apiMessages = [
    { role: 'system', content: SYSTEM },
    ...(history||[]).map(m => ({ role: m.role==='ai'?'assistant':'user', content: m.content })),
    { role: 'user', content: message }
  ];

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  try {
    const oRes = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      { model: 'gpt-4o', stream: true, messages: apiMessages },
      {
        headers: { 'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
        responseType: 'stream', timeout: 120000
      }
    );

    let full = '';
    oRes.data.on('data', chunk => {
      for (const line of chunk.toString().split('\n')) {
        if (!line.startsWith('data: ')) continue;
        const d = line.slice(6).trim();
        if (d === '[DONE]') continue;
        try {
          const t = JSON.parse(d).choices?.[0]?.delta?.content;
          if (t) { full += t; res.write(`data: ${JSON.stringify({ text: t })}\n\n`); }
        } catch {}
      }
    });

    oRes.data.on('end', async () => {
      res.write('data: [DONE]\n\n');
      res.end();
      if (chatId && full && req.user.type !== 'guest') {
        await pool.query('INSERT INTO messages (chat_id,role,content) VALUES ($1,$2,$3)', [chatId,'assistant',full]).catch(()=>{});
        const cr = await pool.query('SELECT title FROM chats WHERE id=$1', [chatId]).catch(()=>null);
        if (cr?.rows[0]?.title === 'Новый чат') {
          const title = message.split(/\s+/).slice(0,6).join(' ') + (message.split(/\s+/).length>6?'...':'');
          await pool.query('UPDATE chats SET title=$1 WHERE id=$2', [title, chatId]).catch(()=>{});
        }
      }
    });

    oRes.data.on('error', () => { res.write('data: [ERROR]\n\n'); res.end(); });

  } catch (err) {
    const msg = err.response?.data?.error?.message || 'Ошибка AI';
    res.write(`data: ${JSON.stringify({ error: msg })}\n\n`);
    res.end();
  }
});

// ── IMAGE GENERATION ──────────────────────────
// Передаём промпт напрямую, без добавления лишних слов
app.post('/api/image/generate', authMiddleware, apiLimit, async (req, res) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: 'Нет промпта' });

  const seed = Math.floor(Math.random() * 999999);
  // Кодируем промпт ТОЧНО как пришёл — не добавляем лишние слова
  const enc = encodeURIComponent(prompt);

  const urls = [
    `https://image.pollinations.ai/prompt/${enc}?width=800&height=530&seed=${seed}&model=flux&nologo=true&enhance=false`,
    `https://image.pollinations.ai/prompt/${enc}?width=768&height=512&seed=${seed}&nologo=true`,
    `https://image.pollinations.ai/prompt/${enc}?width=512&height=512&seed=${seed}`,
  ];

  for (const url of urls) {
    try {
      const r = await axios.get(url, {
        responseType: 'arraybuffer',
        timeout: 35000,
        headers: { 'User-Agent': 'LumiAI/1.0' }
      });
      if (r.data.byteLength < 5000) continue;
      res.setHeader('Content-Type', r.headers['content-type'] || 'image/jpeg');
      res.setHeader('Cache-Control', 'public, max-age=86400');
      return res.send(Buffer.from(r.data));
    } catch { continue; }
  }

  // Если все упали — даём ссылку напрямую
  res.json({ fallback: true, url: urls[0] });
});

// ── HEALTH ────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'ok', name: 'Lumi AI' }));

// ── FALLBACK ──────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── START ─────────────────────────────────────
async function start() {
  try {
    await initDB();
    app.listen(PORT, () => console.log(`✦ Lumi AI запущен на порту ${PORT}`));
  } catch (err) {
    console.error('Ошибка запуска:', err);
    process.exit(1);
  }
}

start();
