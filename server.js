require('dotenv').config();
const express = require('express'), cors = require('cors'), bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'), crypto = require('crypto'), rateLimit = require('express-rate-limit');
const { Pool } = require('pg'), { Resend } = require('resend');

const { DATABASE_URL, JWT_SECRET, RESEND_API_KEY, ADMIN_LOGIN, ADMIN_PASSWORD, ADMIN_EMAIL,
  MAIL_FROM = 'SMM Archive <support@smmarchive.store>',
  FRONTEND_ORIGIN = 'https://smmarchive.store', PORT = 3000 } = process.env;
if (!DATABASE_URL || !JWT_SECRET || JWT_SECRET.length < 32) throw new Error('Нужны DATABASE_URL и JWT_SECRET (минимум 32 символа)');

const db = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;
// Почта: если заданы GMAIL_USER и GMAIL_APP_PASSWORD, письма идут через Gmail (SMTP, нужен платный Render), иначе через Resend
const { GMAIL_USER, GMAIL_APP_PASSWORD } = process.env;
const gmail = GMAIL_USER && GMAIL_APP_PASSWORD ? require('nodemailer').createTransport({ host: 'smtp.gmail.com', port: 465, secure: true,
  auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD }, connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 15000 }) : null;
const app = express();
app.set('trust proxy', 1);
app.use(cors({ origin: FRONTEND_ORIGIN.split(',').map(s => s.trim()), credentials: true }));
app.use(express.json({ limit: '12mb' }));

const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });
const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ success: false, message: 'Ошибка сервера' }); });
const bad = (res, message, code = 400) => res.status(code).json({ success: false, message });
const toId = v => { const n = Number(v); return Number.isSafeInteger(n) && n > 0 && n <= 2147483647 ? n : null; }; // защита от ошибки 22003
const sign = u => jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: '7d' });
const out = u => ({ success: true, token: sign(u), userId: u.id, name: u.login, login: u.login, balance: Number(u.balance),
  bonus_balance: Number(u.bonus_balance), referral_code: u.referral_code, is_admin: u.is_admin, is_tg_verified: u.is_tg_verified });

const auth = (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET); next(); }
  catch { bad(res, 'Нужен вход', 401); }
};
const admin = (req, res, next) => auth(req, res, async () => {
  try { const r = await db.query('select is_admin from users where id=$1', [req.user.id]); // права берём из базы, не из токена
    r.rows[0]?.is_admin === 1 ? next() : bad(res, 'Нет доступа', 403); } catch { bad(res, 'Ошибка сервера', 500); }
});

async function sendMail(to, subject, html) {
  if (gmail) { await gmail.sendMail({ from: `SMM Archive <${GMAIL_USER}>`, to, subject, html }); return; }
  if (!resend) throw new Error('Почта не настроена');
  const { error } = await resend.emails.send({ from: MAIL_FROM, to, subject, html });
  if (error) throw new Error(error.message);
}

// ---------- Регистрация и вход ----------
app.post('/api/auth/register', authLimit, wrap(async (req, res) => {
  const { login, password, email, phone } = req.body;
  if (!/^[\w.-]{3,30}$/.test(login || '') || !/^\S+@\S+\.\S+$/.test(email || '') || (password || '').length < 8)
    return bad(res, 'Логин 3–30 символов, настоящий email, пароль от 8 символов');
  const ex = await db.query('select is_email_verified v from users where lower(login)=lower($1) or lower(email)=lower($2)', [login, email]);
  if (ex.rows.some(u => u.v)) return bad(res, 'Логин или email уже заняты', 409);
  await db.query('delete from users where lower(login)=lower($1) or lower(email)=lower($2)', [login, email]); // старые неподтверждённые
  const code = String(crypto.randomInt(100000, 1000000));
  await db.query(`insert into users(login,email,phone,password_hash,referral_code,email_code,email_code_expires)
    values($1,$2,$3,$4,$5,$6,now()+interval '15 minutes')`,
    [login, email, phone || null, await bcrypt.hash(password, 10), crypto.randomBytes(4).toString('hex').toUpperCase(), code]);
  await sendMail(email, 'Код подтверждения SMM Archive', `<p>Ваш код подтверждения: <b style="font-size:22px">${code}</b></p><p>Он действует 15 минут.</p>`);
  res.json({ success: true, message: 'Код отправлен на почту' });
}));

app.post('/api/auth/verify', authLimit, wrap(async (req, res) => {
  const { login, code } = req.body;
  const r = await db.query('select * from users where lower(login)=lower($1)', [login || '']);
  const u = r.rows[0];
  if (!u || !u.email_code || u.email_code !== String(code) || new Date(u.email_code_expires) < new Date()) return bad(res, 'Неверный или просроченный код');
  await db.query('update users set is_email_verified=true, email_code=null, email_code_expires=null where id=$1', [u.id]);
  res.json(out(u));
}));

// ===== Telegram: привязка по коду, уведомления, рассылка =====
const { TELEGRAM_BOT_TOKEN, TELEGRAM_WEBHOOK_SECRET, TELEGRAM_BOT_USERNAME = 'smmarchive_bot' } = process.env;
const tgApi = (method, body) => fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/${method}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  .then(r => r.json()).catch(e => ({ ok: false, description: String(e) }));
const tgSend = (chat, text) => TELEGRAM_BOT_TOKEN ? tgApi('sendMessage', { chat_id: chat, text: String(text).slice(0, 4000), disable_web_page_preview: true }) : Promise.resolve({ ok: false });
const tgNotifyUser = async (userId, text) => { try { const r = await db.query('select tg_id from users where id=$1 and is_tg_verified=1', [userId]); if (r.rows[0] && r.rows[0].tg_id) await tgSend(r.rows[0].tg_id, text); } catch (e) { console.error('tg user', e.message); } };
const tgNotifyAdmins = async text => { try { const r = await db.query('select tg_id from users where is_admin=1 and is_tg_verified=1 and tg_id is not null'); for (const u of r.rows) await tgSend(u.tg_id, text); } catch (e) { console.error('tg admins', e.message); } };
async function setupTelegram() {
  const base = process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL;
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_WEBHOOK_SECRET || !base) return console.log('Telegram не настроен (нужны TELEGRAM_BOT_TOKEN и TELEGRAM_WEBHOOK_SECRET)');
  const r = await tgApi('setWebhook', { url: base.replace(/\/$/, '') + '/api/telegram/webhook', secret_token: TELEGRAM_WEBHOOK_SECRET, allowed_updates: ['message'] });
  console.log('Telegram webhook:', r.ok ? 'установлен' : 'ОШИБКА ' + r.description);
}
app.post('/api/telegram/webhook', wrap(async (req, res) => {
  if (!TELEGRAM_WEBHOOK_SECRET || req.get('x-telegram-bot-api-secret-token') !== TELEGRAM_WEBHOOK_SECRET) return res.sendStatus(403);
  res.sendStatus(200);
  const m = req.body && req.body.message; if (!m || !m.chat || m.chat.type !== 'private') return;
  const chat = String(m.chat.id), text = String(m.text || '').trim();
  if (/^\d{6}$/.test(text)) {
    const r = await db.query('select id,login from users where tg_code=$1', [text]);
    if (!r.rows[0]) return void tgSend(chat, 'Код не найден или уже использован. Получите новый код в личном кабинете на сайте.');
    await db.query('update users set tg_id=null, is_tg_verified=0 where tg_id=$1', [chat]); // один Telegram = один аккаунт
    await db.query('update users set tg_id=$1, is_tg_verified=1, tg_code=null where id=$2', [chat, r.rows[0].id]);
    return void tgSend(chat, `Готово! Telegram привязан к аккаунту ${r.rows[0].login}. Теперь здесь будут приходить статусы заказов и новости магазина. Отключить: /stop`);
  }
  if (text === '/stop') { await db.query('update users set tg_id=null, is_tg_verified=0 where tg_id=$1', [chat]); return void tgSend(chat, 'Уведомления отключены. Привязать снова можно в личном кабинете на сайте.'); }
  tgSend(chat, 'Здравствуйте! Это бот магазина SMM Archive. Чтобы получать уведомления, зайдите в личный кабинет на smmarchive.store, нажмите «Привязать Telegram» и отправьте сюда 6-значный код.');
}));
app.post('/api/telegram/code', auth, authLimit, wrap(async (req, res) => {
  if (!TELEGRAM_BOT_TOKEN) return bad(res, 'Telegram-бот пока не подключён', 503);
  const code = String(crypto.randomInt(100000, 1000000));
  await db.query('update users set tg_code=$1 where id=$2', [code, req.user.id]);
  res.json({ success: true, code, bot: TELEGRAM_BOT_USERNAME });
}));
app.post('/api/telegram/unlink', auth, wrap(async (req, res) => { await db.query('update users set tg_id=null, is_tg_verified=0, tg_code=null where id=$1', [req.user.id]); res.json({ success: true }); }));
app.get('/api/admin/telegram/stats', admin, wrap(async (_q, res) => res.json({ success: true, linked: Number((await db.query('select count(*) from users where is_tg_verified=1')).rows[0].count), configured: !!TELEGRAM_BOT_TOKEN })));
const bcLimit = rateLimit({ windowMs: 60 * 1000, max: 5 });
app.post('/api/admin/broadcast', admin, bcLimit, wrap(async (req, res) => {
  if (!TELEGRAM_BOT_TOKEN) return bad(res, 'Telegram-бот пока не подключён', 503);
  const text = String(req.body.text || '').trim(); if (!text) return bad(res, 'Введите текст');
  if (text.length > 3500) return bad(res, 'Слишком длинный текст (до 3500 символов)');
  const login = String(req.body.login || '').trim();
  const r = login ? await db.query('select id,tg_id from users where lower(login)=lower($1) and is_tg_verified=1 and tg_id is not null', [login])
    : await db.query('select id,tg_id from users where is_tg_verified=1 and tg_id is not null');
  if (!r.rows.length) return bad(res, login ? 'У этого пользователя не привязан Telegram' : 'Нет клиентов с привязанным Telegram');
  let sent = 0, failed = 0;
  for (const u of r.rows) {
    const d = await tgSend(u.tg_id, text);
    if (d.ok) sent++; else { failed++; if (d.error_code === 403) await db.query('update users set tg_id=null, is_tg_verified=0 where id=$1', [u.id]); } // человек заблокировал бота
    await new Promise(z => setTimeout(z, 50)); // лимит Telegram: не чаще ~20 сообщений в секунду
  }
  res.json({ success: true, sent, failed, total: r.rows.length });
}));

app.post('/api/auth/forgot', authLimit, wrap(async (req, res) => {
  const email = String(req.body.email || '').trim();
  const r = await db.query('select id from users where lower(email)=lower($1) and is_email_verified=true', [email]);
  if (r.rows[0]) {
    const code = String(crypto.randomInt(100000, 1000000));
    await db.query(`update users set email_code=$1, email_code_expires=now()+interval '15 minutes' where id=$2`, [code, r.rows[0].id]);
    await sendMail(email, 'Восстановление пароля SMM Archive', `<p>Код для смены пароля: <b style="font-size:22px">${code}</b></p><p>Он действует 15 минут. Если это были не вы, просто проигнорируйте письмо.</p>`);
  }
  res.json({ success: true, message: 'Если такая почта зарегистрирована, мы отправили на неё код' }); // одинаковый ответ, чтобы нельзя было угадывать почты
}));
app.post('/api/auth/reset', authLimit, wrap(async (req, res) => {
  const { email, code, password } = req.body;
  if ((password || '').length < 8) return bad(res, 'Пароль от 8 символов');
  const r = await db.query('select * from users where lower(email)=lower($1)', [String(email || '')]);
  const u = r.rows[0];
  if (!u || !u.email_code || u.email_code !== String(code) || new Date(u.email_code_expires) < new Date()) return bad(res, 'Неверный или просроченный код');
  await db.query('update users set password_hash=$1, email_code=null, email_code_expires=null where id=$2', [await bcrypt.hash(password, 10), u.id]);
  res.json({ success: true, message: 'Пароль изменён, теперь войдите' });
}));

app.post('/api/auth/login', authLimit, wrap(async (req, res) => {
  const { login, password } = req.body;
  const r = await db.query('select * from users where lower(login)=lower($1) or lower(email)=lower($1)', [login || '']);
  const u = r.rows[0];
  if (!u || !(await bcrypt.compare(password || '', u.password_hash))) return bad(res, 'Неверный логин или пароль', 401);
  if (!u.is_email_verified) return bad(res, 'Подтвердите почту: введите код из письма', 403);
  res.json(out(u));
}));

app.get('/api/auth/profile', auth, wrap(async (req, res) => {
  const r = await db.query('select * from users where id=$1', [req.user.id]);
  r.rows[0] ? res.json(out(r.rows[0])) : bad(res, 'Пользователь не найден', 404);
}));

// ---------- Публичные данные ----------
app.get('/api/products', wrap(async (_q, res) => res.json((await db.query('select * from products order by id desc')).rows.map(({ supplier_url, ...p }) => p)))); // ссылка поставщика покупателям не отдаётся
app.get('/api/admin/products', admin, wrap(async (_q, res) => res.json((await db.query('select * from products order by id desc')).rows))); // для админки: вместе со ссылкой поставщика
app.get('/api/news', wrap(async (_q, res) => res.json((await db.query('select * from news order by id desc limit 50')).rows)));
app.get('/api/reviews', wrap(async (_q, res) => res.json((await db.query('select id,name,rating,comment,created_at from reviews where approved order by id desc limit 50')).rows)));
app.post('/api/reviews', auth, wrap(async (req, res) => {
  const rating = parseInt(req.body.rating), comment = String(req.body.comment || '').trim().slice(0, 1000);
  if (!(rating >= 1 && rating <= 5) || comment.length < 3) return bad(res, 'Поставьте оценку и напишите отзыв');
  const u = (await db.query('select login from users where id=$1', [req.user.id])).rows[0];
  await db.query('insert into reviews(user_id,name,rating,comment) values($1,$2,$3,$4)', [req.user.id, u.login, rating, comment]);
  res.json({ success: true, message: 'Отзыв отправлен на модерацию' });
}));
app.post('/api/promo/check', wrap(async (req, res) => {
  const r = await db.query('select code,percent from promocodes where upper(code)=upper($1) and active and (max_uses is null or uses<max_uses)', [req.body.code || '']);
  r.rows[0] ? res.json({ success: true, ...r.rows[0] }) : bad(res, 'Промокод не найден', 404);
}));

// ---------- Заказы (цены берём ТОЛЬКО из базы) ----------
app.post('/api/orders', auth, wrap(async (req, res) => {
  const { items, delivery_method, address, name, phone, payment_method, promo } = req.body;
  if (!Array.isArray(items) || !items.length || !name || !phone || !address) return bad(res, 'Заполните все поля заказа');
  const ids = items.map(i => toId(i.id));
  if (ids.includes(null)) return bad(res, 'Неверный товар');
  const pr = (await db.query('select id,title,price from products where id=any($1)', [ids])).rows;
  let total = 0; const lines = [];
  for (const i of items) {
    const p = pr.find(x => x.id === toId(i.id)), q = parseInt(i.qty);
    if (!p || !(q > 0 && q <= 20)) return bad(res, 'Товар не найден или неверное количество');
    lines.push({ id: p.id, title: p.title, size: String(i.size || '').slice(0, 10), qty: q, price: Number(p.price) });
    total += Number(p.price) * q;
  }
  let discount = 0, code = null;
  if (promo) {
    const c = (await db.query('select code,percent from promocodes where upper(code)=upper($1) and active and (max_uses is null or uses<max_uses)', [promo])).rows[0];
    if (c) { discount = Math.round(total * c.percent / 100); code = c.code; }
  }
  const final = total - discount, method = payment_method === 'balance' ? 'balance' : 'yoomoney';
  const cl = await db.connect();
  try {
    await cl.query('begin');
    let status = 'Ожидает оплаты';
    if (method === 'balance') {
      const u = await cl.query('update users set balance=balance-$1 where id=$2 and balance>=$1', [final, req.user.id]);
      if (!u.rowCount) { await cl.query('rollback'); return bad(res, 'Недостаточно средств на балансе'); }
      status = 'Оплачен';
    }
    if (code) await cl.query('update promocodes set uses=uses+1 where code=$1', [code]);
    const o = await cl.query(`insert into orders(user_id,items,total,discount,promo_code,status,payment_method,delivery_method,address,name,phone)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) returning id`,
      [req.user.id, JSON.stringify(lines), final, discount, code, status, method, delivery_method || null, address, name, phone]);
    await cl.query('commit');
    tgNotifyUser(req.user.id, `Заказ №${o.rows[0].id} оформлен. Сумма: ${final} ₽. Статус: ${status}.`);
    tgNotifyAdmins(`Новый заказ №${o.rows[0].id}: ${final} ₽, ${name}, ${phone}. Статус: ${status}.`);
    res.json({ success: true, orderId: o.rows[0].id, total: final, status, payUrl: null }); // payUrl появится при подключении кассы
  } catch (e) { await cl.query('rollback'); throw e; } finally { cl.release(); }
}));
app.get('/api/orders/my', auth, wrap(async (req, res) => res.json((await db.query('select * from orders where user_id=$1 order by id desc', [req.user.id])).rows)));

// ---------- Отчёты о загрузке товаров в Telegram-группу ----------
const { TELEGRAM_REPORT_CHAT_ID, TELEGRAM_REPORT_BOT_TOKEN, REPORT_TZ = 'Europe/Moscow' } = process.env;
const CAT_RU = { jackets: 'Куртки', bombers: 'Бомберы', longsleeve: 'Лонгсливы', tshirt: 'Футболки', pants: 'Штаны', shoes: 'Обувь', bags: 'Сумки', accessories: 'Аксессуары', set: 'Сет одежды', other: 'Другое' };
const h = v => String(v == null ? '' : v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const cleanUrl = v => { const u = String(v || '').trim().slice(0, 1000); return /^https?:\/\//i.test(u) ? u : null; };
async function sendProductReport(action, adminId, product) {
  try {
    const token = TELEGRAM_REPORT_BOT_TOKEN || TELEGRAM_BOT_TOKEN;
    if (!token || !TELEGRAM_REPORT_CHAT_ID) return console.log('Отчёт не отправлен: нет TELEGRAM_REPORT_CHAT_ID');
    const who = (await db.query('select login from users where id=$1', [adminId])).rows[0]?.login || ('id ' + adminId);
    const date = new Date().toLocaleString('ru-RU', { timeZone: REPORT_TZ, day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
    let sizes = product.sizes; try { if (typeof sizes === 'string') sizes = JSON.parse(sizes); } catch {}
    const text = [action === 'create' ? '📦 <b>Новый товар загружен</b>' : '✏️ <b>Товар изменён</b>',
      `📅 Дата: ${h(date)}`, `👤 Админ: ${h(who)}`, `🏷 Название: ${h(product.title)}`,
      `📂 Категория: ${h(CAT_RU[product.category] || product.category)}`, `📐 Размеры: ${h(Array.isArray(sizes) ? sizes.join(', ') : sizes || '—')}`,
      `💰 Цена: ${h(Number(product.price).toLocaleString('ru-RU'))} ₽`, `🔗 Поставщик: ${product.supplier_url ? h(product.supplier_url) : 'не указана'}`].join('\n');
    const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ chat_id: TELEGRAM_REPORT_CHAT_ID, text, parse_mode: 'HTML', disable_web_page_preview: true }) }).then(x => x.json());
    if (!r.ok) console.error('Отчёт Telegram:', r.description);
  } catch (e) { console.error('sendProductReport', e.message); } // сбой отчёта не должен ломать загрузку товара
}

// ---------- Админка ----------
const cleanImgs = a => (Array.isArray(a) ? a : []).filter(s => typeof s === 'string' && /^(data:image\/|https:\/\/)/.test(s)).slice(0, 8);
app.post('/api/admin/products', admin, wrap(async (req, res) => {
  const { title, category, price, description, badge, photos, sizes, supplier_url } = req.body;
  if (!title || !(Number(price) > 0)) return bad(res, 'Укажите название и цену');
  const r = await db.query('insert into products(title,category,price,description,badge,photos,sizes,supplier_url) values($1,$2,$3,$4,$5,$6,$7,$8) returning *',
    [title, category || 'other', Number(price), description || '', badge || null, JSON.stringify(cleanImgs(photos)), JSON.stringify((Array.isArray(sizes) ? sizes : []).map(String).slice(0, 15)), cleanUrl(supplier_url)]);
  sendProductReport('create', req.user.id, r.rows[0]); // без await: ответ админу не ждёт Telegram
  const { supplier_url: _s, ...pub } = r.rows[0]; res.json({ success: true, product: pub });
}));
app.delete('/api/admin/products/:id', admin, wrap(async (req, res) => {
  const id = toId(req.params.id); if (!id) return bad(res, 'Неверный ID');
  await db.query('delete from products where id=$1', [id]); res.json({ success: true });
}));
app.patch('/api/admin/products/:id', admin, wrap(async (req, res) => {
  const id = toId(req.params.id); if (!id) return bad(res, 'Неверный ID');
  const { title, category, price, description, badge, photos, sizes, supplier_url } = req.body;
  if (!title || !(Number(price) > 0)) return bad(res, 'Укажите название и цену');
  const r = await db.query('update products set title=$1,category=$2,price=$3,description=$4,badge=$5,photos=$6,sizes=$7,supplier_url=$8 where id=$9 returning *',
    [title, category || 'other', Number(price), description || '', badge || null, JSON.stringify(cleanImgs(photos)), JSON.stringify((Array.isArray(sizes) ? sizes : []).map(String).slice(0, 15)), cleanUrl(supplier_url), id]);
  if (!r.rowCount) return bad(res, 'Товар не найден', 404);
  sendProductReport('update', req.user.id, r.rows[0]);
  res.json({ success: true });
}));
const aiLimit = rateLimit({ windowMs: 60 * 1000, max: 8 });
app.post('/api/admin/ai-describe', admin, aiLimit, wrap(async (req, res) => {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return bad(res, 'ИИ не подключён: добавьте ANTHROPIC_API_KEY в настройки Render', 503);
  const content = cleanImgs(req.body.photos).slice(0, 3).map(p => { const m = /^data:(image\/(?:jpeg|png|webp|gif));base64,(.+)$/.exec(p); return m && { type: 'image', source: { type: 'base64', media_type: m[1], data: m[2] } }; }).filter(Boolean);
  if (!content.length) return bad(res, 'Сначала загрузите фото');
  content.push({ type: 'text', text: `Ты копирайтер магазина архивного streetwear SMM Archive. Название: «${String(req.body.title || '').slice(0, 100)}», раздел: ${String(req.body.category || '').slice(0, 30)}. По фотографиям напиши описание для карточки товара на русском: цвет и заметные детали, что видно по исполнению (швы, фурнитура, подошва, принт), чем интересна именно эта вещь, затем 3–4 коротких совета по уходу для такого типа вещи. Состав ткани, бренд, год и размер указывай только если это видно на фото, иначе не выдумывай. 120–180 слов, без эмодзи и markdown, обычным текстом абзацами.` });
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: process.env.ANTHROPIC_MODEL || 'claude-haiku-5-5', max_tokens: 700, messages: [{ role: 'user', content }] })
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) { console.error('AI error', r.status, JSON.stringify(d).slice(0, 300)); return bad(res, 'ИИ сейчас недоступен: ' + ((d.error && d.error.message) || r.status), 502); }
  const text = (d.content || []).filter(b => b.type === 'text').map(b => b.text).join('\n').trim();
  text ? res.json({ success: true, description: text }) : bad(res, 'ИИ вернул пустой ответ', 502);
}));
app.post('/api/admin/news', admin, wrap(async (req, res) => {
  const { title, text, photo } = req.body;
  if (!title || !text) return bad(res, 'Нужны заголовок и текст');
  const r = await db.query('insert into news(title,text,photo) values($1,$2,$3) returning *', [title, text, cleanImgs([photo])[0] || null]);
  res.json({ success: true, news: r.rows[0] });
}));
app.delete('/api/admin/news/:id', admin, wrap(async (req, res) => {
  const id = toId(req.params.id); if (!id) return bad(res, 'Неверный ID');
  await db.query('delete from news where id=$1', [id]); res.json({ success: true });
}));
app.get('/api/admin/promos', admin, wrap(async (_q, res) => res.json((await db.query('select * from promocodes order by id desc')).rows)));
app.post('/api/admin/promos', admin, wrap(async (req, res) => {
  const code = String(req.body.code || '').trim().toUpperCase(), percent = parseInt(req.body.percent), max = req.body.max_uses ? parseInt(req.body.max_uses) : null;
  if (!/^[A-Z0-9_-]{3,20}$/.test(code) || !(percent >= 1 && percent <= 90)) return bad(res, 'Код 3–20 латинских символов, скидка 1–90%');
  try { await db.query('insert into promocodes(code,percent,max_uses) values($1,$2,$3)', [code, percent, max]); res.json({ success: true }); }
  catch (e) { if (e.code === '23505') return bad(res, 'Такой промокод уже есть', 409); throw e; }
}));
app.delete('/api/admin/promos/:id', admin, wrap(async (req, res) => {
  const id = toId(req.params.id); if (!id) return bad(res, 'Неверный ID');
  await db.query('delete from promocodes where id=$1', [id]); res.json({ success: true });
}));
app.get('/api/admin/orders', admin, wrap(async (_q, res) => res.json((await db.query('select * from orders order by id desc limit 200')).rows)));
app.patch('/api/admin/orders/:id', admin, wrap(async (req, res) => {
  const id = toId(req.params.id); if (!id) return bad(res, 'Неверный ID');
  const ok = ['Ожидает оплаты', 'Оплачен', 'В пути', 'Доставлен', 'Отменён'];
  if (req.body.status && !ok.includes(req.body.status)) return bad(res, 'Неверный статус');
  await db.query('update orders set status=coalesce($1,status), track_number=coalesce($2,track_number) where id=$3', [req.body.status || null, req.body.track_number || null, id]);
  if (req.body.status || req.body.track_number) {
    const o = (await db.query('select user_id,status,track_number from orders where id=$1', [id])).rows[0];
    if (o) tgNotifyUser(o.user_id, `Заказ №${id}: статус «${o.status}».` + (o.track_number ? ` Трек-номер: ${o.track_number}` : ''));
  }
  res.json({ success: true });
}));
app.get('/api/admin/users/search', admin, wrap(async (req, res) => {
  const q = `%${String(req.query.q || '').trim()}%`;
  res.json((await db.query('select id,login,email,balance,is_admin from users where login ilike $1 or email ilike $1 order by id limit 10', [q])).rows);
}));
app.post('/api/admin/users/:id/admin', admin, wrap(async (req, res) => {
  const id = toId(req.params.id); if (!id) return bad(res, 'Неверный ID');
  const me = (await db.query('select login from users where id=$1', [req.user.id])).rows[0];
  if (!me || !ADMIN_LOGIN || me.login.toLowerCase() !== ADMIN_LOGIN.toLowerCase()) return bad(res, 'Назначать админов может только главный администратор', 403);
  const t = (await db.query('select login,is_email_verified from users where id=$1', [id])).rows[0];
  if (!t) return bad(res, 'Пользователь не найден', 404);
  if (t.login.toLowerCase() === ADMIN_LOGIN.toLowerCase()) return bad(res, 'Права главного администратора менять нельзя');
  if (req.body.value && !t.is_email_verified) return bad(res, 'Почта пользователя не подтверждена');
  await db.query('update users set is_admin=$1 where id=$2', [req.body.value ? 1 : 0, id]);
  res.json({ success: true, is_admin: req.body.value ? 1 : 0 });
}));
app.post('/api/admin/users/:id/balance', admin, wrap(async (req, res) => {
  const id = toId(req.params.id), amount = Number(req.body.amount);
  if (!id || !Number.isFinite(amount) || amount === 0 || Math.abs(amount) > 1e6) return bad(res, 'Неверный ID или сумма');
  const r = await db.query('update users set balance=balance+$1 where id=$2 and balance+$1>=0 returning balance', [amount, id]);
  r.rowCount ? res.json({ success: true, balance: Number(r.rows[0].balance) }) : bad(res, 'Пользователь не найден или баланс уйдёт в минус');
}));
app.get('/api/admin/reviews', admin, wrap(async (_q, res) => res.json((await db.query('select * from reviews order by id desc limit 100')).rows)));
app.patch('/api/admin/reviews/:id', admin, wrap(async (req, res) => {
  const id = toId(req.params.id); if (!id) return bad(res, 'Неверный ID');
  await db.query('update reviews set approved=$1 where id=$2', [!!req.body.approved, id]); res.json({ success: true });
}));
app.delete('/api/admin/reviews/:id', admin, wrap(async (req, res) => {
  const id = toId(req.params.id); if (!id) return bad(res, 'Неверный ID');
  await db.query('delete from reviews where id=$1', [id]); res.json({ success: true });
}));

app.get('/', (_q, res) => res.send('SMM Archive API работает'));

// Главный админ создаётся из секретных настроек, а не из кода
async function seedAdmin() {
  if (!ADMIN_LOGIN || !ADMIN_PASSWORD || !ADMIN_EMAIL) return console.log('ADMIN_* не заданы: админ не создан');
  await db.query(`insert into users(login,email,password_hash,is_admin,is_email_verified,referral_code)
    values($1,$2,$3,1,true,$4) on conflict (lower(login)) do update set is_admin=1, password_hash=excluded.password_hash, is_email_verified=true`,
    [ADMIN_LOGIN, ADMIN_EMAIL, await bcrypt.hash(ADMIN_PASSWORD, 10), crypto.randomBytes(4).toString('hex').toUpperCase()]);
  console.log('Админ готов:', ADMIN_LOGIN);
}
db.query('alter table products add column if not exists supplier_url text').then(seedAdmin).then(() => app.listen(PORT, () => { console.log('Server started on port', PORT); setupTelegram().catch(e => console.error('setupTelegram', e.message)); }))
  .catch(e => { console.error('Не удалось подключиться к базе:', e.message); process.exit(1); });
