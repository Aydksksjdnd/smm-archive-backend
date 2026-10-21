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
app.get('/api/products', wrap(async (_q, res) => res.json((await db.query('select * from products order by id desc')).rows)));
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
    res.json({ success: true, orderId: o.rows[0].id, total: final, status, payUrl: null }); // payUrl появится при подключении кассы
  } catch (e) { await cl.query('rollback'); throw e; } finally { cl.release(); }
}));
app.get('/api/orders/my', auth, wrap(async (req, res) => res.json((await db.query('select * from orders where user_id=$1 order by id desc', [req.user.id])).rows)));

// ---------- Админка ----------
const cleanImgs = a => (Array.isArray(a) ? a : []).filter(s => typeof s === 'string' && /^(data:image\/|https:\/\/)/.test(s)).slice(0, 8);
app.post('/api/admin/products', admin, wrap(async (req, res) => {
  const { title, category, price, description, badge, photos, sizes } = req.body;
  if (!title || !(Number(price) > 0)) return bad(res, 'Укажите название и цену');
  const r = await db.query('insert into products(title,category,price,description,badge,photos,sizes) values($1,$2,$3,$4,$5,$6,$7) returning *',
    [title, category || 'other', Number(price), description || '', badge || null, JSON.stringify(cleanImgs(photos)), JSON.stringify((Array.isArray(sizes) ? sizes : []).map(String).slice(0, 15))]);
  res.json({ success: true, product: r.rows[0] });
}));
app.delete('/api/admin/products/:id', admin, wrap(async (req, res) => {
  const id = toId(req.params.id); if (!id) return bad(res, 'Неверный ID');
  await db.query('delete from products where id=$1', [id]); res.json({ success: true });
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
  res.json({ success: true });
}));
app.get('/api/admin/users/search', admin, wrap(async (req, res) => {
  const q = `%${String(req.query.q || '').trim()}%`;
  res.json((await db.query('select id,login,email,balance from users where login ilike $1 or email ilike $1 order by id limit 10', [q])).rows);
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
db.query('select 1').then(seedAdmin).then(() => app.listen(PORT, () => console.log('Server started on port', PORT)))
  .catch(e => { console.error('Не удалось подключиться к базе:', e.message); process.exit(1); });
