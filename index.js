require('dotenv').config();
const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const TikTokStrategy = require('passport-tiktok').Strategy;
const cookieParser = require('cookie-parser');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const path = require('path');
const helmet = require('helmet');
const csurf = require('csurf');
const { v4: uuidv4 } = require('uuid');
const app = express();

// Инициализация базы данных (должна быть до всех маршрутов)
const db = new sqlite3.Database('./spotizoom.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT,
    email TEXT,
    password TEXT,
    description TEXT,
    tiktok TEXT,
    instagram TEXT,
    facebook TEXT,
    telegram TEXT,
    youtube TEXT,
    provider TEXT,
    last_login INTEGER,
    device_id TEXT,
    ip TEXT,
    email_verified INTEGER DEFAULT 0,
    verify_token TEXT,
    subscribe_winner INTEGER DEFAULT 1
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS winners (
    date TEXT PRIMARY KEY,
    user_id TEXT,
    name TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    user_id TEXT,
    date TEXT,
    viewed INTEGER,
    PRIMARY KEY (user_id, date)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  )`);
  db.get("SELECT value FROM settings WHERE key = 'winner_time'", (err, row) => {
    if (!row) {
      db.run("INSERT INTO settings (key, value) VALUES ('winner_time', '00:39')");
    } else if (row.value !== '00:39') {
      db.run("UPDATE settings SET value = '00:39' WHERE key = 'winner_time'");
    }
  });
});


// Подключить парсеры cookie и urlencoded ДО всех маршрутов!
app.use(cookieParser());
app.use(express.urlencoded({ extended: true, limit: '10kb' }));


// Страница запроса сброса пароля (GET)
app.get('/reset-password-request', (req, res) => {
  res.render('reset-password-request', { error: null, message: null });
});

// Обработка формы сброса пароля (POST) — только одна версия!
app.post('/reset-password-request', (req, res) => {
  let email = null;
  if (req.body && typeof req.body.email === 'string') {
    email = req.body.email.trim().toLowerCase();
  }
  if (!email) return res.render('reset-password-request', { error: 'Введите email.', message: null });
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    // Не раскрываем, есть ли email в системе
    if (err || !user) {
      return res.render('reset-password-request', { error: null, message: 'Если такой email есть в системе, инструкция отправлена.' });
    }
    const nodemailer = require('nodemailer');
    const resetToken = require('uuid').v4();
    db.run('UPDATE users SET verify_token = ? WHERE email = ?', [resetToken, email], (err2) => {
      if (err2) return res.render('reset-password-request', { error: null, message: 'Если такой email есть в системе, инструкция отправлена.' });
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.GMAIL_USER,
          pass: process.env.GMAIL_PASS
        }
      });
      const resetUrl = `${req.protocol}://${req.get('host')}/reset-password?token=${resetToken}`;
      const mailOptions = {
        from: `Spotizoom <${process.env.GMAIL_USER}>`,
        to: email,
        subject: 'Spotizoom Password Reset',
        text: `To reset your password, click the link: ${resetUrl}`,
        html: `<p>To reset your password, click the link below:</p><p><a href="${resetUrl}">${resetUrl}</a></p>`
      };
      transporter.sendMail(mailOptions, () => {
        return res.render('reset-password-request', { error: null, message: 'Если такой email есть в системе, инструкция отправлена.' });
      });
    });
  });
});

// Страница сброса пароля (GET)
app.get('/reset-password', (req, res) => {
  const token = req.query.token;
  if (!token) return res.send('Некорректная ссылка для сброса пароля.');
  db.get('SELECT * FROM users WHERE verify_token = ?', [token], (err, user) => {
    if (err || !user) return res.send('Некорректная или устаревшая ссылка для сброса пароля.');
    res.render('reset-password', { token, error: null, message: null });
  });
});

// Обработка сброса пароля (POST)
app.post('/reset-password', (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.render('reset-password', { token, error: 'Введите новый пароль.', message: null });
  db.get('SELECT * FROM users WHERE verify_token = ?', [token], (err, user) => {
    if (err || !user) return res.render('reset-password', { token: null, error: 'Некорректная или устаревшая ссылка.', message: null });
    const bcrypt = require('bcryptjs');
    bcrypt.hash(password, 10, (err2, hash) => {
      if (err2) return res.render('reset-password', { token, error: 'Ошибка смены пароля.', message: null });
      db.run('UPDATE users SET password = ?, verify_token = NULL WHERE id = ?', [hash, user.id], (err3) => {
        if (err3) return res.render('reset-password', { token, error: 'Ошибка смены пароля.', message: null });
        res.render('reset-password', { token: null, error: null, message: 'Пароль успешно изменён! Теперь вы можете войти.' });
      });
    });
  });
});

// Подтверждение email по токену
app.get('/verify', (req, res) => {
  const token = req.query.token;
  if (!token) return res.send('Invalid verification link.');
  db.get('SELECT * FROM users WHERE verify_token = ?', [token], (err, user) => {
    if (err || !user) return res.send('Invalid or expired verification link.');
    db.run('UPDATE users SET email_verified = 1, verify_token = NULL WHERE id = ?', [user.id], (err2) => {
      if (err2) return res.send('Verification failed.');
      res.send('Email successfully verified! You can now log in.');
    });
  });
});
// Принудительный выбор нового победителя (только для админа)
// (Этот обработчик должен быть после const app = express();)
setImmediate(() => {
  app.post('/admin/force-winner', ensureAdmin, (req, res) => {
    const nowNY = require('moment-timezone')().tz('America/New_York');
    const today = nowNY.format('YYYY-MM-DD');
    const yesterday = nowNY.clone().subtract(24, 'hours').format('YYYY-MM-DD');
    db.all(`SELECT u.id, u.name FROM users u JOIN sessions s ON u.id = s.user_id WHERE s.date >= ? AND s.date <= ? AND s.viewed = 1`, [yesterday, today], (err, users) => {
      if (err) {
        return res.render('admin', { winnerTime: '', message: 'Ошибка выборки пользователей!' });
      }
      if (users && users.length > 0) {
        const winner = users[Math.floor(Math.random() * users.length)];
        db.run(`INSERT OR REPLACE INTO winners (date, user_id, name) VALUES (?, ?, ?)`, [today, winner.id, winner.name], (err2) => {
          if (err2) {
            return res.render('admin', { winnerTime: '', message: 'Ошибка сохранения победителя!' });
          }
          db.get("SELECT value FROM settings WHERE key = 'winner_time'", (err3, row) => {
            const winnerTime = row && row.value ? row.value : '19:00';
            res.render('admin', { winnerTime, message: 'Победитель выбран заново!' });
          });
        });
      } else {
        db.get("SELECT value FROM settings WHERE key = 'winner_time'", (err3, row) => {
          const winnerTime = row && row.value ? row.value : '19:00';
          res.render('admin', { winnerTime, message: 'Нет подходящих пользователей для выбора!' });
        });
      }
    });
  });
});
// Middleware для доступа только админу по email
function ensureAdmin(req, res, next) {
  if (!req.user) {
    console.error('[ADMIN] req.user отсутствует! path:', req.path, '| session:', req.session);
    return res.status(403).send('Доступ запрещён (нет пользователя)');
  }
  if (!req.user.email) {
    console.error('[ADMIN] req.user.email отсутствует! path:', req.path, '| user:', req.user);
    return res.status(403).send('Доступ запрещён (нет email)');
  }
  if (req.user.email === 'edmongaribian@gmail.com') {
    return next();
  }
  console.warn('[ADMIN] Попытка доступа не-админа:', req.user.email, '| path:', req.path);
  res.status(403).send('Доступ запрещён');
}
// Глобальный обработчик ошибок для Express
app.use((err, req, res, next) => {
  console.error('[GLOBAL ERROR]', err.stack || err);
  res.status(500).send('Внутренняя ошибка сервера. Попробуйте позже.');
});
// ...existing code...
// Подключить cookieParser до всех других app.use
app.use(cookieParser());
// Middleware: назначить уникальный device_id для каждого устройства (если нет)
app.use((req, res, next) => {
  if (!req.cookies) req.cookies = {};
  if (!req.cookies.device_id) {
    const deviceId = uuidv4();
    res.cookie('device_id', deviceId, { httpOnly: true, sameSite: 'lax', maxAge: 365*24*60*60*1000 });
    req.cookies.device_id = deviceId;
  }
  next();
});


db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT,
    email TEXT,
    password TEXT,
    description TEXT,
    tiktok TEXT,
    instagram TEXT,
    facebook TEXT,
    telegram TEXT,
    youtube TEXT,
    provider TEXT,
    last_login INTEGER,
    device_id TEXT,
    ip TEXT,
    email_verified INTEGER DEFAULT 0,
    verify_token TEXT,
    subscribe_winner INTEGER DEFAULT 1
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS winners (
    date TEXT PRIMARY KEY,
    user_id TEXT,
    name TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    user_id TEXT,
    date TEXT,
    viewed INTEGER,
    PRIMARY KEY (user_id, date)
  )`);

  // Таблица настроек для хранения времени выбора победителя
  db.run(`CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  )`);
  // Значение по умолчанию: 19:00 (7 вечера)
  db.get("SELECT value FROM settings WHERE key = 'winner_time'", (err, row) => {
    if (!row) {
      db.run("INSERT INTO settings (key, value) VALUES ('winner_time', '00:39')");
    } else if (row.value !== '00:39') {
      db.run("UPDATE settings SET value = '00:39' WHERE key = 'winner_time'");
    }
  });
});


app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "script-src": ["'self'", "'unsafe-inline'"],
        "img-src": ["'self'", "data:"],
      },
    },
  })
);

// Страница запроса сброса пароля (GET)
app.get('/reset-password-request', (req, res) => {
  res.render('reset-password-request', { error: null, message: null });
});

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    // secure: true, // включить для production с https
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 дней
  }
}));
app.use(passport.initialize());
app.use(passport.session());

// Логирование случаев, когда req.user не определён
app.use((req, res, next) => {
  if (typeof req.user === 'undefined') {
    console.log('[DEBUG] req.user is undefined for path:', req.path);
  }
  next();
});
// CSRF только для обычных форм, исключая аутентификацию
const csrfProtection = csurf();
app.use((req, res, next) => {
  // Не применять CSRF к маршрутам аутентификации
  const skip = [
    '/auth/google',
    '/auth/google/callback',
    '/auth/email',
    '/login',
    '/viewed',
    '/reset-password', // отключаем CSRF для сброса пароля
    '/reset-password-request' // отключаем CSRF для запроса сброса пароля
  ];
  if (skip.includes(req.path)) return next();
  return csrfProtection(req, res, next);
});
// CSRF-токен для всех форм
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken ? req.csrfToken() : '';
  next();
});
// Middleware для отметки просмотра главной страницы (теперь после passport.session)
// Удалено: просмотр засчитывается только через AJAX /viewed на главной странице

// Passport serialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser((id, done) => {
  db.get('SELECT * FROM users WHERE id = ?', [id], (err, user) => {
    done(err, user);
  });
});
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
}, (accessToken, refreshToken, profile, done) => {
  const email = (profile.emails && profile.emails[0] && profile.emails[0].value) ? profile.emails[0].value : null;
  db.get('SELECT * FROM users WHERE id = ?', [profile.id], (err, user) => {
    if (err) return done(err);
    if (user) {
      // Только обновляем name, email, provider, last_login
      db.run(`UPDATE users SET name = ?, email = ?, provider = 'google', last_login = ? WHERE id = ?`,
        [profile.displayName, email, Date.now(), profile.id], (err) => {
          if (err) return done(err);
          db.get('SELECT * FROM users WHERE id = ?', [profile.id], (err, user) => {
            if (err) return done(err);
            return done(null, user);
          });
        });
    } else {
      // Новый пользователь — все поля
      db.run(`INSERT INTO users (id, name, email, provider, last_login, description, tiktok, instagram, facebook, telegram, password) VALUES (?, ?, ?, 'google', ?, '', '', '', '', '', NULL)`,
        profile.id, profile.displayName, email, Date.now(), (err) => {
          if (err) return done(err);
          db.get('SELECT * FROM users WHERE id = ?', [profile.id], (err, user) => {
            if (err) return done(err);
            return done(null, user);
          });
        });
    }
  });
}));

// Google OAuth routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', {
  failureRedirect: '/login'
}), (req, res) => {
  res.redirect('/');
});

// Admin: страница и обработчик для смены времени выбора победителя

app.get('/admin', ensureAdmin, (req, res) => {
  db.get("SELECT value FROM settings WHERE key = 'winner_time'", (err, row) => {
    const winnerTime = row && row.value ? row.value : '19:00';
    res.render('admin', { winnerTime, message: null });
  });
});

app.post('/admin/time', ensureAdmin, (req, res) => {
  const newTime = req.body.winner_time;
  // Проверка формата ЧЧ:ММ
  if (!/^\d{2}:\d{2}$/.test(newTime)) {
    return db.get("SELECT value FROM settings WHERE key = 'winner_time'", (err, row) => {
      const winnerTime = row && row.value ? row.value : '19:00';
      res.render('admin', { winnerTime, message: 'Некорректный формат времени!' });
    });
  }
  db.run("UPDATE settings SET value = ? WHERE key = 'winner_time'", [newTime], function(err) {
    if (err || this.changes === 0) {
      // Если не обновилось (нет строки), пробуем вставить
      db.run("INSERT OR REPLACE INTO settings (key, value) VALUES ('winner_time', ?)", [newTime], (err2) => {
        if (!err2) {
          startWinnerCron(newTime);
        }
        db.get("SELECT value FROM settings WHERE key = 'winner_time'", (err3, row) => {
          const winnerTime = row && row.value ? row.value : '19:00';
          res.render('admin', { winnerTime, message: err2 ? 'Ошибка сохранения!' : 'Время успешно обновлено!' });
        });
      });
    } else {
      startWinnerCron(newTime);
      db.get("SELECT value FROM settings WHERE key = 'winner_time'", (err2, row) => {
        const winnerTime = row && row.value ? row.value : '19:00';
        res.render('admin', { winnerTime, message: err ? 'Ошибка сохранения!' : 'Время успешно обновлено!' });
      });
    }
  });
});

// Logout
app.get('/logout', function(req, res, next) {
  req.logout(function(err) {
    if (err) {
      console.error('Logout error:', err);
      return next(err);
    }
    req.session.destroy(() => {
      res.redirect('/');
    });
  });
});

// Главная страница
app.get('/', (req, res) => {
  const nowNY = require('moment-timezone')().tz('America/New_York');
  const todayNY = nowNY.format('YYYY-MM-DD');
  db.get("SELECT value FROM settings WHERE key = 'winner_time'", (err, row) => {
    const winnerTime = row && row.value ? row.value : '19:00';
    db.get(`SELECT w.*, u.name, u.description, u.tiktok, u.instagram, u.facebook, u.telegram, u.youtube, u.provider FROM winners w LEFT JOIN users u ON w.user_id = u.id WHERE w.date = ?`, [todayNY], (err, winner) => {
      let eligible = false;
      if (req.user) {
        db.get(`SELECT * FROM sessions WHERE user_id = ? AND date = ? AND viewed = 1`, [req.user.id, todayNY], (err, session) => {
          if (session) eligible = true;
          res.render('index', { user: req.user, winner, eligible, winnerTime });
        });
      } else {
        res.render('index', { user: null, winner, eligible: false, winnerTime });
      }
    });
  });
});

// Страница входа
app.get('/login', (req, res) => {
  res.render('login', { user: req.user, error: null, message: null });
});

// Вход через email
// Вход через email с ограничением на количество аккаунтов на устройство и IP, а также запрет временных email
const bcrypt = require('bcryptjs');
const tempMailDomains = [
  'mailinator.com', '10minutemail.com', 'guerrillamail.com', 'yopmail.com', 'tempmail.com', 'trashmail.com', 'getnada.com', 'dispostable.com', 'maildrop.cc', 'fakeinbox.com', 'sharklasers.com', 'spamgourmet.com', 'mailnesia.com', 'mintemail.com', 'throwawaymail.com', 'mailcatch.com', 'mytemp.email', 'temp-mail.org', 'moakt.com', 'emailondeck.com', 'mail-temp.com', 'tempail.com', 'tempinbox.com', 'temp-mail.io', 'mailpoof.com', 'mailbox52.ga', 'mvrht.com', 'mail7.io', 'dropmail.me', 'mail.tm', '1secmail.com', 'linshiyouxiang.net', 'mailnesia.com', 'mailnull.com', 'spambog.com', 'spambog.ru', 'spambog.com.br', 'spambog.de', 'spambog.net', 'spambog.xyz', 'spambog.pl', 'spambog.tk', 'spambog.cf', 'spambog.ga', 'spambog.ml', 'spambog.gq', 'spambog.eu', 'spambog.us', 'spambog.info', 'spambog.biz', 'spambog.org', 'spambog.site', 'spambog.top', 'spambog.space', 'spambog.store', 'spambog.email', 'spambog.pro', 'spambog.cc', 'spambog.co', 'spambog.me', 'spambog.app', 'spambog.dev', 'spambog.page', 'spambog.tech', 'spambog.xyz', 'spambog.club', 'spambog.online', 'spambog.site', 'spambog.fun', 'spambog.world', 'spambog.today', 'spambog.lol', 'spambog.run', 'spambog.click', 'spambog.link', 'spambog.team', 'spambog.group', 'spambog.zone', 'spambog.city', 'spambog.center', 'spambog.place', 'spambog.one', 'spambog.best', 'spambog.cool', 'spambog.expert', 'spambog.guru', 'spambog.io', 'spambog.ai', 'spambog.dev', 'spambog.app', 'spambog.page', 'spambog.tech', 'spambog.xyz', 'spambog.club', 'spambog.online', 'spambog.site', 'spambog.fun', 'spambog.world', 'spambog.today', 'spambog.lol', 'spambog.run', 'spambog.click', 'spambog.link', 'spambog.team', 'spambog.group', 'spambog.zone', 'spambog.city', 'spambog.center', 'spambog.place', 'spambog.one', 'spambog.best', 'spambog.cool', 'spambog.expert', 'spambog.guru', 'spambog.io', 'spambog.ai', 'spambog.dev', 'spambog.app', 'spambog.page', 'spambog.tech', 'spambog.xyz', 'spambog.club', 'spambog.online', 'spambog.site', 'spambog.fun', 'spambog.world', 'spambog.today', 'spambog.lol', 'spambog.run', 'spambog.click', 'spambog.link', 'spambog.team', 'spambog.group', 'spambog.zone', 'spambog.city', 'spambog.center', 'spambog.place', 'spambog.one', 'spambog.best', 'spambog.cool', 'spambog.expert', 'spambog.guru', 'spambog.io', 'spambog.ai', 'spambog.dev', 'spambog.app', 'spambog.page', 'spambog.tech', 'spambog.xyz', 'spambog.club', 'spambog.online', 'spambog.site', 'spambog.fun', 'spambog.world', 'spambog.today', 'spambog.lol', 'spambog.run', 'spambog.click', 'spambog.link', 'spambog.team', 'spambog.group', 'spambog.zone', 'spambog.city', 'spambog.center', 'spambog.place', 'spambog.one', 'spambog.best', 'spambog.cool', 'spambog.expert', 'spambog.guru', 'spambog.io', 'spambog.ai', 'spambog.dev', 'spambog.app', 'spambog.page', 'spambog.tech', 'spambog.xyz', 'spambog.club', 'spambog.online', 'spambog.site', 'spambog.fun', 'spambog.world', 'spambog.today', 'spambog.lol', 'spambog.run', 'spambog.click', 'spambog.link', 'spambog.team', 'spambog.group', 'spambog.zone', 'spambog.city', 'spambog.center', 'spambog.place', 'spambog.one', 'spambog.best', 'spambog.cool', 'spambog.expert', 'spambog.guru', 'spambog.io', 'spambog.ai', 'spambog.dev', 'spambog.app', 'spambog.page', 'spambog.tech', 'spambog.xyz', 'spambog.club', 'spambog.online', 'spambog.site', 'spambog.fun', 'spambog.world', 'spambog.today', 'spambog.lol', 'spambog.run', 'spambog.click', 'spambog.link', 'spambog.team', 'spambog.group', 'spambog.zone', 'spambog.city', 'spambog.center', 'spambog.place', 'spambog.one', 'spambog.best', 'spambog.cool', 'spambog.expert', 'spambog.guru', 'spambog.io', 'spambog.ai', 'spambog.dev', 'spambog.app', 'spambog.page', 'spambog.tech', 'spambog.xyz', 'spambog.club', 'spambog.online', 'spambog.site', 'spambog.fun', 'spambog.world', 'spambog.today', 'spambog.lol', 'spambog.run', 'spambog.click', 'spambog.link', 'spambog.team', 'spambog.group', 'spambog.zone', 'spambog.city', 'spambog.center', 'spambog.place', 'spambog.one', 'spambog.best', 'spambog.cool', 'spambog.expert', 'spambog.guru'];

// Middleware для ограничения регистрации по device_id и IP
// Ограничения только при регистрации (если пользователя с таким email нет)
app.use('/auth/email', (req, res, next) => {
  if (req.method === 'POST') {
    const email = req.body.email && req.body.email.toLowerCase();
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
      if (user) return next(); // Вход — пропускаем ограничения
      // Регистрация — применяем ограничения
      const deviceId = req.cookies && req.cookies.device_id ? req.cookies.device_id : undefined;
      const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
      // 1. Проверка временного email
      if (email) {
        const domain = email.split('@')[1];
        if (tempMailDomains.some(d => domain.endsWith(d))) {
          return res.render('login', { user: null, error: 'Temporary/disposable emails are not allowed.', message: null });
        }
      }
      // 2. Проверка device_id (не более 20 аккаунтов на устройство)
      db.all('SELECT id FROM users WHERE device_id = ?', [deviceId], (err, rows) => {
        if (rows && rows.length >= 20) {
          return res.render('login', { user: null, error: 'No more than 20 accounts per device are allowed.', message: null });
        }
        // 3. Проверка IP (не более 30 аккаунтов за 7 дней)
        const now = Date.now();
        const weekAgo = now - 7 * 24 * 60 * 60 * 1000;
        db.all('SELECT id, last_login FROM users WHERE ip = ?', [ip], (err2, rows2) => {
          const recentCount = (rows2 || []).filter(u => u.last_login && u.last_login >= weekAgo).length;
          if (recentCount >= 30) {
            return res.render('login', { user: null, error: 'No more than 30 accounts per IP per week are allowed.', message: null });
          }
          next();
        });
      });
    });
  } else {
    next();
  }
});

// При регистрации сохраняем device_id и ip
// ...existing code...
app.post('/auth/email', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.render('login', { user: null, error: 'Введите email и пароль.', message: null });
  }
  db.get('SELECT * FROM users WHERE email = ? AND provider = ?', [email, 'email'], (err, user) => {
    if (user) {
      // Проверка пароля через bcrypt (подтверждение email не требуется)
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (isMatch) {
          req.login(user, (err) => {
            if (err) return res.render('login', { user: null, error: 'Ошибка входа.', message: null });
            return res.redirect('/');
          });
        } else {
          // Просто показываем ошибку, не отправляем email
          return res.render('login', { user: null, error: 'Неверный пароль.', message: null });
        }
      });
    } else {
      // Регистрация нового пользователя с подтверждением email
      const nodemailer = require('nodemailer');
      const { v4: uuidv4 } = require('uuid');
      const verifyToken = uuidv4();
      bcrypt.hash(password, 10, (err, hash) => {
        const deviceId = req.cookies && req.cookies.device_id ? req.cookies.device_id : undefined;
        const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        db.run('INSERT INTO users (id, name, email, password, provider, last_login, device_id, ip, email_verified, verify_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)',
          uuidv4(), email, email, hash, 'email', Date.now(), deviceId, ip, verifyToken, (err) => {
            if (err) return res.render('login', { user: null, error: 'Registration error.', message: null });
            // Отправка письма
            const transporter = nodemailer.createTransport({
              service: 'gmail',
              auth: {
                user: process.env.GMAIL_USER,
                pass: process.env.GMAIL_PASS
              }
            });
            const verifyUrl = `${req.protocol}://${req.get('host')}/verify?token=${verifyToken}`;
            const mailOptions = {
              from: `Spotizoom <${process.env.GMAIL_USER}>`,
              to: email,
              subject: 'Confirm your email for Spotizoom',
              text: `Please confirm your email by clicking the link: ${verifyUrl}`,
              html: `<p>Please confirm your email by clicking the link below:</p><p><a href="${verifyUrl}">${verifyUrl}</a></p>`
            };
            transporter.sendMail(mailOptions, (error, info) => {
              if (error) {
                console.error('[EMAIL ERROR]', error);
                return res.render('login', { user: null, error: 'Failed to send confirmation email.', message: null });
              }
              console.log('[EMAIL SUCCESS] Confirmation email sent:', info && info.response ? info.response : info);
              res.render('login', { user: null, error: null, message: 'Регистрация успешна! Проверьте вашу почту для подтверждения.' });
            });
          });
      });
    }
  });
});

// Страница профиля (GET)
app.get('/profile', (req, res) => {
  console.log('USER:', req.user);
  if (!req.user) {
    return res.redirect('/login');
  }
  res.render('profile', { user: req.user });
});

// Страница политики конфиденциальности
app.get('/privacy', (req, res) => {
  const fs = require('fs');
  fs.readFile(path.join(__dirname, 'PRIVACY.md'), 'utf8', (err, data) => {
    if (err) return res.status(500).send('Ошибка загрузки политики.');
     res.render('privacy', { privacy: data, user: req.user });
  });
});

// Обработка редактирования профиля (POST)
app.post('/profile', (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  const newName = req.body.displayName;
  const description = req.body.description || '';
  const tiktok = req.body.tiktok || '';
  const instagram = req.body.instagram || '';
  const facebook = req.body.facebook || '';
  const telegram = req.body.telegram || '';
  const youtube = req.body.youtube || '';
  const subscribe_winner = req.body.subscribe_winner === '1' ? 1 : 0;
  db.run(`UPDATE users SET name = ?, description = ?, tiktok = ?, instagram = ?, facebook = ?, telegram = ?, youtube = ?, subscribe_winner = ? WHERE id = ?`,
    [newName, description, tiktok, instagram, facebook, telegram, youtube, subscribe_winner, req.user.id], (err) => {
    if (!err) {
      req.user.displayName = newName;
      req.user.description = description;
      req.user.tiktok = tiktok;
      req.user.instagram = instagram;
      req.user.facebook = facebook;
      req.user.telegram = telegram;
      req.user.youtube = youtube;
      req.user.subscribe_winner = subscribe_winner;
    }
    res.redirect('/profile');
  });
});



// Автоматический выбор победителя по времени из БД
const cron = require('node-cron');
const moment = require('moment-timezone');

let winnerCronTask = null;
let lastWinnerTime = null;

function startWinnerCron(time) {
  if (winnerCronTask) {
    winnerCronTask.stop();
    winnerCronTask = null;
  }
  const [hour, minute] = time.split(':');
  const cronExpr = `${minute} ${hour} * * *`;
  console.log('[CRON] cronExpr:', cronExpr, '| Нью-Йоркское время:', time);
  winnerCronTask = cron.schedule(cronExpr, () => {
    const nowNY = moment().tz('America/New_York');
    const today = nowNY.format('YYYY-MM-DD');
    const yesterday = nowNY.clone().subtract(24, 'hours').format('YYYY-MM-DD');
    console.log('[CRON] Сработал cron! Дата Нью-Йорка:', today, '| Ограничение по дате >=', yesterday);
    db.all(`SELECT u.id, u.name FROM users u JOIN sessions s ON u.id = s.user_id WHERE s.date >= ? AND s.date <= ? AND s.viewed = 1`, [yesterday, today], (err, users) => {
      if (err) {
        console.error('[CRON] Ошибка выборки пользователей:', err);
        return;
      }
      console.log('[CRON] Найдено пользователей для выбора:', users ? users.length : 0);
      if (users && users.length > 0) {
        const winner = users[Math.floor(Math.random() * users.length)];
        // Сохраняем победителя в БД
        db.run(`INSERT OR REPLACE INTO winners (date, user_id, name) VALUES (?, ?, ?)`, [today, winner.id, winner.name], (err2) => {
          if (err2) {
            console.error('[CRON] Ошибка сохранения победителя:', err2);
            return;
          }
          // Отправляем общее письмо всем подписанным
          db.all('SELECT email FROM users WHERE subscribe_winner = 1 AND email_verified = 1', (err3, rows) => {
            if (err3) {
              console.error('[CRON] Ошибка выборки email для рассылки:', err3);
              return;
            }
            if (rows && rows.length > 0) {
              const nodemailer = require('nodemailer');
              const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                  user: process.env.GMAIL_USER,
                  pass: process.env.GMAIL_PASS
                }
              });
              const siteUrl = process.env.SITE_URL || 'https://spotizoom.com';
              const mailOptions = {
                from: `Spotizoom <${process.env.GMAIL_USER}>`,
                bcc: rows.map(r => r.email).join(','),
                subject: 'Spotizoom: A new winner has been selected!',
                text: `A new winner has been selected on Spotizoom! Visit the homepage to see details: ${siteUrl}`,
                html: `<p>A new winner has been selected on Spotizoom!<br>Visit <a href="${siteUrl}">${siteUrl}</a> to see details.</p>`
              };
              transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                  console.error('[CRON] Ошибка отправки email:', error);
                } else {
                  console.log('[CRON] Уведомления о победителе отправлены:', info && info.response ? info.response : info);
                }
              });
            } else {
              console.log('[CRON] Нет подписчиков для рассылки уведомления о победителе.');
            }
          });
        });
      } else {
        console.log('[CRON] Нет подходящих пользователей для выбора победителя на', today);
      }
    });
  }, {
    timezone: 'America/New_York'
  });
  lastWinnerTime = time;
  console.log('[CRON] Текущее время выбора победителя:', time);
  console.log('Планировщик победителя запущен на', time, 'по Нью-Йорку');
}

function checkWinnerTimeUpdate() {
  db.get("SELECT value FROM settings WHERE key = 'winner_time'", (err, row) => {
    let time = '19:00';
    if (row && row.value) time = row.value;
    if (time !== lastWinnerTime) {
      startWinnerCron(time);
    }
  });
}

// Проверять обновление winner_time каждую минуту
setInterval(checkWinnerTimeUpdate, 60000);

// Запуск при старте
checkWinnerTimeUpdate();

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// AJAX-маршрут для отметки просмотра главной страницы
app.post('/viewed', (req, res) => {
  if (!req.user) return res.json({ success: false });
  // Используем дату Нью-Йорка для согласованности с cron
  const nowNY = require('moment-timezone')().tz('America/New_York');
  const todayNY = nowNY.format('YYYY-MM-DD');
  if (!req.session.viewedToday) {
    db.run(`INSERT OR REPLACE INTO sessions (user_id, date, viewed) VALUES (?, ?, 1)`, [req.user.id, todayNY], (err) => {
      if (err) return res.json({ success: false });
      req.session.viewedToday = true;
      return res.json({ success: true });
    });
  } else {
    return res.json({ success: true });
  }
});
