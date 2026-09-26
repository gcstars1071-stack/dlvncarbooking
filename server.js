// ─────────────────────────────────────────────────────────────────────────
// DLHI VINA Vehicle Reservation — backend
//
// Serves the static app (public/index.html) and adds three concerns that
// cannot live safely in the browser:
//   1. SSO consume — verify a short-lived RS256 ticket minted by Task
//      (flowgantt) against its public JWKS, then start a real Car session.
//   2. Session    — an HttpOnly signed cookie, so identity is server-owned.
//   3. Telegram   — proxy sendMessage / getUpdates so the bot token stays in
//      a server env var and never ships to the browser.
//
// Data itself still lives in Firebase Firestore accessed from the browser
// (unchanged in this phase). Env vars are documented in .env.example.
// ─────────────────────────────────────────────────────────────────────────
import express from 'express';
import cookieParser from 'cookie-parser';
import { createRemoteJWKSet, jwtVerify, SignJWT } from 'jose';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
app.set('trust proxy', true);        // Railway sits behind a proxy (x-forwarded-*)
app.use(express.json({ limit: '256kb' }));
app.use(cookieParser());

const PORT = process.env.PORT || 8080;

// ── SSO config (from Task's provisional contract) ─────────────────────────
const SSO = {
  jwksUrl:  process.env.SSO_JWKS_URL  || 'https://task.dlhienergy.com.vn/.well-known/jwks.json',
  issuer:   process.env.SSO_ISSUER    || 'flowgantt',
  audience: process.env.SSO_AUDIENCE  || 'car',
};
const SSO_ENABLED = !!SSO.jwksUrl && !SSO.jwksUrl.startsWith('PASTE');
const jwks = SSO_ENABLED ? createRemoteJWKSet(new URL(SSO.jwksUrl)) : null;

// ── session config ────────────────────────────────────────────────────────
const SESSION_SECRET = new TextEncoder().encode(
  process.env.SESSION_SECRET || 'dev-only-insecure-session-secret-change-me'
);
const SESSION_COOKIE = 'car_session';
const SESSION_TTL_SEC = 12 * 60 * 60;   // 12h
const PROD = process.env.NODE_ENV === 'production';

// ── telegram config ───────────────────────────────────────────────────────
const TG_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TG_GROUP = process.env.TELEGRAM_CHAT_ID || '';   // group id(s), comma separated
const TG_ENABLED = !!TG_TOKEN;

// ── jti replay guard (single instance, 60s tickets → in-memory is enough) ──
const usedJti = new Set();
function rememberJti(jti, expSec) {
  usedJti.add(jti);
  const ttl = Math.max(0, expSec * 1000 - Date.now()) + 5000;
  const h = setTimeout(() => usedJti.delete(jti), ttl);
  h.unref?.();
}

// origin as the public sees it (Railway proxy rewrites host to internal addr)
function publicOrigin(req) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  const host  = req.headers['x-forwarded-host']  || req.headers['host'];
  return `${proto}://${host}`;
}

async function makeSessionCookie(identity) {
  const token = await new SignJWT({
    name: identity.name || '',
    username: identity.username || '',
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(identity.sub)
    .setIssuedAt()
    .setExpirationTime(`${SESSION_TTL_SEC}s`)
    .sign(SESSION_SECRET);
  return token;
}

function setSession(res, token) {
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: PROD,
    sameSite: 'lax',
    maxAge: SESSION_TTL_SEC * 1000,
    path: '/',
  });
}

// ── SSO consume: verify ticket → session → redirect home ──────────────────
app.get('/api/sso/consume', async (req, res) => {
  const origin = publicOrigin(req);
  const fail = (why) => {
    console.warn('[sso/consume] failed:', why);
    return res.redirect(`${origin}/?sso=failed`);
  };
  if (!SSO_ENABLED) return fail('SSO not configured');
  const ticket = req.query.ticket;
  if (!ticket || typeof ticket !== 'string') return fail('missing ticket');

  try {
    const { payload } = await jwtVerify(ticket, jwks, {
      issuer: SSO.issuer,
      audience: SSO.audience,
      algorithms: ['RS256'],      // pin — never let the lib auto-detect (alg confusion)
      clockTolerance: 30,         // ±30s skew
    });
    const sub = payload.sub;
    const jti = payload.jti;
    if (!sub || !jti) return fail('missing sub/jti');
    if (usedJti.has(jti)) return fail('ticket already used');
    rememberJti(jti, typeof payload.exp === 'number' ? payload.exp : Date.now() / 1000 + 60);

    const identity = {
      sub: String(sub),
      name: typeof payload.name === 'string' ? payload.name : '',
      username: typeof payload.preferred_username === 'string' ? payload.preferred_username : '',
    };
    const token = await makeSessionCookie(identity);
    setSession(res, token);
    return res.redirect(`${origin}/`);
  } catch (err) {
    return fail(err.message);
  }
});

// ── who am I (client reads this to bridge the cookie into its app state) ──
app.get('/api/me', async (req, res) => {
  const token = req.cookies[SESSION_COOKIE];
  if (!token) return res.json({ user: null });
  try {
    const { payload } = await jwtVerify(token, SESSION_SECRET, { algorithms: ['HS256'] });
    return res.json({
      user: {
        ssoSubject: `flowgantt:${payload.sub}`,
        sub: payload.sub,
        name: payload.name || '',
        username: payload.username || '',
      },
    });
  } catch {
    return res.json({ user: null });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(SESSION_COOKIE, { path: '/' });
  res.json({ ok: true });
});

// ── telegram proxy: send ──────────────────────────────────────────────────
// body: { text, recipients?: string[], replyTo?: { [chatId]: message_id } }
// returns { [chatId]: message_id } for the chats that accepted the message.
app.post('/api/notify', async (req, res) => {
  if (!TG_ENABLED) return res.json({});
  const { text, recipients = [], replyTo = {} } = req.body || {};
  if (!text || typeof text !== 'string') return res.status(400).json({ error: 'text required' });

  const ids = new Set();
  TG_GROUP.split(',').map((s) => s.trim()).filter(Boolean).forEach((x) => ids.add(x));
  (Array.isArray(recipients) ? recipients : []).forEach((x) => { if (x) ids.add(String(x).trim()); });

  const out = {};
  await Promise.all([...ids].map(async (id) => {
    try {
      const body = new URLSearchParams({ chat_id: id, text, disable_web_page_preview: 'true' });
      if (replyTo && replyTo[id]) {
        body.set('reply_to_message_id', String(replyTo[id]));
        body.set('allow_sending_without_reply', 'true');
      }
      const r = await fetch(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, { method: 'POST', body });
      const j = await r.json();
      if (j && j.ok && j.result) out[id] = j.result.message_id;
    } catch (e) {
      console.warn('[notify] send failed', id, e.message);
    }
  }));
  res.json(out);
});

// ── telegram proxy: recent private senders (for the Alerts tab) ───────────
app.get('/api/tg-updates', async (req, res) => {
  if (!TG_ENABLED) return res.json({ result: [] });
  try {
    const r = await fetch(`https://api.telegram.org/bot${TG_TOKEN}/getUpdates?_=${Date.now()}`);
    const j = await r.json();
    // only surface private-chat identities the client needs; never leak the token
    const people = [];
    (j.result || []).forEach((u) => {
      const c = (u.message || {}).chat;
      if (c && c.type === 'private') {
        people.push({ id: String(c.id), first_name: c.first_name || '', last_name: c.last_name || '', username: c.username || '' });
      }
    });
    res.json({ result: people });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.get('/healthz', (req, res) => res.json({ ok: true, sso: SSO_ENABLED, telegram: TG_ENABLED }));

// ── static app ────────────────────────────────────────────────────────────
app.use(express.static(join(__dirname, 'public'), { extensions: ['html'] }));
app.get('*', (req, res) => res.sendFile(join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => {
  console.log(`car-booking listening on :${PORT}  (sso=${SSO_ENABLED}, telegram=${TG_ENABLED})`);
});
