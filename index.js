/**
 * MaisonMind — Backend Proxy
 * Handles: server-side API key, BYO user key, rate limiting, usage tracking
 *
 * Requires environment variables (see .env.example):
 *   ANTHROPIC_API_KEY   — server-side Anthropic key (fallback)
 *   FIREBASE_PROJECT_ID — Firestore project
 *   FIREBASE_PRIVATE_KEY, FIREBASE_CLIENT_EMAIL — service account
 *   PORT                — default 3001
 *   ALLOWED_ORIGIN      — your frontend domain (CORS)
 *   USER_KEY_SECRET     — 32-char secret for AES-256 encryption
 */

'use strict';
require('dotenv').config();

const express      = require('express');
const cors         = require('cors');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const admin        = require('firebase-admin');
const crypto       = require('crypto');

// ─── Firebase init ────────────────────────────────────────────────────────────
admin.initializeApp({
  credential: admin.credential.cert({
    projectId:   process.env.FIREBASE_PROJECT_ID,
    privateKey:  process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
  }),
});
const db = admin.firestore();

// ─── Encryption helpers (AES-256-GCM) ────────────────────────────────────────
const ENC_SECRET = process.env.USER_KEY_SECRET;   // must be exactly 32 chars

function encryptKey(plaintext) {
  if (!ENC_SECRET || ENC_SECRET.length !== 32) {
    throw new Error('USER_KEY_SECRET must be exactly 32 characters');
  }
  const iv         = crypto.randomBytes(12);
  const cipher     = crypto.createCipheriv('aes-256-gcm', Buffer.from(ENC_SECRET), iv);
  const encrypted  = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag    = cipher.getAuthTag();
  // iv (12) + authTag (16) + ciphertext → hex
  return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted.toString('hex');
}

function decryptKey(storedValue) {
  if (!ENC_SECRET || ENC_SECRET.length !== 32) {
    throw new Error('USER_KEY_SECRET must be exactly 32 characters');
  }
  const [ivHex, authTagHex, encHex] = storedValue.split(':');
  const iv         = Buffer.from(ivHex, 'hex');
  const authTag    = Buffer.from(authTagHex, 'hex');
  const encrypted  = Buffer.from(encHex, 'hex');
  const decipher   = crypto.createDecipheriv('aes-256-gcm', Buffer.from(ENC_SECRET), iv);
  decipher.setAuthTag(authTag);
  return decipher.update(encrypted, undefined, 'utf8') + decipher.final('utf8');
}

// ─── API key validation helpers ───────────────────────────────────────────────
function isValidAnthropicKey(key) {
  // Anthropic keys start with sk-ant- and are typically 100+ chars
  return typeof key === 'string'
    && /^sk-ant-[a-zA-Z0-9\-_]{40,}$/.test(key.trim());
}

function maskKey(key) {
  if (!key || key.length < 12) return '***';
  return key.slice(0, 8) + '...' + key.slice(-4);
}

// ─── Rate limiters (server-key usage only) ───────────────────────────────────
//
// Per-IP burst limiter: 10 req/min at the transport level
const burstLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  keyGenerator: (req) => req.ip,
  skip: () => false,              // always enforced (even for BYO users at transport)
  message: { error: 'too_many_requests', message: 'Rallenta! Max 10 richieste/minuto.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── Per-user Firestore rate limit check (server-key path only) ───────────────
const SERVER_KEY_RPM   = 5;     // server-key users: max 5 AI calls/min
const SERVER_KEY_DAILY = 50;    // server-key users: max 50 AI calls/day

async function checkServerKeyRateLimit(userId) {
  const now      = Date.now();
  const minAgo   = now - 60_000;
  const dayStart = new Date();
  dayStart.setHours(0, 0, 0, 0);

  const usageRef = db.collection('usage').doc(userId);
  const snap     = await usageRef.get();
  const data     = snap.exists ? snap.data() : { rpm_calls: [], daily_count: 0, day: '' };

  // Sliding window RPM
  const recentCalls = (data.rpm_calls || []).filter(t => t > minAgo);
  if (recentCalls.length >= SERVER_KEY_RPM) {
    return { allowed: false, reason: 'rpm', recentCalls };
  }

  // Daily reset
  const todayStr = dayStart.toISOString().slice(0, 10);
  const dailyCount = data.day === todayStr ? (data.daily_count || 0) : 0;
  if (dailyCount >= SERVER_KEY_DAILY) {
    return { allowed: false, reason: 'daily', dailyCount };
  }

  return {
    allowed: true,
    recentCalls,
    dailyCount,
    todayStr,
    usageRef,
  };
}

async function recordServerKeyUsage(userId, checkResult, model) {
  const now = Date.now();
  const { recentCalls, dailyCount, todayStr, usageRef } = checkResult;

  await usageRef.set({
    rpm_calls:              [...recentCalls, now],
    daily_count:            dailyCount + 1,
    day:                    todayStr,
    last_used:              now,
    last_model:             model,
    key_type:               'server',
    total_analyses_lifetime: admin.firestore.FieldValue.increment(1),
  }, { merge: true });
}

// ─── Per-user BYO usage tracking (separate, no limits enforced) ──────────────
async function recordByoUsage(userId, model) {
  const now      = Date.now();
  const dayStart = new Date();
  dayStart.setHours(0, 0, 0, 0);
  const todayStr = dayStart.toISOString().slice(0, 10);

  const ref  = db.collection('usage_byo').doc(userId);
  const snap = await ref.get();
  const data = snap.exists ? snap.data() : {};

  const dailyCount = data.day === todayStr ? (data.daily_count || 0) : 0;

  await ref.set({
    daily_count: dailyCount + 1,
    day:         todayStr,
    total_calls: admin.firestore.FieldValue.increment(1),
    last_used:   now,
    last_model:  model,
    key_type:    'byo',
  }, { merge: true });
}

// ─── Retrieve user's decrypted personal key (if set) ─────────────────────────
async function getUserPersonalKey(userId) {
  const snap = await db.collection('user_api_keys').doc(userId).get();
  if (!snap.exists) return null;
  const { encrypted_key, provider } = snap.data();
  if (!encrypted_key) return null;
  try {
    return { key: decryptKey(encrypted_key), provider: provider || 'anthropic' };
  } catch {
    // decryption failure → treat as no key (don't expose)
    return null;
  }
}

// ─── Express app ──────────────────────────────────────────────────────────────
const app = express();

app.use(helmet());
app.use(express.json({ limit: '64kb' }));   // prevent oversized payloads
// CORS: accetta origini dalla variabile ALLOWED_ORIGINS (o tutte se *)
const allowedOrigins = (process.env.ALLOWED_ORIGINS || process.env.ALLOWED_ORIGIN || '*')
  .split(',').map(o => o.trim()).filter(Boolean);
const allowAll = allowedOrigins.includes('*');

app.use(cors({
  origin: function(origin, callback) {
    // Permetti sempre richieste senza origin (curl, Postman, mobile)
    if(!origin) return callback(null, true);
    // Permetti tutto se ALLOWED_ORIGINS=*
    if(allowAll) return callback(null, true);
    // Controlla lista origini
    if(allowedOrigins.includes(origin)) return callback(null, true);
    // Blocca
    callback(new Error('CORS: origine non consentita: ' + origin));
  },
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'X-User-Id', 'Authorization'],
  credentials: true,
}));

// ─── Firebase token verification middleware ──────────────────────────────────
// Verifica che la richiesta venga da un utente Firebase autenticato.
// Estrae l'UID reale dal token — ignora X-User-Id (non affidabile).
async function verifyFirebaseToken(req, res, next) {
  // Health check bypasses auth
  if (req.path === '/health') return next();

  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({
      error:   'unauthorized',
      message: 'Token di autenticazione mancante. Effettua il login.',
    });
  }

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    // Attach verified UID to request — all routes use this
    req.uid = decoded.uid;
    req.userEmail = decoded.email || '';
    next();
  } catch (err) {
    return res.status(401).json({
      error:   'invalid_token',
      message: 'Sessione scaduta. Effettua nuovamente il login.',
    });
  }
}

// Apply to ALL routes (before route definitions)
app.use(verifyFirebaseToken);

// ─────────────────────────────────────────────────────────────────────────────
// ROUTE 1: POST /api/chat
// Main proxy for Anthropic /v1/messages
// Headers required: X-User-Id (your auth system's uid)
// Body: { system, messages, model?, max_tokens? }
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/chat', burstLimiter, async (req, res) => {
  const userId = req.uid; // verified Firebase UID from token

  const { system, messages, model, max_tokens } = req.body;

  // Basic input validation
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'invalid_request', message: 'messages array required.' });
  }
  if (system && typeof system !== 'string') {
    return res.status(400).json({ error: 'invalid_request', message: 'system must be a string.' });
  }
  if (messages.length > 20) {
    return res.status(400).json({ error: 'invalid_request', message: 'Too many messages.' });
  }

  const resolvedModel      = typeof model === 'string' && /^claude-[a-z0-9\-\.]+$/.test(model)
    ? model
    : 'claude-sonnet-4-20250514';
  const resolvedMaxTokens  = typeof max_tokens === 'number' && max_tokens > 0 && max_tokens <= 4096
    ? max_tokens
    : 1000;

  let apiKey;
  let keyType;

  // ── Step 1: Try user's personal key ──────────────────────────────────────
  const personal = await getUserPersonalKey(userId);
  if (personal) {
    apiKey  = personal.key;
    keyType = 'byo';
  } else {
    // ── Step 2a: Enforce lifetime analysis limit (3 free analyses) ──────────
    const usageSnap = await db.collection('usage').doc(userId).get();
    const lifetimeCount = usageSnap.exists ? (usageSnap.data().total_analyses_lifetime || 0) : 0;
    if (lifetimeCount >= 3) {
      return res.status(429).json({
        error:   'analysis_limit_reached',
        reason:  'lifetime',
        message: 'Hai esaurito le 3 analisi gratuite. Inserisci la tua chiave API personale in ⚙️ Impostazioni per continuare.',
      });
    }
    // ── Step 2b: Enforce server-key rate limits ─────────────────────────────
    const check = await checkServerKeyRateLimit(userId);
    if (!check.allowed) {
      const msg = check.reason === 'rpm'
        ? `Limite di velocità raggiunto (${SERVER_KEY_RPM} richieste/min). Aggiungi la tua chiave API per richieste illimitate.`
        : `Limite giornaliero raggiunto (${SERVER_KEY_DAILY} richieste/giorno). Aggiungi la tua chiave API per continuare.`;
      return res.status(429).json({
        error:   'rate_limited',
        reason:  check.reason,
        message: msg,
      });
    }
    apiKey      = process.env.ANTHROPIC_API_KEY;
    keyType     = 'server';
    // Record usage optimistically (before the call, to prevent racing)
    await recordServerKeyUsage(userId, check, resolvedModel);
  }

  if (!apiKey) {
    return res.status(503).json({ error: 'service_unavailable', message: 'No API key available.' });
  }

  // ── Step 3: Forward to Anthropic ─────────────────────────────────────────
  try {
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model:      resolvedModel,
        max_tokens: resolvedMaxTokens,
        ...(system ? { system } : {}),
        messages,
      }),
    });

    const data = await upstream.json();

    if (!upstream.ok) {
      // Anthropic returned an error — don't expose raw error to client
      const status = upstream.status === 401 ? 401 : upstream.status === 429 ? 429 : 502;
      return res.status(status).json({
        error:   'upstream_error',
        message: upstream.status === 401
          ? 'Chiave API non valida. Controlla le impostazioni.'
          : `Errore AI (${upstream.status})`,
      });
    }

    // Track BYO usage after confirmed success
    if (keyType === 'byo') {
      recordByoUsage(userId, resolvedModel).catch(console.error); // non-blocking
    }

    // Return only what the frontend needs — never echo back keys
    return res.json({
      content:  data.content,
      key_type: keyType,         // tells frontend which source was used
    });

  } catch (err) {
    console.error('[/api/chat] upstream fetch failed:', err.message);
    return res.status(502).json({ error: 'upstream_unavailable', message: 'Servizio AI non raggiungibile.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ROUTE 2: POST /api/user/api-key
// Save or update user's personal API key
// Body: { key: "sk-ant-..." }
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/user/api-key', async (req, res) => {
  const userId = req.uid; // verified Firebase UID from token

  const rawKey = (req.body?.key || '').trim();

  if (!rawKey) {
    return res.status(400).json({ error: 'invalid_request', message: 'key is required.' });
  }

  // Validate format
  if (!isValidAnthropicKey(rawKey)) {
    return res.status(422).json({
      error:   'invalid_key_format',
      message: 'Formato chiave non valido. Le chiavi Anthropic iniziano con sk-ant-.',
    });
  }

  // Live validation: call /v1/models (cheap, read-only endpoint) to verify key works
  try {
    const testRes = await fetch('https://api.anthropic.com/v1/models', {
      headers: {
        'x-api-key':         rawKey,
        'anthropic-version': '2023-06-01',
      },
    });
    if (testRes.status === 401) {
      return res.status(422).json({
        error:   'key_rejected',
        message: 'Chiave API rifiutata da Anthropic. Verifica che sia corretta e attiva.',
      });
    }
    if (!testRes.ok && testRes.status !== 404) {
      // 404 on /v1/models is acceptable on some plans — not a key problem
      console.warn(`[api-key validation] unexpected status ${testRes.status} from Anthropic`);
    }
  } catch (err) {
    console.error('[api-key validation] network error:', err.message);
    return res.status(502).json({
      error:   'validation_failed',
      message: 'Impossibile verificare la chiave. Riprova più tardi.',
    });
  }

  // Encrypt and store
  try {
    const encrypted = encryptKey(rawKey);
    await db.collection('user_api_keys').doc(userId).set({
      encrypted_key: encrypted,
      provider:      'anthropic',
      key_hint:      maskKey(rawKey),     // e.g. "sk-ant-..." for UI display only
      updated_at:    admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });

    return res.json({
      success:  true,
      key_hint: maskKey(rawKey),
      message:  'Chiave API salvata con successo.',
    });
  } catch (err) {
    console.error('[api-key save] error:', err.message);
    return res.status(500).json({ error: 'save_failed', message: 'Salvataggio fallito. Riprova.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ROUTE 3: GET /api/user/api-key/status
// Returns whether a personal key is set (and its masked hint) — never the key itself
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/user/api-key/status', async (req, res) => {
  const userId = req.uid; // verified Firebase UID from token

  const snap = await db.collection('user_api_keys').doc(userId).get();
  if (!snap.exists || !snap.data()?.encrypted_key) {
    return res.json({ has_key: false });
  }

  return res.json({
    has_key:    true,
    key_hint:   snap.data().key_hint || '***',
    provider:   snap.data().provider || 'anthropic',
    updated_at: snap.data().updated_at,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// ROUTE 4: DELETE /api/user/api-key
// Remove user's personal API key
// ─────────────────────────────────────────────────────────────────────────────
app.delete('/api/user/api-key', async (req, res) => {
  const userId = req.uid; // verified Firebase UID from token

  await db.collection('user_api_keys').doc(userId).delete();
  return res.json({ success: true, message: 'Chiave API rimossa.' });
});

// ─────────────────────────────────────────────────────────────────────────────
// ROUTE 5: GET /api/user/usage
// Returns current usage counters for the requesting user
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/user/usage', async (req, res) => {
  const userId = req.uid; // verified Firebase UID from token

  const [serverSnap, byoSnap, keySnap] = await Promise.all([
    db.collection('usage').doc(userId).get(),
    db.collection('usage_byo').doc(userId).get(),
    db.collection('user_api_keys').doc(userId).get(),
  ]);

  const now      = Date.now();
  const minAgo   = now - 60_000;
  const dayStart = new Date(); dayStart.setHours(0,0,0,0);
  const todayStr = dayStart.toISOString().slice(0,10);

  const sv   = serverSnap.exists ? serverSnap.data() : {};
  const bv   = byoSnap.exists ? byoSnap.data() : {};
  const hasKey = keySnap.exists && !!keySnap.data()?.encrypted_key;

  const recentRpm = (sv.rpm_calls || []).filter(t => t > minAgo).length;
  const dailySv   = sv.day === todayStr ? (sv.daily_count || 0) : 0;
  const dailyByo  = bv.day === todayStr ? (bv.daily_count || 0) : 0;

  return res.json({
    has_personal_key:        hasKey,
    total_analyses_lifetime: sv.total_analyses_lifetime || 0,
    server_key: {
      rpm_used:    recentRpm,
      rpm_limit:   SERVER_KEY_RPM,
      daily_used:  dailySv,
      daily_limit: SERVER_KEY_DAILY,
    },
    byo_key: {
      daily_used:  dailyByo,
      total_calls: bv.total_calls || 0,
    },
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Health check
// ─────────────────────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Brigata proxy listening on :${PORT}`));
