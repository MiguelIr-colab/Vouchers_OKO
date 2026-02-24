require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { randomUUID, createHmac } = require('crypto');
const Stripe = require('stripe');

/* ================== ENV CHECK ================== */
if (!process.env.STRIPE_SECRET_KEY) throw new Error('Missing STRIPE_SECRET_KEY');
if (!process.env.STRIPE_WEBHOOK_SECRET) console.warn('⚠️ Missing STRIPE_WEBHOOK_SECRET');
if (!process.env.N8N_FORWARD_URL) console.warn('⚠️ Missing N8N_FORWARD_URL');

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: '2025-01-27.acacia',
  appInfo: { name: 'OKO Gift Cards', version: '2.0.0' },
});

const app = express();

/* ================== BASIC HARDENING ================== */
app.set('trust proxy', 1);
app.disable('x-powered-by');

/* Force HTTPS behind reverse proxy */
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.status(400).send('HTTPS required');
    }
    next();
  });
}

app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: false,
}));

/* ================== CORS ================== */
app.use(cors({
  origin: (origin, cb) => {
    const allow = (process.env.ALLOWED_ORIGINS || '')
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);

    if (!origin || allow.includes(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  },
  credentials: false,
}));

/* ================== GLOBAL RATE LIMIT ================== */
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
}));

/* ================== WEBHOOK (RAW BODY) ================== */
app.post('/webhook',
  express.raw({ type: 'application/json', limit: '1mb' }),
  async (req, res) => {

    const sig = req.headers['stripe-signature'];
    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error('Webhook signature failed:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      if (event.type === 'payment_intent.succeeded') {
        const pi = event.data.object;

        const forwardPayload = {
          event: 'gift_card_purchased',
          amount: pi.amount,
          currency: pi.currency,
          payment_intent_id: pi.id,
          created: pi.created,
          customer: {
            name: pi.metadata?.name || '',
            email: pi.metadata?.email || '',
            phone: pi.metadata?.phone || '',
          },
        };

        const headers = { 'Content-Type': 'application/json' };

        if (process.env.FORWARD_SIGNING_SECRET) {
          const signature = createHmac('sha256', process.env.FORWARD_SIGNING_SECRET)
            .update(JSON.stringify(forwardPayload))
            .digest('hex');
          headers['X-OKO-Signature'] = signature;
        }

        try {
          await fetch(process.env.N8N_FORWARD_URL, {
            method: 'POST',
            headers,
            body: JSON.stringify(forwardPayload),
            signal: AbortSignal.timeout(5000)
          });
        } catch (e) {
          console.error('Forward to n8n failed:', e.message);
        }
      }

    } catch (err) {
      console.error('Webhook handler error:', err);
    }

    return res.json({ received: true });
  }
);

/* ================== JSON PARSER ================== */
app.use(express.json({ limit: '200kb' }));

/* ================== PAYMENT LIMITER ================== */
const paymentLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
});

/* ================== CREATE PAYMENT INTENT ================== */
app.post('/create-payment-intent', paymentLimiter, async (req, res) => {
  try {
    const { amount, name, email, phone, message, preset } = req.body || {};

    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email' });
    }

    const PRESETS = [5000, 10000, 15000, 20000, 30000, 40000, 50000, 60000];
    const MIN = 3000;
    const MAX = 60000;

    let finalAmount = Number(amount);

    if (preset === true) {
      if (!Number.isInteger(finalAmount) || !PRESETS.includes(finalAmount)) {
        return res.status(400).json({ error: 'Invalid preset amount' });
      }
    } else {
      if (!Number.isInteger(finalAmount))
        return res.status(400).json({ error: 'Invalid amount' });

      if (finalAmount < MIN || finalAmount > MAX)
        return res.status(400).json({ error: 'Amount out of range' });
    }

    const safe = (v, n) => typeof v === 'string' ? v.slice(0, n) : undefined;

    const metadata = {
      name: safe(name, 120) || '',
      email: safe(email, 200) || '',
      phone: safe(phone, 50) || '',
      note: safe(message, 300) || '',
      purpose: 'gift_card',
    };

    const idempotencyKey = req.headers['x-idempotency-key'] || randomUUID();

    const pi = await stripe.paymentIntents.create({
      amount: finalAmount,
      currency: 'chf',
      automatic_payment_methods: { enabled: true },
      description: 'Restaurant Gift Card',
      metadata,
    }, { idempotencyKey });

    return res.json({
      clientSecret: pi.client_secret,
      paymentIntentId: pi.id,
      livemode: pi.livemode,
    });

  } catch (err) {
    console.error('create-payment-intent error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ================== HEALTH ================== */
app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/', (_req, res) => res.send('OKO giftcards API'));

/* ================== DEV DIAG ONLY ================== */
if (process.env.NODE_ENV !== 'production') {
  app.get('/__diag', async (_req, res) => {
    const key = process.env.STRIPE_SECRET_KEY || '';
    const mode = key.startsWith('sk_test_') ? 'TEST'
      : key.startsWith('sk_live_') ? 'LIVE' : 'UNKNOWN';
    res.json({ mode });
  });
}

/* ================== START ================== */
const PORT = Number(process.env.PORT || 4242);

app.listen(PORT, '0.0.0.0', () =>
  console.log(`Server running on :${PORT}`)
);

process.on('unhandledRejection', (r) => console.error('unhandledRejection', r));
process.on('uncaughtException', (e) => {
  console.error('uncaughtException', e);
  process.exit(1);
});

