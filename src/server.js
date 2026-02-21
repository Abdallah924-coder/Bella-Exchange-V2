const path = require('path');
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { readJSON, writeJSON, ensureFile, initializeDataStore } = require('./db');
const { sendEmail } = require('./mailer');
const { sendTelegramMessage, sendTelegramProof } = require('./telegram');
require('dotenv').config();

const app = express();
const port = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';

if (isProduction) {
  app.set('trust proxy', 1);
}

const uploadDir = path.join(__dirname, '..', 'uploads');
const fs = require('fs');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 }
});

const CRYPTOS = ['BTC', 'ETH', 'BNB', 'SOL', 'POL', 'USDT', 'USDC', 'TRON', 'XRP', 'ADA'];
const NETWORKS = ['BTC', 'ERC20', 'TRC20', 'BEP20', 'SOL', 'POLYGON'];
const CRYPTO_NETWORKS = {
  BTC: ['BTC'],
  ETH: ['ERC20'],
  BNB: ['BEP20'],
  SOL: ['SOL'],
  POL: ['POLYGON'],
  USDT: ['ERC20', 'TRC20', 'BEP20'],
  USDC: ['ERC20', 'TRC20', 'BEP20'],
  TRON: ['TRC20'],
  XRP: ['ERC20'],
  ADA: ['ERC20']
};
const PRICE_IDS = {
  BTC: 'bitcoin',
  ETH: 'ethereum',
  BNB: 'binancecoin',
  SOL: 'solana',
  POL: 'matic-network',
  USDT: 'tether',
  USDC: 'usd-coin',
  TRON: 'tron',
  XRP: 'ripple',
  ADA: 'cardano'
};

let pricesCache = { updatedAt: null, prices: null };
const PRICE_REFRESH_MS = Number(process.env.PRICE_REFRESH_MS || 300000);

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function escapeTelegramHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function isStrongPassword(password) {
  const value = String(password || '');
  return value.length >= 8 &&
    /[a-z]/.test(value) &&
    /[A-Z]/.test(value) &&
    /\d/.test(value) &&
    /[^A-Za-z0-9]/.test(value);
}

ensureFile('users.json', []);
ensureFile('transactions.json', []);
ensureFile('messages.json', []);
ensureFile('password_resets.json', []);
ensureFile('settings.json', {
  buyRate: 635,
  sellRate: 590,
  phoneNumber: '06 668 94 48',
  recipientName: 'Michy Magellan DEVOUE-LI-MBOUITY',
  prices: {
    BTC: 98500,
    ETH: 5400,
    BNB: 730,
    SOL: 190,
    POL: 0.95,
    USDT: 1,
    USDC: 1,
    TRON: 0.21,
    XRP: 1.2,
    ADA: 1.1
  },
  depositAddresses: {
    BTC: { BTC: '1F7nZDdEw6AcEWRWG18LLDCiHggh3vYFoW' },
    ETH: { ERC20: '0x90439961b090f8b51c28023e30213e318db227f3' },
    BNB: { BEP20: '0x90439961b090f8b51c28023e30213e318db227f3' },
    SOL: { SOL: '4rFEr619w8g96qFBd9DcrUjTDSFXbtCC3iDfANVEYPz5' },
    POL: { POLYGON: '0x90439961b090f8b51c28023e30213e318db227f3' },
    USDT: {
      ERC20: '0x90439961b090f8b51c28023e30213e318db227f3',
      TRC20: 'TATtuLm5JBWHZvtACk2AJ2iqPGJRpnZ5Rt',
      BEP20: '0x90439961b090f8b51c28023e30213e318db227f3'
    },
    USDC: {
      ERC20: '0x90439961b090f8b51c28023e30213e318db227f3',
      TRC20: 'TATtuLm5JBWHZvtACk2AJ2iqPGJRpnZ5Rt',
      BEP20: '0x90439961b090f8b51c28023e30213e318db227f3'
    },
    TRON: { TRC20: 'TATtuLm5JBWHZvtACk2AJ2iqPGJRpnZ5Rt' },
    XRP: { ERC20: 'rNxp4h8apvRis6mJf9Sh8C6iRxfrDWN7AV' },
    ADA: { ERC20: 'addr1vydyaf6zcg98yujwqutdgla4x64kr854nz6q67dvzk2t7hc2ancw5' }
  }
});

async function bootstrapAdmin() {
  const users = readJSON('users.json', []);
  const adminEmail = normalizeEmail(process.env.ADMIN_EMAIL || 'admin@bellaexchange.cg');
  const existingAdmin = users.find((u) => normalizeEmail(u.email) === adminEmail);
  const adminPhone = String(process.env.ADMIN_PHONE || '242 06 114 97 92').trim();
  if (existingAdmin) {
    let changed = false;
    if (existingAdmin.role !== 'admin') {
      existingAdmin.role = 'admin';
      changed = true;
    }
    if (adminPhone && existingAdmin.phone !== adminPhone) {
      existingAdmin.phone = adminPhone;
      changed = true;
    }
    if (changed) {
      writeJSON('users.json', users);
    }
    return;
  }

  const password = process.env.ADMIN_PASSWORD || 'Admin123!';
  const passwordHash = await bcrypt.hash(password, 10);
  users.push({
    id: uuidv4(),
    email: adminEmail,
    fullName: 'Administrateur Bella Exchange',
    phone: adminPhone,
    passwordHash,
    role: 'admin',
    createdAt: new Date().toISOString()
  });
  writeJSON('users.json', users);
  console.log('Admin cree:', adminEmail, 'mot de passe:', password);
}

function getSettings() {
  return readJSON('settings.json', {});
}

function runInBackground(taskFactories, context) {
  Promise.allSettled(taskFactories.map((task) => task()))
    .then((results) => {
      const failed = results.filter((r) => r.status === 'rejected');
      if (failed.length) {
        console.error(`[NOTIFY ERROR] ${context}: ${failed.length} task(s) failed`);
      }
    })
    .catch((err) => {
      console.error('[NOTIFY ERROR]', context, err?.message || err);
    });
}

async function refreshLivePrices() {
  const now = Date.now();
  if (pricesCache.updatedAt && now - pricesCache.updatedAt < PRICE_REFRESH_MS && pricesCache.prices) {
    return pricesCache.prices;
  }

  const ids = Object.values(PRICE_IDS).join(',');
  const url = `https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=usd`;
  try {
    const response = await fetch(url, { headers: { accept: 'application/json' } });
    if (!response.ok) {
      throw new Error(`CoinGecko HTTP ${response.status}`);
    }
    const data = await response.json();
    const settings = getSettings();
    const nextPrices = { ...(settings.prices || {}) };

    Object.entries(PRICE_IDS).forEach(([symbol, id]) => {
      if (data[id] && typeof data[id].usd === 'number') {
        nextPrices[symbol] = data[id].usd;
      }
    });

    settings.prices = nextPrices;
    writeJSON('settings.json', settings);
    pricesCache = { updatedAt: now, prices: nextPrices };
    return nextPrices;
  } catch (err) {
    const settings = getSettings();
    pricesCache = { updatedAt: now, prices: settings.prices || {} };
    return settings.prices || {};
  }
}

function authRequired(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

function adminRequired(req, res, next) {
  if (!req.session.user) {
    return res.status(403).send('Acces refuse');
  }

  const users = readJSON('users.json', []);
  const dbUser = users.find((u) => u.id === req.session.user.id);
  const envAdminEmail = normalizeEmail(process.env.ADMIN_EMAIL || '');
  const sessionEmail = normalizeEmail(req.session.user.email);

  if (dbUser && dbUser.role === 'admin') {
    req.session.user.role = 'admin';
    return next();
  }

  if (sessionEmail && envAdminEmail && sessionEmail === envAdminEmail) {
    if (dbUser) {
      dbUser.role = 'admin';
      writeJSON('users.json', users);
    }
    req.session.user.role = 'admin';
    return next();
  }

  if (req.session.user.role !== 'admin') {
    return res.status(403).send('Acces refuse');
  }

  next();
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  name: 'bella.sid',
  secret: process.env.SESSION_SECRET || 'bella_exchange_secret',
  resave: false,
  saveUninitialized: false,
  proxy: isProduction,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProduction,
    maxAge: 1000 * 60 * 60 * 24
  }
}));
app.use('/public', express.static(path.join(__dirname, '..', 'public')));
app.use('/uploads', express.static(uploadDir));
app.get('/manifest.webmanifest', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'manifest.webmanifest'));
});
app.get('/service-worker.js', (req, res) => {
  res.setHeader('Service-Worker-Allowed', '/');
  res.sendFile(path.join(__dirname, '..', 'public', 'service-worker.js'));
});

app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  res.locals.settings = getSettings();
  next();
});

app.get('/', async (req, res) => {
  const livePrices = await refreshLivePrices();
  const prices = Object.entries(livePrices || {}).map(([symbol, value]) => ({ symbol, value }));
  res.render('home', { title: 'Bella Exchange | Echange Crypto au Congo', prices, cryptos: CRYPTOS });
});

app.get('/buy', authRequired, (req, res) => {
  res.render('buy', {
    title: 'Acheter des Cryptos | Bella Exchange',
    cryptos: CRYPTOS,
    cryptoNetworks: CRYPTO_NETWORKS,
    error: req.query.error || null
  });
});

app.get('/sell', authRequired, (req, res) => {
  res.render('sell', {
    title: 'Vendre des Cryptos | Bella Exchange',
    cryptos: CRYPTOS,
    networks: NETWORKS,
    cryptoNetworks: CRYPTO_NETWORKS,
    error: req.query.error || null
  });
});

app.get('/contact', (req, res) => {
  res.render('contact', { title: 'Contact | Bella Exchange', query: req.query });
});

app.get('/profile', authRequired, (req, res) => {
  const transactions = readJSON('transactions.json', [])
    .filter((t) => t.userId === req.session.user.id)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, 10);
  res.render('profile', { title: 'Mon Profil | Bella Exchange', transactions });
});

app.get('/admin', adminRequired, (req, res) => {
  const transactions = readJSON('transactions.json', [])
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.render('admin', {
    title: 'Administration | Bella Exchange',
    transactions,
    networks: NETWORKS,
    cryptos: CRYPTOS,
    cryptoNetworks: CRYPTO_NETWORKS
  });
});

app.get('/waiting', authRequired, (req, res) => {
  res.render('waiting', { title: 'Transaction en attente | Bella Exchange' });
});

app.get('/login', (req, res) => {
  res.render('login', { title: 'Connexion | Bella Exchange', error: null, success: req.query.success || null });
});

app.get('/register', (req, res) => {
  res.render('register', { title: 'Inscription | Bella Exchange', error: null });
});

app.get('/forgot-password', (req, res) => {
  res.render('forgot-password', { title: 'Mot de passe oublie | Bella Exchange', error: null, success: req.query.success || null });
});

app.get('/reset-password', (req, res) => {
  const token = String(req.query.token || '');
  if (!token) {
    return res.status(400).render('reset-password', {
      title: 'Reinitialiser | Bella Exchange',
      error: 'Lien invalide.',
      token: ''
    });
  }

  const resets = readJSON('password_resets.json', []);
  const entry = resets.find((r) => r.token === token && !r.used && new Date(r.expiresAt) > new Date());
  if (!entry) {
    return res.status(400).render('reset-password', {
      title: 'Reinitialiser | Bella Exchange',
      error: 'Lien invalide ou expire.',
      token: ''
    });
  }

  return res.render('reset-password', { title: 'Reinitialiser | Bella Exchange', error: null, token });
});

app.post('/auth/register', async (req, res) => {
  const { fullName, phone, password } = req.body;
  const email = normalizeEmail(req.body.email);
  const users = readJSON('users.json', []);
  const existing = users.find((u) => normalizeEmail(u.email) === email);

  if (existing) {
    return res.status(400).render('register', { title: 'Inscription | Bella Exchange', error: 'Cet email est deja utilise.' });
  }
  if (!isStrongPassword(password)) {
    return res.status(400).render('register', {
      title: 'Inscription | Bella Exchange',
      error: 'Mot de passe trop faible (8+ caracteres, majuscule, minuscule, chiffre, symbole).'
    });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: uuidv4(),
    fullName,
    email,
    phone,
    passwordHash,
    role: 'user',
    createdAt: new Date().toISOString()
  };
  users.push(user);
  writeJSON('users.json', users);

  req.session.user = { id: user.id, email: user.email, fullName: user.fullName, role: user.role, phone: user.phone };
  req.session.save(() => {
    res.redirect('/profile');
  });
});

app.post('/auth/login', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const { password } = req.body;
  const users = readJSON('users.json', []);
  const user = users.find((u) => normalizeEmail(u.email) === email);

  if (!user) {
    return res.status(401).render('login', {
      title: 'Connexion | Bella Exchange',
      error: 'Identifiants invalides.',
      success: null
    });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(401).render('login', {
      title: 'Connexion | Bella Exchange',
      error: 'Identifiants invalides.',
      success: null
    });
  }

  const envAdminEmail = normalizeEmail(process.env.ADMIN_EMAIL || '');
  const effectiveRole = (normalizeEmail(user.email) === envAdminEmail) ? 'admin' : user.role;

  req.session.user = {
    id: user.id,
    email: user.email,
    fullName: user.fullName,
    role: effectiveRole,
    phone: user.phone
  };
  req.session.save(() => {
    res.redirect(effectiveRole === 'admin' ? '/admin' : '/profile');
  });
});

app.post('/auth/forgot-password', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const users = readJSON('users.json', []);
  const user = users.find((u) => normalizeEmail(u.email) === email);

  if (user) {
    const resets = readJSON('password_resets.json', []);
    const token = crypto.randomBytes(32).toString('hex');
    resets.push({
      id: uuidv4(),
      userId: user.id,
      email: user.email,
      token,
      used: false,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString()
    });
    writeJSON('password_resets.json', resets);

    const rawBaseUrl = String(process.env.BASE_URL || `http://localhost:${port}`).trim();
    const baseUrl = rawBaseUrl.endsWith('/') ? rawBaseUrl : `${rawBaseUrl}/`;
    const resetUrl = new URL('reset-password', baseUrl);
    resetUrl.searchParams.set('token', token);
    const resetLink = resetUrl.toString();
    runInBackground([
      () => sendEmail({
        to: user.email,
        subject: 'Bella Exchange - Reinitialisation mot de passe',
        text:
          `Bonjour ${user.fullName || ''},\n` +
          `Cliquez sur ce lien pour reinitialiser votre mot de passe:\n${resetLink}\n` +
          `Ce lien expire dans 30 minutes.`
      })
    ], `forgot-password:${user.email}`);
  }

  return res.redirect('/forgot-password?success=Si+le+compte+existe,+un+email+a+ete+envoye.');
});

app.post('/auth/reset-password', async (req, res) => {
  const token = String(req.body.token || '');
  const password = String(req.body.password || '');
  const confirmPassword = String(req.body.confirmPassword || '');

  if (!token) {
    return res.status(400).render('reset-password', { title: 'Reinitialiser | Bella Exchange', error: 'Token manquant.', token: '' });
  }
  if (password !== confirmPassword) {
    return res.status(400).render('reset-password', { title: 'Reinitialiser | Bella Exchange', error: 'Les mots de passe ne correspondent pas.', token });
  }
  if (!isStrongPassword(password)) {
    return res.status(400).render('reset-password', {
      title: 'Reinitialiser | Bella Exchange',
      error: 'Mot de passe trop faible (8+ caracteres, majuscule, minuscule, chiffre, symbole).',
      token
    });
  }

  const resets = readJSON('password_resets.json', []);
  const resetEntry = resets.find((r) => r.token === token && !r.used && new Date(r.expiresAt) > new Date());
  if (!resetEntry) {
    return res.status(400).render('reset-password', { title: 'Reinitialiser | Bella Exchange', error: 'Lien invalide ou expire.', token: '' });
  }

  const users = readJSON('users.json', []);
  const user = users.find((u) => u.id === resetEntry.userId);
  if (!user) {
    return res.status(400).render('reset-password', { title: 'Reinitialiser | Bella Exchange', error: 'Utilisateur introuvable.', token: '' });
  }

  user.passwordHash = await bcrypt.hash(password, 10);
  resetEntry.used = true;
  resetEntry.usedAt = new Date().toISOString();
  writeJSON('users.json', users);
  writeJSON('password_resets.json', resets);

  return res.redirect('/login?success=Mot+de+passe+reinitialise.+Connectez-vous.');
});

app.post('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.post('/contact', (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = normalizeEmail(req.body.email);
  const message = String(req.body.message || '').trim();
  if (!name || !email || !message) {
    return res.redirect('/contact?error=Veuillez+remplir+tous+les+champs.');
  }
  const messages = readJSON('messages.json', []);
  messages.push({
    id: uuidv4(),
    name,
    email,
    message,
    createdAt: new Date().toISOString()
  });
  writeJSON('messages.json', messages);
  res.redirect('/contact?ok=1');
});

app.get('/api/deposit-address', authRequired, (req, res) => {
  const { crypto, network } = req.query;
  const allowedNetworks = CRYPTO_NETWORKS[crypto] || [];
  if (!allowedNetworks.includes(network)) {
    return res.status(400).json({ error: 'Reseau invalide pour cette crypto.', address: null });
  }
  const settings = getSettings();
  const address = settings.depositAddresses?.[crypto]?.[network] || 'Adresse non configuree';
  res.json({ address, crypto, network });
});

app.get('/api/prices', async (req, res) => {
  const prices = await refreshLivePrices();
  res.json({
    updatedAt: new Date(pricesCache.updatedAt || Date.now()).toISOString(),
    prices
  });
});

app.post('/transactions/buy', authRequired, upload.single('proof'), async (req, res) => {
  const settings = getSettings();
  const transactions = readJSON('transactions.json', []);
  const user = req.session.user;
  const usdAmount = Number(req.body.usdAmount || 0);
  if (!usdAmount || usdAmount <= 0) {
    return res.status(400).send('Montant USD invalide');
  }
  const amountFCFA = Math.round(usdAmount * Number(settings.buyRate));
  const crypto = req.body.crypto;
  const network = req.body.network;
  const allowedNetworks = CRYPTO_NETWORKS[crypto] || [];
  if (!allowedNetworks.includes(network)) {
    return res.redirect('/buy?error=Reseau+invalide+pour+la+crypto+selectionnee.');
  }
  const configuredAddress = settings.depositAddresses?.[crypto]?.[network];
  if (!configuredAddress) {
    return res.redirect('/buy?error=Adresse+de+depot+non+configuree+pour+cette+crypto/reseau.');
  }
  if (!req.file) {
    return res.redirect('/buy?error=Veuillez+joindre+une+preuve+de+paiement.');
  }

  const tx = {
    id: uuidv4(),
    type: 'buy',
    userId: user.id,
    email: user.email,
    phone: user.phone,
    crypto,
    network,
    cryptoAddress: req.body.cryptoAddress,
    usdAmount,
    amountFCFA,
    rate: settings.buyRate,
    paymentNumber: settings.phoneNumber,
    paymentRecipient: settings.recipientName,
    proofPath: null,
    proofFileName: req.file ? req.file.originalname : null,
    status: 'pending',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  transactions.push(tx);
  writeJSON('transactions.json', transactions);

  res.redirect('/waiting');
  runInBackground([
    () => sendEmail({
      to: tx.email,
      subject: 'Bella Exchange - Transaction recue',
      text:
        `Votre transaction ${tx.id} (${usdAmount} USD / ${amountFCFA} FCFA) a ete prise en compte et est en attente de validation.\n` +
        `Paiement a envoyer au: ${settings.phoneNumber}\n` +
        `Nom beneficiaire: ${settings.recipientName}\n` +
        `Adresse crypto de reception: ${tx.cryptoAddress}`
    }),
    () => sendEmail({
      to: process.env.ADMIN_NOTIFY_EMAIL || process.env.ADMIN_EMAIL || 'admin@bellaexchange.cg',
      subject: `Nouvelle commande ACHAT ${tx.id}`,
      text:
        `Nouvelle commande ACHAT\n` +
        `ID: ${tx.id}\n` +
        `Client: ${tx.email}\n` +
        `Telephone client: ${tx.phone || '-'}\n` +
        `Crypto: ${tx.crypto}/${tx.network}\n` +
        `Montant: ${usdAmount} USD (${amountFCFA} FCFA)\n` +
        `Adresse crypto client: ${tx.cryptoAddress || '-'}\n` +
        `Numero de paiement: ${settings.phoneNumber}\n` +
        `Nom beneficiaire: ${settings.recipientName}\n` +
        `Preuve: ${tx.proofFileName || 'aucune'}`,
      attachments: req.file ? [{
        filename: req.file.originalname || `preuve-achat-${tx.id}`,
        content: req.file.buffer,
        contentType: req.file.mimetype || 'application/octet-stream'
      }] : undefined
    }),
    () => sendTelegramMessage(
      `🟢 <b>Nouvelle commande ACHAT</b>\n` +
      `ID: <code>${escapeTelegramHtml(tx.id)}</code>\n` +
      `Client: ${escapeTelegramHtml(tx.email)}\n` +
      `Tel client: ${escapeTelegramHtml(tx.phone || '-')}\n` +
      `Crypto: ${escapeTelegramHtml(tx.crypto)}/${escapeTelegramHtml(tx.network)}\n` +
      `Montant: ${escapeTelegramHtml(usdAmount)} USD (${escapeTelegramHtml(amountFCFA)} FCFA)\n` +
      `Adr. client: <code>${escapeTelegramHtml(tx.cryptoAddress || '-')}</code>\n` +
      `Paiement: ${escapeTelegramHtml(settings.phoneNumber)} (${escapeTelegramHtml(settings.recipientName)})`
    ),
    () => sendTelegramProof({
      fileBuffer: req.file?.buffer,
      fileName: req.file?.originalname,
      mimeType: req.file?.mimetype,
      caption: `Preuve ACHAT ${tx.id}`
    })
  ], `buy:${tx.id}`);
});

app.post('/transactions/sell', authRequired, upload.single('proof'), async (req, res) => {
  const settings = getSettings();
  const transactions = readJSON('transactions.json', []);
  const user = req.session.user;
  const usdAmount = Number(req.body.usdAmount || 0);
  if (!usdAmount || usdAmount <= 0) {
    return res.status(400).send('Montant USD invalide');
  }
  const amountFCFA = Math.round(usdAmount * Number(settings.sellRate));
  const crypto = req.body.crypto;
  const network = req.body.network;
  const allowedNetworks = CRYPTO_NETWORKS[crypto] || [];
  if (!allowedNetworks.includes(network)) {
    return res.redirect('/sell?error=Reseau+invalide+pour+la+crypto+selectionnee.');
  }
  const address = settings.depositAddresses?.[crypto]?.[network];
  if (!address) {
    return res.redirect('/sell?error=Adresse+de+depot+non+configuree+pour+cette+crypto/reseau.');
  }
  if (!req.file) {
    return res.redirect('/sell?error=Veuillez+joindre+une+preuve+de+transfert.');
  }

  const tx = {
    id: uuidv4(),
    type: 'sell',
    userId: user.id,
    email: user.email,
    phone: req.body.phone,
    senderName: req.body.senderName,
    crypto,
    network,
    depositAddress: address,
    usdAmount,
    amountFCFA,
    rate: settings.sellRate,
    proofPath: null,
    proofFileName: req.file ? req.file.originalname : null,
    status: 'pending',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  transactions.push(tx);
  writeJSON('transactions.json', transactions);

  res.redirect('/waiting');
  runInBackground([
    () => sendEmail({
      to: tx.email,
      subject: 'Bella Exchange - Vente en attente',
      text:
        `Votre ordre de vente ${tx.id} (${usdAmount} USD / ${amountFCFA} FCFA) a ete pris en compte et sera verifie par l'administration.\n` +
        `Adresse de depot a utiliser: ${address}\n` +
        `Reseau: ${tx.network}`
    }),
    () => sendEmail({
      to: process.env.ADMIN_NOTIFY_EMAIL || process.env.ADMIN_EMAIL || 'admin@bellaexchange.cg',
      subject: `Nouvelle commande VENTE ${tx.id}`,
      text:
        `Nouvelle commande VENTE\n` +
        `ID: ${tx.id}\n` +
        `Client: ${tx.email}\n` +
        `Telephone paiement client: ${tx.phone || '-'}\n` +
        `Nom client: ${tx.senderName || '-'}\n` +
        `Crypto: ${tx.crypto}/${tx.network}\n` +
        `Montant: ${usdAmount} USD (${amountFCFA} FCFA)\n` +
        `Adresse de depot: ${address}\n` +
        `Preuve: ${tx.proofFileName || 'aucune'}`,
      attachments: req.file ? [{
        filename: req.file.originalname || `preuve-vente-${tx.id}`,
        content: req.file.buffer,
        contentType: req.file.mimetype || 'application/octet-stream'
      }] : undefined
    }),
    () => sendTelegramMessage(
      `🟠 <b>Nouvelle commande VENTE</b>\n` +
      `ID: <code>${escapeTelegramHtml(tx.id)}</code>\n` +
      `Client: ${escapeTelegramHtml(tx.email)}\n` +
      `Tel paiement: ${escapeTelegramHtml(tx.phone || '-')}\n` +
      `Nom client: ${escapeTelegramHtml(tx.senderName || '-')}\n` +
      `Crypto: ${escapeTelegramHtml(tx.crypto)}/${escapeTelegramHtml(tx.network)}\n` +
      `Montant: ${escapeTelegramHtml(usdAmount)} USD (${escapeTelegramHtml(amountFCFA)} FCFA)\n` +
      `Depot: <code>${escapeTelegramHtml(address)}</code>`
    ),
    () => sendTelegramProof({
      fileBuffer: req.file?.buffer,
      fileName: req.file?.originalname,
      mimeType: req.file?.mimetype,
      caption: `Preuve VENTE ${tx.id}`
    })
  ], `sell:${tx.id}`);
});

app.post('/admin/transactions/:id/approve', adminRequired, async (req, res) => {
  const transactions = readJSON('transactions.json', []);
  const tx = transactions.find((item) => item.id === req.params.id);
  if (!tx) return res.status(404).send('Transaction introuvable');

  tx.status = 'approved';
  tx.updatedAt = new Date().toISOString();
  writeJSON('transactions.json', transactions);

  res.redirect('/admin');
  runInBackground([
    () => sendEmail({
      to: tx.email,
      subject: 'Bella Exchange - Transaction validee',
      text: `Votre transaction ${tx.id} a ete validee avec succes.`
    }),
    () => sendEmail({
      to: process.env.ADMIN_NOTIFY_EMAIL || process.env.ADMIN_EMAIL || 'admin@bellaexchange.cg',
      subject: `Transaction validee ${tx.id}`,
      text: `Transaction validee\nID: ${tx.id}\nType: ${tx.type}\nClient: ${tx.email}`
    }),
    () => sendTelegramMessage(
      `✅ <b>Transaction validée</b>\n` +
      `ID: <code>${escapeTelegramHtml(tx.id)}</code>\n` +
      `Type: ${escapeTelegramHtml(tx.type)}\n` +
      `Client: ${escapeTelegramHtml(tx.email)}`
    )
  ], `approve:${tx.id}`);
});

app.post('/admin/settings', adminRequired, (req, res) => {
  const settings = getSettings();
  settings.depositAddresses = settings.depositAddresses || {};
  settings.buyRate = Number(req.body.buyRate || settings.buyRate);
  settings.sellRate = Number(req.body.sellRate || settings.sellRate);
  settings.phoneNumber = req.body.phoneNumber || settings.phoneNumber;
  settings.recipientName = req.body.recipientName || settings.recipientName;

  CRYPTOS.forEach((crypto) => {
    (CRYPTO_NETWORKS[crypto] || []).forEach((network) => {
      const key = `addr_${crypto}_${network}`;
      if (req.body[key]) {
        settings.depositAddresses[crypto] = settings.depositAddresses[crypto] || {};
        settings.depositAddresses[crypto][network] = req.body[key];
      }
    });
  });

  writeJSON('settings.json', settings);
  res.redirect('/admin');
});

initializeDataStore()
  .then(() => bootstrapAdmin())
  .then(() => {
    app.listen(port, () => {
      console.log(`Bella Exchange lance sur http://localhost:${port}`);
    });
  })
  .catch((err) => {
    console.error('[STARTUP ERROR]', err?.message || err);
    process.exit(1);
  });
