const fs = require('fs');
const path = require('path');

const dataDir = path.join(__dirname, '..', 'data');
const useDatabase = Boolean(process.env.DATABASE_URL);
const dbState = {
  initialized: false,
  pool: null,
  cache: new Map(),
  writeChain: Promise.resolve()
};

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function getPgPool() {
  if (!useDatabase) return null;
  if (dbState.pool) return dbState.pool;

  let Pool;
  try {
    ({ Pool } = require('pg'));
  } catch (err) {
    throw new Error('DATABASE_URL est defini mais la dependance "pg" est absente.');
  }

  const isSsl = String(process.env.DATABASE_SSL || 'false') === 'true';
  dbState.pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: isSsl ? { rejectUnauthorized: false } : undefined
  });
  return dbState.pool;
}

function queuePersist(fileName, value) {
  if (!useDatabase || !dbState.pool) return;
  const payload = JSON.stringify(value);
  dbState.writeChain = dbState.writeChain
    .then(() => dbState.pool.query(
      `INSERT INTO app_json_store (key, payload, updated_at)
       VALUES ($1, $2::jsonb, NOW())
       ON CONFLICT (key)
       DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW()`,
      [fileName, payload]
    ))
    .catch((err) => {
      console.error('[DB WRITE ERROR]', fileName, err?.message || err);
    });
}

async function initializeDataStore() {
  if (!useDatabase || dbState.initialized) {
    dbState.initialized = true;
    return;
  }

  const pool = getPgPool();
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_json_store (
      key TEXT PRIMARY KEY,
      payload JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const existing = await pool.query('SELECT key, payload FROM app_json_store');
  const existingKeys = new Set();
  for (const row of existing.rows) {
    dbState.cache.set(row.key, row.payload);
    existingKeys.add(row.key);
  }

  for (const [key, value] of dbState.cache.entries()) {
    if (!existingKeys.has(key)) {
      await pool.query(
        `INSERT INTO app_json_store (key, payload, updated_at)
         VALUES ($1, $2::jsonb, NOW())
         ON CONFLICT (key) DO NOTHING`,
        [key, JSON.stringify(value)]
      );
    }
  }

  dbState.initialized = true;
}

function ensureFile(fileName, initialValue) {
  if (useDatabase) {
    if (!dbState.cache.has(fileName)) {
      dbState.cache.set(fileName, clone(initialValue));
    }
    return fileName;
  }

  const filePath = path.join(dataDir, fileName);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, JSON.stringify(initialValue, null, 2));
  }
  return filePath;
}

function readJSON(fileName, initialValue = []) {
  if (useDatabase) {
    if (!dbState.cache.has(fileName)) {
      dbState.cache.set(fileName, clone(initialValue));
    }
    return clone(dbState.cache.get(fileName));
  }

  const filePath = ensureFile(fileName, initialValue);
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function writeJSON(fileName, value) {
  if (useDatabase) {
    const next = clone(value);
    dbState.cache.set(fileName, next);
    queuePersist(fileName, next);
    return;
  }

  const filePath = ensureFile(fileName, value);
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

module.exports = { readJSON, writeJSON, ensureFile, initializeDataStore };
