const session = require('express-session');
const { readJSON, writeJSON, ensureFile } = require('./db');

const STORE_FILE = 'sessions.json';
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

class JsonSessionStore extends session.Store {
  constructor(options = {}) {
    super();
    this.ttlMs = Number(options.ttlMs || DEFAULT_TTL_MS);
    this.cleanupIntervalMs = Number(options.cleanupIntervalMs || 15 * 60 * 1000);
    ensureFile(STORE_FILE, {});

    this.cleanupTimer = setInterval(() => {
      this.pruneExpired();
    }, this.cleanupIntervalMs);
    this.cleanupTimer.unref?.();
  }

  get(sid, callback) {
    try {
      const sessions = readJSON(STORE_FILE, {});
      const entry = sessions[sid];
      if (!entry) return callback(null, null);
      if (this.isExpired(entry)) {
        delete sessions[sid];
        writeJSON(STORE_FILE, sessions);
        return callback(null, null);
      }
      return callback(null, entry.session || null);
    } catch (err) {
      return callback(err);
    }
  }

  set(sid, sessionData, callback) {
    try {
      const sessions = readJSON(STORE_FILE, {});
      const expiresAt = this.resolveExpiry(sessionData);
      sessions[sid] = {
        session: sessionData,
        expiresAt
      };
      writeJSON(STORE_FILE, sessions);
      callback?.(null);
    } catch (err) {
      callback?.(err);
    }
  }

  destroy(sid, callback) {
    try {
      const sessions = readJSON(STORE_FILE, {});
      if (sessions[sid]) {
        delete sessions[sid];
        writeJSON(STORE_FILE, sessions);
      }
      callback?.(null);
    } catch (err) {
      callback?.(err);
    }
  }

  touch(sid, sessionData, callback) {
    return this.set(sid, sessionData, callback);
  }

  pruneExpired() {
    try {
      const sessions = readJSON(STORE_FILE, {});
      let changed = false;
      for (const [sid, entry] of Object.entries(sessions)) {
        if (this.isExpired(entry)) {
          delete sessions[sid];
          changed = true;
        }
      }
      if (changed) {
        writeJSON(STORE_FILE, sessions);
      }
    } catch (err) {
      console.error('[SESSION STORE ERROR]', err?.message || err);
    }
  }

  resolveExpiry(sessionData) {
    const expires = sessionData?.cookie?.expires;
    if (expires) {
      const asDate = new Date(expires);
      if (!Number.isNaN(asDate.getTime())) {
        return asDate.toISOString();
      }
    }
    return new Date(Date.now() + this.ttlMs).toISOString();
  }

  isExpired(entry) {
    const expiresAt = entry?.expiresAt;
    if (!expiresAt) return false;
    const expiryTs = new Date(expiresAt).getTime();
    if (Number.isNaN(expiryTs)) return false;
    return expiryTs <= Date.now();
  }
}

function createSessionStore(options = {}) {
  return new JsonSessionStore(options);
}

module.exports = { createSessionStore };
