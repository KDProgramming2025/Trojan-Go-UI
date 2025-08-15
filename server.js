const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');
const mysql = require('mysql2/promise');
const fs = require('fs');

const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8'));

const app = express();
app.use(express.json());

// Serve static frontend
app.use(express.static(path.join(__dirname, 'public')));

// MySQL pool
const pool = mysql.createPool({
  host: cfg.mysql.host,
  port: cfg.mysql.port,
  user: cfg.mysql.user,
  password: cfg.mysql.password,
  database: cfg.mysql.database,
  waitForConnections: true,
  connectionLimit: 10,
  namedPlaceholders: true,
  // Return BIGINT as string to avoid JS precision loss
  decimalNumbers: false
});

async function init() {
  const conn = await pool.getConnection();
  try {
    await conn.query(`
      CREATE TABLE IF NOT EXISTS ui_users (
        user_id INT UNSIGNED NOT NULL PRIMARY KEY,
        display_name VARCHAR(128) NOT NULL,
        plain_password VARCHAR(256) NOT NULL,
        expires_at DATETIME NULL,
        quota_backup BIGINT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_ui_users_users FOREIGN KEY (user_id)
          REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Backfill column if coming from older version (ignore duplicate errors)
    try {
      await conn.query(`ALTER TABLE ui_users ADD COLUMN quota_backup BIGINT NULL`);
    } catch (e) {
      // ER_DUP_FIELDNAME -> already exists
    }
  } finally {
    conn.release();
  }
}
init().catch(err => {
  console.error('Failed to init DB:', err);
  process.exit(1);
});

function sha224Hex(s) {
  return crypto.createHash('sha224').update(s, 'utf8').digest('hex');
}

// Format a Date (or date-like) as UTC "YYYY-MM-DD HH:mm:ss"
function toSqlUtc(dt) {
  if (!dt) return null;
  const d = (dt instanceof Date) ? dt : new Date(dt);
  if (isNaN(d.getTime())) return null;
  const pad = n => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

// trojan-go API: list online users (hashes)
function fetchOnlineHashes() {
  return new Promise((resolve) => {
    const args = ['-api-addr', cfg.trojan_api.addr, '-api', 'list'];
    execFile(cfg.trojan_api.bin, args, { timeout: 4000 }, (err, stdout) => {
      if (err) return resolve(new Set());
      try {
        const arr = JSON.parse(stdout);
        const set = new Set();
        for (const it of arr) {
          const hash = it?.status?.user?.hash;
          if (hash) set.add(hash);
        }
        resolve(set);
      } catch {
        resolve(new Set());
      }
    });
  });
}

// Compose trojan:// link for v2rayN/NG
function makeTrojanUrl(plainPassword, displayNameOrUsername) {
  const host = cfg.link.host;
  const port = cfg.link.port;
  const wsHost = cfg.link.ws_host || host;
  const sni = cfg.link.sni || host;
  const path = cfg.link.ws_path || '/';
  const tag = displayNameOrUsername || 'user';
  return `trojan://${encodeURIComponent(plainPassword)}@${host}:${port}` +
         `?security=tls&type=ws&host=${encodeURIComponent(wsHost)}&path=${encodeURIComponent(path)}&sni=${encodeURIComponent(sni)}#${encodeURIComponent(tag)}`;
}

// GET /api/users -> list with computed fields and trojan url
app.get('/api/users', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT u.id, u.username, u.password, u.quota, u.upload, u.download,
             m.display_name, m.plain_password, m.expires_at, m.quota_backup
      FROM users u
      LEFT JOIN ui_users m ON m.user_id = u.id
      ORDER BY u.id DESC
    `);

    const onlineSet = await fetchOnlineHashes();
    const now = new Date();

    const result = rows.map(r => {
      const used = BigInt(String(r.upload || 0)) + BigInt(String(r.download || 0));
      const quota = BigInt(String(r.quota));
      const unlimited = quota < 0n;
      const remainingBytes = unlimited ? -1n : (quota > used ? (quota - used) : 0n);

      let expiresAtSql = null;
      let expired = false;
      if (r.expires_at) {
        expiresAtSql = toSqlUtc(r.expires_at);
        const exp = new Date(expiresAtSql + 'Z');
        expired = exp <= now;
      }

      const enabled = quota !== 0n && !expired;

      const name = r.display_name || r.username;
      const trojanUrl = r.plain_password ? makeTrojanUrl(r.plain_password, name) : null;

      return {
        id: r.id,
        username: r.username,
        name,
        online: onlineSet.has(r.password),
        used_bytes: used.toString(),
        quota_bytes: String(r.quota),
        remaining_bytes: remainingBytes === -1n ? "-1" : remainingBytes.toString(),
        remaining_days: expiresAtSql ? Math.ceil((new Date(expiresAtSql + 'Z') - now) / 86400000) : null,
        expires_at: expiresAtSql,
        enabled,
        trojan_url: trojanUrl
      };
    });

    res.json(result);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'failed_to_list_users' });
  }
});

// GET /api/users/:id -> detail for editor
app.get('/api/users/:id', async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: 'invalid_id' });
  try {
    const [rows] = await pool.query(`
      SELECT u.id, u.username, u.password, u.quota, u.upload, u.download,
             m.display_name, m.plain_password, m.expires_at, m.quota_backup
      FROM users u
      LEFT JOIN ui_users m ON m.user_id = u.id
      WHERE u.id = ?
      LIMIT 1
    `, [id]);
    if (rows.length === 0) return res.status(404).json({ error: 'not_found' });

    const r = rows[0];
    const used = BigInt(String(r.upload || 0)) + BigInt(String(r.download || 0));
    const quota = BigInt(String(r.quota));
    const unlimited = quota < 0n;
    const remainingBytes = unlimited ? -1n : (quota > used ? (quota - used) : 0n);
    const expiresAtSql = r.expires_at ? toSqlUtc(r.expires_at) : null;
    const now = new Date();
    const expired = expiresAtSql ? (new Date(expiresAtSql + 'Z') <= now) : false;
    const enabled = quota !== 0n && !expired;

    res.json({
      id: r.id,
      username: r.username,
      display_name: r.display_name,
      used_bytes: used.toString(),
      quota_bytes: String(r.quota),
      remaining_bytes: remainingBytes === -1n ? "-1" : remainingBytes.toString(),
      remaining_days: expiresAtSql ? Math.ceil((new Date(expiresAtSql + 'Z') - now) / 86400000) : null,
      expires_at: expiresAtSql,
      enabled
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'failed_to_get_user' });
  }
});

// POST /api/users { username, plain_password, quota_bytes, expires_at }
app.post('/api/users', async (req, res) => {
  try {
    const { username, plain_password, quota_bytes, expires_at, display_name } = req.body || {};
    if (!username || !plain_password) {
      return res.status(400).json({ error: 'username_and_plain_password_required' });
    }
    const quota = (quota_bytes === undefined || quota_bytes === null || quota_bytes === '') ? -1 : BigInt(quota_bytes);
    const hash = sha224Hex(plain_password);

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      const [r1] = await conn.query(
        `INSERT INTO users (username, password, quota) VALUES (?, ?, ?)`,
        [username, hash, quota.toString()]
      );
      const userId = r1.insertId;

      await conn.query(
        `INSERT INTO ui_users (user_id, display_name, plain_password, expires_at)
         VALUES (?, ?, ?, ?)`,
        [userId, display_name || username, plain_password, expires_at || null]
      );

      await conn.commit();
      res.json({ id: userId });
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'failed_to_create_user' });
  }
});

// PUT /api/users/:id { username?, plain_password?, quota_bytes?, expires_at?, display_name? }
app.put('/api/users/:id', async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: 'invalid_id' });

  try {
    const { username, plain_password, quota_bytes, expires_at, display_name } = req.body || {};
    const fieldsUsers = [];
    const valsUsers = [];
    const fieldsUi = [];
    const valsUi = [];

    if (username) {
      fieldsUsers.push('username = ?');
      valsUsers.push(username);
      if (!display_name) {
        fieldsUi.push('display_name = ?');
        valsUi.push(username);
      }
    }
    if (plain_password !== undefined && plain_password !== null && plain_password !== '') {
      fieldsUsers.push('password = ?');
      valsUsers.push(sha224Hex(plain_password));
      fieldsUi.push('plain_password = ?');
      valsUi.push(plain_password);
    }
    if (quota_bytes !== undefined && quota_bytes !== null && quota_bytes !== '') {
      fieldsUsers.push('quota = ?');
      valsUsers.push(BigInt(quota_bytes).toString());
    }
    if (display_name) {
      fieldsUi.push('display_name = ?');
      valsUi.push(display_name);
    }
    const hasExpires = ('expires_at' in (req.body || {}));
    if (hasExpires) {
      fieldsUi.push('expires_at = ?');
      valsUi.push(expires_at || null);
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      if (fieldsUsers.length) {
        valsUsers.push(id);
        await conn.query(`UPDATE users SET ${fieldsUsers.join(', ')} WHERE id = ?`, valsUsers);
      }
      if (fieldsUi.length) {
        valsUi.push(id);
        await conn.query(`UPDATE ui_users SET ${fieldsUi.join(', ')} WHERE user_id = ?`, valsUi);
      }

      // If expiry moved to future and user was soft-disabled, re-enable immediately
      if (hasExpires && expires_at) {
        await conn.query(`
          UPDATE users u
          JOIN ui_users m ON m.user_id = u.id
          SET u.quota = COALESCE(m.quota_backup, CASE WHEN u.quota = 0 THEN -1 ELSE u.quota END),
              m.quota_backup = NULL
          WHERE u.id = ? AND m.expires_at > UTC_TIMESTAMP() AND u.quota = 0
        `, [id]);
      }

      await conn.commit();
      res.json({ ok: true });
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'failed_to_update_user' });
  }
});

// POST /api/users/:id/disable -> soft-disable: store backup once, set quota=0
app.post('/api/users/:id/disable', async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: 'invalid_id' });
  try {
    await pool.query(`
      UPDATE users u
      JOIN ui_users m ON m.user_id = u.id
      SET m.quota_backup = CASE WHEN m.quota_backup IS NULL AND u.quota <> 0 THEN u.quota ELSE m.quota_backup END,
          u.quota = 0
      WHERE u.id = ?
    `, [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'failed_to_disable_user' });
  }
});

// POST /api/users/:id/enable -> restore backup or default to -1 if none and not expired
app.post('/api/users/:id/enable', async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: 'invalid_id' });
  try {
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [rows] = await conn.query(`
        SELECT u.quota AS q, m.quota_backup AS bkp, m.expires_at AS exp
        FROM users u JOIN ui_users m ON m.user_id = u.id
        WHERE u.id = ? FOR UPDATE
      `, [id]);
      if (rows.length === 0) {
        await conn.rollback();
        return res.status(404).json({ error: 'not_found' });
      }
      const r = rows[0];
      const expSql = r.exp ? toSqlUtc(r.exp) : null;
      if (expSql && new Date(expSql + 'Z') <= new Date()) {
        await conn.rollback();
        return res.status(400).json({ error: 'expired', message: 'Extend expiry before enabling.' });
      }
      const newQuota = (r.bkp !== null && r.bkp !== undefined) ? String(r.bkp)
                       : (String(r.q) === '0' ? '-1' : String(r.q));
      await conn.query(`UPDATE users SET quota = ? WHERE id = ?`, [newQuota, id]);
      await conn.query(`UPDATE ui_users SET quota_backup = NULL WHERE user_id = ?`, [id]);
      await conn.commit();
      res.json({ ok: true });
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'failed_to_enable_user' });
  }
});

// DELETE /api/users/:id
app.delete('/api/users/:id', async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: 'invalid_id' });
  try {
    await pool.query(`DELETE FROM users WHERE id = ?`, [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'failed_to_delete_user' });
  }
});

// POST /api/users/:id/reset-traffic
app.post('/api/users/:id/reset-traffic', async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: 'invalid_id' });
  try {
    await pool.query(`UPDATE users SET upload = 0, download = 0 WHERE id = ?`, [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'failed_to_reset_traffic' });
  }
});

// Background enforcement (every 60s):
// A) If expired -> soft-disable (set quota=0 and store backup once)
// B) If not expired and was soft-disabled (has backup) -> restore
setInterval(async () => {
  try {
    // Disable expired (store backup once)
    await pool.query(`
      UPDATE users u
      JOIN ui_users m ON m.user_id = u.id
      SET m.quota_backup = CASE WHEN m.quota_backup IS NULL AND u.quota <> 0 THEN u.quota ELSE m.quota_backup END,
          u.quota = 0
      WHERE m.expires_at IS NOT NULL AND m.expires_at <= UTC_TIMESTAMP() AND u.quota <> 0
    `);

    // Re-enable if expiry now in the future and user is at 0 but has backup
    await pool.query(`
      UPDATE users u
      JOIN ui_users m ON m.user_id = u.id
      SET u.quota = m.quota_backup, m.quota_backup = NULL
      WHERE m.expires_at IS NOT NULL AND m.expires_at > UTC_TIMESTAMP()
        AND u.quota = 0 AND m.quota_backup IS NOT NULL
    `);
  } catch (e) {
    // silent
  }
}, 60 * 1000);

app.listen(cfg.listen.port, cfg.listen.host, () => {
  console.log(`tgui listening on http://${cfg.listen.host}:${cfg.listen.port}`);
});