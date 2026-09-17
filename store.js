const { DatabaseSync } = require('node:sqlite');
const { mkdirSync } = require('node:fs');
const path = require('node:path');
const { createClient } = require('@supabase/supabase-js');

const bucket = 'driver-documents';

function checked(result) {
  if (result.error) throw result.error;
  return result.data;
}

function createLocalStore() {
  const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
  mkdirSync(dataDir, { recursive: true });
  const db = new DatabaseSync(path.join(dataDir, 'applications.sqlite'));
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS applications (
      id TEXT PRIMARY KEY, submitted_at TEXT NOT NULL, data_json TEXT NOT NULL,
      id_image_name TEXT NOT NULL, id_image_type TEXT NOT NULL, id_image BLOB NOT NULL,
      license_image_name TEXT, license_image_type TEXT, license_image BLOB
    );
    CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, expires_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
  `);
  return {
    async hasSession(hash) {
      return Boolean(db.prepare('SELECT 1 FROM sessions WHERE token_hash = ? AND expires_at > ?')
        .get(hash, new Date().toISOString()));
    },
    async createSession(hash, expiresAt) {
      db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(new Date().toISOString());
      db.prepare('INSERT INTO sessions (token_hash, expires_at) VALUES (?, ?)').run(hash, expiresAt);
    },
    async deleteSession(hash) {
      db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hash);
    },
    async createApplication(application, idFile, licenseFile) {
      db.prepare(`INSERT INTO applications (
        id, submitted_at, data_json, id_image_name, id_image_type, id_image,
        license_image_name, license_image_type, license_image
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        application.id, application.submittedAt, JSON.stringify(application),
        idFile.originalname, application.idImageType, idFile.buffer,
        licenseFile?.originalname || null, application.licenseImageType || null,
        licenseFile?.buffer || null
      );
    },
    async listApplications() {
      return db.prepare('SELECT data_json FROM applications ORDER BY submitted_at DESC')
        .all().map(row => JSON.parse(row.data_json));
    },
    async getAttachment(id, field) {
      const prefix = field === 'idImage' ? 'id_image' : 'license_image';
      const row = db.prepare(`SELECT ${prefix}_name AS name, ${prefix}_type AS type, ${prefix} AS data
        FROM applications WHERE id = ?`).get(id);
      return row?.data ? row : null;
    },
    async clearApplications() {
      db.prepare('DELETE FROM applications').run();
    }
  };
}

function createSupabaseStore(client) {
  const files = client.storage.from(bucket);
  return {
    async hasSession(hash) {
      const rows = checked(await client.from('sessions').select('token_hash')
        .eq('token_hash', hash).gt('expires_at', new Date().toISOString()).limit(1));
      return rows.length > 0;
    },
    async createSession(hash, expiresAt) {
      checked(await client.from('sessions').delete().lte('expires_at', new Date().toISOString()));
      checked(await client.from('sessions').insert({ token_hash: hash, expires_at: expiresAt }));
    },
    async deleteSession(hash) {
      checked(await client.from('sessions').delete().eq('token_hash', hash));
    },
    async createApplication(application, idFile, licenseFile) {
      const idPath = `${application.id}/id`;
      const licensePath = licenseFile ? `${application.id}/license` : null;
      const uploaded = [];
      try {
        checked(await files.upload(idPath, idFile.buffer, {
          contentType: application.idImageType, upsert: false
        }));
        uploaded.push(idPath);
        if (licenseFile) {
          checked(await files.upload(licensePath, licenseFile.buffer, {
            contentType: application.licenseImageType, upsert: false
          }));
          uploaded.push(licensePath);
        }
        checked(await client.from('applications').insert({
          id: application.id,
          submitted_at: application.submittedAt,
          data_json: application,
          id_image_path: idPath,
          license_image_path: licensePath
        }));
      } catch (error) {
        if (uploaded.length) {
          try { checked(await files.remove(uploaded)); }
          catch (cleanupError) { console.error('Upload cleanup failed:', cleanupError); }
        }
        throw error;
      }
    },
    async listApplications() {
      const applications = [];
      for (let from = 0; ; from += 500) {
        const rows = checked(await client.from('applications').select('data_json')
          .order('submitted_at', { ascending: false }).order('id', { ascending: false })
          .range(from, from + 499));
        applications.push(...rows.map(row => row.data_json));
        if (rows.length < 500) return applications;
      }
    },
    async getAttachment(id, field) {
      const row = checked(await client.from('applications')
        .select('data_json,id_image_path,license_image_path').eq('id', id).maybeSingle());
      if (!row) return null;
      const isId = field === 'idImage';
      const filePath = isId ? row.id_image_path : row.license_image_path;
      if (!filePath) return null;
      const blob = checked(await files.download(filePath));
      return {
        name: isId ? row.data_json.idImageName : row.data_json.licenseImageName,
        type: isId ? row.data_json.idImageType : row.data_json.licenseImageType,
        data: Buffer.from(await blob.arrayBuffer())
      };
    },
    async clearApplications() {
      // Remove one batch at a time, then delete only those rows. New submissions are untouched.
      for (;;) {
        const rows = checked(await client.from('applications')
          .select('id,id_image_path,license_image_path').order('id').limit(100));
        if (!rows.length) return;
        const paths = rows.flatMap(row => [row.id_image_path, row.license_image_path].filter(Boolean));
        checked(await files.remove(paths));
        checked(await client.from('applications').delete().in('id', rows.map(row => row.id)));
      }
    }
  };
}

function createStore() {
  const backend = process.env.DATA_BACKEND || (process.env.NODE_ENV === 'production' ? 'supabase' : 'sqlite');
  if (backend === 'sqlite' && process.env.NODE_ENV !== 'production') return createLocalStore();
  if (backend !== 'supabase') throw new Error('Production requires Supabase storage.');
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error('Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY before starting production.');
  return createSupabaseStore(createClient(url, key, {
    auth: { autoRefreshToken: false, persistSession: false }
  }));
}

module.exports = { createStore, createSupabaseStore };
