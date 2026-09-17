const express = require('express');
const multer = require('multer');
const { createHash, randomBytes, timingSafeEqual } = require('node:crypto');
const path = require('node:path');
const { createStore } = require('./store');

const adminPassword = process.env.ADMIN_PASSWORD;
if (!adminPassword) {
  throw new Error('Set ADMIN_PASSWORD before starting the server.');
}

const store = createStore();

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '8kb' }));
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('Referrer-Policy', 'no-referrer');
  if (req.path.startsWith('/api/')) res.set('Cache-Control', 'no-store');
  next();
});

const SESSION_COOKIE = 'driver_admin_session';
const SESSION_MS = 12 * 60 * 60 * 1000;
const passwordHash = createHash('sha256').update(adminPassword).digest();
const loginAttempts = new Map();

function sameOrigin(req, res, next) {
  const origin = req.get('origin');
  if (origin && origin !== `${req.protocol}://${req.get('host')}`) {
    return res.status(403).json({ error: 'الطلب غير مسموح.' });
  }
  next();
}

function sessionToken(req) {
  const cookie = (req.get('cookie') || '').split('; ').find(part => part.startsWith(`${SESSION_COOKIE}=`));
  return cookie ? cookie.slice(SESSION_COOKIE.length + 1) : '';
}

async function authenticated(req) {
  const token = sessionToken(req);
  if (!/^[a-f0-9]{64}$/.test(token)) return false;
  const tokenHash = createHash('sha256').update(token).digest('hex');
  return store.hasSession(tokenHash);
}

async function requireAdmin(req, res, next) {
  if (!await authenticated(req)) return res.status(401).json({ error: 'يرجى تسجيل الدخول.' });
  next();
}

app.get('/api/health', (req, res) => res.json({ ok: true }));
app.get('/api/session', async (req, res) => res.json({ authenticated: await authenticated(req) }));

app.post('/api/login', sameOrigin, async (req, res) => {
  const key = req.ip;
  const now = Date.now();
  const attempt = loginAttempts.get(key) || { count: 0, until: now + 15 * 60 * 1000 };
  if (attempt.until < now) {
    attempt.count = 0;
    attempt.until = now + 15 * 60 * 1000;
  }
  if (attempt.count >= 10) {
    return res.status(429).json({ error: 'محاولات كثيرة. حاول مرة أخرى بعد قليل.' });
  }
  const supplied = createHash('sha256').update(String(req.body?.password || '')).digest();
  if (!timingSafeEqual(supplied, passwordHash)) {
    attempt.count += 1;
    loginAttempts.set(key, attempt);
    return res.status(401).json({ error: 'كلمة المرور غير صحيحة.' });
  }
  loginAttempts.delete(key);
  const token = randomBytes(32).toString('hex');
  const expiresAt = new Date(now + SESSION_MS).toISOString();
  try {
    await store.createSession(createHash('sha256').update(token).digest('hex'), expiresAt);
  } catch (error) {
    console.error('Admin session creation failed:', error);
    throw error;
  }
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: req.secure,
    sameSite: 'strict',
    path: '/',
    maxAge: SESSION_MS
  });
  res.json({ authenticated: true });
});

app.post('/api/logout', sameOrigin, async (req, res) => {
  const token = sessionToken(req);
  if (/^[a-f0-9]{64}$/.test(token)) {
    await store.deleteSession(createHash('sha256').update(token).digest('hex'));
  }
  res.clearCookie(SESSION_COOKIE, { path: '/' });
  res.json({ authenticated: false });
});

const fields = [
  'fullName', 'nationality', 'idNumber', 'idExpiry', 'birthDate', 'job',
  'mobile', 'email', 'hasLicense', 'licenseType', 'licenseExpiry',
  'hasVehicle', 'city', 'canRelocate', 'logisticsExp', 'transferSponsor',
  'transferCount', 'workType', 'notes', 'language'
];
const requiredFields = [
  'fullName', 'nationality', 'idNumber', 'idExpiry', 'birthDate', 'job',
  'mobile', 'email', 'hasLicense', 'hasVehicle', 'city', 'canRelocate',
  'logisticsExp', 'transferSponsor', 'workType'
];
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 4 * 1024 * 1024, fieldSize: 5000, files: 2, fields: 22, parts: 24 },
  fileFilter: (req, file, callback) => {
    if (!['idImage', 'licenseImage'].includes(file.fieldname)) {
      return callback(new Error('ملف غير متوقع.'));
    }
    callback(null, true);
  }
}).fields([{ name: 'idImage', maxCount: 1 }, { name: 'licenseImage', maxCount: 1 }]);

function detectedType(buffer) {
  if (buffer.subarray(0, 5).toString() === '%PDF-') return 'application/pdf';
  if (buffer.subarray(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff]))) return 'image/jpeg';
  if (buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) return 'image/png';
  if (['GIF87a', 'GIF89a'].includes(buffer.subarray(0, 6).toString())) return 'image/gif';
  if (buffer.subarray(0, 4).toString() === 'RIFF' && buffer.subarray(8, 12).toString() === 'WEBP') return 'image/webp';
  if (buffer.subarray(4, 8).toString() === 'ftyp' && /^(heic|heix|hevc|mif1)$/.test(buffer.subarray(8, 12).toString())) return 'image/heic';
  return null;
}

app.post('/api/applications', sameOrigin, upload, async (req, res) => {
  const data = Object.fromEntries(fields.map(field => [field, String(req.body[field] || '').trim()]));
  if (requiredFields.some(field => !data[field]) || !req.files?.idImage?.[0]) {
    return res.status(400).json({ error: 'يرجى استكمال جميع البيانات والصورة المطلوبة.' });
  }
  if (!/^\d{10}$/.test(data.idNumber) || !/^05\d{8}$/.test(data.mobile) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) {
    return res.status(400).json({ error: 'رقم الهوية أو الجوال أو البريد الإلكتروني غير صالح.' });
  }
  if (['hasLicense', 'hasVehicle', 'canRelocate', 'logisticsExp'].some(field => !['نعم', 'لا'].includes(data[field])) ||
      !['نعم', 'لا', 'غير مطلوب'].includes(data.transferSponsor)) {
    return res.status(400).json({ error: 'أحد الاختيارات غير صالح.' });
  }
  const idFile = req.files.idImage[0];
  const licenseFile = req.files.licenseImage?.[0] || null;
  const idType = detectedType(idFile.buffer);
  const licenseType = licenseFile ? detectedType(licenseFile.buffer) : null;
  if (!idType || (licenseFile && !licenseType)) {
    return res.status(400).json({ error: 'ارفع صورة أو ملف PDF صالحًا.' });
  }
  const id = randomBytes(16).toString('hex');
  const submittedAt = new Date().toISOString();
  const application = {
    ...data, id, submittedAt, status: 'جديد',
    idImageName: idFile.originalname,
    idImageType: idType,
    licenseImageName: licenseFile?.originalname || '',
    licenseImageType: licenseType || ''
  };
  await store.createApplication(application, idFile, licenseFile);
  res.status(201).json({ id });
});

app.get('/api/applications', requireAdmin, async (req, res) => {
  const applications = await store.listApplications();
  res.json(applications);
});

app.get('/api/applications/:id/files/:field', requireAdmin, async (req, res) => {
  if (!['idImage', 'licenseImage'].includes(req.params.field)) {
    return res.status(404).json({ error: 'الملف غير موجود.' });
  }
  const row = await store.getAttachment(req.params.id, req.params.field);
  if (!row?.data) return res.status(404).json({ error: 'الملف غير موجود.' });
  const filename = encodeURIComponent(row.name);
  const disposition = req.query.download === '1' || row.type === 'application/pdf' ? 'attachment' : 'inline';
  res.set('Content-Type', row.type);
  res.set('Content-Disposition', `${disposition}; filename="file"; filename*=UTF-8''${filename}`);
  res.send(row.data);
});

app.delete('/api/applications', sameOrigin, requireAdmin, async (req, res) => {
  await store.clearApplications();
  res.json({ ok: true });
});

const publicFiles = ['index.html', 'driver_registration_form.html', 'thanks.html', 'dashboard.html'];
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
for (const file of publicFiles) {
  app.get(`/${file}`, (req, res) => res.sendFile(path.join(__dirname, file)));
}

app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    return res.status(400).json({ error: 'الملفات كبيرة جدًا أو عددها غير مسموح. الحد 4 ميجابايت لكل ملف.' });
  }
  if (error.message === 'ملف غير متوقع.') return res.status(400).json({ error: error.message });
  console.error(error);
  res.status(500).json({ error: 'حدث خطأ في الخادم.' });
});

const port = Number(process.env.PORT || 3000);
app.listen(port, '0.0.0.0', () => console.log(`Server listening on http://localhost:${port}`));
