const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { createServer } = require('node:net');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

async function freePort() {
  const server = createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

test('registration, protected files, login and logout', async () => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'driver-registration-'));
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, ['server.js'], {
    cwd: __dirname,
    env: { ...process.env, PORT: String(port), DATA_DIR: dataDir, ADMIN_PASSWORD: 'test-password' },
    stdio: 'ignore'
  });
  try {
    let ready = false;
    for (let i = 0; i < 50; i++) {
      if (child.exitCode !== null) break;
      try {
        const response = await fetch(`${base}/api/health`);
        ready = response.ok;
        if (ready) break;
      } catch {}
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.equal(ready, true, 'server should start');

    const anonymousList = await fetch(`${base}/api/applications`);
    assert.equal(anonymousList.status, 401);
    const wrongLogin = await fetch(`${base}/api/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'wrong' })
    });
    assert.equal(wrongLogin.status, 401);
    const foreignLogin = await fetch(`${base}/api/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'https://example.com' },
      body: JSON.stringify({ password: 'test-password' })
    });
    assert.equal(foreignLogin.status, 403);

    const form = new FormData();
    const values = {
      fullName: 'اختبار مستخدم', nationality: 'سعودي', idNumber: '1234567890',
      idExpiry: '2030-01-01', birthDate: '1990-01-01', job: 'مندوب',
      mobile: '0512345678', email: 'test@example.com', hasLicense: 'نعم',
      hasVehicle: 'لا', city: 'الرياض', canRelocate: 'نعم', logisticsExp: 'لا',
      transferSponsor: 'غير مطلوب', workType: 'توصيل طرود', notes: 'ملاحظة'
    };
    for (const [name, value] of Object.entries(values)) form.append(name, value);
    const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScL/nwAAAABJRU5ErkJggg==', 'base64');
    const invalidForm = new FormData();
    for (const [name, value] of Object.entries(values)) invalidForm.append(name, value);
    invalidForm.append('idImage', new Blob(['not an image'], { type: 'image/png' }), 'invalid.png');
    assert.equal((await fetch(`${base}/api/applications`, { method: 'POST', body: invalidForm })).status, 400);
    form.append('idImage', new Blob([png], { type: 'image/png' }), 'id.png');
    const submitted = await fetch(`${base}/api/applications`, { method: 'POST', body: form });
    assert.equal(submitted.status, 201);
    const { id } = await submitted.json();
    assert.equal((await fetch(`${base}/api/applications/${id}/files/idImage`)).status, 401);
    const diskDb = new DatabaseSync(path.join(dataDir, 'applications.sqlite'));
    const stored = diskDb.prepare('SELECT id_image FROM applications WHERE id = ?').get(id);
    assert.deepEqual(Buffer.from(stored.id_image), png);
    diskDb.close();

    const login = await fetch(`${base}/api/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'test-password' })
    });
    assert.equal(login.status, 200);
    const cookie = login.headers.get('set-cookie').split(';')[0];
    assert.match(login.headers.get('set-cookie'), /HttpOnly/);
    const list = await fetch(`${base}/api/applications`, { headers: { Cookie: cookie } });
    assert.equal(list.status, 200);
    const applications = await list.json();
    assert.equal(applications.length, 1);
    assert.equal(applications[0].fullName, values.fullName);
    assert.equal(applications[0].workType, values.workType);
    assert.equal(applications[0].idImageName, 'id.png');

    const attachment = await fetch(`${base}/api/applications/${id}/files/idImage`, { headers: { Cookie: cookie } });
    assert.equal(attachment.status, 200);
    assert.equal(attachment.headers.get('content-type'), 'image/png');
    assert.deepEqual(Buffer.from(await attachment.arrayBuffer()), png);

    const deleted = await fetch(`${base}/api/applications`, {
      method: 'DELETE', headers: { Cookie: cookie }
    });
    assert.equal(deleted.status, 200);
    assert.equal((await fetch(`${base}/api/applications`, { headers: { Cookie: cookie } }).then(response => response.json())).length, 0);
    assert.equal((await fetch(`${base}/api/applications/${id}/files/idImage`, { headers: { Cookie: cookie } })).status, 404);

    const logout = await fetch(`${base}/api/logout`, { method: 'POST', headers: { Cookie: cookie } });
    assert.equal(logout.status, 200);
    assert.equal((await fetch(`${base}/api/applications`, { headers: { Cookie: cookie } })).status, 401);
  } finally {
    child.kill();
    await new Promise(resolve => child.once('exit', resolve));
    rmSync(dataDir, { recursive: true, force: true });
  }
});
