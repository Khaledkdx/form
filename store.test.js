const test = require('node:test');
const assert = require('node:assert/strict');
const { createSupabaseStore } = require('./store');

function response(data = null, error = null) {
  return { data, error };
}

test('removes uploaded files when database insert fails', async () => {
  const uploaded = [];
  const removed = [];
  const client = {
    storage: { from: () => ({
      async upload(path) { uploaded.push(path); return response(); },
      async remove(paths) { removed.push(...paths); return response(); }
    }) },
    from: () => ({
      async insert() { return response(null, new Error('database unavailable')); }
    })
  };
  const store = createSupabaseStore(client);
  const application = {
    id: 'test-id', submittedAt: new Date().toISOString(),
    idImageType: 'image/png', licenseImageType: 'image/png'
  };
  const file = { buffer: Buffer.from('png'), originalname: 'image.png' };
  await assert.rejects(store.createApplication(application, file, file), /database unavailable/);
  assert.deepEqual(uploaded, ['test-id/id', 'test-id/license']);
  assert.deepEqual(removed, uploaded);
});

test('removes first file when second upload fails', async () => {
  const removed = [];
  const client = {
    storage: { from: () => ({
      async upload(path) {
        return path.endsWith('license') ? response(null, new Error('storage full')) : response();
      },
      async remove(paths) { removed.push(...paths); return response(); }
    }) }
  };
  const store = createSupabaseStore(client);
  const application = { id: 'test-id', idImageType: 'image/png', licenseImageType: 'image/png' };
  const file = { buffer: Buffer.from('png') };
  await assert.rejects(store.createApplication(application, file, file), /storage full/);
  assert.deepEqual(removed, ['test-id/id']);
});

test('clear removes private files before deleting their rows', async () => {
  const events = [];
  let rows = [{ id: 'test-id', id_image_path: 'test-id/id', license_image_path: 'test-id/license' }];
  const client = {
    storage: { from: () => ({
      async remove(paths) { events.push(['files', paths]); return response(); }
    }) },
    from: () => ({
      select() { return this; },
      order() { return this; },
      limit() { return Promise.resolve(response(rows)); },
      delete() { return this; },
      in(field, ids) {
        events.push(['rows', ids]);
        rows = [];
        return Promise.resolve(response());
      }
    })
  };
  await createSupabaseStore(client).clearApplications();
  assert.deepEqual(events, [
    ['files', ['test-id/id', 'test-id/license']],
    ['rows', ['test-id']]
  ]);
});
