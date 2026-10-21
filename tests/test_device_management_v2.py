"""Regression tests for KeyHub device management v2.

Uses a separate temporary SQLite database and never touches Neon.
"""
import os
import tempfile
import unittest

TMP = tempfile.TemporaryDirectory()
os.environ['DATABASE_URL'] = 'sqlite:///' + TMP.name + '/keyhub-test.sqlite'
os.environ['JWT_SECRET'] = 'J' * 64
os.environ['KEY_PEPPER'] = 'K' * 64
os.environ['ALLOWED_ORIGINS'] = ''

from fastapi.testclient import TestClient
from app.db import SessionLocal
from app.main import app
from app.models import LicenseKey, User
from app.security import hash_password, new_license, secret_digest, now_ts


class DeviceManagementTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client_ctx = TestClient(app)
        cls.client = cls.client_ctx.__enter__()
        with SessionLocal() as db:
            admin = User(email='keyhub-test-user-741@gmail.com',
                         password_hash=hash_password('Secure-Test-Password-12345'),
                         is_admin=True, is_active=True)
            db.add(admin)
            db.flush()
            cls.raw_license = new_license()
            db.add(LicenseKey(owner_id=admin.id,
                              prefix=cls.raw_license[0],
                              key_digest=secret_digest(cls.raw_license[1]),
                              device_limit=1,
                              expires_at=now_ts() + 86400,
                              note='Regression test'))
            db.commit()
        login = cls.client.post('/api/v1/auth/login', json={
            'email': 'keyhub-test-user-741@gmail.com',
            'password': 'Secure-Test-Password-12345'
        })
        assert login.status_code == 200, login.text
        cls.headers = {'Authorization': 'Bearer ' + login.json()['access_token']}
        listed = cls.client.get('/api/v1/keys', headers=cls.headers)
        assert listed.status_code == 200, listed.text
        cls.key_id = listed.json()[0]['id']

    @classmethod
    def tearDownClass(cls):
        cls.client_ctx.__exit__(None, None, None)
        TMP.cleanup()

    def test_activation_rename_history_and_removal(self):
        payload = {'key': self.raw_license[1],
                   'device_id': '33333333-3333-3333-3333-333333333333',
                   'label': 'iPhone'}
        activated = self.client.post('/api/v1/keys/activate-with-key', json=payload)
        self.assertEqual(activated.status_code, 200, activated.text)
        self.assertTrue(activated.json()['valid'])
        code = activated.json()['device_code']
        self.assertTrue(code.startswith('KH-'))

        url = f'/api/v1/keys/{self.key_id}/devices'
        listed = self.client.get(url, headers=self.headers)
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual(len(listed.json()), 1)
        old_device = listed.json()[0]
        self.assertEqual(old_device['device_code'], code)
        self.assertIsInstance(old_device['last_verified_at'], int)
        old_id = old_device['id']

        # Verifications update last-seen but do not grow the audit history.
        verified = self.client.post('/api/v1/keys/verify', json=payload)
        self.assertEqual(verified.status_code, 200, verified.text)
        self.assertTrue(verified.json()['valid'])

        other = dict(payload, device_id='44444444-4444-4444-4444-444444444444')
        limit = self.client.post('/api/v1/keys/activate-with-key', json=other)
        self.assertEqual(limit.status_code, 409, limit.text)

        renamed = self.client.post(f'{url}/{old_id}/rename',
                                   json={'label': 'iPhone 13 - Khach A'},
                                   headers=self.headers)
        self.assertEqual(renamed.status_code, 200, renamed.text)
        self.assertEqual(renamed.json()['label'], 'iPhone 13 - Khach A')
        self.assertEqual(renamed.json()['device_code'], code)
        self.assertEqual(renamed.json()['last_verified_at'], old_device['last_verified_at'])

        history_url = f'{url}/history'
        history = self.client.get(history_url, headers=self.headers)
        self.assertEqual(history.status_code, 200, history.text)
        self.assertEqual({e['event_type'] for e in history.json()}, {'activated', 'renamed'})
        self.assertEqual(len(history.json()), 2)

        # Unchanged name doesn't create a duplicate event.
        again = self.client.post(f'{url}/{old_id}/rename',
                                 json={'label': 'iPhone 13 - Khach A'},
                                 headers=self.headers)
        self.assertEqual(again.status_code, 200, again.text)
        history = self.client.get(history_url, headers=self.headers)
        self.assertEqual(len(history.json()), 2)

        removed = self.client.delete(f'{url}/{old_id}', headers=self.headers)
        self.assertEqual(removed.status_code, 200, removed.text)
        self.assertEqual(self.client.get(url, headers=self.headers).json(), [])
        history = self.client.get(history_url, headers=self.headers)
        self.assertEqual(len(history.json()), 3)
        self.assertIn('removed', {e['event_type'] for e in history.json()})
        self.assertFalse(self.client.post('/api/v1/keys/verify',
                                          json=payload).json()['valid'])

    def test_unauthorized_history_and_rename(self):
        history = self.client.get(f'/api/v1/keys/{self.key_id}/devices/history')
        self.assertEqual(history.status_code, 401)


if __name__ == '__main__':
    unittest.main()
