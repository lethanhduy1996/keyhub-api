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
from app.models import Activation, DeviceAuditEvent, DeviceHeartbeat, LicenseKey, User
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

    def test_admin_can_only_delete_inactive_licenses(self):
        with SessionLocal() as db:
            owner = db.scalar(__import__('sqlalchemy').select(User).where(
                User.email == 'keyhub-test-user-741@gmail.com'))
            self.assertIsNotNone(owner)
            specs = [('expired', now_ts()-60, None),
                     ('revoked', now_ts()+86400, now_ts()-30),
                     ('active', now_ts()+86400, None)]
            key_ids = {}
            for label, expiry, revoked in specs:
                prefix, secret = new_license()
                row = LicenseKey(owner_id=owner.id,
                                 prefix=prefix, key_digest=secret_digest(secret),
                                 device_limit=1, expires_at=expiry,
                                 revoked_at=revoked, note=label)
                db.add(row)
                db.flush()
                key_ids[label] = row.id
                if label == 'revoked':
                    digest = secret_digest('test-device-identifier-abc')
                    db.add(Activation(key_id=row.id, device_hash=digest,
                                      label='test phone'))
                    db.add(DeviceHeartbeat(key_id=row.id, device_hash=digest,
                                           last_verified_at=now_ts()))
                    db.add(DeviceAuditEvent(key_id=row.id,
                                            device_code='KH-TESTDEVICE-ABCDEF12',
                                            label='test phone',
                                            event_type='activated'))
            db.commit()
        url = '/api/v1/keys'
        # Authentication and confirmations enforced on the backend.
        anonymous = self.client.delete(url+'/inactive?confirm=true')
        self.assertEqual(anonymous.status_code, 401)
        not_confirmed = self.client.delete(url+'/inactive', headers=self.headers)
        self.assertEqual(not_confirmed.status_code, 400)
        active = self.client.delete(url+'/'+key_ids['active'],
                                    headers=self.headers)
        self.assertEqual(active.status_code, 409)

        # Both expired and revoked can be deleted individually.
        for kind in ('expired','revoked'):
            deleted = self.client.delete(url+'/'+key_ids[kind], headers=self.headers)
            self.assertEqual(deleted.status_code, 200, deleted.text)
            missing = self.client.delete(url+'/'+key_ids[kind],
                                         headers=self.headers)
            self.assertEqual(missing.status_code, 404)
        with SessionLocal() as db:
            self.assertIsNone(db.get(LicenseKey, key_ids['revoked']))
            self.assertFalse(db.query(Activation).filter_by(
                key_id=key_ids['revoked']).count())
            self.assertFalse(db.query(DeviceHeartbeat).filter_by(
                key_id=key_ids['revoked']).count())
            self.assertFalse(db.query(DeviceAuditEvent).filter_by(
                key_id=key_ids['revoked']).count())
            self.assertIsNotNone(db.get(LicenseKey, key_ids['active']))

        # Bulk cleanup removes inactive records only; active ones survive.
        with SessionLocal() as db:
            owner = db.scalar(__import__('sqlalchemy').select(User).where(
                User.email == 'keyhub-test-user-741@gmail.com'))
            for label in ('expired-bulk','revoked-bulk'):
                prefix, secret = new_license()
                db.add(LicenseKey(owner_id=owner.id, prefix=prefix,
                    key_digest=secret_digest(secret), device_limit=1,
                    expires_at=now_ts()-120 if label.startswith('expired') else now_ts()+86400,
                    revoked_at=now_ts() if label.startswith('revoked') else None,
                    note=label))
            db.commit()
        cleaned = self.client.delete(url+'/inactive?confirm=true',
                                     headers=self.headers)
        self.assertEqual(cleaned.status_code, 200, cleaned.text)
        self.assertGreaterEqual(cleaned.json()['deleted'], 2)
        self.assertEqual(cleaned.json()['remaining'], 0)
        with SessionLocal() as db:
            self.assertIsNotNone(db.get(LicenseKey, key_ids['active']))
        cleaned_again=self.client.delete(url+'/inactive?confirm=true',
                                         headers=self.headers)
        self.assertEqual(cleaned_again.json()['deleted'], 0)

    def test_telegram_bot_authorization_idempotence_and_key_lifecycle(self):
        from unittest.mock import AsyncMock, patch
        from app.config import get_settings
        from app.models import TelegramProcessedUpdate
        from app.security import license_prefix

        settings = get_settings()
        originals = {
            key: getattr(settings, key)
            for key in ('telegram_bot_token', 'telegram_webhook_secret',
                        'telegram_admin_ids', 'telegram_owner_email',
                        'telegram_webhook_base_url')
        }
        settings.telegram_bot_token = '123456:fake-test-telegram-token'
        settings.telegram_webhook_secret = 'webhookSecret12345'
        settings.telegram_admin_ids = '74123456'
        settings.telegram_owner_email = 'keyhub-test-user-741@gmail.com'
        settings.telegram_webhook_base_url = ''

        url = '/api/v1/telegram/webhook'
        headers = {'X-Telegram-Bot-Api-Secret-Token': settings.telegram_webhook_secret}
        def message(update_id, telegram_id, text):
            return {'update_id': update_id, 'message': {
                'message_id': update_id,
                'from': {'id': telegram_id},
                'chat': {'id': telegram_id, 'type': 'private'},
                'text': text
            }}
        def callback(update_id, telegram_id, data):
            return {'update_id': update_id, 'callback_query': {
                'id': 'callback' + str(update_id),
                'from': {'id': telegram_id},
                'message': {'message_id': update_id,
                            'chat': {'id': telegram_id, 'type': 'private'}},
                'data': data
            }}
        def count_keys():
            with SessionLocal() as db:
                return db.query(LicenseKey).count()
        try:
            with patch('app.telegram_bot.telegram_api_call',
                       new_callable=AsyncMock) as telegram:
                telegram.return_value = {'ok': True}
                denied = self.client.post(url, json=message(
                    74100001, 74123456, '/taokey 30 1'))
                self.assertEqual(denied.status_code, 403)

                initial_count = count_keys()
                unauth = self.client.post(url, headers=headers, json=message(
                    74100002, 74123457, '/taokey 30 1'))
                self.assertEqual(unauth.status_code, 200, unauth.text)
                self.assertEqual(count_keys(), initial_count)
                self.assertIn('74123457', str(telegram.call_args_list))

                # Group/chat spoofing is ignored by the bot.
                blocked_group = message(74100003, 74123456, '/taokey 30 1')
                blocked_group['message']['chat'] = {'id': -7412, 'type': 'group'}
                before_calls = telegram.call_count
                group = self.client.post(url, headers=headers, json=blocked_group)
                self.assertEqual(group.status_code, 200)
                self.assertEqual(telegram.call_count, before_calls)

                prompted = self.client.post(url, headers=headers, json=message(
                    74100004, 74123456, '/taokey 30 1'))
                self.assertEqual(prompted.status_code, 200, prompted.text)
                self.assertEqual(count_keys(), initial_count)
                self.assertIn('issue:30:1', str(telegram.call_args))

                created = self.client.post(url, headers=headers, json=callback(
                    74100005, 74123456, 'issue:30:1'))
                self.assertEqual(created.status_code, 200, created.text)
                self.assertEqual(count_keys(), initial_count + 1)
                key_message = next(
                    entry.args[1]['text'] for entry in reversed(telegram.call_args_list)
                    if entry.args[0] == 'sendMessage' and 'ĐÃ TẠO LICENSE' in entry.args[1]['text']
                )
                secret = key_message.splitlines()[2]
                prefix = license_prefix(secret)
                self.assertIsNotNone(prefix)
                self.assertIn('protect_content', str(telegram.call_args_list))
                call_count = telegram.call_count
                replay = self.client.post(url, headers=headers, json=callback(
                    74100005, 74123456, 'issue:30:1'))
                self.assertEqual(replay.status_code, 200, replay.text)
                self.assertEqual(telegram.call_count, call_count)
                self.assertEqual(count_keys(), initial_count + 1)

                renewed = self.client.post(url, headers=headers, json=callback(
                    74100006, 74123456, 'renew:' + prefix + ':7'))
                self.assertEqual(renewed.status_code, 200, renewed.text)
                with SessionLocal() as db:
                    item = db.scalar(__import__('sqlalchemy').select(LicenseKey).where(
                        LicenseKey.prefix == prefix))
                    self.assertGreater(item.expires_at, now_ts() + 30*86400)

                ask_delete = self.client.post(url, headers=headers, json=callback(
                    74100007, 74123456, 'delete:' + prefix))
                self.assertEqual(ask_delete.status_code, 200)
                self.assertIn('Không thể xóa License còn hiệu lực', str(telegram.call_args))
                self.assertEqual(count_keys(), initial_count + 1)

                revoke = self.client.post(url, headers=headers, json=callback(
                    74100008, 74123456, 'revoke:' + prefix))
                self.assertEqual(revoke.status_code, 200, revoke.text)
                with SessionLocal() as db:
                    item = db.scalar(__import__('sqlalchemy').select(LicenseKey).where(
                        LicenseKey.prefix == prefix))
                    self.assertIsNotNone(item.revoked_at)

                deleted = self.client.post(url, headers=headers, json=callback(
                    74100009, 74123456, 'delete:' + prefix))
                self.assertEqual(deleted.status_code, 200, deleted.text)
                self.assertEqual(count_keys(), initial_count)

                # Delivery errors rollback the side effect AND the update claim.
                telegram.side_effect = RuntimeError('Simulated Telegram unavailable')
                unavailable = self.client.post(url, headers=headers, json=callback(
                    74100010, 74123456, 'issue:1:1'))
                self.assertEqual(unavailable.status_code, 502)
                self.assertEqual(count_keys(), initial_count)
                with SessionLocal() as db:
                    self.assertIsNone(db.get(TelegramProcessedUpdate, 74100010))
                telegram.side_effect = None
                delivered = self.client.post(url, headers=headers, json=callback(
                    74100010, 74123456, 'issue:1:1'))
                self.assertEqual(delivered.status_code, 200, delivered.text)
                self.assertEqual(count_keys(), initial_count+1)
        finally:
            for key, value in originals.items():
                setattr(settings, key, value)

    def test_unauthorized_history_and_rename(self):
        history = self.client.get(f'/api/v1/keys/{self.key_id}/devices/history')
        self.assertEqual(history.status_code, 401)


if __name__ == '__main__':
    unittest.main()
