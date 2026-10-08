import base64
import hashlib
import json
import unittest
from pathlib import Path
from unittest import mock
import uuid

import requests

from app.action import Action, RetryableError, VerificationError
from app.config import get_or_create_device_fingerprint, load_config
from app.notify import NotifyError, TelegramNotifier


class FakeResponse:
    def __init__(self, url, text='', json_data=None, headers=None, status_code=200):
        self.url = url
        self.text = text
        self._json_data = json_data
        self.headers = headers or {}
        self.status_code = status_code

    def json(self):
        if self._json_data is None:
            raise ValueError('no json')
        return self._json_data


class FakeSession:
    def __init__(self, responses):
        self.responses = responses
        self.headers = {}
        self.calls = []

    def _pop(self, method, url):
        key = (method, url)
        if key not in self.responses or not self.responses[key]:
            raise AssertionError(f'unexpected {method} {url}')
        return self.responses[key].pop(0)

    def get(self, url, **kwargs):
        self.calls.append(('GET', url, kwargs))
        return self._pop('GET', url)

    def post(self, url, data=None, **kwargs):
        self.calls.append(('POST', url, {'data': data, **kwargs}))
        return self._pop('POST', url)


def build_challenge(number=7, salt='salt?expires=9999999999&', algorithm='SHA-256'):
    challenge = hashlib.sha256(f'{salt}{number}'.encode('utf-8')).hexdigest()
    return {
        'algorithm': algorithm,
        'challenge': challenge,
        'maxnumber': 50,
        'salt': salt,
        'signature': 'signed',
    }


class ActionTests(unittest.TestCase):
    def setUp(self):
        # Every test is offline. Never invoke a live challenge solver or allow
        # a real HTTP request, even if a regression forgets to inject a session.
        self.http_guard = mock.patch(
            'requests.sessions.Session.request',
            side_effect=AssertionError('offline test: real HTTP is disabled'),
        )
        self.http_guard.start()
        self.addCleanup(self.http_guard.stop)
        self.fake_altcha = base64.b64encode(json.dumps({
            'algorithm': 'SHA-256',
            'challenge': build_challenge()['challenge'],
            'number': 7,
            'salt': 'salt?expires=9999999999&',
            'signature': 'signed',
        }).encode('utf-8')).decode('ascii')
        self.solver = mock.patch.object(Action, '_solve_altcha', return_value=self.fake_altcha)
        self.solver_mock = self.solver.start()
        self.addCleanup(self.solver.stop)

    def test_load_config_merges_default_and_local_files(self):
        tmp = Path('.test-config-tmp') / str(uuid.uuid4())
        tmp.mkdir(parents=True, exist_ok=True)
        try:
            default_path = tmp / 'config.default.json'
            local_path = tmp / 'config.local.json'
            default_path.write_text(json.dumps({
                'email': '',
                'passwd': '',
                'secret': '',
                'code': '',
                'verify_method': '',
                'host': 'cordcloud.one',
                'trust_device': 'false',
                'insecure_skip_verify': 'false',
                'telegram_bot_token': '',
                'telegram_chat_id': '',
                'device_fingerprint': '',
            }), encoding='utf-8')
            local_path.write_text(json.dumps({
                'email': 'user@example.com',
                'passwd': 'passwd',
                'code': '123456',
            }), encoding='utf-8')

            config = load_config((default_path, local_path))
        finally:
            if local_path.exists():
                local_path.unlink()
            if default_path.exists():
                default_path.unlink()
            tmp.rmdir()

        self.assertEqual(config['email'], 'user@example.com')
        self.assertEqual(config['passwd'], 'passwd')
        self.assertEqual(config['code'], '123456')
        self.assertEqual(config['host'], 'cordcloud.one')

    def test_device_fingerprint_is_persisted_only_in_local_config(self):
        tmp = Path('.test-config-tmp') / str(uuid.uuid4())
        tmp.mkdir(parents=True, exist_ok=True)
        try:
            local_path = tmp / 'config.local.json'
            local_path.write_text('{}', encoding='utf-8')
            config = load_config((local_path,))

            fingerprint = get_or_create_device_fingerprint(config, local_path=local_path)
            saved = json.loads(local_path.read_text(encoding='utf-8'))

            self.assertEqual(saved['device_fingerprint'], fingerprint)
            self.assertEqual(get_or_create_device_fingerprint(config, local_path=local_path), fingerprint)
        finally:
            if local_path.exists():
                local_path.unlink()
            tmp.rmdir()

    def test_login_submits_csrf_altcha_and_fingerprint(self):
        login_html = '''
        <form action="javascript:void(0);" method="POST" id="login-form">
            <input type="hidden" name="csrf_token" value="csrf-1">
            <input type="email" id="email" name="Email" value="">
            <input type="password" id="passwd" name="Password" value="">
            <altcha-widget challengeurl="/auth/altcha/challenge"></altcha-widget>
        </form>
        '''
        challenge = build_challenge()
        session = FakeSession({
            ('GET', 'https://cordcloud.one/auth/login'): [
                FakeResponse('https://cordcloud.one/auth/login', text=login_html),
            ],
            ('GET', 'https://cordcloud.one/auth/altcha/challenge'): [
                FakeResponse('https://cordcloud.one/auth/altcha/challenge', json_data=challenge),
            ],
            ('POST', 'https://cordcloud.one/auth/login'): [
                FakeResponse('https://cordcloud.one/auth/login', json_data={'ret': 1, 'msg': '登录成功'}),
            ],
        })

        action = Action('user@example.com', 'passwd', host='cordcloud.one', session=session)
        result = action.login()

        self.assertEqual(result['ret'], 1)
        _, _, post_kwargs = session.calls[-1]
        form_data = post_kwargs['data']
        self.assertEqual(form_data['email'], 'user@example.com')
        self.assertEqual(form_data['passwd'], 'passwd')
        self.assertEqual(form_data['csrf_token'], 'csrf-1')
        self.assertEqual(form_data['device_fingerprint'], action.device_fingerprint)
        self.assertTrue(post_kwargs['verify'])

        payload = json.loads(base64.b64decode(form_data['altcha']).decode('utf-8'))
        self.assertEqual(payload['challenge'], challenge['challenge'])
        self.assertEqual(payload['number'], 7)

    def test_login_handles_device_2fa(self):
        login_html = '''
        <form action="javascript:void(0);" method="POST" id="login-form">
            <input type="hidden" name="csrf_token" value="csrf-1">
            <altcha-widget challengeurl="/auth/altcha/challenge"></altcha-widget>
        </form>
        '''
        session = FakeSession({
            ('GET', 'https://cordcloud.one/auth/login'): [
                FakeResponse('https://cordcloud.one/auth/login', text=login_html),
            ],
            ('GET', 'https://cordcloud.one/auth/altcha/challenge'): [
                FakeResponse('https://cordcloud.one/auth/altcha/challenge', json_data=build_challenge()),
            ],
            ('POST', 'https://cordcloud.one/auth/login'): [
                FakeResponse(
                    'https://cordcloud.one/auth/login',
                    json_data={
                        'ret': 2,
                        'msg': '需要设备验证',
                        'need_device_2fa': True,
                        'methods': {'email': True, 'ga': True},
                        'token': 'abc',
                        'redirect': '/auth/login/2fa?token=abc',
                    },
                ),
            ],
            ('POST', 'https://cordcloud.one/auth/login/2fa/verify'): [
                FakeResponse('https://cordcloud.one/auth/login/2fa/verify', json_data={'ret': 1, 'msg': '登录成功'}),
            ],
        })

        action = Action('user@example.com', 'passwd', secret='JBSWY3DPEHPK3PXP', host='cordcloud.one', session=session)
        with mock.patch.object(Action, '_current_code', return_value='123456'):
            result = action.login()

        self.assertEqual(result['ret'], 1)
        _, _, post_kwargs = session.calls[-1]
        form_data = post_kwargs['data']
        self.assertEqual(form_data['code'], '123456')
        self.assertEqual(form_data['trust_device'], '0')
        self.assertEqual(form_data['token'], 'abc')
        self.assertEqual(form_data['method'], 'ga')
        self.assertTrue(post_kwargs['verify'])
        verify_get_calls = [call for call in session.calls if call[0] == 'GET' and '/auth/login/2fa?' in call[1]]
        self.assertEqual(verify_get_calls, [])

    def test_login_can_explicitly_trust_device(self):
        login_html = '''
        <form action="javascript:void(0);" method="POST" id="login-form">
            <input type="hidden" name="csrf_token" value="csrf-1">
            <altcha-widget challengeurl="/auth/altcha/challenge"></altcha-widget>
        </form>
        '''
        verify_html = '''
        <form action="javascript:void(0);" method="POST" id="verify-form">
            <input type="hidden" name="token" value="abc">
            <input type="hidden" name="method" id="verify-method" value="email">
            <input type="text" id="code" name="code" value="">
        </form>
        '''
        session = FakeSession({
            ('GET', 'https://cordcloud.one/auth/login'): [
                FakeResponse('https://cordcloud.one/auth/login', text=login_html),
            ],
            ('GET', 'https://cordcloud.one/auth/altcha/challenge'): [
                FakeResponse('https://cordcloud.one/auth/altcha/challenge', json_data=build_challenge()),
            ],
            ('POST', 'https://cordcloud.one/auth/login'): [
                FakeResponse(
                    'https://cordcloud.one/auth/login',
                    json_data={
                        'ret': 2,
                        'msg': '需要设备验证',
                        'need_device_2fa': True,
                        'methods': {'email': True},
                        'redirect': '/auth/login/2fa?token=abc',
                    },
                ),
            ],
            ('GET', 'https://cordcloud.one/auth/login/2fa?token=abc'): [
                FakeResponse('https://cordcloud.one/auth/login/2fa?token=abc', text=verify_html),
            ],
            ('POST', 'https://cordcloud.one/auth/login/2fa/verify'): [
                FakeResponse('https://cordcloud.one/auth/login/2fa/verify', json_data={'ret': 1, 'msg': '登录成功'}),
            ],
        })

        action = Action(
            'user@example.com',
            'passwd',
            code='123456',
            host='cordcloud.one',
            session=session,
            trust_device=True,
        )
        result = action.login()

        self.assertEqual(result['ret'], 1)
        _, _, post_kwargs = session.calls[-1]
        self.assertEqual(post_kwargs['data']['trust_device'], '1')

    def test_login_respects_explicit_email_verify_method(self):
        login_html = '''
        <form action="javascript:void(0);" method="POST" id="login-form">
            <input type="hidden" name="csrf_token" value="csrf-1">
            <altcha-widget challengeurl="/auth/altcha/challenge"></altcha-widget>
        </form>
        '''
        verify_html = '''
        <form action="javascript:void(0);" method="POST" id="verify-form">
            <input type="hidden" name="csrf_token" value="csrf-2">
            <input type="hidden" name="token" value="abc">
            <input type="hidden" name="method" id="verify-method" value="email">
            <input type="text" id="code" name="code" value="">
        </form>
        '''
        session = FakeSession({
            ('GET', 'https://cordcloud.one/auth/login'): [
                FakeResponse('https://cordcloud.one/auth/login', text=login_html),
            ],
            ('GET', 'https://cordcloud.one/auth/altcha/challenge'): [
                FakeResponse('https://cordcloud.one/auth/altcha/challenge', json_data=build_challenge()),
            ],
            ('POST', 'https://cordcloud.one/auth/login'): [
                FakeResponse(
                    'https://cordcloud.one/auth/login',
                    json_data={
                        'ret': 2,
                        'msg': '需要设备验证',
                        'need_device_2fa': True,
                        'methods': {'email': True, 'ga': True},
                        'token': 'abc',
                        'redirect': '/auth/login/2fa?token=abc',
                    },
                ),
            ],
            ('GET', 'https://cordcloud.one/auth/login/2fa?token=abc'): [
                FakeResponse('https://cordcloud.one/auth/login/2fa?token=abc', text=verify_html),
            ],
            ('POST', 'https://cordcloud.one/auth/login/2fa/verify'): [
                FakeResponse('https://cordcloud.one/auth/login/2fa/verify', json_data={'ret': 1, 'msg': '登录成功'}),
            ],
        })

        action = Action(
            'user@example.com',
            'passwd',
            secret='JBSWY3DPEHPK3PXP',
            code='654321',
            verify_method='email',
            host='cordcloud.one',
            session=session,
        )
        result = action.login()

        self.assertEqual(result['ret'], 1)
        _, _, post_kwargs = session.calls[-1]
        form_data = post_kwargs['data']
        self.assertEqual(form_data['method'], 'email')
        self.assertEqual(form_data['code'], '654321')
        self.assertEqual(form_data['csrf_token'], 'csrf-2')

    def test_html_attributes_decode_entities_like_the_browser(self):
        action = Action('user@example.com', 'passwd')
        fields = action._extract_inputs(
            '<input type="hidden" name="csrf_token" value="token&amp;&quot;&#39;">'
        )
        self.assertEqual(fields['csrf_token'], 'token&"\'')
        self.assertEqual(action._extract_altcha_url(
            '<altcha-widget challengeurl="/auth/altcha/challenge?a=1&amp;b=2">'
        ), 'https://cordcloud.us/auth/altcha/challenge?a=1&b=2')
        self.assertEqual(action._extract_form_action(
            '<form action="/auth/login?a=1&amp;b=2">',
            'https://cordcloud.us/auth/login',
        ), 'https://cordcloud.us/auth/login?a=1&b=2')

    def test_login_verification_rejection_is_not_device_2fa(self):
        action = Action('user@example.com', 'passwd', verify_method='ga')
        page = FakeResponse('https://cordcloud.us/auth/login')
        rejection = {'ret': 0, 'msg': '系统无法接受您的验证结果，请刷新页面后重试'}
        with mock.patch.object(action, '_get', return_value=page), \
                mock.patch.object(action, '_submit_form', return_value=rejection), \
                mock.patch.object(action, '_device_2fa') as device_2fa:
            with self.assertRaisesRegex(VerificationError, '尚未进入设备二次验证'):
                action.login()
        device_2fa.assert_not_called()

    def test_ga_without_secret_does_not_reuse_email_code(self):
        action = Action('user@example.com', 'passwd', code='123456')
        self.assertEqual(action._current_code('ga'), '')
        self.assertEqual(action._current_code('email'), '123456')

    def test_auto_email_2fa_without_code_stops_without_submitting(self):
        session = FakeSession({})
        action = Action('user@example.com', 'passwd', verify_method='auto', session=session)
        result = action._device_2fa({
            'ret': 2, 'need_device_2fa': True, 'methods': {'email': True},
            'token': 'synthetic-token', 'redirect': '/auth/login/2fa?token=synthetic-token',
        })
        self.assertEqual(result['ret'], 0)
        self.assertIn('code', result['msg'])
        self.assertEqual(session.calls, [])

    def test_non_json_response_does_not_log_page_or_token(self):
        action = Action('user@example.com', 'passwd')
        response = FakeResponse('https://cordcloud.us/auth/login', text='private-token-123')
        with self.assertRaises(RetryableError) as raised:
            action._decode_json(response, '登录')
        self.assertNotIn('private-token-123', str(raised.exception))
        self.assertIn('HTTP 200', str(raised.exception))

    def test_json_array_cannot_count_as_api_success(self):
        action = Action('user@example.com', 'passwd')
        response = FakeResponse('https://cordcloud.us/auth/login', json_data=[{'ret': 1}])
        with self.assertRaisesRegex(RetryableError, '非对象 JSON'):
            action._decode_json(response, '登录')

    def test_http_error_cannot_count_as_api_success(self):
        action = Action('user@example.com', 'passwd')
        response = FakeResponse(
            'https://cordcloud.us/auth/login', json_data={'ret': 1}, status_code=403,
        )
        with self.assertRaisesRegex(RetryableError, 'HTTP 403'):
            action._decode_json(response, '登录')

    def test_network_exceptions_do_not_log_tokenized_url(self):
        for method in ('get', 'post'):
            with self.subTest(method=method):
                session = mock.Mock()
                getattr(session, method).side_effect = requests.RequestException(
                    'failed https://cordcloud.us/auth/login/2fa?token=private-token-123'
                )
                action = Action('user@example.com', 'passwd', session=session)
                with self.assertRaises(RetryableError) as raised:
                    if method == 'get':
                        action._get('/auth/login/2fa?token=private-token-123')
                    else:
                        action._post('/auth/login/2fa/verify', {})
                self.assertNotIn('private-token-123', str(raised.exception))

    def test_login_does_not_fetch_a_real_challenge(self):
        # The ordinary login regression must use only the canned proof fixture.
        action = Action('user@example.com', 'passwd')
        page = FakeResponse('https://cordcloud.us/auth/login')
        html = '<altcha-widget challengeurl="/auth/altcha/challenge"></altcha-widget>'
        with mock.patch.object(action, '_post', return_value=FakeResponse(
            page.url, json_data={'ret': 1},
        )) as post:
            action._submit_form(page, html, {})
        self.solver_mock.assert_called_once()
        self.assertEqual(post.call_args.args[1]['altcha'], self.fake_altcha)

    def test_telegram_notifier_sends_message(self):
        notifier = TelegramNotifier(bot_token='bot-token', chat_id='123456')
        response = mock.Mock(status_code=200)
        response.json.return_value = {'ok': True, 'result': {'message_id': 1}}

        with mock.patch('app.notify.requests.post', return_value=response) as mocked_post:
            self.assertTrue(notifier.send('签到成功'))

        mocked_post.assert_called_once()
        _, kwargs = mocked_post.call_args
        self.assertEqual(kwargs['data']['chat_id'], '123456')
        self.assertEqual(kwargs['data']['text'], '签到成功')

    def test_telegram_notifier_raises_on_api_error(self):
        notifier = TelegramNotifier(bot_token='bot-token', chat_id='123456')
        response = mock.Mock(status_code=400)
        response.json.return_value = {'ok': False, 'description': 'chat not found'}

        with mock.patch('app.notify.requests.post', return_value=response):
            with self.assertRaises(NotifyError):
                notifier.send('签到失败')

    def test_telegram_exception_does_not_log_bot_token(self):
        notifier = TelegramNotifier(bot_token='private-bot-token', chat_id='123456')
        with mock.patch('app.notify.requests.post', side_effect=requests.RequestException(
            'failed https://api.telegram.org/botprivate-bot-token/sendMessage'
        )):
            with self.assertRaises(NotifyError) as raised:
                notifier.send('test')
        self.assertNotIn('private-bot-token', str(raised.exception))

    def test_telegram_non_json_does_not_log_response(self):
        notifier = TelegramNotifier(bot_token='private-bot-token', chat_id='123456')
        response = FakeResponse('https://api.telegram.org', text='private-response-data')
        with mock.patch('app.notify.requests.post', return_value=response):
            with self.assertRaises(NotifyError) as raised:
                notifier.send('test')
        self.assertNotIn('private-response-data', str(raised.exception))

    def test_telegram_rejects_non_object_json(self):
        notifier = TelegramNotifier(bot_token='private-bot-token', chat_id='123456')
        response = FakeResponse('https://api.telegram.org', json_data=[])
        with mock.patch('app.notify.requests.post', return_value=response):
            with self.assertRaisesRegex(NotifyError, '非对象 JSON'):
                notifier.send('test')

    def test_check_in_uses_user_csrf_token(self):
        user_html = '''
        <div class="dashboard">
            <input type="hidden" name="csrf_token" value="csrf-user">
        </div>
        '''
        session = FakeSession({
            ('GET', 'https://cordcloud.one/user'): [
                FakeResponse('https://cordcloud.one/user', text=user_html),
            ],
            ('POST', 'https://cordcloud.one/user/checkin'): [
                FakeResponse('https://cordcloud.one/user/checkin', json_data={'ret': 1, 'msg': '签到成功'}),
            ],
        })

        action = Action('user@example.com', 'passwd', host='cordcloud.one', session=session)
        result = action.check_in()

        self.assertEqual(result['ret'], 1)
        _, _, post_kwargs = session.calls[-1]
        self.assertEqual(post_kwargs['data']['csrf_token'], 'csrf-user')


if __name__ == '__main__':
    unittest.main()
