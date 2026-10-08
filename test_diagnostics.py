"""Offline diagnostic/security regressions. No live solving or HTTP."""
import base64
import json
import runpy
import types
import unittest
from unittest import mock

import app
from app.action import Action, RequestSafetyError
from app.diagnostics import describe_challenge, describe_form
from test import FakeResponse, FakeSession, build_challenge


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.logs = []
        self.http_guard = mock.patch('requests.sessions.Session.request', side_effect=AssertionError('real HTTP forbidden'))
        self.http_guard.start()
        self.addCleanup(self.http_guard.stop)
        self.solver = mock.patch.object(Action, '_solve_altcha', return_value='synthetic-proof')
        self.solver_mock = self.solver.start()
        self.addCleanup(self.solver.stop)

    def action(self, responses=None, diagnostics=True):
        return Action('private-email', 'private-password', host='cordcloud.one',
                      session=FakeSession(responses or {}), diagnostics=diagnostics,
                      diagnostic_logger=self.logs.append)

    def records(self):
        return [json.loads(line.removeprefix('[diagnostic] ')) for line in self.logs]

    def test_diagnostics_off_emits_nothing(self):
        action = self.action(diagnostics=False)
        action._diagnose('login_result', outcome='accepted')
        self.assertEqual(self.logs, [])

    def test_form_metadata_never_contains_untrusted_values_or_unknown_names(self):
        html = '''<form id="login-form"><input name="csrf_token" value="secret-csrf">
        <input name="csrf_token" value="secret-csrf-2"><input name="secret-as-name" value="secret-value">
        <altcha-widget name="secret-widget-name" challenge="secret-challenge" challengeurl="/auth/x?token=secret-query">
        </altcha-widget></form>'''
        record = describe_form(html)
        self.assertEqual(record['csrf_input_count'], 2)
        self.assertEqual(record['duplicate_known_fields'], ['csrf_token'])
        self.assertEqual(record['unknown_field_count'], 1)
        self.assertEqual(record['widget_name'], 'other')
        self.assertEqual(record['widget_protocol_attributes'], ['challenge', 'challengeurl', 'name'])
        self.assertNotIn('secret-', json.dumps(record))

    def test_challenge_metadata_redacts_algorithm_and_field_names(self):
        record = describe_challenge({
            'algorithm': 'secret-algorithm', 'challenge': 'secret-hash',
            'salt': 'secret-salt', 'signature': 'secret-signature', 'secret-key': 'secret-value',
            'maxnumber': 'secret-not-a-number',
        })
        self.assertEqual(record['algorithm'], 'other')
        self.assertFalse(record['maxnumber_is_integer'])
        self.assertNotIn('secret-', json.dumps(record))

    def test_normal_challenge_shape(self):
        record = describe_challenge(build_challenge())
        self.assertEqual(record['algorithm'], 'SHA-256')
        self.assertTrue(record['required_strings_present'])
        self.assertTrue(record['maxnumber_is_integer'])

    def test_known_proof_self_check_without_solving(self):
        challenge = build_challenge()
        payload = {key: challenge[key] for key in ('algorithm', 'challenge', 'salt', 'signature')}
        payload['number'] = 7  # Known test fixture; no search is performed.
        proof = base64.b64encode(json.dumps(payload).encode()).decode()
        action = self.action()
        self.assertTrue(action._altcha_self_check(challenge, proof))
        payload['number'] = 8
        wrong = base64.b64encode(json.dumps(payload).encode()).decode()
        self.assertFalse(action._altcha_self_check(challenge, wrong))
        self.assertFalse(action._altcha_self_check(challenge, 'not base64'))
        self.assertFalse(action._altcha_self_check(challenge, base64.b64encode(b'null').decode()))
        self.solver_mock.assert_not_called()

    def test_cross_origin_actions_rejected_before_solver_or_submission(self):
        for target in ('https://attacker.invalid/auth', '//attacker.invalid/auth',
                       'http://cordcloud.one/auth', 'https://cordcloud.one:444/auth',
                       'https://private:credential@cordcloud.one/auth'):
            with self.subTest(target=target):
                action = self.action()
                html = f'<form action="{target}"><altcha-widget challengeurl="/challenge"></altcha-widget></form>'
                with self.assertRaises(RequestSafetyError):
                    action._submit_form(FakeResponse('https://cordcloud.one/auth/login'), html, {})
                self.assertEqual(action.session.calls, [])
        self.solver_mock.assert_not_called()

    def test_cross_origin_challenge_rejected_before_solver(self):
        action = self.action()
        html = '<form><altcha-widget challengeurl="https://attacker.invalid/?token=secret"></altcha-widget></form>'
        with self.assertRaises(RequestSafetyError):
            action._submit_form(FakeResponse('https://cordcloud.one/auth/login'), html, {})
        self.solver_mock.assert_not_called()
        self.assertEqual(action.session.calls, [])

    def test_unrecognized_widget_protocol_stops_before_login_post(self):
        action = self.action()
        html = '<form id="login-form"><altcha-widget challenge="/new-protocol"></altcha-widget></form>'
        from app.action import VerificationError
        with self.assertRaises(VerificationError):
            action._submit_form(FakeResponse('https://cordcloud.one/auth/login'), html, {})
        self.solver_mock.assert_not_called()
        self.assertEqual(action.session.calls, [])
        self.assertEqual(self.records()[-1]['reason'], 'unsupported_challenge')

    def test_post_redirect_does_not_forward_credentials_cross_origin(self):
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                action = self.action({('POST', 'https://cordcloud.one/auth/login'): [
                    FakeResponse('https://cordcloud.one/auth/login', status_code=status,
                                 headers={'Location': 'https://attacker.invalid/?token=private-token'})]})
                with self.assertRaises(RequestSafetyError):
                    action._post('/auth/login', {'passwd': 'private-password'}, stage='login_post')
                self.assertEqual(len(action.session.calls), 1)
                self.assertFalse(action.session.calls[0][2]['allow_redirects'])
        self.assertNotIn('private-', '\n'.join(self.logs))

    def test_cross_origin_get_redirect_is_rejected(self):
        action = self.action({('GET', 'https://cordcloud.one/auth/login'): [
            FakeResponse('https://cordcloud.one/auth/login', status_code=302,
                         headers={'Location': 'https://attacker.invalid/'})]})
        with self.assertRaises(RequestSafetyError):
            action._get('/auth/login')
        self.assertEqual(len(action.session.calls), 1)

    def test_same_origin_redirect_is_bounded_and_does_not_log_query(self):
        url = 'https://cordcloud.one/auth/login'
        target = url + '?token=private-token'
        action = self.action({
            ('GET', url): [FakeResponse(url, status_code=302, headers={'Location': target})],
            ('GET', target): [FakeResponse(target, text='private-html', headers={'Content-Type': 'text/html; charset=utf-8'})],
        })
        action._get('/auth/login', stage='login_get')
        self.assertEqual(len(action.session.calls), 2)
        self.assertEqual(self.records()[-1]['redirect_count'], 1)
        self.assertEqual(self.records()[-1]['content_type'], 'html')
        self.assertNotIn('private-', '\n'.join(self.logs))

    def test_same_origin_redirect_loop_stops(self):
        url = 'https://cordcloud.one/auth/login'
        action = self.action({('GET', url): [FakeResponse(url, status_code=302, headers={'Location': '/auth/login'}) for _ in range(6)]})
        with self.assertRaises(RequestSafetyError):
            action._get('/auth/login')
        self.assertEqual(len(action.session.calls), 6)

    def test_same_origin_post_302_drops_body_and_307_preserves_it(self):
        for status in (302, 307):
            with self.subTest(status=status):
                url, target = 'https://cordcloud.one/auth/login', 'https://cordcloud.one/auth/next'
                next_method = 'GET' if status == 302 else 'POST'
                action = self.action({
                    ('POST', url): [FakeResponse(url, status_code=status, headers={'Location': '/auth/next'})],
                    (next_method, target): [FakeResponse(target, json_data={'ret': 1})],
                })
                action._post('/auth/login', {'passwd': 'private-password'})
                _, _, kwargs = action.session.calls[1]
                self.assertFalse(kwargs['allow_redirects'])
                if status == 302:
                    self.assertNotIn('data', kwargs)
                else:
                    self.assertEqual(kwargs['data'], {'passwd': 'private-password'})

    def test_access_denial_stops_before_solver_or_post(self):
        for status in (403, 429):
            with self.subTest(status=status):
                url = 'https://cordcloud.one/auth/login'
                action = self.action({('GET', url): [FakeResponse(url, text='private-reflected-html', status_code=status)]})
                with self.assertRaises(RequestSafetyError):
                    action.login()
                self.assertEqual(len(action.session.calls), 1)
        self.solver_mock.assert_not_called()
        self.assertNotIn('private-', '\n'.join(self.logs))

    def test_device_2fa_result_is_sanitized_and_not_followed(self):
        url = 'https://cordcloud.one/auth/login'
        action = self.action({
            ('GET', url): [FakeResponse(url, text='<form id="login-form"><input name="csrf_token" value="private-csrf"></form>')],
            ('POST', url): [FakeResponse(url, json_data={'ret': 2, 'need_device_2fa': True,
                'token': 'private-token', 'msg': 'private-reflected-value', 'methods': {'email': True},
                'redirect': '/auth/login/2fa?token=private-token'})],
        })
        with mock.patch.object(action, '_device_2fa') as device:
            result = action.login()
        device.assert_not_called()
        self.assertEqual(result, {'ret': 2, 'diagnostic_outcome': 'device_2fa_required'})
        self.assertNotIn('private-', json.dumps(result) + '\n'.join(self.logs))
        self.assertEqual(len(action.session.calls), 2)

    def test_server_rejection_is_only_classified(self):
        action = self.action()
        with mock.patch.object(action, '_get', return_value=FakeResponse('https://cordcloud.one/auth/login')), \
             mock.patch.object(action, '_submit_form', return_value={'ret': 0, 'msg': '系统无法接受您的验证结果 private-reflected-value'}):
            result = action.login()
        self.assertEqual(result, {'ret': 0, 'diagnostic_outcome': 'verification_rejected'})
        self.assertNotIn('private-', json.dumps(result) + '\n'.join(self.logs))

    def test_diagnostic_public_methods_cannot_checkin_or_use_otp(self):
        action = self.action()
        for method, args in ((action.check_in, ()), (action.info, ()), (action._device_2fa, ({},))):
            with self.assertRaises(RequestSafetyError):
                method(*args)
        with mock.patch.object(action, 'login', return_value={'ret': 2}), \
             mock.patch.object(action, 'check_in') as checkin:
            self.assertEqual(action.run(), {'ret': 2})
        checkin.assert_not_called()
        self.assertEqual(action.session.calls, [])

    def run_entrypoint(self, result=None, error=None, extra_inputs=None):
        inputs = {'diagnostics': 'true', 'email': 'private-email', 'passwd': 'private-password', 'host': 'cordcloud.one'}
        inputs.update(extra_inputs or {})
        core = mock.Mock()
        core.get_input.side_effect = lambda key: inputs.get(key, '')
        toolkit = types.ModuleType('actions_toolkit')
        toolkit.core = core
        log = mock.Mock()
        action = mock.Mock()
        action.login.return_value = result
        action.login.side_effect = error
        with mock.patch.dict('sys.modules', {'actions_toolkit': toolkit, 'app.log': log}), \
             mock.patch.object(app, 'log', log, create=True), \
             mock.patch('app.action.Action', return_value=action) as constructor, \
             mock.patch('app.config.load_config', return_value={}), \
             mock.patch('app.config.get_or_create_device_fingerprint') as persist, \
             mock.patch('app.notify.TelegramNotifier') as notifier:
            namespace = runpy.run_path('main.py', run_name='__main__')
        persist.assert_not_called()
        notifier.assert_not_called()
        action.check_in.assert_not_called()
        action.info.assert_not_called()
        output = repr(log.mock_calls)
        self.assertNotIn('private-', output)
        return namespace, action, constructor, log

    def test_entrypoint_stops_at_login_even_if_authenticated(self):
        namespace, action, constructor, log = self.run_entrypoint(result={'ret': 1, 'msg': 'private-reflected-msg'})
        self.assertTrue(namespace['success'])
        self.assertTrue(constructor.call_args.kwargs['diagnostics'])
        action.login.assert_called_once()
        log.set_failed.assert_not_called()

    def test_entrypoint_stops_at_2fa(self):
        _, action, _, log = self.run_entrypoint(result={'ret': 2, 'msg': 'private-reflected-msg'})
        action.login.assert_called_once()
        log.set_failed.assert_not_called()

    def test_entrypoint_redacts_unexpected_exception_without_retry(self):
        _, action, _, log = self.run_entrypoint(error=RuntimeError('private-password private-query'))
        action.login.assert_called_once()
        log.set_failed.assert_called_once()

    def test_entrypoint_rejects_multiple_hosts(self):
        _, action, constructor, log = self.run_entrypoint(extra_inputs={'host': 'cordcloud.one,cordcloud.biz'})
        constructor.assert_not_called()
        action.login.assert_not_called()
        log.set_failed.assert_called_once()

    def test_entrypoint_rejects_disabled_tls(self):
        _, action, constructor, log = self.run_entrypoint(extra_inputs={'insecure_skip_verify': 'true'})
        constructor.assert_not_called()
        action.login.assert_not_called()
        log.set_failed.assert_called_once()


if __name__ == '__main__':
    unittest.main()
