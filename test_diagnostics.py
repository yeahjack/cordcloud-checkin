"""Offline diagnostic/security regressions. No live solving or HTTP."""
import base64
import json
import runpy
import types
import unittest
from unittest import mock

import app
from app.action import Action, RequestSafetyError
from app.diagnostics import describe_challenge, describe_form, describe_page
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


class PageOnlyTests(unittest.TestCase):
    def setUp(self):
        self.logs = []
        self.http_guard = mock.patch('requests.sessions.Session.request', side_effect=AssertionError('real HTTP forbidden'))
        self.http_guard.start()
        self.addCleanup(self.http_guard.stop)

    def action(self, responses=None, **kwargs):
        return Action('', '', host='cordcloud.one', page_only=True, session=FakeSession(responses or {}),
                      diagnostic_logger=self.logs.append, **kwargs)

    def test_page_summary_only_emits_fixed_categories(self):
        html = '''<form id="login-form" action="javascript:void(0)">
        <input name="Email" value="private-email"><input name="Password" value="private-password">
        <input name="csrf_token" value="private-csrf"><input name="private-unknown-name" value="private-value">
        </form><script src="/assets/login.js?token=private-query"></script>
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?secret=private-query"></script>
        <script src="https://static.geetest.com/gt.js?token=private-query"></script>
        <script src="https://cdn.jsdelivr.net/npm/altcha/dist/altcha.js"></script>
        <script src="https://private-host.invalid/private-path"></script>
        <script>window.grecaptcha; const hidden='private-inline';</script>'''
        record = describe_page(html, 'https://cordcloud.one/auth/login')
        self.assertEqual(record['provider_markers'], ['altcha', 'geetest', 'recaptcha', 'turnstile'])
        self.assertEqual(record['form_action_categories'], {'scripted': 1})
        self.assertEqual(record['known_fields'], ['Email', 'Password', 'csrf_token'])
        self.assertEqual(record['script_source_categories'], {
            'same_origin': 1, 'cloudflare_challenge_cdn': 1, 'geetest_cdn': 1,
            'public_package_cdn': 1, 'other_external': 1, 'inline': 1,
        })
        self.assertNotIn('private-', json.dumps(record))

    def test_form_action_category_does_not_include_query_or_unknown_path(self):
        html = '''<form action="/auth/login?token=private-query"></form>
        <form action="/private-path"></form><form action="https://private-host.invalid/"></form>'''
        record = describe_page(html, 'https://cordcloud.one/auth/login')
        self.assertEqual(record['form_action_categories'], {'cross_origin': 1, 'login': 1, 'same_origin_other': 1})
        self.assertNotIn('private-', json.dumps(record))

    def test_page_mode_makes_only_one_get_and_no_script_requests(self):
        url = 'https://cordcloud.one/auth/login'
        action = self.action({('GET', url): [FakeResponse(url, text='<script src="/captcha.js"></script><form></form>')]})
        with mock.patch.object(action, '_solve_altcha') as solver:
            record = action.inspect_login_page()
        solver.assert_not_called()
        self.assertEqual(len(action.session.calls), 1)
        method, target, kwargs = action.session.calls[0]
        self.assertEqual((method, target), ('GET', url))
        self.assertNotIn('data', kwargs)
        self.assertFalse(kwargs['allow_redirects'])
        self.assertTrue(kwargs['verify'])
        self.assertEqual(record['script_source_categories'], {'same_origin': 1})
        self.assertEqual(action.device_fingerprint, '')

    def test_page_mode_rejects_credentials(self):
        for kwargs in ({'email': 'private-email'}, {'passwd': 'private-password'},
                       {'secret': 'private-secret'}, {'code': 'private-otp'}):
            values = {'email': '', 'passwd': '', **kwargs}
            with self.assertRaises(RequestSafetyError):
                Action(**values, host='cordcloud.one', page_only=True)

    def test_page_mode_clears_inherited_auth_and_disables_environment_auth(self):
        import requests
        session = requests.Session()
        session.headers['Authorization'] = 'private-auth'
        session.headers['Cookie'] = 'private-cookie'
        session.auth = ('private-user', 'private-password')
        session.cookies.set('session', 'private-value')
        Action('', '', host='cordcloud.one', page_only=True, session=session)
        self.assertIsNone(session.auth)
        self.assertFalse(session.trust_env)
        self.assertNotIn('Authorization', session.headers)
        self.assertNotIn('Cookie', session.headers)
        self.assertFalse(session.cookies)

    def test_page_mode_blocks_login_solver_post_and_other_get_paths(self):
        action = self.action()
        operations = [lambda: action.login(), lambda: action._solve_altcha('/challenge', ''),
                      lambda: action._post('/auth/login', {}), lambda: action._get('/auth/altcha/challenge'),
                      lambda: action._get('/auth/login?token=private-token'), lambda: action.check_in()]
        for operation in operations:
            with self.assertRaises(RequestSafetyError):
                operation()
        self.assertEqual(action.session.calls, [])

    def test_page_mode_does_not_follow_even_same_origin_redirect(self):
        url = 'https://cordcloud.one/auth/login'
        action = self.action({('GET', url): [FakeResponse(url, status_code=302, headers={'Location': '/auth/login?private=token'})]})
        with self.assertRaises(RequestSafetyError):
            action.inspect_login_page()
        self.assertEqual(len(action.session.calls), 1)
        self.assertNotIn('private', '\n'.join(self.logs))

    def test_page_mode_rejects_disabled_tls(self):
        action = self.action(verify_tls=False)
        with self.assertRaises(RequestSafetyError):
            action.inspect_login_page()
        self.assertEqual(action.session.calls, [])

    def test_page_mode_entrypoint_never_reads_account_or_config(self):
        core, log = mock.Mock(), mock.Mock()
        def get_input(name):
            if name not in {'page_only', 'host', 'inspect_scripts'}:
                raise AssertionError('account or other input must not be read')
            return {'page_only': 'true', 'host': 'cordcloud.one', 'inspect_scripts': 'false'}[name]
        core.get_input.side_effect = get_input
        toolkit = types.ModuleType('actions_toolkit')
        toolkit.core = core
        action = mock.Mock()
        with mock.patch.dict('sys.modules', {'actions_toolkit': toolkit, 'app.log': log}), \
             mock.patch.object(app, 'log', log, create=True), \
             mock.patch('app.action.Action', return_value=action) as constructor, \
             mock.patch('app.config.load_config') as config, \
             mock.patch('app.notify.TelegramNotifier') as notifier:
            with self.assertRaises(SystemExit) as exit_code:
                runpy.run_path('main.py', run_name='__main__')
        self.assertEqual(exit_code.exception.code, 0)
        config.assert_not_called()
        notifier.assert_not_called()
        constructor.assert_called_once_with('', '', host='cordcloud.one', page_only=True, inspect_scripts=False,
                                            diagnostic_logger=log.info)
        action.inspect_login_page.assert_called_once()
        action.login.assert_not_called()
        action.check_in.assert_not_called()
        core.set_secret.assert_not_called()

    def test_page_workflow_step_contains_no_secret_reference(self):
        from pathlib import Path
        workflow = Path('.github/workflows/cordcloud.yml').read_text()
        page_step = workflow.split('- name: Read login page structure without credentials', 1)[1].split('- name:', 1)[0]
        self.assertNotIn('secrets.', page_step)
        for credential in ('email:', 'passwd:', 'secret:', 'code:', 'telegram_'):
            self.assertNotIn(credential, page_step)
        self.assertIn('page_only: true', page_step)


class StaticProtocolTests(unittest.TestCase):
    def test_normalized_code_redacts_all_values_and_unknown_identifiers(self):
        from app.protocol_inspection import protocol_windows
        source = '''// private-comment
        const privateIdentifier = 'private-secret'; const stamp = 123456789;
        const altcha = await fetch('/auth/altcha/challenge?token=private-token');
        const payload = {email: 'private-email', passwd: 'private-password', csrf_token: 'private-csrf',
          number: 123456, signature: 'private-signature', salt: 'private-salt'};
        fetch('/auth/login', {method:'POST', body: JSON.stringify(payload)});'''
        windows = protocol_windows(source)
        output = ' '.join(windows)
        self.assertTrue(windows)
        self.assertNotIn('private', output)
        self.assertNotIn('123456', output)
        self.assertIn('/auth/altcha/challenge?<query>', output)
        self.assertIn('/auth/login', output)
        self.assertIn('csrf_token', output)
        self.assertIn("'POST'", output)

    def test_no_execution_and_template_values_are_redacted(self):
        from app.protocol_inspection import protocol_windows
        output = ' '.join(protocol_windows('const altcha = `private-${dangerous()}`; privateFunction(999999);'))
        self.assertNotIn('dangerous', output)
        self.assertNotIn('private', output)
        self.assertNotIn('999999', output)
        self.assertIn('altcha', output)

    def test_full_inline_structure_includes_calls_without_provider_name(self):
        from app.protocol_inspection import protocol_windows
        source = "const privateHandler = () => $.ajax({data: {passwd: 'private-password'}}); eval('private-source');"
        output = ' '.join(protocol_windows(source, include_all=True))
        self.assertIn('ajax', output)
        self.assertIn('passwd', output)
        self.assertIn('eval', output)
        self.assertNotIn('private', output)

    def test_only_observed_same_origin_js_are_selected_and_queries_removed(self):
        from app.protocol_inspection import script_sources
        html = '''<script>window.altcha;</script><script src="/assets/login.js?token=private-token"></script>
        <script src="https://attacker.invalid/steal.js"></script><script src="/auth/altcha/challenge"></script>
        <script src="/private%2Ftoken.js"></script><script src="https://user:pass@cordcloud.one/code.js"></script>'''
        inline, urls = script_sources(html, 'https://cordcloud.one/auth/login')
        self.assertIn('window.altcha;', inline)
        self.assertEqual(urls, ['https://cordcloud.one/assets/login.js'])

    def test_static_source_reads_are_bounded(self):
        from app.protocol_inspection import script_sources
        html = ''.join(f'<script src="/assets/file{i}.js"></script>' for i in range(20))
        _, urls = script_sources(html, 'https://cordcloud.one/auth/login')
        self.assertEqual(len(urls), 6)

    def test_public_script_hints_omit_paths_queries_and_opaque_basenames(self):
        from app.protocol_inspection import public_script_hints
        html = '''<script src="https://cdn.example.net/private-path/altcha@2.1.4/dist/altcha.min.js?token=private-token"></script>
        <script src="/assets/private123456789.js?secret=private-query"></script>'''
        hints = public_script_hints(html, 'https://cordcloud.one/auth/login')
        self.assertEqual(hints[0]['hostname'], 'cdn.example.net')
        self.assertEqual(hints[0]['basename'], 'altcha.min.js')
        self.assertEqual(hints[0]['altcha_package_version'], '2.1.4')
        self.assertEqual(hints[1]['basename'], '<redacted-basename>')
        self.assertNotIn('private', json.dumps(hints))

    def test_opt_in_reads_static_js_without_post_or_challenge_requests(self):
        url, js_url = 'https://cordcloud.one/auth/login', 'https://cordcloud.one/assets/login.js'
        session = FakeSession({
            ('GET', url): [FakeResponse(url, text='<form></form><script src="/assets/login.js?private=token"></script>')],
            ('GET', js_url): [FakeResponse(js_url, text="const altcha = fetch('/auth/altcha/challenge');")],
        })
        logs = []
        action = Action('', '', host='cordcloud.one', page_only=True, inspect_scripts=True,
                        session=session, diagnostic_logger=logs.append)
        with mock.patch('requests.sessions.Session.request', side_effect=AssertionError('real HTTP forbidden')), \
             mock.patch.object(action, '_solve_altcha') as solver:
            action.inspect_login_page()
        solver.assert_not_called()
        self.assertEqual([(m, u) for m, u, _ in session.calls], [('GET', url), ('GET', js_url)])
        self.assertNotIn('private', '\n'.join(logs))
        self.assertTrue(any('protocol_static_js' in line for line in logs))

    def test_static_js_denial_stops_following_resources(self):
        url, js_url = 'https://cordcloud.one/auth/login', 'https://cordcloud.one/assets/first.js'
        session = FakeSession({
            ('GET', url): [FakeResponse(url, text='<script src="/assets/first.js"></script><script src="/assets/next.js"></script>')],
            ('GET', js_url): [FakeResponse(js_url, status_code=403)],
        })
        action = Action('', '', host='cordcloud.one', page_only=True, inspect_scripts=True,
                        session=session, diagnostic_logger=lambda _: None)
        with self.assertRaises(RequestSafetyError):
            action.inspect_login_page()
        self.assertEqual(len(session.calls), 2)


if __name__ == '__main__':
    unittest.main()
