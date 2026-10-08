import json
import os
import unittest
from unittest import mock

import browser_checkin as flow


class BrowserFlowTests(unittest.TestCase):
    def setUp(self):
        self.messages = []
        patch = mock.patch.object(flow, 'emit', side_effect=lambda stage, **fields: self.messages.append({'stage': stage, **fields}))
        patch.start()
        self.addCleanup(patch.stop)

    def route(self, url, method='GET'):
        route = mock.Mock()
        route.request.url, route.request.method = url, method
        route.request.is_navigation_request.return_value = False
        return route

    def test_login_result_redacts_device_token_and_message(self):
        result = flow.login_outcome({'ret': 2, 'need_device_2fa': True, 'methods': {'email': True},
                                     'token': 'private-token', 'msg': 'private-address'})
        self.assertEqual(result, {'outcome': 'device_2fa_required', 'methods': ['email'], 'code_delivery': 'not_reported'})
        self.assertNotIn('private', json.dumps(result))

    def test_rejection_is_classified_without_raw_message(self):
        self.assertEqual(flow.login_outcome({'ret': 0, 'msg': '系统无法接受您的验证结果 private-token'}),
                         {'outcome': 'verification_rejected'})
        self.assertEqual(flow.login_outcome([]), {'outcome': 'invalid_response'})

    def test_checkin_requires_actual_success_or_checked_message(self):
        self.assertEqual(flow.checkin_outcome({'ret': 1, 'msg': '签到成功，获得了385MB流量 private-email'})['reward'], '385MB')
        self.assertEqual(flow.checkin_outcome({'ret': 0, 'msg': '您似乎已经签到过了...'})['outcome'], 'already_checked_in')
        self.assertEqual(flow.checkin_outcome({'ret': 1, 'msg': 'private-data'})['outcome'], 'unconfirmed')

    def test_credentials_cannot_go_cross_origin(self):
        guard = flow.Guard('https://cordcloud.one')
        guard.credential_phase = True
        for url, method in [('https://attacker.invalid/?email=private-email', 'GET'),
                            ('https://attacker.invalid/login', 'POST'), ('http://cordcloud.one/login', 'POST')]:
            route = self.route(url, method)
            guard.route(route)
            route.abort.assert_called_once()
            route.continue_.assert_not_called()

    def test_duplicate_login_checkin_and_otp_posts_blocked(self):
        guard = flow.Guard('https://cordcloud.one')
        for path in ('/auth/login', '/user/checkin'):
            first, second = self.route(guard.base + path, 'POST'), self.route(guard.base + path, 'POST')
            guard.route(first)
            guard.route(second)
            first.continue_.assert_called_once()
            second.abort.assert_called_once()
        otp = self.route(guard.base + '/auth/login/2fa/verify', 'POST')
        guard.route(otp)
        otp.abort.assert_called_once()

    def test_access_denial_stops_all_further_requests(self):
        guard = flow.Guard('https://cordcloud.one')
        response = mock.Mock(url=guard.base + '/auth/login?token=private-token', status=403)
        response.request.method = 'GET'
        guard.response(response)
        with self.assertRaises(flow.FlowStop):
            guard.ensure_allowed()
        route = self.route(guard.base + '/auth/login')
        guard.route(route)
        route.abort.assert_called_once()
        self.assertNotIn('private', json.dumps(self.messages))

    def fake_page(self, result):
        page = mock.Mock()
        page.goto.return_value.status = 200
        page.evaluate.return_value = True
        page.locator.return_value.count.return_value = 1
        pending = mock.MagicMock()
        pending.__enter__.return_value.value.json.return_value = result
        page.expect_response.return_value = pending
        return page

    def test_inspection_never_reads_credentials_or_posts_login(self):
        page = self.fake_page({'ret': 1})
        with mock.patch.object(flow.os, 'getenv', side_effect=AssertionError('credentials must not be read')):
            self.assertEqual(flow.run_browser(page, flow.Guard('https://cordcloud.one'), 'inspect'), 0)
        page.expect_response.assert_not_called()

    def test_two_factor_stops_without_checkin_or_otp(self):
        page = self.fake_page({'ret': 2, 'need_device_2fa': True, 'methods': {'email': True}, 'msg': 'private-address'})
        button = mock.Mock()
        with mock.patch.dict(os.environ, {'INPUT_EMAIL': 'private-email', 'INPUT_PASSWD': 'private-password'}), \
             mock.patch.object(flow, 'unique_visible', return_value=button):
            with self.assertRaisesRegex(flow.FlowStop, '^device_2fa_required$'):
                flow.run_browser(page, flow.Guard('https://cordcloud.one'), 'checkin')
        button.click.assert_called_once()
        page.expect_response.assert_called_once()
        page.wait_for_url.assert_not_called()
        self.assertNotIn('private', json.dumps(self.messages))

    def test_cap_wait_observes_without_calling_solver(self):
        page = mock.Mock()
        page.evaluate.return_value = True
        flow.wait_cap(page, flow.Guard('https://cordcloud.one'))
        self.assertNotIn('.solve(', page.evaluate.call_args.args[0])
        self.assertEqual(self.messages[-1], {'stage': 'captcha', 'provider': 'cap', 'ready': True})

    def test_browser_has_no_stealth_proxy_or_persistent_profile(self):
        from pathlib import Path
        source = Path('browser_checkin.py').read_text()
        self.assertIn('playwright.chromium.launch(headless=True)', source)
        for prohibited in ('launch_persistent_context', 'ignore_https_errors=', 'user_agent=', 'proxy=', 'storage_state=', 'tracing.start'):
            self.assertNotIn(prohibited, source)


if __name__ == '__main__':
    unittest.main()
