"""Use the site's normal CAP component in an ephemeral, standard browser.

No stealth flags, saved profile, screenshots, traces, raw response logging or
credential-bearing cross-origin requests. No OTP or account-security changes.
"""
import json
import os
import re
import sys
from urllib.parse import urlparse


class FlowStop(RuntimeError):
    pass


def emit(stage, **fields):
    print('[browser] ' + json.dumps({'stage': stage, **fields}, sort_keys=True), flush=True)


def origin(url):
    parsed = urlparse(url)
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80)


def login_outcome(result):
    if not isinstance(result, dict):
        return {'outcome': 'invalid_response'}
    if result.get('ret') == 1:
        return {'outcome': 'accepted'}
    if result.get('ret') == 2 and result.get('need_device_2fa'):
        methods = result.get('methods') or {}
        message = str(result.get('msg', ''))
        return {'outcome': 'device_2fa_required',
                'methods': [name for name in ('email', 'ga') if isinstance(methods, dict) and methods.get(name)],
                'code_delivery': 'reported_sent' if '已发送' in message and ('验证码' in message or '邮箱' in message) else 'not_reported'}
    msg = str(result.get('msg', ''))
    return {'outcome': 'verification_rejected' if '系统无法接受您的验证结果' in msg else 'rejected'}


def checkin_outcome(result):
    if not isinstance(result, dict):
        return {'outcome': 'invalid_response'}
    msg = str(result.get('msg', ''))
    if '已经签到' in msg or '今日已签到' in msg:
        return {'outcome': 'already_checked_in', 'message_kind': 'already_checked_in'}
    if result.get('ret') == 1 and ('签到' in msg or '流量' in msg):
        reward = re.search(r'(\d{1,6}(?:\.\d{1,3})?)\s*(MB|GB)', msg, re.I)
        return {'outcome': 'success', 'message_kind': 'checkin_confirmed',
                'reward': reward.group(1) + reward.group(2).upper() if reward else 'not_reported'}
    return {'outcome': 'unconfirmed'}


class Guard:
    def __init__(self, base):
        self.base = base
        self.denied = False
        self.credential_phase = False
        self.login_posts = 0
        self.checkin_posts = 0

    def route(self, route):
        request = route.request
        parsed = urlparse(request.url)
        same = origin(request.url) == origin(self.base)
        if self.denied or parsed.scheme not in {'https', 'data', 'blob', 'about'}:
            route.abort()
            return
        if not same and (request.is_navigation_request() or self.credential_phase or request.method not in {'GET', 'HEAD'}):
            route.abort()
            return
        if same and request.method == 'POST' and parsed.path == '/auth/login':
            self.login_posts += 1
            if self.login_posts > 1:
                route.abort()
                return
        if same and request.method == 'POST' and parsed.path == '/user/checkin':
            self.checkin_posts += 1
            if self.checkin_posts > 1:
                route.abort()
                return
        if same and '/auth/login/2fa' in parsed.path and request.method != 'GET':
            route.abort()
            return
        route.continue_()

    def response(self, response):
        if origin(response.url) != origin(self.base):
            return
        path = urlparse(response.url).path
        if response.status in {403, 429}:
            self.denied = True
            emit('access_restricted', http_status=response.status)
        if path in {'/auth/login', '/user/checkin'} or '/cap/' in path or path.endswith('.wasm'):
            kind = 'login' if path == '/auth/login' else ('checkin' if path == '/user/checkin' else 'captcha_asset_or_api')
            emit('network', kind=kind, http_status=response.status,
                 method=response.request.method if response.request.method in {'GET', 'POST'} else 'other')

    def ensure_allowed(self):
        if self.denied:
            raise FlowStop('access_restricted')


CAP_READY_JS = """() => {
  const widgets = Array.from(document.querySelectorAll('cap-widget'));
  const input = document.querySelector('input[name="cap-token"]');
  return widgets.some(w => typeof w.token === 'string' && w.token.length > 0)
    || Boolean(input && input.value);
}"""


def wait_cap(page, guard):
    # The website itself calls solve(). Observe the normal component; never
    # fabricate a proof or repeatedly invoke its solver ourselves.
    for _ in range(90):
        guard.ensure_allowed()
        if page.evaluate(CAP_READY_JS):
            emit('captcha', provider='cap', ready=True)
            return
        page.wait_for_timeout(1000)
    emit('captcha', provider='cap', ready=False)
    raise FlowStop('cap_not_ready')


def unique_visible(page, selectors):
    for selector in selectors:
        matches = page.locator(selector)
        visible = [matches.nth(i) for i in range(min(matches.count(), 10)) if matches.nth(i).is_visible()]
        if len(visible) == 1:
            return visible[0]
    raise FlowStop('ambiguous_or_missing_control')


def matching_response(response, base, path):
    return origin(response.url) == origin(base) and urlparse(response.url).path == path and response.request.method == 'POST'


def run_browser(page, guard, mode):
    response = page.goto(guard.base + '/auth/login', wait_until='domcontentloaded', timeout=30000)
    guard.ensure_allowed()
    if response is None or response.status != 200:
        raise FlowStop('login_page_unavailable')
    page.locator('#login-form').wait_for(state='visible', timeout=15000)
    emit('page', login_form=True, cap_widgets=page.locator('cap-widget').count())
    wait_cap(page, guard)
    if mode == 'inspect':
        emit('complete', outcome='browser_inspection_only')
        return 0
    email, passwd = os.getenv('INPUT_EMAIL', ''), os.getenv('INPUT_PASSWD', '')
    if not email or not passwd:
        raise FlowStop('missing_account_inputs')
    guard.credential_phase = True
    page.locator('#email').fill(email)
    page.locator('#passwd').fill(passwd)
    button = unique_visible(page, ['#login', '#login-btn', '#login-form button[type="submit"]',
                                   '#login-form button:has-text("登录")'])
    with page.expect_response(lambda res: matching_response(res, guard.base, '/auth/login'), timeout=30000) as pending:
        button.click()
    guard.ensure_allowed()
    result = login_outcome(pending.value.json())
    emit('login_result', **result)
    if result['outcome'] != 'accepted':
        raise FlowStop(result['outcome'])
    if mode == 'login':
        emit('complete', outcome='login_only_no_checkin')
        return 0
    page.wait_for_url(lambda url: urlparse(str(url)).path.startswith('/user'), timeout=30000)
    guard.ensure_allowed()
    button = unique_visible(page, ['#checkin', '#checkin-btn', '#checkin_button',
                                   'button:has-text("签到")', 'a:has-text("签到")'])
    text = button.inner_text()
    if not button.is_enabled() and ('已签到' in text or '已经签到' in text):
        emit('checkin_result', outcome='already_checked_in', message_kind='disabled_checkin_control')
        return 0
    with page.expect_response(lambda res: matching_response(res, guard.base, '/user/checkin'), timeout=30000) as pending:
        button.click()
    guard.ensure_allowed()
    result = checkin_outcome(pending.value.json())
    emit('checkin_result', **result)
    if result['outcome'] not in {'success', 'already_checked_in'}:
        raise FlowStop('checkin_unconfirmed')
    return 0


def main():
    mode = os.getenv('BROWSER_MODE', 'inspect')
    if mode not in {'inspect', 'login', 'checkin'}:
        emit('stopped', reason='invalid_mode')
        return 1
    # The workflow is intentionally scoped to the one existing account site.
    base = 'https://cordcloud.one'
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context()
            guard = Guard(base)
            context.route('**/*', guard.route)
            context.on('response', guard.response)
            try:
                return run_browser(context.new_page(), guard, mode)
            finally:
                context.close()
                browser.close()
    except FlowStop as exc:
        # FlowStop values are fixed identifiers defined in this file only.
        emit('stopped', reason=str(exc))
        return 1
    except Exception:
        # Browser errors can include DOM text/URLs. Never print their payload.
        emit('stopped', reason='browser_operation_failed')
        return 1


if __name__ == '__main__':
    sys.exit(main())
