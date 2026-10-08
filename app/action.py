import base64
import hashlib
import json
import re
import secrets
from html import unescape
from typing import Dict, Optional, Tuple
from urllib.parse import parse_qs, urljoin, urlparse

from app.diagnostics import content_type_category, describe_challenge, describe_form, describe_page, emit
from app.protocol_inspection import protocol_windows, script_sources

import requests
from requests import exceptions as request_exceptions

try:
    import pyotp
except ImportError:  # pragma: no cover - runtime dependency is installed in the action image
    pyotp = None


class ActionError(RuntimeError):
    pass


class AuthError(ActionError):
    pass


class VerificationError(AuthError):
    """The login form's verification failed before device 2FA was reached."""


class RequestSafetyError(AuthError):
    """Do not retry another host after an access restriction or unsafe URL."""


class RetryableError(ActionError):
    pass


class Action:
    INPUT_TAG_RE = re.compile(r'<input\b([^>]*)>', re.I)
    ATTR_RE = re.compile(r'([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*([\'"])(.*?)\2', re.S)
    FORM_ACTION_RE = re.compile(r'<form\b[^>]*action\s*=\s*([\'"])(.*?)\1', re.I | re.S)
    ALTCHA_RE = re.compile(r'challengeurl\s*=\s*([\'"])(.*?)\1', re.I | re.S)

    def __init__(
        self,
        email: str,
        passwd: str,
        secret: str = '',
        code: str = '',
        verify_method: str = '',
        host: str = 'cordcloud.us',
        session: Optional[requests.Session] = None,
        trust_device: bool = False,
        verify_tls: bool = True,
        device_fingerprint: str = '',
        diagnostics: bool = False,
        diagnostic_logger=None,
        page_only: bool = False,
        inspect_scripts: bool = False,
    ):
        if page_only and any((email, passwd, secret, code)):
            raise RequestSafetyError('只读页面诊断不接受账号或凭据')
        self.email = email
        self.passwd = passwd
        self.secret = secret
        self.code = code
        self.verify_method = verify_method.strip().lower()
        self.host = host.replace('https://', '').replace('http://', '').strip().rstrip('/')
        self.session = session or requests.session()
        if page_only:
            # A pure page probe must not inherit netrc credentials, proxy
            # configuration, Authorization headers or an authenticated jar.
            self.session.trust_env = False
            self.session.auth = None
            self.session.headers.pop('Authorization', None)
            self.session.headers.pop('Cookie', None)
            if hasattr(self.session, 'cookies'):
                self.session.cookies.clear()
        self.timeout = 15
        self.trust_device = trust_device
        self.verify_tls = verify_tls
        self.device_fingerprint = '' if page_only else (device_fingerprint or self._build_device_fingerprint())
        self.diagnostics = diagnostics or page_only
        self.page_only = page_only
        self.inspect_scripts = inspect_scripts
        self._page_read_paths = {'/auth/login'}
        self.diagnostic_logger = diagnostic_logger or print
        self.session.headers.update({
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/134.0.0.0 Safari/537.36'
            ),
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        })

    def format_url(self, path: str) -> str:
        base = f'https://{self.host}/'
        return urljoin(base, path.lstrip('/'))

    def _build_device_fingerprint(self) -> str:
        return secrets.token_hex(16)

    def _diagnose(self, stage: str, **metadata):
        if self.diagnostics:
            emit(self.diagnostic_logger, stage, **metadata)

    def _same_origin_url(self, path: str, base: str = '') -> str:
        try:
            url = urljoin(base or self.format_url(''), str(path))
            parsed, expected = urlparse(url), urlparse(self.format_url(''))
            valid = (
                parsed.scheme == expected.scheme == 'https'
                and parsed.hostname == expected.hostname
                and (parsed.port or 443) == (expected.port or 443)
                and not parsed.username and not parsed.password
                and not expected.username and not expected.password
            )
        except ValueError:
            valid = False
        if not valid:
            self._diagnose('request_blocked', reason='unsafe_origin')
            raise RequestSafetyError('已阻止跨域或非 HTTPS 请求；未发送该请求')
        return url

    def _build_headers(self, referer: str = '', xhr: bool = False) -> Dict[str, str]:
        headers = {
            'Referer': referer or self.format_url('auth/login'),
            'Origin': self.format_url('').rstrip('/'),
        }
        if xhr:
            headers.update({
                'Accept': 'application/json, text/javascript, */*; q=0.01',
                'X-Requested-With': 'XMLHttpRequest',
            })
        return headers

    def _request(self, method: str, path: str, data=None, referer: str = '', stage: str = 'request'):
        url = self._same_origin_url(path)
        if self.page_only:
            target = urlparse(url)
            if method != 'GET' or target.path not in self._page_read_paths or target.query or data:
                raise RequestSafetyError('只读诊断仅允许已批准的 GET 路径，不携带请求数据')
            if not self.verify_tls:
                raise RequestSafetyError('只读页面诊断必须保持 TLS 校验')
        if referer:
            self._same_origin_url(referer)
        try:
            # Requests must not automatically forward credentials on a 307/308
            # redirect. Resolve and validate every hop before sending it.
            for redirects in range(6):
                kwargs = {
                    'timeout': self.timeout, 'verify': self.verify_tls,
                    'headers': self._build_headers(referer=referer, xhr=method == 'POST'),
                    'allow_redirects': False,
                }
                if method == 'POST':
                    kwargs['data'] = data
                response = getattr(self.session, method.lower())(url, **kwargs)
                self._diagnose(stage, http_status=response.status_code,
                               content_type=content_type_category(response), redirect_count=redirects)
                if response.status_code in {403, 429}:
                    self._diagnose('request_blocked', reason='access_restricted')
                    raise RequestSafetyError(f'站点限制访问（HTTP {response.status_code}）；已停止，不切换域名重试')
                if response.status_code not in {301, 302, 303, 307, 308}:
                    return response
                if self.page_only:
                    self._diagnose('page_only_blocked', reason='redirect')
                    raise RequestSafetyError('只读页面诊断不跟随重定向')
                location = response.headers.get('Location')
                if not location:
                    raise RequestSafetyError('重定向缺少目标地址；已停止')
                next_url = self._same_origin_url(location, base=url)
                if method == 'POST' and response.status_code in {301, 302, 303}:
                    method, data = 'GET', None
                referer, url = url, next_url
            raise RequestSafetyError('同源重定向次数超出上限；已停止')
        except request_exceptions.SSLError as exc:
            raise RetryableError('TLS 证书验证失败；请检查站点证书，不要关闭证书校验') from exc
        except request_exceptions.Timeout as exc:
            raise RetryableError('请求超时') from exc
        except request_exceptions.RequestException as exc:
            raise RetryableError('网络请求失败；已省略可能包含验证 token 的请求地址') from exc

    def _get(self, path: str, referer: str = '', stage: str = 'request'):
        return self._request('GET', path, referer=referer, stage=stage)

    def _post(self, path: str, data: Dict[str, str], referer: str = '', stage: str = 'request'):
        return self._request('POST', path, data=data, referer=referer, stage=stage)

    def _parse_attrs(self, raw_attrs: str) -> Dict[str, str]:
        attrs = {}
        for name, _, value in self.ATTR_RE.findall(raw_attrs):
            attrs[name.lower()] = unescape(value)
        return attrs

    def _extract_inputs(self, html: str) -> Dict[str, str]:
        data = {}
        for match in self.INPUT_TAG_RE.finditer(html):
            attrs = self._parse_attrs(match.group(1))
            name = attrs.get('name')
            if not name:
                continue
            input_type = attrs.get('type', '').lower()
            if input_type in {'submit', 'button', 'image', 'file'}:
                continue
            data[name] = attrs.get('value', '')
        return data

    def _extract_form_action(self, html: str, fallback_url: str) -> str:
        match = self.FORM_ACTION_RE.search(html)
        if not match:
            return fallback_url
        action = unescape(match.group(2)).strip()
        if not action or action.lower().startswith('javascript:'):
            return fallback_url
        return urljoin(fallback_url, action)

    def _extract_altcha_url(self, html: str) -> str:
        match = self.ALTCHA_RE.search(html)
        if not match:
            return ''
        return urljoin(self.format_url(''), unescape(match.group(2)).strip())

    def _hash_hex(self, algorithm: str, value: str) -> str:
        normalized = algorithm.lower().replace('-', '')
        return hashlib.new(normalized, value.encode('utf-8')).hexdigest()

    def _solve_altcha(self, challenge_url: str, referer: str) -> str:
        if self.page_only:
            raise RequestSafetyError('只读页面诊断不获取或求解验证挑战')
        response = self._get(challenge_url, referer=referer, stage='altcha_get')
        challenge = self._decode_json(response, 'ALTCHA')
        if self.diagnostics:
            self._diagnose('altcha_structure', **describe_challenge(challenge))
        algorithm = challenge.get('algorithm', 'SHA-256')
        salt = challenge['salt']
        expected = challenge['challenge']
        maxnumber = int(challenge.get('maxnumber', 1000000))
        signature = challenge['signature']

        solved_number = None
        for number in range(maxnumber + 1):
            if self._hash_hex(algorithm, f'{salt}{number}') == expected:
                solved_number = number
                break

        if solved_number is None:
            raise RuntimeError('ALTCHA 验证求解失败')

        payload = {
            'algorithm': algorithm,
            'challenge': expected,
            'number': solved_number,
            'salt': salt,
            'signature': signature,
        }
        encoded = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        proof = base64.b64encode(encoded).decode('ascii')
        if self.diagnostics:
            self_check = self._altcha_self_check(challenge, proof)
            self._diagnose('altcha_proof', self_check=self_check)
            if not self_check:
                raise VerificationError('ALTCHA 本地结构与摘要自检失败；未提交登录')
        return proof

    def _altcha_self_check(self, challenge: dict, proof: str) -> bool:
        """Check serialization/hash consistency, not the server HMAC or expiry."""
        try:
            payload = json.loads(base64.b64decode(proof, validate=True))
            number = payload['number']
            return (
                type(number) is int and 0 <= number <= int(challenge.get('maxnumber', 1000000))
                and payload['algorithm'] == challenge.get('algorithm', 'SHA-256')
                and all(payload[key] == challenge[key] for key in ('salt', 'challenge', 'signature'))
                and self._hash_hex(payload['algorithm'], f'{payload["salt"]}{number}') == challenge['challenge']
            )
        except (ValueError, TypeError, KeyError, OverflowError):
            return False

    def _decode_json(self, response, action_name: str) -> dict:
        if response.status_code >= 400:
            raise RetryableError(f'{action_name} 请求失败（HTTP {response.status_code}）')
        try:
            result = response.json()
        except ValueError as exc:
            raise RetryableError(
                f'{action_name} 未返回 JSON（HTTP {response.status_code}）；'
                '已省略响应正文，请检查站点页面结构或访问限制'
            ) from exc
        if not isinstance(result, dict):
            raise RetryableError(f'{action_name} 返回了非对象 JSON，无法确认操作结果')
        return result

    def _current_code(self, method: str = '') -> str:
        chosen_method = (method or '').strip().lower()
        if chosen_method == 'email':
            return self.code
        if chosen_method == 'ga' and not self.secret:
            return ''
        if self.secret:
            if pyotp is None:
                raise RuntimeError('缺少 pyotp 依赖，无法生成两步验证码')
            return pyotp.TOTP(self.secret).now()
        return self.code

    def _submit_form(self, page_response, html: str, overrides: Dict[str, str]) -> dict:
        form_data = self._extract_inputs(html)
        form_data.update(overrides)

        altcha_url = self._extract_altcha_url(html)
        action_url = self._same_origin_url(self._extract_form_action(html, fallback_url=page_response.url))
        if altcha_url:
            self._same_origin_url(altcha_url)
        if self.diagnostics:
            form_metadata = describe_form(html)
            self._diagnose('login_form', csrf_present=bool(form_data.get('csrf_token')),
                           challengeurl_detected=bool(altcha_url), **form_metadata)
            if form_metadata['widget_count'] and not altcha_url:
                self._diagnose('login_form_blocked', reason='unsupported_challenge')
                raise VerificationError('诊断检测到无法识别的挑战接口；未提交登录')
            if not form_metadata['form_count']:
                self._diagnose('login_form_blocked', reason='unsupported_form')
                raise VerificationError('诊断未识别到登录表单；未提交登录')
        if altcha_url:
            form_data['altcha'] = self._solve_altcha(altcha_url, referer=page_response.url)

        response = self._post(action_url, form_data, referer=page_response.url, stage='login_post')
        return self._decode_json(response, '表单提交')

    def _needs_device_2fa(self, result: dict) -> bool:
        return result.get('ret') == 2 and bool(result.get('need_device_2fa'))

    def _result_token(self, result: dict) -> str:
        token = str(result.get('token', '')).strip()
        if token:
            return token

        redirect = str(result.get('redirect', '')).strip()
        if not redirect:
            return ''

        parsed = urlparse(redirect)
        return parse_qs(parsed.query).get('token', [''])[0].strip()

    def _device_2fa_method(self, result: dict, form_data: Dict[str, str]) -> str:
        methods = result.get('methods') or {}
        if self.verify_method:
            if self.verify_method not in {'auto', 'ga', 'email'}:
                raise AuthError(f'不支持的 verify_method：{self.verify_method}，仅支持 ga、email 或留空自动选择')
            if self.verify_method == 'ga':
                if not methods.get('ga'):
                    raise AuthError('当前账号未启用验证器二步验证，无法使用 verify_method=ga')
                if not self.secret:
                    raise AuthError('verify_method=ga 需要同时提供 secret')
                return 'ga'
            if self.verify_method == 'email':
                if not methods.get('email'):
                    raise AuthError('当前账号未启用邮箱二步验证，无法使用 verify_method=email')
                if not self.code:
                    raise AuthError('verify_method=email 需要同时提供 code')
                return 'email'

        if self.secret and methods.get('ga'):
            return 'ga'
        if self.code and methods.get('email'):
            return 'email'

        default_method = str(form_data.get('method', 'email')).strip().lower()
        if default_method in methods and methods.get(default_method):
            return default_method
        if methods.get('ga'):
            return 'ga'
        if methods.get('email'):
            return 'email'
        return 'email'

    def _device_2fa(self, result: dict) -> dict:
        if self.diagnostics:
            raise RequestSafetyError('诊断模式不提交设备二次验证码')
        verify_url = result.get('redirect') or f'/auth/login/2fa?token={result.get("token", "")}'
        method = self._device_2fa_method(result, {})
        current_code = self._current_code(method)
        if not current_code:
            msg = result.get('msg') or '登录需要设备二次验证'
            missing = 'secret' if method == 'ga' else 'code'
            return {
                'ret': 0,
                'msg': f'{msg}，当前方式需要提供 {missing} 参数后再试',
            }

        token = self._result_token(result)
        if not token:
            raise RetryableError('站点返回的设备验证 token 缺失，无法继续完成二步验证')
        if method == 'ga':
            referer = verify_url if str(verify_url).startswith('http') else self.format_url(verify_url)
            payload = {
                'token': token,
                'code': current_code,
                'method': 'ga',
                'trust_device': '1' if self.trust_device else '0',
            }
            response = self._post('/auth/login/2fa/verify', payload, referer=referer)
            return self._decode_json(response, '表单提交')

        page = self._get(verify_url, referer=self.format_url('auth/login'))
        html = page.text
        if '验证会话已过期或无效' in html:
            return {'ret': 0, 'msg': '设备二次验证会话已过期或无效，请稍后重试'}

        form_data = self._extract_inputs(html)
        method = self._device_2fa_method(result, form_data)
        current_code = self._current_code(method)
        payload = {
            'token': form_data.get('token', token),
            'code': current_code,
            'method': method,
            'trust_device': '1' if self.trust_device else '0',
        }
        if 'csrf_token' in form_data:
            payload['csrf_token'] = form_data['csrf_token']

        response = self._post('/auth/login/2fa/verify', payload, referer=page.url)
        return self._decode_json(response, '表单提交')

    def _get_user_page(self):
        response = self._get('user', referer=self.format_url('auth/login'))
        path = urlparse(response.url).path
        if '/auth/login' in path or 'id="login-form"' in response.text:
            raise RetryableError('当前会话未登录，站点返回了登录页')
        return response

    def login(self) -> dict:
        if self.page_only:
            raise RequestSafetyError('只读页面诊断不执行登录')
        login_page = self._get('auth/login', stage='login_get')
        if login_page.status_code >= 400:
            raise RetryableError(f'登录页面请求失败（HTTP {login_page.status_code}）')
        overrides = {
            'email': self.email,
            'passwd': self.passwd,
            'device_fingerprint': self.device_fingerprint,
        }
        result = self._submit_form(login_page, login_page.text, overrides=overrides)
        outcome = 'accepted' if result.get('ret') == 1 else (
            'device_2fa_required' if self._needs_device_2fa(result) else (
                'verification_rejected' if '系统无法接受您的验证结果' in str(result.get('msg', '')) else 'rejected'
            )
        )
        self._diagnose('login_result', outcome=outcome)
        if self.diagnostics:
            # Never expose a server message or reflected token to the runner.
            return {'ret': 1 if outcome == 'accepted' else (2 if outcome == 'device_2fa_required' else 0),
                    'diagnostic_outcome': outcome}
        if self._needs_device_2fa(result):
            return self._device_2fa(result)
        if result.get('ret') != 1 and '系统无法接受您的验证结果' in str(result.get('msg', '')):
            raise VerificationError(
                '登录前验证未被站点接受，尚未进入设备二次验证；'
                '需核对当前登录页面的验证流程，不能据此判断为缺少 TOTP'
            )
        return result

    def inspect_login_page(self) -> dict:
        if not self.page_only:
            raise RequestSafetyError('页面结构探查需要明确开启只读模式')
        page = self._get('/auth/login', stage='page_get')
        if page.status_code >= 400:
            raise RetryableError(f'页面请求失败（HTTP {page.status_code}）')
        metadata = describe_page(page.text, page.url)
        self._diagnose('page_structure', **metadata)
        if self.inspect_scripts:
            inline, sources = script_sources(page.text, page.url)
            for index, source in enumerate(inline):
                windows = protocol_windows(source)
                if windows:
                    self._diagnose('protocol_inline', source_index=index, normalized_windows=windows)
            for index, url in enumerate(sources):
                self._page_read_paths.add(urlparse(url).path)
                if hasattr(self.session, 'cookies'):
                    self.session.cookies.clear()
                script = self._get(url, stage='static_js_get')
                content_type = script.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
                if (script.status_code != 200 or len(script.text) > 200000 or content_type not in
                        {'', 'text/plain', 'text/javascript', 'application/javascript', 'application/x-javascript'}):
                    self._diagnose('static_js_skipped', source_index=index, reason='status_size_or_type')
                    continue
                windows = protocol_windows(script.text)
                if windows:
                    self._diagnose('protocol_static_js', source_index=index, normalized_windows=windows)
        return metadata

    def check_in(self) -> dict:
        if self.diagnostics:
            raise RequestSafetyError('诊断模式不执行签到')
        user_page = self._get_user_page()
        form_data = self._extract_inputs(user_page.text)
        payload = {}
        if 'csrf_token' in form_data:
            payload['csrf_token'] = form_data['csrf_token']
        response = self._post('user/checkin', payload, referer=user_page.url)
        return self._decode_json(response, '签到')

    def info(self) -> Tuple:
        if self.diagnostics:
            raise RequestSafetyError('诊断模式不查询账号流量')
        html = self._get_user_page().text
        today_used = re.search(
            '<span class="traffic-info">今日已用</span>(.*?)<code class="card-tag tag-red">(.*?)</code>',
            html,
            re.S,
        )
        total_used = re.search(
            '<span class="traffic-info">过去已用</span>(.*?)<code class="card-tag tag-orange">(.*?)</code>',
            html,
            re.S,
        )
        rest = re.search(
            '<span class="traffic-info">剩余流量</span>(.*?)<code class="card-tag tag-green" id="remain">(.*?)</code>',
            html,
            re.S,
        )
        if today_used and total_used and rest:
            return today_used.group(2), total_used.group(2), rest.group(2)
        return ()

    def run(self):
        if self.page_only:
            return self.inspect_login_page()
        result = self.login()
        if self.diagnostics:
            return result
        self.check_in()
        self.info()
