"""Value-free metadata for one explicitly requested login diagnostic.

HTML names are untrusted too: only known protocol names may be logged.
Unknown names and duplicate names are represented by counts.
"""
import json
from collections import Counter
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse


FORM_FIELDS = frozenset({
    'email', 'Email', 'passwd', 'Password', 'csrf_token', 'device_fingerprint',
    'remember', 'remember_me', 'altcha', 'code', 'token', 'method', 'trust_device',
    'g-recaptcha-response', 'h-captcha-response', 'cf-turnstile-response',
    'geetest_challenge', 'geetest_validate', 'geetest_seccode',
    'captcha_id', 'lot_number', 'captcha_output', 'pass_token', 'gen_time',
})
CHALLENGE_FIELDS = frozenset({'algorithm', 'challenge', 'salt', 'signature', 'maxnumber'})
ALGORITHMS = frozenset({'SHA-256', 'SHA-384', 'SHA-512'})


def field_summary(fields, allowed=FORM_FIELDS):
    names = list(fields)
    return {
        'known_fields': sorted(set(names) & allowed),
        'unknown_field_count': sum(name not in allowed for name in names),
    }


class FormSummary(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = 0
        self.login_form = False
        self.widgets = 0
        self.names = []
        self.widget_name = 'absent'
        self.widget_attributes = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.forms += 1
            self.login_form |= attrs.get('id') == 'login-form'
        elif tag == 'input' and attrs.get('name'):
            self.names.append(attrs['name'])
        elif tag == 'altcha-widget':
            self.widgets += 1
            self.widget_attributes.update(set(attrs) & {'challengeurl', 'challenge', 'challengejson', 'name'})
            name = attrs.get('name')
            self.widget_name = 'default' if name is None else ('altcha' if name == 'altcha' else 'other')

    def metadata(self):
        counts = Counter(self.names)
        return {
            'form_count': self.forms,
            'login_form_present': self.login_form,
            'widget_count': self.widgets,
            'widget_name': self.widget_name,
            'widget_protocol_attributes': sorted(self.widget_attributes),
            'csrf_input_count': counts['csrf_token'],
            'duplicate_known_fields': sorted(name for name, count in counts.items() if count > 1 and name in FORM_FIELDS),
            'unknown_duplicate_count': sum(count > 1 and name not in FORM_FIELDS for name, count in counts.items()),
            **field_summary(self.names),
        }


def describe_form(html):
    parser = FormSummary()
    parser.feed(html)
    return parser.metadata()


def _url_category(raw, base, script=False):
    """Classify without retaining or reporting the URL, path, query or hash."""
    if not raw or raw.lower().startswith('javascript:'):
        return 'inline' if script else 'scripted'
    try:
        parsed, origin = urlparse(urljoin(base, raw)), urlparse(base)
        if parsed.scheme != 'https' or parsed.username or parsed.password:
            return 'non_https_or_credentials'
        same_origin = parsed.hostname == origin.hostname and (parsed.port or 443) == (origin.port or 443)
        if script:
            if same_origin:
                return 'same_origin'
            host = parsed.hostname or ''
            if host == 'challenges.cloudflare.com':
                return 'cloudflare_challenge_cdn'
            if host in {'www.google.com', 'www.recaptcha.net', 'www.gstatic.com'} and 'recaptcha' in parsed.path:
                return 'recaptcha_cdn'
            if host == 'geetest.com' or host.endswith('.geetest.com') or host.endswith('.geevisit.com'):
                return 'geetest_cdn'
            if host == 'hcaptcha.com' or host.endswith('.hcaptcha.com'):
                return 'hcaptcha_cdn'
            if host in {'cdn.jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com'}:
                return 'public_package_cdn'
            return 'other_external'
        if not same_origin:
            return 'cross_origin'
        return {
            '/auth/login': 'login', '/auth/login/2fa': 'device_2fa',
            '/auth/login/2fa/verify': 'device_2fa', '/auth/register': 'register',
        }.get(parsed.path.rstrip('/'), 'same_origin_other')
    except ValueError:
        return 'unparseable'


class PageSummary(FormSummary):
    def __init__(self, base):
        super().__init__()
        self.base = base
        self.script_categories = Counter()
        self.action_categories = Counter()

    def handle_starttag(self, tag, attrs):
        super().handle_starttag(tag, attrs)
        attrs = dict(attrs)
        if tag == 'script':
            self.script_categories[_url_category(attrs.get('src', ''), self.base, script=True)] += 1
        if tag == 'form':
            self.action_categories[_url_category(attrs.get('action', ''), self.base)] += 1


def describe_page(html, base):
    parser = PageSummary(base)
    parser.feed(html)
    lowered = html.lower()
    signatures = {
        'altcha': ('altcha',), 'geetest': ('geetest', 'geevisit'),
        'turnstile': ('turnstile',), 'recaptcha': ('recaptcha', 'grecaptcha'),
        'hcaptcha': ('hcaptcha',), 'cloudflare_challenge': ('/cdn-cgi/challenge-platform/',),
    }
    return {
        **parser.metadata(),
        'provider_markers': sorted(name for name, tokens in signatures.items() if any(token in lowered for token in tokens)),
        'script_source_categories': dict(sorted(parser.script_categories.items())),
        'form_action_categories': dict(sorted(parser.action_categories.items())),
    }


def describe_challenge(challenge):
    algorithm = challenge.get('algorithm', 'SHA-256')
    return {
        **field_summary(challenge, CHALLENGE_FIELDS),
        'algorithm': algorithm if isinstance(algorithm, str) and algorithm in ALGORITHMS else 'other',
        'required_strings_present': all(isinstance(challenge.get(key), str) and bool(challenge[key])
                                        for key in ('salt', 'challenge', 'signature')),
        'maxnumber_is_integer': type(challenge.get('maxnumber', 1000000)) is int,
    }


def content_type_category(response):
    value = str(response.headers.get('Content-Type', '')).split(';', 1)[0].strip().lower()
    if value in {'application/json', 'text/json'}:
        return 'json'
    if value in {'text/html', 'application/xhtml+xml'}:
        return 'html'
    return 'other' if value else 'missing'


def emit(logger, stage, **metadata):
    # Callers supply fixed stage/metadata keys and sanitized metadata above.
    logger('[diagnostic] ' + json.dumps({'stage': stage, **metadata}, sort_keys=True, ensure_ascii=True))
