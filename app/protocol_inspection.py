"""Read-only JavaScript structure inspection. Never evaluates JavaScript.

Output is built from fixed vocabulary and punctuation. All other identifiers
are anonymized, numbers are replaced, and non-protocol string values vanish.
"""
import re
from posixpath import basename
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlunparse


WORDS = frozenset('''async await function return const let var if else try catch throw new for while
true false null undefined this typeof in of instanceof window document fetch then json text
JSON stringify parse Object keys values assign Array from isArray push join split replace
Math floor random Date now Promise resolve reject Uint8Array TextEncoder encode crypto subtle
digest SHA256 SHA512 btoa atob parseInt parseFloat addEventListener removeEventListener
querySelector querySelectorAll getElementById createElement appendChild setAttribute getAttribute
value checked target detail preventDefault body headers method credentials contentType data url ajax
email Email passwd Password csrf_token device_fingerprint remember_me altcha algorithm challenge
challengeurl challengeUrl challengejson challengeJson salt signature maxnumber number payload solution
proof token expires expire result response status ret msg success error code captcha captcha_id
captcha_response altcha_response solved verified state solveChallenge verifySolution solve createChallenge
challengeResponse challengeResult v1 v2 worker script src type name nonce dispatchEvent CustomEvent
form submit login loading disabled html hide show on click val serialize serializeArray get post
length map filter find includes startsWith toString toLowerCase charCodeAt encodeURIComponent
decodeURIComponent setTimeout clearTimeout console log warn error location href protocol hostname
sessionStorage localStorage getItem setItem removeItem Altcha ALTCHA altcha2 pow hmac hash hashes checksum
maxNumber base64 workload complexity pbkdf2 PBKDF2 argon2 argon2id scrypt counter eval unescape
String fromCharCode charCodeAt'''.split())
LITERALS = frozenset('''GET POST application/json application/x-www-form-urlencoded
SHA-256 SHA-384 SHA-512 sha256 sha384 sha512 email Email passwd Password csrf_token
device_fingerprint remember_me altcha altcha_response algorithm challenge challengeurl challengejson
salt signature maxnumber number payload solution proof token expires captcha captcha_response
solve solved verified state statechange change submit click code ret msg worker true false v1 v2 v3
altcha2 pow hmac hash checksum workload complexity pbkdf2 argon2 argon2id scrypt nonce'''.split())
PATHS = frozenset({'/auth/login', '/auth/altcha/challenge', '/auth/altcha', '/auth/altcha2/challenge',
                   '/auth/login/2fa', '/auth/login/2fa/verify'})
SELECTORS = frozenset({'#email', '#Email', '#passwd', '#Password', '#login-form', '#csrf_token',
                       'altcha-widget', '#altcha', '[name="altcha"]', '[name="csrf_token"]'})
TOKEN = re.compile(
    r'(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)'
    r'|(?P<string>"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`)'
    r'|(?P<number>\b(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?))'
    r'|(?P<word>[A-Za-z_$][A-Za-z0-9_$]*)|(?P<punct>[^\s])'
)


def _literal(raw):
    if raw.startswith('`'):
        return ''
    value = re.sub(r'\\([\\/\'\"])', r'\1', raw[1:-1])
    return re.sub(r'\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))',
                  lambda m: chr(int(m.group(1) or m.group(2), 16)), value)


def protocol_windows(source, include_all=False):
    aliases, rendered, anchors = {}, [], []
    for match in TOKEN.finditer(source):
        kind, raw = match.lastgroup, match.group()
        if kind == 'comment':
            continue
        if kind == 'string':
            value = _literal(raw)
            if 'altcha' in value.lower() or value in {'/auth/login', 'auth/login', 'login', 'passwd', 'csrf_token'}:
                anchors.append(len(rendered))
            path = urlparse(value).path if value.startswith('/auth/') else ''
            if path in PATHS:
                token = repr(path + ('?<query>' if '?' in value else ''))
            else:
                token = repr(value) if value in LITERALS | PATHS | SELECTORS else "'<string>'"
        elif kind == 'word':
            if 'altcha' in raw.lower() or raw in {'solveChallenge', 'createChallenge', 'passwd', 'csrf_token', 'ajax', 'fetch'}:
                anchors.append(len(rendered))
            if raw in WORDS:
                token = raw
            else:
                token = aliases.setdefault(raw, f'id{len(aliases) + 1}')
        elif kind == 'number':
            token = '<number>'
        else:
            token = raw if raw in '{}[]().,;:=+-*/!<>?&|%^~' else '<symbol>'
        rendered.append(token)
    if include_all and rendered:
        return [' '.join(rendered[:8000])]
    windows, covered = [], -1
    for index in anchors:
        if index <= covered:
            continue
        start, end = max(0, index - 90), min(len(rendered), index + 150)
        windows.append(' '.join(rendered[start:end]))
        covered = end - 1
        if len(windows) == 3:
            break
    return windows


class ScriptSources(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.inline, self.sources, self._parts, self._inside = [], [], [], False

    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            self._inside, self._parts = True, []
            src = dict(attrs).get('src')
            if src:
                self.sources.append(src)

    def handle_data(self, data):
        if self._inside:
            self._parts.append(data)

    def handle_endtag(self, tag):
        if tag == 'script' and self._inside:
            self.inline.append(''.join(self._parts))
            self._inside = False


def script_sources(html, base):
    parser = ScriptSources()
    parser.feed(html)
    origin = urlparse(base)
    sources = []
    for raw in parser.sources:
        try:
            url = urlparse(urljoin(base, raw))
            if (url.scheme != 'https' or url.hostname != origin.hostname
                    or (url.port or 443) != (origin.port or 443) or url.username or url.password):
                continue
            if (not re.fullmatch(r'/[A-Za-z0-9_./-]+\.js', url.path)
                    or '..' in url.path.split('/') or len(url.path) > 256):
                continue
            # Public static assets only. Never forward a page-supplied query.
            clean = urlunparse(url._replace(query='', fragment=''))
            if clean not in sources:
                sources.append(clean)
        except ValueError:
            continue
    return parser.inline, sources[:6]


def public_script_hints(html, base):
    """Public host/static basename only: never full paths, query or userinfo."""
    parser = ScriptSources()
    parser.feed(html)
    origin = urlparse(base)
    hints = []
    for raw in parser.sources:
        try:
            url = urlparse(urljoin(base, raw))
            if url.scheme != 'https' or not url.hostname or url.username or url.password:
                continue
            filename = basename(url.path)
            safe_filename = filename if re.fullmatch(r'[A-Za-z][A-Za-z_.-]{0,38}\.js', filename) else '<redacted-basename>'
            version = re.search(r'(?i)altcha[@/][~^v]?(\d{1,2}\.\d{1,3}\.\d{1,3})(?:/|$)', url.path)
            hints.append({
                'hostname': url.hostname,
                'basename': safe_filename,
                'same_origin': url.hostname == origin.hostname and (url.port or 443) == (origin.port or 443),
                'altcha_reference': 'altcha' in url.path.lower(),
                'altcha_package_version': version.group(1) if version else 'unknown',
            })
        except ValueError:
            continue
    return hints[:20]
